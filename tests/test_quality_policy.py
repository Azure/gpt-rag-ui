"""Negative fixtures for the repository-local static policy, not runtime imports."""

import importlib.util
import copy
import datetime
import json
import os
import subprocess
import sys
import tempfile
import shutil
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / ".github" / "scripts" / "check-quality.py"
spec = importlib.util.spec_from_file_location("quality_policy", SCRIPT)
quality = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quality)


class QualityPolicyTests(unittest.TestCase):
    def graph(self, sources, **policy):
        return quality.analyze_sources(sources, policy)

    def test_clean_public_facade_and_relative_sibling_have_no_artificial_cycle(self):
        result = self.graph({
            "pkg": "from . import sibling\n",
            "pkg.sibling": "VALUE = 1\n",
            "consumer": "from pkg import sibling\n",
        })
        self.assertEqual([], result["findings"])
        self.assertEqual({"pkg.sibling"}, result["graph"]["consumer"])

    def test_all_static_cycle_shapes_fail(self):
        for sources in (
            {"a": "import b", "b": "import a"},
            {"a": "import b", "b": "import c", "c": "import a"},
            {"a": "def run():\n import b", "b": "if TYPE_CHECKING:\n import a"},
            {"pkg.a": "from . import b", "pkg.b": "from other import c", "other.c": "import pkg.a"},
        ):
            with self.subTest(sources=sources):
                self.assertIn("cycle", {f["rule"] for f in self.graph(sources)["findings"]})

    def test_forbidden_direction_is_transitive(self):
        result = self.graph(
            {"lower": "import middle", "middle": "import api", "api": ""},
            forbidden=[{"from": "lower", "to": "api"}],
        )
        self.assertEqual(["lower", "middle", "api"], next(
            f["dependency_path"] for f in result["findings"] if f["rule"] == "forbidden"
        ))

    def test_private_imports_and_attributes_require_exact_allowance(self):
        for statement in ("from pkg._internal import value", "from pkg import _internal",
                          "from pkg.public import _value as other",
                          "import pkg.public as p\nx = p._value"):
            with self.subTest(statement=statement):
                result = self.graph({
                    "pkg._internal": "value = 1", "pkg.public": "_value = 1", "consumer": statement,
                })
                self.assertIn("private-import", {f["rule"] for f in result["findings"]})
        result = self.graph(
            {"pkg._internal": "value = 1", "pkg": "from ._internal import value", "consumer": "from pkg import value"},
            private_allowances=[{"importer": "pkg", "target": "pkg._internal", "member": "value"}],
        )
        self.assertEqual([], result["findings"])

    def test_unrelated_function_alias_cannot_hide_private_access(self):
        result = self.graph({
            "owner": "_private = 1",
            "consumer": "def first():\n import owner as client\n return client._private\n"
                        "def unrelated():\n import os as client\n return client.name",
        })
        self.assertIn("private-import", {f["rule"] for f in result["findings"]})

    def test_private_package_init_resolves_its_actual_package_owner(self):
        result = self.graph(
            {"pkg": "", "pkg._internal": "from ..public import value", "pkg.public": "value = 1"},
            modules=[{"import_name": "pkg._internal", "path": "pkg/_internal/__init__.py"}],
        )
        self.assertEqual([], result["findings"])
        self.assertEqual({"pkg.public"}, result["graph"]["pkg._internal"])

    def test_literal_dynamic_import_joins_cycle_variable_is_not_certified(self):
        result = self.graph({"a": 'import importlib\nimportlib.import_module("b")', "b": "import a"})
        self.assertIn("cycle", {f["rule"] for f in result["findings"]})
        result = self.graph({"a": "from importlib import import_module as load\nload(target)"})
        self.assertIn("dynamic-import", {f["rule"] for f in result["findings"]})
        for statement in ('from builtins import __import__ as load\nload("b")',
                          'import importlib as i\ni.import_module(name="b")',
                          'import importlib\nload = importlib.import_module\nload("b")'):
            with self.subTest(statement=statement):
                self.assertIn("cycle", {f["rule"] for f in self.graph({"a": statement, "b": "import a"})["findings"]})

    def test_broad_handler_aliases_tuples_logging_and_groups_are_inventoried(self):
        samples = [
            "try:\n run()\nexcept:\n pass",
            "try:\n run()\nexcept Exception:\n logger.exception('failed')",
            "try:\n run()\nexcept BaseException:\n raise",
            "from builtins import Exception as Error\ntry:\n run()\nexcept Error:\n raise",
            "import builtins as b\ntry:\n run()\nexcept (ValueError, b.Exception):\n raise",
            "try:\n run()\nexcept* Exception:\n raise",
            "Error = Exception\ntry:\n run()\nexcept Error:\n raise",
            "try:\n run()\nexcept get_error():\n raise",
        ]
        for source in samples:
            with self.subTest(source=source):
                self.assertEqual(1, len(quality.broad_handlers("module", source)))
        self.assertEqual([], quality.broad_handlers("module", "try:\n run()\nexcept ValueError:\n raise"))

    def test_handler_fingerprint_changes_when_outcome_changes(self):
        a = quality.broad_handlers("module", "try:\n run()\nexcept Exception:\n raise")[0]
        b = quality.broad_handlers("module", "try:\n run()\nexcept Exception:\n return_value = None")[0]
        self.assertNotEqual(a["handler_fingerprint"], b["handler_fingerprint"])

    def test_debt_is_individual_and_multiplicity_sensitive(self):
        a = {"module_id": "a", "symbol": "run", "source_fingerprint": "source",
             "rule": "assignment", "message_fingerprint": "message"}
        baseline = [{**a, "id": "legacy-a", "occurrences": 1}]
        self.assertEqual([], quality.compare_debt([a], baseline))
        self.assertTrue(quality.compare_debt([{**a, "rule": "return-value"}], baseline))
        self.assertTrue(quality.compare_debt([a, a], baseline))
        self.assertTrue(quality.compare_debt([], baseline))

    def test_protected_baseline_cannot_be_grown_or_scope_reduced(self):
        self.assertTrue(quality.policy_changes({"a"}, set(), [], []))
        self.assertTrue(quality.policy_changes({"a"}, {"a"}, [], [{"id": "new"}]))
        self.assertEqual([], quality.policy_changes({"a"}, {"a", "b"}, [], []))

    def test_move_requires_one_to_one_identity(self):
        base = [{"id": "a", "path": "a.py"}]
        moved = [{"id": "a", "path": "src/pkg/a.py"}]
        self.assertEqual([], quality.validate_moves(
            base, moved, {"a.py": "src/pkg/a.py"}, {"a.py": "x = 1"}, {"src/pkg/a.py": "\nx = 1"}))
        self.assertTrue(quality.validate_moves(base, moved + [{"id": "a", "path": "other.py"}], {}))
        self.assertTrue(quality.validate_moves(base, moved, {}))

    def test_annotation_removal_and_suppression_are_policy_findings(self):
        old = "def run(value: str) -> str:\n return value\n"
        new = "def run(value):\n return value  # type: ignore\n"
        self.assertTrue(quality.source_policy_changes(old, new))
        self.assertEqual([], quality.source_policy_changes(old, "\n" + old))

    def test_missing_invalid_or_unknown_record_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "policy.json"
            with self.assertRaises(quality.PolicyError):
                quality.read_record(path)
            for content in ("{", json.dumps({"schema_version": 999})):
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(quality.PolicyError):
                    quality.read_record(path)

    def test_real_ruff_rejects_new_undefined_name(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.py"
            source.write_text("result = undefined_name\n", encoding="utf-8")
            result = quality.execute(
                [sys.executable, "-m", "ruff", "check", "--isolated", "--select", "F821",
                 "--output-format", "json", str(source)],
                cwd=root, allowed=(0, 1),
            )
            self.assertEqual(1, result.returncode)
            self.assertEqual("F821", json.loads(result.stdout)[0]["code"])

    def test_real_mypy_rejects_new_in_scope_diagnostic(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "sample.py"
            source.write_text('count: int = "wrong"\n', encoding="utf-8")
            config = root / "mypy.ini"
            config.write_text("[mypy]\npython_version = 3.12\n", encoding="utf-8")
            result = quality.execute(
                [sys.executable, "-m", "mypy", "--config-file", str(config), "--no-incremental",
                 "--output", "json", str(source)], cwd=root, allowed=(0, 1),
            )
            self.assertEqual(1, result.returncode)
            diagnostic = json.loads(result.stdout.splitlines()[0])
            self.assertEqual("assignment", diagnostic["code"])
            identity = quality.diagnostic_identity(diagnostic, source.read_text(), "sample")
            self.assertTrue(quality.compare_debt([identity], []))

    def test_timeout_and_crash_are_errors_not_success(self):
        with patch.object(quality.subprocess, "run", side_effect=subprocess.TimeoutExpired("tool", 1)):
            with self.assertRaises(quality.PolicyError):
                quality.execute(["tool"], cwd=Path.cwd())
        with patch.object(quality.subprocess, "run", return_value=subprocess.CompletedProcess(["tool"], 2, "", "crashed")):
            with self.assertRaises(quality.PolicyError):
                quality.execute(["tool"], cwd=Path.cwd())

    def test_exception_never_accepts_test_existence_as_execution(self):
        source = "def run():\n try:\n  work()\n except Exception:\n  raise\n"
        handler = quality.broad_handlers("module", source)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "test_failure.py").write_text("def test_failure():\n pass\n", encoding="utf-8")
            record = {**handler, "id": "boundary", "state": "active", "reason": "Boundary translation",
                  "boundary": "public operation", "failure_outcome": "propagation",
                  "diagnostic_path": "logger", "review": "protected base fixture",
                  "evidence_tests": ["test_failure.py::test_failure"]}
            self.assertTrue(quality.validate_exception_records([handler], [record], root)[0])
            for changed in ({**record, "state": "proposed"}, {**record, "handler_fingerprint": "stale"},
                        {**record, "evidence_tests": []}, {**record, "caught_types": ["BaseException"]}):
                self.assertTrue(quality.validate_exception_records([handler], [changed], root)[0])

    def test_aggregate_needs_fixed_jobs_and_fresh_reports(self):
        results = {name: "success" for name in quality.REQUIRED_JOBS}
        reports = {name: {"status": "passed", "head_sha": "head", "base_sha": "base"}
                   for name in quality.CHECKS}
        self.assertTrue(quality.aggregate(results, reports, "head", "base"))
        for status in ("skipped", "neutral", "failure", "cancelled", None):
            self.assertTrue(quality.aggregate({**results, "unit-tests": status}, reports, "head", "base"))
        self.assertTrue(quality.aggregate(results, {}, "head", "base"))
        self.assertTrue(quality.aggregate(results, reports, "different", "base"))


class QualityHardeningTests(unittest.TestCase):
    def records(self):
        root = SCRIPT.parents[2]
        return {name: json.loads((root / ".quality" / f"{name}.json").read_text())
                for name in quality.RECORD_NAMES}

    def test_four_record_schemas_require_every_field_and_reject_unknowns(self):
        records = self.records()
        quality.validate_records(records)
        for name, record in records.items():
            for field in record:
                with self.subTest(record=name, missing=field):
                    candidate = copy.deepcopy(records)
                    del candidate[name][field]
                    with self.assertRaises(quality.PolicyError):
                        quality.validate_records(candidate)
            candidate = copy.deepcopy(records)
            candidate[name]["self_approved"] = True
            with self.assertRaises(quality.PolicyError):
                quality.validate_records(candidate)

    def test_nested_schema_types_references_duplicates_and_paths_fail(self):
        mutations = [
            lambda r: r["policy"]["modules"][0].update(path="../outside.py"),
            lambda r: r["policy"]["modules"][0].update(extra="ignored"),
            lambda r: r["policy"]["modules"][0].update(area="unclassified"),
            lambda r: r["policy"]["modules"][0].update(public_exports=["*"]),
            lambda r: r["policy"]["modules"][0].pop("responsibilities"),
            lambda r: r["policy"]["modules"].append(copy.deepcopy(r["policy"]["modules"][0])),
            lambda r: r["policy"]["toolchain"].update(ruff=">=0.16"),
            lambda r: r["policy"]["required_checks"].remove("unit-tests"),
            lambda r: r["typing-scope"]["module_ids"].append("unknown"),
            lambda r: r["typing-scope"].update(schema_version=True),
            lambda r: r["typing-scope"].update(move_map={"a.py": "x.py", "b.py": "x.py"}),
        ]
        for mutate in mutations:
            records = self.records()
            mutate(records)
            with self.subTest(mutation=mutate), self.assertRaises(quality.PolicyError):
                quality.validate_records(records)

    def test_nonempty_debt_and_exception_schemas_validate_all_fields(self):
        records = self.records()
        module = records["typing-scope"]["module_ids"][0]
        records["typing-baseline"]["entries"] = [{
            "id": "debt", "module_id": module, "symbol": "run", "review": "protected fixture",
            "source_fingerprint": "a" * 64, "rule": "assignment", "message_fingerprint": "b" * 64,
            "occurrences": 1, "introduced_at": "c" * 40, "rationale": "Inherited exact finding",
            "removal_stage": "blocking"}]
        records["exceptions"]["entries"] = [{
            "id": "boundary", "module_id": module, "symbol": "run", "review": "protected fixture",
            "handler_fingerprint": "d" * 64, "caught_types": ["Exception"], "boundary": "SDK",
            "reason": "Required translation", "failure_outcome": "failure-translation",
            "diagnostic_path": "raised domain error", "evidence_tests": ["tests/test_failure.py::Case.test_failure"],
            "state": "active", "review_by_stage": "strict", "expires_on": "2099-01-01"}]
        quality.validate_records(records)
        for name in ("typing-baseline", "exceptions"):
            for field in records[name]["entries"][0]:
                candidate = copy.deepcopy(records)
                del candidate[name]["entries"][0][field]
                with self.subTest(record=name, missing=field), self.assertRaises(quality.PolicyError):
                    quality.validate_records(candidate)
        for mutate in (
            lambda r: r["typing-baseline"]["entries"][0].update(occurrences=True),
            lambda r: r["typing-baseline"]["entries"][0].update(source_fingerprint="*"),
            lambda r: r["exceptions"]["entries"][0].update(state="approved-by-myself"),
            lambda r: r["exceptions"]["entries"][0].update(expires_on="tomorrow"),
            lambda r: r["exceptions"]["entries"][0].update(evidence_tests=["tests/a.py::test_missing_class"]),
            lambda r: r["exceptions"]["entries"].append({**r["exceptions"]["entries"][0], "id": "duplicate-site"}),
        ):
            candidate = copy.deepcopy(records)
            mutate(candidate)
            with self.subTest(mutation=mutate), self.assertRaises(quality.PolicyError):
                quality.validate_records(candidate)

    def test_json_duplicate_keys_are_not_silently_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exceptions.json"
            path.write_text('{"schema_version":1,"entries":[],"entries":[]}')
            with self.assertRaises(quality.PolicyError):
                quality.read_record(path)

    def test_signature_policy_preserves_qualified_vars_varargs_and_types(self):
        pairs = [
            ("class A:\n def run(self, x: int) -> int: return x\nclass B:\n def run(self): pass",
             "class A:\n def run(self, x): return x\nclass B:\n def run(self): pass"),
            ("def run(*x: int, **kw: str) -> int: return 1",
             "def run(*x, **kw) -> int: return 1"),
            ("def run(x: int) -> int: return x",
             "from typing import Any as Loose\ndef run(x: Loose) -> Loose: return x"),
            ("value: int = 1", "value = 1"),
            ("def run(x: int) -> int: return x", "def other(x): return x"),
            ("def run(x: int) -> int: return x", "def run(y: int) -> int: return y"),
            ("def run(x: int) -> int: return x",
             "from typing import no_type_check as unchecked\n@unchecked\ndef run(x: int) -> int: return x"),
            ("from typing import no_type_check as unchecked\nclass A:\n def run(self, x: int): pass",
             "from typing import no_type_check as unchecked\n@unchecked\nclass A:\n def run(self, x: int): pass"),
            ("Alias = int\ndef run(x: Alias) -> Alias: return x",
             "from typing import Any\nAlias = Any\ndef run(x: Alias) -> Alias: return x"),
            ("from typing import overload\n@overload\ndef run(x: int) -> int: ...\ndef run(x): return x",
             "from typing import overload\n@overload\ndef run(x): ...\ndef run(x): return x"),
        ]
        for old, new in pairs:
            with self.subTest(new=new):
                self.assertTrue(quality.source_policy_changes(old, new))
        self.assertEqual([], quality.source_policy_changes("x = '# type: ignore'", "x = '# noqa'"))
        self.assertEqual([], quality.source_policy_changes(
            "from typing import Literal\ndef run() -> Literal['a']: return 'a'",
            "from typing import Literal, Protocol\ndef run() -> Literal['a']: return 'a'"))

    def test_count_neutral_suppression_move_and_alias_bypass_fail(self):
        old = "a = wrong  # type: ignore[name-defined]\nb = other\n"
        new = "a = wrong\nb = other  # type: ignore[name-defined]\n"
        self.assertTrue(quality.source_policy_changes(old, new))
        self.assertTrue(quality.source_policy_changes(
            "", "from typing import no_type_check_decorator as bypass"))
        self.assertEqual([], quality.source_policy_changes(old, "\n" + old))

    def test_moves_need_unchanged_source_and_split_debt_cannot_duplicate(self):
        base = [{"id": "owner", "path": "old.py"}]
        moved = [{"id": "owner", "path": "new.py"}]
        mapping = {"old.py": "new.py"}
        self.assertTrue(quality.validate_moves(base, moved, mapping))
        self.assertTrue(quality.validate_moves(base, moved, mapping,
                                             {"old.py": "x = 1"}, {"new.py": "x = 'new debt'"}))
        self.assertTrue(quality.validate_moves(base, [{"id": "child", "path": "new.py"}], mapping))
        debt = dict(id="original", module_id="owner", symbol="run", source_fingerprint="a",
                    rule="assignment", message_fingerprint="b", occurrences=1)
        self.assertTrue(quality.policy_changes({"owner"}, {"owner", "child"}, [debt],
                                             [debt, {**debt, "id": "copy", "module_id": "child"}]))
        self.assertEqual([], quality.effective_debt([debt], []))
        self.assertEqual([], quality.effective_debt([], [debt]))
        self.assertEqual([debt], quality.effective_debt([debt], [debt]))
        self.assertEqual([], quality.compare_debt([], quality.effective_debt([debt], [])))
        self.assertTrue(quality.compare_debt([debt], quality.effective_debt([], [debt])))

    def test_adapter_exports_and_calls_are_exact_not_just_no_definitions(self):
        source = "from pkg.owner import run as run\n"
        declaration = quality.adapter_surface(source)
        modules = [{"id": "legacy", "import_name": "legacy", "area": "legacy", "adapter": declaration},
                   {"id": "owner", "import_name": "pkg.owner", "area": "services",
                    "public_exports": ["run"]}]
        def check(candidate, owner="def run(): pass"):
            return quality.validate_adapters({"legacy": candidate, "pkg.owner": owner}, modules)
        self.assertEqual([], check(source))
        for mutation in (source + "state = []", source + "run()", "from pkg.owner import missing as run",
                         source + "from os import system", source + "from pkg.owner import run as extra",
                         "from pkg.owner import *"):
            with self.subTest(mutation=mutation):
                self.assertTrue(check(mutation))
        self.assertTrue(check(source, "def other(): pass"))

    def test_dynamic_inventory_joins_all_targets_and_requires_live_evidence(self):
        source = "from importlib import import_module as load\nload(target)\n"
        site = quality.dynamic_sites("a", source)[0]
        entry = {**site, "targets": ["b"], "evidence_tests": ["tests/test_a.py::Case.test_failure"],
                 "reason": "Bounded plugin registry", "review": "protected fixture"}
        policy = {"dynamic_imports": [entry]}
        sources = {"a": source, "b": "import a"}
        result = quality.analyze_sources(sources, policy)
        rules = {f["rule"] for f in result["findings"]}
        self.assertIn("dynamic-evidence", rules)
        self.assertIn("cycle", rules)
        result = quality.analyze_sources(sources, policy, verified_tests=set(entry["evidence_tests"]))
        self.assertNotIn("dynamic-evidence", {f["rule"] for f in result["findings"]})
        entry["site_fingerprint"] = "stale"
        self.assertTrue(quality.analyze_sources(sources, policy)["findings"])
        first = "def first():\n from importlib import import_module\n import_module(target)\n"
        second = "def second():\n from importlib import import_module\n import_module(target)\n"
        site = quality.dynamic_sites("a", first)[0]
        record = {**entry, **site}
        result = quality.analyze_sources({"a": first + second, "b": ""}, {"dynamic_imports": [record]},
                                         verified_tests=set(record["evidence_tests"]))
        self.assertIn("dynamic-import", {f["rule"] for f in result["findings"]})
        records = self.records()
        records["policy"]["dynamic_imports"] = [{**record, "module": records["policy"]["modules"][0]["import_name"],
                                                 "targets": []}]
        with self.assertRaises(quality.PolicyError):
            quality.validate_records(records)

    def test_malformed_mypy_severity_is_not_silently_uncovered(self):
        valid = {"file": "a.py", "line": 1, "column": 1, "end_line": 1, "end_column": 2,
                 "message": "bad assignment", "hint": None, "code": "assignment", "severity": "error"}
        self.assertEqual([valid], quality.mypy_diagnostics(json.dumps(valid), 1))
        for changed in ({**valid, "severity": "unknown"}, {**valid, "severity": None},
                        {**valid, "line": True}, {**valid, "code": None}):
            with self.subTest(diagnostic=changed), self.assertRaises(quality.PolicyError):
                quality.mypy_diagnostics(json.dumps(changed), 0)

    def test_handler_approval_binds_try_operation_and_distinct_sites(self):
        before = "try:\n safe()\nexcept Exception:\n raise\n"
        after = "try:\n different()\nexcept Exception:\n raise\n"
        self.assertNotEqual(quality.broad_handlers("a", before)[0]["handler_fingerprint"],
                            quality.broad_handlers("a", after)[0]["handler_fingerprint"])
        handlers = quality.broad_handlers("a", before + before)
        self.assertEqual(2, len({h["handler_fingerprint"] for h in handlers}))

    def test_expiry_stage_and_executed_exception_evidence_are_required(self):
        handler = quality.broad_handlers("a", "try:\n work()\nexcept Exception:\n raise")[0]
        selector = "tests/test_a.py::Case.test_failure"
        record = {**handler, "id": "approved", "state": "active", "boundary": "SDK",
                  "reason": "Preserve failure translation", "failure_outcome": "propagation",
                  "diagnostic_path": "propagated exception", "evidence_tests": [selector],
                  "review": "protected fixture", "review_by_stage": "strict",
                  "expires_on": "2099-01-01"}
        kwargs = {"verified_tests": {selector}, "stage": "blocking",
                  "today": datetime.date(2026, 9, 6)}
        self.assertEqual([], quality.validate_exception_records([handler], [record], Path.cwd(), **kwargs)[0])
        for changed in ({**record, "expires_on": "2026-09-05"}, {**record, "review_by_stage": "bootstrap"},
                        {**record, "state": "maintainer-approved"}, {**record, "caught_types": ["BaseException"]}):
            self.assertTrue(quality.validate_exception_records([handler], [changed], Path.cwd(), **kwargs)[0])
        self.assertTrue(quality.validate_exception_records([handler], [record], Path.cwd())[0])

    def test_protected_minimum_keeps_ids_and_covers_every_new_module(self):
        old = [{"id": "stable", "import_name": "a", "path": "a.py"}]
        new = [{"id": "laundered", "import_name": "a", "path": "a.py"},
               {"id": "new", "import_name": "b", "path": "b.py"}]
        identities, scope = quality.effective_scope(old, new, {"stable"}, set(), {"a", "b", "unknown"})
        self.assertEqual("stable", identities["a"])
        self.assertTrue({"stable", "new", "unknown"} <= scope)

    def test_aggregate_checks_policy_digest_nested_outcomes_and_run_context(self):
        results, reports, tests = quality_fixture_reports()
        kwargs = {"test_report": tests, "run_id": "run:1", "toolchain": {"ruff": "0.16.5"}}
        self.assertEqual([], quality.aggregate(results, reports, "head", "base", **kwargs))
        for mutation in (
            lambda r: r["lint"].update(policy_sha="head"),
            lambda r: r["lint"]["checks"]["lint"].update(status="not_run"),
            lambda r: r["lint"].update(run_id="previous"),
            lambda r: r["lint"].update(toolchain={"ruff": "wrong"}),
            lambda r: r["lint"]["checks"]["lint"]["findings"].append({"rule": "hidden"}),
        ):
            candidate = copy.deepcopy(reports)
            mutation(candidate)
            quality.seal_report(candidate["lint"])
            self.assertTrue(quality.aggregate(results, candidate, "head", "base", **kwargs))
        reports["lint"]["duration_seconds"] = 99
        self.assertTrue(quality.aggregate(results, reports, "head", "base", **kwargs))


class EvidenceIntegrationTests(unittest.TestCase):
    def fixture(self, root):
        (root / "tests").mkdir()
        (root / "sample.py").write_text("value: int = 1\n", encoding="utf-8")
        (root / "tests" / "test_boundary.py").write_text(
            "import os, unittest\nclass Boundary(unittest.TestCase):\n"
            " def test_failure(self):\n"
            "  mode = os.environ.get('FIXTURE_MODE', 'passed')\n"
            "  if mode == 'skipped': self.skipTest('fixture')\n"
            "  with self.subTest(boundary=True): self.assertNotEqual(mode, 'failed')\n", encoding="utf-8")
        quality.execute(["git", "init", "--quiet"], cwd=root)
        quality.execute(["git", "add", "."], cwd=root)
        quality.execute(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                         "commit", "--quiet", "-m", "fixture"], cwd=root)
        return quality.git(root, "rev-parse", "HEAD")

    def test_real_unittest_receipt_rejects_skips_stale_source_and_failed_subtests(self):
        runner = SCRIPT.with_name("run-unittest.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            sha = self.fixture(root)
            env = {**os.environ, "QUALITY_RUN_ID": "fixture:1"}
            env.pop("GITHUB_RUN_ID", None)
            for mode in ("passed", "skipped", "failed"):
                result = subprocess.run([sys.executable, str(runner), "--base-ref", sha,
                                         "--report", str(root / "evidence.json")],
                                        cwd=root, env={**env, "FIXTURE_MODE": mode},
                                        text=True, capture_output=True, timeout=60)
                report = quality.read_record(root / "evidence.json")
                selector = "tests/test_boundary.py::Boundary.test_failure"
                self.assertEqual(1, report["tests_run"], result.stderr)
                if mode == "failed":
                    self.assertEqual(1, result.returncode, result.stderr)
                    with self.assertRaises(quality.PolicyError):
                        quality.verified_test_evidence(root, report, sha, sha, quality.source_digest(root), "fixture:1")
                    continue
                self.assertEqual(0, result.returncode, result.stderr)
                verified = quality.verified_test_evidence(root, report, sha, sha, quality.source_digest(root), "fixture:1")
                self.assertEqual({selector} if mode == "passed" else set(), verified)
                for field, wrong in (("head_sha", "other"), ("run_id", "old"), ("source_digest", "stale")):
                    modified = {**report, field: wrong}
                    quality.seal_report(modified)
                    with self.assertRaises(quality.PolicyError):
                        quality.verified_test_evidence(root, modified, sha, sha, quality.source_digest(root), "fixture:1")
                changed = copy.deepcopy(report)
                changed["tests"][0]["symbol_fingerprint"] = "wrong"
                quality.seal_report(changed)
                with self.assertRaises(quality.PolicyError):
                    quality.verified_test_evidence(root, changed, sha, sha, quality.source_digest(root), "fixture:1")

    def protected_fixture(self, root):
        (root / ".quality").mkdir()
        (root / ".github" / "scripts").mkdir(parents=True)
        for filename in ("check-quality.py", "run-unittest.py", "aggregate-quality.py"):
            shutil.copy2(SCRIPT.with_name(filename), root / ".github" / "scripts" / filename)
        sha = self.fixture(root)
        policy = {
            "schema_version": 1, "runtime_roots": ["*.py"], "modules": [
                {"id": "sample", "path": "sample.py", "import_name": "sample", "area": "services",
                 "public_exports": ["value"], "legacy_aliases": [], "source_revision": sha,
                 "responsibilities": "fixture", "private_modules": [], "allowed_importers": [],
                 "typing_status": "blocking"}],
            "toolchain": {name: quality.importlib.metadata.version(name) for name in quality.TOOLS},
            "required_checks": list(quality.REQUIRED_JOBS), "forbidden": [], "private_allowances": [],
            "dynamic_imports": [], "review": {"owner": "@fixture", "reference": "fixture",
                                               "state": "active", "reason": "Test-only protected policy"}}
        records = {"policy": policy,
                   "typing-scope": {"schema_version": 1, "module_ids": ["sample"], "coverage_stage": "blocking",
                                    "planned_expansion": ["strict"], "move_map": {}, "review": "fixture"},
                   "typing-baseline": {"schema_version": 1, "entries": []},
                   "exceptions": {"schema_version": 1, "entries": []}}
        for name, record in records.items():
            (root / ".quality" / f"{name}.json").write_text(json.dumps(record), encoding="utf-8")
        (root / "pyproject.toml").write_text(
            '[tool.mypy]\npython_version="3.12"\ncheck_untyped_defs=true\n', encoding="utf-8")
        quality.execute(["git", "add", "."], cwd=root)
        quality.execute(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                         "commit", "--quiet", "-m", "protected policy"], cwd=root)
        return quality.git(root, "rev-parse", "HEAD")

    def test_real_protected_base_rejects_config_codeowners_and_annotation_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            base = self.protected_fixture(root)
            self.assertEqual("passed", quality.run_checks(root, base, ("policy",))["status"])
            for path, content, rule in (
                ("sample.py", "value = 1\n", "annotation-removal"),
                ("sample.py", "value: int = 1  # type: ignore\n", "suppression-growth"),
                (".github/CODEOWNERS", "* @candidate\n", "policy-change"),
                ("pyproject.toml", "[tool.mypy]\nignore_errors=true\n", "policy-change"),
                (".github/scripts/check-quality.py", "raise SystemExit(0)\n", "policy-change"),
            ):
                target = root / path
                old = target.read_text() if target.exists() else None
                target.write_text(content, encoding="utf-8")
                try:
                    report = quality.run_checks(root, base, ("policy",))
                    self.assertIn(rule, {f["rule"] for f in report["checks"]["policy"]["findings"]})
                finally:
                    if old is None:
                        target.unlink()
                    else:
                        target.write_text(old, encoding="utf-8")
            (root / "new.py").write_text("value: int = 'wrong'\n", encoding="utf-8")
            report = quality.run_checks(root, base, ("typing",))
            self.assertEqual("violations", report["status"])
            self.assertIn("new", report["coverage"]["blocking"])

    def test_auto_typed_new_module_scope_must_survive_the_next_pr(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            base = self.protected_fixture(root)
            path = root / ".quality" / "policy.json"
            policy = quality.read_record(path)
            (root / "added.py").write_text("value: int = 1\n", encoding="utf-8")
            added = {**policy["modules"][0], "id": "added", "import_name": "added",
                     "path": "added.py", "typing_status": "uncovered"}
            policy["modules"].append(added)
            path.write_text(json.dumps(policy), encoding="utf-8")
            report = quality.run_checks(root, base, ("policy", "typing"))
            self.assertIn("added", report["coverage"]["blocking"])
            self.assertIn("unrecorded-coverage", {f["rule"] for f in report["checks"]["policy"]["findings"]})
            added["typing_status"] = "blocking"
            path.write_text(json.dumps(policy), encoding="utf-8")
            scope_path = root / ".quality" / "typing-scope.json"
            scope = quality.read_record(scope_path)
            scope["module_ids"].append("added")
            scope_path.write_text(json.dumps(scope), encoding="utf-8")
            self.assertEqual("passed", quality.run_checks(root, base, ("policy", "typing"))["status"])
            quality.execute(["git", "add", "."], cwd=root)
            quality.execute(["git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                             "commit", "--quiet", "-m", "persisted expansion"], cwd=root)
            next_base = quality.git(root, "rev-parse", "HEAD")
            scope["module_ids"].remove("added")
            scope_path.write_text(json.dumps(scope), encoding="utf-8")
            added["typing_status"] = "uncovered"
            path.write_text(json.dumps(policy), encoding="utf-8")
            report = quality.run_checks(root, next_base, ("policy", "typing"))
            self.assertIn("added", report["coverage"]["blocking"])
            self.assertIn("scope-reduction", {f["rule"] for f in report["checks"]["policy"]["findings"]})

    def test_real_aggregate_rejects_failed_jobs_and_resealed_wrong_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            base = self.protected_fixture(root)
            reports = root / ".artifacts"
            reports.mkdir()
            env = {**os.environ, "QUALITY_RUN_ID": "fixture:1", "QUALITY_RESULT": "success",
                   "TEST_RESULT": "success", "CONTAINER_RESULT": "success"}
            env.pop("GITHUB_RUN_ID", None)
            result = subprocess.run([sys.executable, str(SCRIPT.with_name("run-unittest.py")),
                                     "--base-ref", base, "--report", str(reports / "unittest.json")],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(0, result.returncode, result.stderr)
            tests = quality.read_record(reports / "unittest.json")
            for name in quality.CHECKS:
                report = {key: tests[key] for key in ("schema_version", "repository", "head_sha", "base_sha",
                                                     "run_id", "source_digest", "status")}
                report.update(policy_sha=base, toolchain={n: quality.importlib.metadata.version(n) for n in quality.TOOLS},
                              checks={name: {"status": "passed", "findings": []}},
                              test_evidence_digest=tests["artifact_integrity"])
                (reports / f"{name}.json").write_text(json.dumps(quality.seal_report(report)), encoding="utf-8")
            command = [sys.executable, "-O", str(SCRIPT.with_name("aggregate-quality.py")),
                       "--base-ref", base, "--reports-dir", str(reports)]
            result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(0, result.returncode, result.stderr)
            originals = {path: path.read_text() for path in reports.glob("*.json")}
            for field in ("head_sha", "base_sha", "run_id", "source_digest"):
                for path, content in originals.items():
                    forged = json.loads(content)
                    forged[field] = "agreed-but-not-the-independent-expected-value"
                    path.write_text(json.dumps(quality.seal_report(forged)), encoding="utf-8")
                result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=60)
                self.assertNotEqual(0, result.returncode, result.stderr)
                for path, content in originals.items():
                    path.write_text(content, encoding="utf-8")
            for job in ("TEST_RESULT", "CONTAINER_RESULT"):
                for state in ("skipped", "neutral", "failure", "cancelled", ""):
                    result = subprocess.run(command, cwd=root, env={**env, job: state},
                                            capture_output=True, text=True, timeout=60)
                    self.assertNotEqual(0, result.returncode, result.stderr)
            path = reports / "lint.json"
            report = quality.read_record(path)
            report["policy_sha"] = "candidate"
            path.write_text(json.dumps(quality.seal_report(report)), encoding="utf-8")
            result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=60)
            self.assertNotEqual(0, result.returncode, result.stderr)
            path.unlink()
            result = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=60)
            self.assertNotEqual(0, result.returncode, result.stderr)


def quality_fixture_reports():
    tests = {"schema_version": 1, "repository": "Azure/gpt-rag-ui", "head_sha": "head",
             "base_sha": "base", "run_id": "run:1", "source_digest": "sources", "status": "passed",
             "tests": [], "tests_run": 1}
    quality.seal_report(tests)
    reports = {}
    for name in quality.CHECKS:
        report = {key: tests[key] for key in ("schema_version", "repository", "head_sha", "base_sha",
                                              "run_id", "source_digest", "status")}
        report.update(policy_sha="base", toolchain={"ruff": "0.16.5"}, duration_seconds=1,
                      checks={name: {"status": "passed", "findings": []}},
                      test_evidence_digest=tests["artifact_integrity"])
        quality.seal_report(report)
        reports[name] = report
    return {name: "success" for name in quality.REQUIRED_JOBS}, reports, tests


if __name__ == "__main__":
    unittest.main()
