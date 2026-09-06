"""Negative fixtures for the repository-local static policy, not runtime imports."""

import importlib.util
import json
import subprocess
import sys
import tempfile
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

    def test_literal_dynamic_import_joins_cycle_variable_is_not_certified(self):
        result = self.graph({"a": 'import importlib\nimportlib.import_module("b")', "b": "import a"})
        self.assertIn("cycle", {f["rule"] for f in result["findings"]})
        result = self.graph({"a": "from importlib import import_module as load\nload(target)"})
        self.assertIn("dynamic-import", {f["rule"] for f in result["findings"]})

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
        self.assertEqual([], quality.validate_moves(base, moved, {"a.py": "src/pkg/a.py"}))
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

    def test_exception_needs_exact_source_active_review_and_existing_behavior_test(self):
        source = "def run():\n try:\n  work()\n except Exception:\n  raise\n"
        handler = quality.broad_handlers("module", source)[0]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "test_failure.py").write_text("def test_failure():\n pass\n", encoding="utf-8")
            record = {**handler, "id": "boundary", "state": "active", "reason": "Boundary translation",
                  "boundary": "public operation", "failure_outcome": "propagation",
                  "diagnostic_path": "logger", "review": "protected base fixture",
                  "evidence_tests": ["test_failure.py::test_failure"]}
            self.assertEqual([], quality.validate_exception_records([handler], [record], root)[0])
            for changed in ({**record, "state": "proposed"}, {**record, "handler_fingerprint": "stale"},
                        {**record, "evidence_tests": []}, {**record, "caught_types": ["BaseException"]}):
                self.assertTrue(quality.validate_exception_records([handler], [changed], root)[0])

    def test_aggregate_needs_fixed_jobs_and_fresh_reports(self):
        results = {name: "success" for name in quality.REQUIRED_JOBS}
        reports = {name: {"status": "passed", "head_sha": "head", "base_sha": "base"}
                   for name in quality.CHECKS}
        self.assertEqual([], quality.aggregate(results, reports, "head", "base"))
        for status in ("skipped", "neutral", "failure", "cancelled", None):
            self.assertTrue(quality.aggregate({**results, "unit-tests": status}, reports, "head", "base"))
        self.assertTrue(quality.aggregate(results, {}, "head", "base"))
        self.assertTrue(quality.aggregate(results, reports, "different", "base"))


if __name__ == "__main__":
    unittest.main()
