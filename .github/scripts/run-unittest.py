"""Run the existing unittest suite and record exact, non-skipped execution evidence."""

import argparse
import importlib.util
import inspect
import json
import logging
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("quality_policy", Path(__file__).with_name("check-quality.py"))
quality = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quality)
LOGGER = logging.getLogger("quality.unittest")


class EvidenceResult(unittest.TextTestResult):
    def __init__(self, *args, root, **kwargs):
        super().__init__(*args, **kwargs)
        self.root = root
        self.entries = []
        self.current = None
        self.metadata_errors = []

    def startTest(self, test):
        super().startTest(test)
        self.current = {"test_id": test.id(), "status": "not_run"}
        method = inspect.unwrap(getattr(test, test._testMethodName))
        source_file = inspect.getsourcefile(method)
        try:
            if source_file is None:
                raise quality.PolicyError("Test has no inspectable source")
            filename = Path(source_file).resolve().relative_to(self.root).as_posix()
            selector = f"{filename}::{method.__qualname__}"
            self.current.update(quality.evidence_test_metadata(self.root, selector))
        except (quality.PolicyError, ValueError, OSError, SyntaxError) as exc:
            self.metadata_errors.append(f"{test.id()}: {exc}")

    def stopTest(self, test):
        self.entries.append(self.current)
        self.current = None
        super().stopTest(test)

    def addSuccess(self, test):
        super().addSuccess(test)
        self.current["status"] = "passed"

    def addFailure(self, test, err):
        super().addFailure(test, err)
        if self.current is not None:
            self.current["status"] = "failure"

    def addError(self, test, err):
        super().addError(test, err)
        if self.current is not None:
            self.current["status"] = "error"

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        if self.current is not None:
            self.current["status"] = "skipped"

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.current["status"] = "expected_failure"

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.current["status"] = "unexpected_success"

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self.current["status"] = "failure"


def run(root, base, pattern):
    head = quality.git(root, "rev-parse", "HEAD")
    base = quality.git(root, "rev-parse", "--verify", f"{base}^{{commit}}")
    run_id = quality.run_context()
    if not run_id:
        raise quality.PolicyError("Set QUALITY_RUN_ID for local evidence; CI uses run ID and attempt")
    before = quality.source_digest(root)
    suite = unittest.defaultTestLoader.discover(str(root / "tests"), pattern=pattern)
    if suite.countTestCases() == 0:
        raise quality.PolicyError("No tests collected")
    runner = unittest.TextTestRunner(verbosity=2, resultclass=lambda *args, **kwargs: EvidenceResult(
        *args, root=root, **kwargs))
    result = runner.run(suite)
    unchanged = before == quality.source_digest(root)
    status = "passed" if result.wasSuccessful() and result.testsRun > 0 and unchanged and not result.metadata_errors else "violations"
    return quality.seal_report({
        "schema_version": 1, "repository": "Azure/gpt-rag-ui", "base_sha": base, "head_sha": head,
        "run_id": run_id, "source_digest": before, "status": status,
        "tests_run": result.testsRun, "tests": result.entries,
        "metadata_errors": result.metadata_errors, "source_unchanged": unchanged,
        "discovery_pattern": pattern,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--pattern", default="test_*.py")
    args = parser.parse_args()
    try:
        report = run(Path.cwd().resolve(), args.base_ref, args.pattern)
    except (quality.PolicyError, ValueError, TypeError, OSError, SyntaxError, ImportError) as exc:
        LOGGER.error("Unittest evidence incomplete: %s", exc)
        report = quality.seal_report({"schema_version": 1, "status": "error", "error": str(exc)})
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return {"passed": 0, "violations": 1, "error": 2}[report["status"]]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    raise SystemExit(main())
