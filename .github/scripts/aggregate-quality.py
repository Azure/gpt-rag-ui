"""Aggregate real same-workflow results using the protected evaluator, not PR output."""

import argparse
import importlib.util
import logging
import os
from pathlib import Path

spec = importlib.util.spec_from_file_location("quality_policy", Path(__file__).with_name("check-quality.py"))
quality = importlib.util.module_from_spec(spec)
spec.loader.exec_module(quality)
LOGGER = logging.getLogger("quality.aggregate")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--reports-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        root = Path.cwd().resolve()
        base = quality.git(root, "rev-parse", "--verify", f"{args.base_ref}^{{commit}}")
        head = quality.git(root, "rev-parse", "HEAD")
        policy_text = quality.base_text(root, base, ".quality/policy.json")
        if not policy_text:
            raise quality.PolicyError("Unapproved bootstrap: protected policy is missing")
        policy = quality.parse_json(policy_text)
        quality.validate_record("policy", policy)
        expected = {f"{name}.json" for name in quality.CHECKS} | {"unittest.json"}
        if {path.name for path in args.reports_dir.iterdir()} != expected:
            raise quality.PolicyError("Missing or unexpected aggregate artifact")
        tests = quality.read_record(args.reports_dir / "unittest.json")
        quality.verified_test_evidence(root, tests, head, base, quality.source_digest(root), quality.run_context())
        if tests.get("discovery_pattern") != "test_*.py":
            raise quality.PolicyError("Aggregate requires the complete unittest discovery pattern")
        reports = {name: quality.read_record(args.reports_dir / f"{name}.json") for name in quality.CHECKS}
        results = {name: os.environ.get("QUALITY_RESULT") for name in quality.CHECKS}
        results["unit-tests"] = os.environ.get("TEST_RESULT")
        results["container-tests"] = os.environ.get("CONTAINER_RESULT")
        failures = quality.aggregate(results, reports, head, base, test_report=tests,
                                     run_id=quality.run_context(), toolchain=policy["toolchain"])
        for failure in failures:
            LOGGER.error("%s", failure)
        return 1 if failures else 0
    except (quality.PolicyError, ValueError, TypeError, KeyError, OSError, SyntaxError) as exc:
        LOGGER.error("Aggregate evidence incomplete: %s", exc)
        return 2


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    raise SystemExit(main())
