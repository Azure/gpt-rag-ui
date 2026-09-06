"""Read-only Python quality checks. Candidate records cannot approve their own debt."""

from __future__ import annotations

import argparse
import ast
from collections import Counter, deque
import graphlib
import hashlib
import importlib.metadata
import json
import logging
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import tomllib

CHECKS = ("lint", "typing", "architecture", "exceptions", "policy")
REQUIRED_JOBS = (*CHECKS, "unit-tests")
LOGGER = logging.getLogger("quality")
TIMEOUT = 300


class PolicyError(RuntimeError):
    """Invalid inputs or incomplete execution; never a passing check."""


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def read_record(path):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise PolicyError(f"Cannot read policy record: {path.name}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise PolicyError(f"Unsupported policy record: {path.name}")
    return value


def execute(command, *, cwd, allowed=(0,)):
    try:
        result = subprocess.run(command, cwd=cwd, text=True, encoding="utf-8",
                                capture_output=True, timeout=TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PolicyError(f"Tool did not complete: {command[0]}") from exc
    if result.returncode not in allowed:
        raise PolicyError(f"Tool failed ({result.returncode}): {command[0]}: {result.stderr[:1000]}")
    return result


def git(root, *args):
    return execute(["git", "--no-pager", *args], cwd=root).stdout.strip()


def base_text(root, revision, path):
    result = execute(["git", "show", f"{revision}:{path}"], cwd=root, allowed=(0, 128))
    return result.stdout if result.returncode == 0 else None


def discover(root):
    """Discover new root modules/packages independently of candidate policy inventory."""
    files = set(root.glob("*.py"))
    for directory in root.iterdir():
        if directory.is_dir() and not directory.name.startswith(".") and (
            directory.name == "src" or
            ((directory / "__init__.py").exists() and directory.name not in {"tests", "build", "dist"})
        ):
            files.update(directory.rglob("*.py"))
    if not files:
        raise PolicyError("No runtime sources discovered")
    modules = {}
    paths = {}
    for path in sorted(files):
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise PolicyError("Runtime source escapes repository")
        relative = path.relative_to(root).as_posix()
        parts = list(path.relative_to(root).with_suffix("").parts)
        if parts[0] == "src":
            parts.pop(0)
        if parts[-1] == "__init__":
            parts.pop()
        name = ".".join(parts)
        if name in modules:
            raise PolicyError(f"Duplicate module identity: {name}")
        modules[name] = path.read_text(encoding="utf-8")
        paths[name] = relative
    return modules, paths


def finding(rule, module, line, reason, **details):
    return {"rule": rule, "module": module, "line": line, "reason": reason, **details}


def analyze_sources(sources, policy):
    graph = {name: set() for name in sources}
    findings = []
    allowances = {(a["importer"], a["target"], a["member"])
                  for a in policy.get("private_allowances", [])}
    first_roots = {name.split(".")[0] for name in sources}

    def add(importer, target, member, line):
        if target not in sources:
            if target.split(".")[0] in first_roots:
                findings.append(finding("unresolved-import", importer, line, target))
            return
        graph[importer].add(target)
        private = any(p.startswith("_") for p in target.split(".")) or member.startswith("_")
        if private and importer != target and (importer, target, member) not in allowances:
            findings.append(finding("private-import", importer, line, f"{target}.{member}"))

    for name, source in sources.items():
        tree = ast.parse(source, filename=name)
        aliases = {}
        dynamic_names = {"__import__", "importlib.import_module"}
        # Packages are identified from inventory; fixtures may infer a parent with children.
        package = name if any(other.startswith(name + ".") for other in sources) else name.rpartition(".")[0]
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    aliases[alias.asname or alias.name] = alias.name
                    add(name, alias.name, "", node.lineno)
                    if alias.name == "importlib":
                        dynamic_names.add(f"{alias.asname or alias.name}.import_module")
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    segments = package.split(".") if package else []
                    if node.level > len(segments):
                        findings.append(finding("unresolved-import", name, node.lineno, "Relative import escapes root"))
                        continue
                    prefix = ".".join(segments[:len(segments) - node.level + 1])
                    target = ".".join(p for p in (prefix, node.module) if p)
                else:
                    target = node.module or ""
                for alias in node.names:
                    child = f"{target}.{alias.name}"
                    if target == "importlib" and alias.name == "import_module":
                        dynamic_names.add(alias.asname or alias.name)
                    if child in sources:
                        aliases[alias.asname or alias.name] = child
                        add(name, child, "", node.lineno)
                    else:
                        add(name, target, alias.name, node.lineno)
            elif isinstance(node, ast.Call) and ast.unparse(node.func) in dynamic_names:
                argument = node.args[0] if node.args else None
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    add(name, argument.value, "", node.lineno)
                else:
                    findings.append(finding("dynamic-import", name, node.lineno, "Unclassified variable import target"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
                target = aliases.get(ast.unparse(node.value))
                if target:
                    add(name, target, node.attr, node.lineno)
    try:
        tuple(graphlib.TopologicalSorter(graph).static_order())
    except graphlib.CycleError as exc:
        path = exc.args[1]
        findings.append(finding("cycle", path[0], 0, "Static dependency cycle", dependency_path=path))
    for contract in policy.get("forbidden", []):
        starts = [n for n in graph if n == contract["from"] or n.startswith(contract["from"] + ".")]
        for start in starts:
            queue = deque([(start, [start])])
            visited = {start}
            while queue:
                current, path = queue.popleft()
                for target in sorted(graph[current]):
                    route = [*path, target]
                    if target == contract["to"] or target.startswith(contract["to"] + "."):
                        findings.append(finding("forbidden", start, 0, "Forbidden dependency direction", dependency_path=route))
                        queue.clear()
                        break
                    if target not in visited:
                        visited.add(target)
                        queue.append((target, route))
    return {"graph": graph, "findings": findings}


def broad_handlers(module, source):
    tree = ast.parse(source, filename=module)
    aliases = {"Exception": "Exception", "BaseException": "BaseException",
               "builtins.Exception": "Exception", "builtins.BaseException": "BaseException"}
    uncertain = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == "builtins":
            for alias in node.names:
                if alias.name in {"Exception", "BaseException"}:
                    aliases[alias.asname or alias.name] = alias.name
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "builtins":
                    for caught in ("Exception", "BaseException"):
                        aliases[f"{alias.asname or alias.name}.{caught}"] = caught
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            uncertain.update(t.id for t in targets if isinstance(t, ast.Name))
    handlers = []

    def visit(node, symbol):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbol = ".".join(p for p in (symbol, node.name) if p)
        if isinstance(node, ast.ExceptHandler):
            types = node.type.elts if isinstance(node.type, ast.Tuple) else [node.type]
            caught = [aliases.get(ast.unparse(t), ast.unparse(t)) if t is not None else "bare" for t in types]
            unsupported = any(t is not None and (
                not isinstance(t, (ast.Name, ast.Attribute)) or ast.unparse(t) in uncertain
            ) for t in types)
            if unsupported or any(t in {"bare", "Exception", "BaseException"} for t in caught):
                handlers.append({
                    "module_id": module, "symbol": symbol or "<module>", "line": node.lineno,
                    "handler_fingerprint": digest(ast.dump(node, include_attributes=False)),
                    "caught_types": caught, "unsupported": unsupported,
                })
        for child in ast.iter_child_nodes(node):
            visit(child, symbol)
    visit(tree, "")
    return handlers


def debt_key(entry):
    return tuple(entry[key] for key in (
        "module_id", "symbol", "source_fingerprint", "rule", "message_fingerprint"
    ))


def compare_debt(current, baseline):
    actual = Counter(debt_key(e) for e in current)
    allowed = Counter()
    for entry in baseline:
        allowed[debt_key(entry)] += entry["occurrences"]
    findings = []
    for key, count in (actual - allowed).items():
        findings.append(finding("new-type-debt", key[0], 0, f"{key[1]}: {key[3]} ({count} new)", identity=list(key)))
    for key, count in (allowed - actual).items():
        findings.append(finding("retire-type-debt", key[0], 0, f"Retire stale baseline allowance ({count})", identity=list(key)))
    return findings


def policy_changes(base_scope, candidate_scope, base_debt, candidate_debt):
    findings = []
    if not base_scope <= candidate_scope:
        findings.append(finding("scope-reduction", "", 0, "Blocking coverage cannot shrink"))
    old = {e["id"]: e for e in base_debt}
    if any(e["id"] not in old or old[e["id"]] != e for e in candidate_debt):
        findings.append(finding("baseline-growth", "", 0, "Candidate cannot approve new or changed debt"))
    return findings


def validate_moves(base, candidate, move_map):
    findings = []
    ids = [m["id"] for m in candidate]
    paths = [m["path"] for m in candidate]
    if len(ids) != len(set(ids)) or len(paths) != len(set(paths)):
        findings.append(finding("ambiguous-move", "", 0, "Module IDs and destinations must be one-to-one"))
    current = {m["id"]: m for m in candidate}
    for old in base:
        new = current.get(old["id"])
        if new is None or (
            old["path"] != new["path"] and move_map.get(old["path"]) != new["path"]
        ):
            findings.append(finding("unreviewed-move", old["id"], 0, "Missing one-to-one move allocation"))
    return findings


def source_policy_changes(old, new):
    directive = re.compile(r"#.*(?:noqa|type:\s*ignore|mypy:|ruff:|pyright:)")
    extra = Counter(directive.findall(new)) - Counter(directive.findall(old))
    findings = [finding("suppression-growth", "", 0, "New suppression requires protected review")] if extra else []

    def signatures(source):
        result = {}
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                result[node.name] = {a.arg for a in args if a.annotation is not None}
                if node.returns is not None:
                    result[node.name].add("<return>")
        return result
    before, after = signatures(old), signatures(new)
    for name, annotations in before.items():
        if name in after and not annotations <= after[name]:
            findings.append(finding("annotation-removal", "", 0, name))
    return findings


def aggregate(results, reports, head, base):
    failures = [name for name in REQUIRED_JOBS if results.get(name) != "success"]
    for name in CHECKS:
        report = reports.get(name, {})
        if report.get("status") != "passed" or report.get("head_sha") != head or report.get("base_sha") != base:
            failures.append(f"{name}: missing, failed or stale report")
    return failures


def diagnostic_identity(diagnostic, source, module_id):
    tree = ast.parse(source)
    line = diagnostic["line"]
    symbol = "<module>"
    context = tree
    def visit(node, path):
        nonlocal symbol, context
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            path = ".".join(p for p in (path, node.name) if p)
            if node.lineno <= line <= node.end_lineno:
                symbol, context = path, node
        for child in ast.iter_child_nodes(node):
            visit(child, path)
    visit(tree, "")
    return {
        "module_id": module_id, "symbol": symbol,
        "source_fingerprint": digest(ast.dump(context, include_attributes=False)),
        "rule": diagnostic["code"], "message_fingerprint": digest(diagnostic["message"]),
    }


def validate_exception_records(handlers, records, root):
    root = root.resolve()
    fields = ("module_id", "symbol", "handler_fingerprint")
    actual = {tuple(h[k] for k in fields): h for h in handlers}
    findings, used = [], []
    for entry in records:
        key = tuple(entry[k] for k in fields)
        handler = actual.pop(key, None)
        evidence = entry.get("evidence_tests", [])
        valid = (handler is not None and entry.get("state") == "active"
                 and entry.get("caught_types") == handler["caught_types"]
                 and all(entry.get(k) for k in ("reason", "boundary", "failure_outcome", "diagnostic_path", "review"))
                 and evidence)
        if valid:
            for test in evidence:
                file_name, separator, test_name = test.partition("::")
                path = root / file_name
                if not separator or not path.is_file() or not path.resolve().is_relative_to(root):
                    valid = False
                    break
                tree = ast.parse(path.read_text(encoding="utf-8"))
                if not any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == test_name for n in ast.walk(tree)):
                    valid = False
        if not valid:
            findings.append(finding("exception-review", entry["module_id"], handler["line"] if handler else 0,
                                    f"Inactive, changed, stale or unevidenced exception: {entry['id']}"))
        else:
            used.append(entry["id"])
    findings.extend(finding("unapproved-handler", h["module_id"], h["line"], h["symbol"]) for h in actual.values())
    return findings, used


def run_checks(root, base, requested):
    root = root.resolve()
    base_sha = git(root, "rev-parse", "--verify", f"{base}^{{commit}}")
    head_sha = git(root, "rev-parse", "HEAD")
    records = {name: read_record(root / ".quality" / f"{name}.json")
               for name in ("policy", "typing-scope", "typing-baseline", "exceptions")}
    base_policy_text = base_text(root, base_sha, ".quality/policy.json")
    minimum = json.loads(base_policy_text) if base_policy_text else records["policy"]
    if minimum.get("schema_version") != 1:
        raise PolicyError("Unsupported protected policy")
    versions = {}
    for name, version in minimum["toolchain"].items():
        try:
            versions[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError as exc:
            raise PolicyError(f"Missing pinned tool: {name}") from exc
        if versions[name] != version:
            raise PolicyError(f"Wrong {name} version: expected {version}, found {versions[name]}")
    sources, paths = discover(root)
    modules = records["policy"]["modules"]
    module_ids = {m["import_name"]: m["id"] for m in modules}
    if any(paths.get(m["import_name"]) != m["path"] for m in modules):
        raise PolicyError("Module inventory name/path does not match discovered source")
    unknown = set(sources) - module_ids.keys()
    scope = set(records["typing-scope"]["module_ids"])
    scope.update(unknown)
    findings = {name: [] for name in requested}
    reports = {}
    started = time.monotonic()
    if "policy" in requested:
        output = findings["policy"]
        if not base_policy_text:
            output.append(finding("bootstrap-review", "", 0, "Protected base has no policy; maintainer bootstrap approval and administrator activation required"))
        else:
            base_records = {}
            for name in ("typing-scope", "typing-baseline", "exceptions"):
                text = base_text(root, base_sha, f".quality/{name}.json")
                if text is None:
                    raise PolicyError(f"Protected base missing {name}")
                base_records[name] = json.loads(text)
            output.extend(policy_changes(set(base_records["typing-scope"]["module_ids"]), scope,
                                         base_records["typing-baseline"]["entries"], records["typing-baseline"]["entries"]))
            output.extend(validate_moves(minimum["modules"], modules, records["typing-scope"]["move_map"]))
            for field in ("runtime_roots", "toolchain", "forbidden", "private_allowances", "required_checks"):
                if minimum[field] != records["policy"][field]:
                    output.append(finding("policy-change", "", 0, f"Protected review required: {field}"))
            if base_records["exceptions"] != records["exceptions"]:
                output.append(finding("policy-change", "", 0, "Exception changes require protected review"))
            for name in (".github/scripts/check-quality.py", ".github/workflows/tests.yml",
                         ".github/CODEOWNERS", "requirements-quality.txt"):
                old = base_text(root, base_sha, name)
                current = (root / name).read_text(encoding="utf-8") if (root / name).exists() else None
                if old != current:
                    output.append(finding("policy-change", "", 0, f"Protected review required: {name}"))
            old_config = tomllib.loads(base_text(root, base_sha, "pyproject.toml"))
            current_config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
            if old_config.get("tool", {}).get("mypy") != current_config.get("tool", {}).get("mypy") or (
                old_config.get("tool", {}).get("ruff") != current_config.get("tool", {}).get("ruff")
            ) or old_config.get("tool", {}).get("importlinter") != current_config.get("tool", {}).get("importlinter"):
                output.append(finding("policy-change", "", 0, "Tool settings require protected review"))
        output.extend(validate_moves([], modules, {}))
        inventory_paths = {m["path"] for m in modules}
        if inventory_paths - set(paths.values()):
            output.append(finding("missing-module", "", 0, "Inventoried runtime source missing"))
        for name, source in sources.items():
            old = base_text(root, base_sha, paths[name]) or ""
            if not old and not base_policy_text:
                # Bootstrap move records retain the original source's suppression history.
                migration = read_record(root / ".quality" / "migration.json")
                previous = next((m for m in migration["modules"] if m["import_name"] == name), None)
                if previous:
                    old = base_text(root, base_sha, previous["source_path"]) or ""
            output.extend({**f, "module": name} for f in source_policy_changes(old, source))
        # Nested config must not silently change tool discovery/suppression behavior.
        for folder in ("src", "connectors"):
            for name in ("pyproject.toml", "ruff.toml", ".ruff.toml", "mypy.ini", ".mypy.ini", "setup.cfg"):
                if any((root / folder).rglob(name)):
                    output.append(finding("nested-config", folder, 0, name))
    config_text = base_text(root, base_sha, "pyproject.toml") if base_policy_text else None
    config_text = config_text or (root / "pyproject.toml").read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="gpt-rag-quality-") as temporary:
        config_path = Path(temporary) / "pyproject.toml"
        config_path.write_text(config_text, encoding="utf-8")
        if "lint" in requested:
            result = execute([sys.executable, "-m", "ruff", "check", "--config", str(config_path),
                              "--no-cache", "--output-format", "json", *paths.values()], cwd=root, allowed=(0, 1))
            diagnostics = json.loads(result.stdout)
            if result.returncode and not diagnostics:
                raise PolicyError("Ruff failed without structured diagnostics")
            for d in diagnostics:
                findings["lint"].append(finding(d["code"], Path(d["filename"]).relative_to(root).as_posix(),
                                                 d["location"]["row"], d["message"]))
        if "typing" in requested:
            if base_policy_text:
                scope.update(json.loads(base_text(root, base_sha, ".quality/typing-scope.json"))["module_ids"])
            targets = [paths[n] for n in sources if module_ids.get(n, n) in scope]
            if not targets:
                raise PolicyError("Empty blocking typing scope")
            result = execute([sys.executable, "-m", "mypy", "--config-file", str(config_path),
                              "--no-incremental", "--output", "json", *targets], cwd=root, allowed=(0, 1))
            diagnostics = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
            if result.returncode and not diagnostics:
                raise PolicyError("Mypy failed without structured diagnostics")
            reverse = {path: name for name, path in paths.items()}
            current = []
            imported = []
            for d in diagnostics:
                if d["severity"] != "error":
                    continue
                path = d["file"].replace("\\", "/")
                name = reverse.get(path)
                if name and module_ids.get(name, name) in scope:
                    current.append(diagnostic_identity(d, sources[name], module_ids.get(name, name)))
                else:
                    imported.append(d)
            debt = records["typing-baseline"]["entries"]
            if base_policy_text:
                debt = json.loads(base_text(root, base_sha, ".quality/typing-baseline.json"))["entries"]
            findings["typing"].extend(compare_debt(current, debt))
            reports["imported_type_diagnostics"] = imported
        if "architecture" in requested:
            result = analyze_sources(sources, minimum)
            findings["architecture"].extend(result["findings"])
            import grimp
            graph = grimp.build_graph("gpt_rag_ui", include_external_packages=False, cache_dir=None)
            for importer in graph.modules:
                for target in graph.find_modules_directly_imported_by(importer):
                    if importer in sources and target in sources and target not in result["graph"][importer]:
                        findings["architecture"].append(finding("graph-disagreement", importer, 0, target))
            executable = Path(sys.executable).parent / ("lint-imports.exe" if sys.platform == "win32" else "lint-imports")
            result = execute([str(executable), "--config", str(config_path), "--no-cache"], cwd=root, allowed=(0, 1))
            if result.returncode:
                findings["architecture"].append(finding("import-linter", "", 0, result.stdout[-3000:]))
        if "exceptions" in requested:
            handlers = [dict(h, module_id=module_ids.get(name, name))
                        for name, source in sources.items() for h in broad_handlers(name, source)]
            entries = records["exceptions"]["entries"]
            if base_policy_text:
                entries = json.loads(base_text(root, base_sha, ".quality/exceptions.json"))["entries"]
            output, used = validate_exception_records(handlers, entries, root)
            findings["exceptions"].extend(output)
            reports["exception_ids_used"] = used
            reports["handler_inventory"] = handlers
    reports.update({
        "schema_version": 1, "repository": "Azure/gpt-rag-ui",
        "base_sha": base_sha, "head_sha": head_sha, "policy_sha": base_sha if base_policy_text else None,
        "toolchain": versions, "duration_seconds": round(time.monotonic() - started, 3),
        "checks": {name: {"status": "violations" if value else "passed", "findings": value}
                   for name, value in findings.items()},
        "coverage": {"blocking": sorted(scope), "uncovered": sorted(set(module_ids.values()) - scope)},
        "status": "violations" if any(findings.values()) else "passed",
    })
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", choices=("all", *CHECKS), default="all")
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    requested = CHECKS if args.check == "all" else (args.check,)
    try:
        report = run_checks(Path.cwd(), args.base_ref, requested)
    except (PolicyError, ValueError, KeyError, TypeError, SyntaxError, OSError) as exc:
        LOGGER.error("Quality execution incomplete: %s", exc)
        report = {"schema_version": 1, "status": "error", "error": str(exc)}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    for name, check in report.get("checks", {}).items():
        LOGGER.warning("%s: %s (%s findings)", name, check["status"], len(check["findings"]))
    return {"passed": 0, "violations": 1, "error": 2}[report["status"]]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    raise SystemExit(main())
