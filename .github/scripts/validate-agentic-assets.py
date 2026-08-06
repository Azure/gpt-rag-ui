#!/usr/bin/env python3
"""Validate repository Copilot agents, skills, and scoped instructions."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml
from yaml.constructor import ConstructorError
from yaml.resolver import BaseResolver


ROOT = Path(__file__).resolve().parents[2]
FRONTMATTER_BOUNDARY = "---"
LOCAL_LINK = re.compile(r"\[[^\]]+\]\((?!https?://|mailto:|#)([^)]+)\)")
ASSET_NAME = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
TOOL_NAME = re.compile(
    r"^[A-Za-z0-9_.:-]+(?:/[A-Za-z0-9_.:*?-]+)?$"
)


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def construct_unique_mapping(
    loader: UniqueKeyLoader,
    node: yaml.MappingNode,
    deep: bool = False,
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found an unhashable key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    construct_unique_mapping,
)


def read_frontmatter(path: Path) -> tuple[dict[str, object], str]:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines or lines[0].strip() != FRONTMATTER_BOUNDARY:
        raise ValueError("missing opening YAML frontmatter boundary")

    try:
        end = next(
            index
            for index, line in enumerate(lines[1:], start=1)
            if line.strip() == FRONTMATTER_BOUNDARY
        )
    except StopIteration as exc:
        raise ValueError("missing closing YAML frontmatter boundary") from exc

    frontmatter = "\n".join(lines[1:end])
    try:
        metadata = yaml.load(frontmatter, Loader=UniqueKeyLoader)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML frontmatter: {exc}") from exc
    if not isinstance(metadata, dict) or not all(
        isinstance(key, str) for key in metadata
    ):
        raise ValueError("YAML frontmatter must be a string-keyed mapping")

    return metadata, text


def require_strings(
    path: Path,
    metadata: dict[str, object],
    fields: tuple[str, ...],
    errors: list[str],
) -> None:
    for field in fields:
        value = metadata.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(
                f"{path.relative_to(ROOT)}: {field!r} must be a non-empty string"
            )


def validate_agent(
    path: Path,
    metadata: dict[str, object],
    names: set[str],
    errors: list[str],
) -> None:
    require_strings(path, metadata, ("description",), errors)
    default_name = path.name.removesuffix(".agent.md")
    declared_name = metadata.get("name")
    name = default_name
    if declared_name is not None:
        if not isinstance(declared_name, str) or not declared_name.strip():
            errors.append(
                f"{path.relative_to(ROOT)}: 'name' must be a non-empty string"
            )
            return
        name = declared_name
        if not ASSET_NAME.fullmatch(name):
            errors.append(
                f"{path.relative_to(ROOT)}: agent name must be lowercase kebab-case"
            )
        if name != default_name:
            errors.append(f"{path.relative_to(ROOT)}: agent name must match filename")

    if name in names:
        errors.append(f"{path.relative_to(ROOT)}: duplicate agent {name!r}")
    names.add(name)

    if "tools" not in metadata:
        return

    configured_tools = metadata["tools"]
    if isinstance(configured_tools, str):
        tools = (
            []
            if not configured_tools.strip()
            else [tool.strip() for tool in configured_tools.split(",")]
        )
    elif isinstance(configured_tools, list):
        tools = configured_tools
    else:
        errors.append(
            f"{path.relative_to(ROOT)}: 'tools' must be a string or string list"
        )
        return

    if not all(isinstance(tool, str) and tool.strip() for tool in tools):
        errors.append(
            f"{path.relative_to(ROOT)}: 'tools' entries must be non-empty strings"
        )
        return

    normalized_tools = [tool.strip() for tool in tools]
    invalid_tools = sorted(
        tool
        for tool in normalized_tools
        if tool != "*" and not TOOL_NAME.fullmatch(tool)
    )
    if invalid_tools:
        errors.append(
            f"{path.relative_to(ROOT)}: invalid tool names: {invalid_tools}"
        )
    if len(normalized_tools) != len(
        {tool.casefold() for tool in normalized_tools}
    ):
        errors.append(f"{path.relative_to(ROOT)}: duplicate tool aliases")


def validate_skill(
    path: Path,
    metadata: dict[str, object],
    names: set[str],
    errors: list[str],
) -> None:
    require_strings(path, metadata, ("name", "description"), errors)
    name = metadata.get("name")
    if not isinstance(name, str):
        return
    if not ASSET_NAME.fullmatch(name):
        errors.append(
            f"{path.relative_to(ROOT)}: skill name must be lowercase kebab-case"
        )
    if name != path.parent.name:
        errors.append(f"{path.relative_to(ROOT)}: skill name must match directory")
    if name in names:
        errors.append(f"{path.relative_to(ROOT)}: duplicate skill {name!r}")
    names.add(name)


def validate_instruction(
    path: Path,
    metadata: dict[str, object],
    errors: list[str],
) -> None:
    require_strings(path, metadata, ("applyTo",), errors)
    apply_to = metadata.get("applyTo")
    if isinstance(apply_to, str) and any(
        not pattern.strip() for pattern in apply_to.split(",")
    ):
        errors.append(f"{path.relative_to(ROOT)}: 'applyTo' has an empty pattern")


def validate_local_links(path: Path, text: str, errors: list[str]) -> None:
    for target in LOCAL_LINK.findall(text):
        target_path = target.split("#", 1)[0]
        if not target_path:
            continue
        resolved = (path.parent / target_path).resolve()
        if not resolved.is_relative_to(ROOT.resolve()) or not resolved.exists():
            errors.append(
                f"{path.relative_to(ROOT)}: local link does not exist: {target}"
            )


def main() -> int:
    errors: list[str] = []
    agent_names: set[str] = set()
    skill_names: set[str] = set()

    groups = (
        (ROOT / ".github" / "agents", "*.agent.md", "agent"),
        (ROOT / ".github" / "skills", "*/SKILL.md", "skill"),
        (ROOT / ".github" / "instructions", "*.instructions.md", "instruction"),
    )

    for directory, pattern, asset_kind in groups:
        paths = sorted(directory.rglob(pattern))
        if not paths:
            errors.append(f"{directory.relative_to(ROOT)}: no matching assets")
            continue

        for path in paths:
            try:
                metadata, text = read_frontmatter(path)
            except (OSError, UnicodeError, ValueError) as exc:
                errors.append(f"{path.relative_to(ROOT)}: {exc}")
                continue

            validate_local_links(path, text, errors)

            if asset_kind == "agent":
                validate_agent(path, metadata, agent_names, errors)
            elif asset_kind == "skill":
                validate_skill(path, metadata, skill_names, errors)
            else:
                validate_instruction(path, metadata, errors)

    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    print(
        f"Validated {len(agent_names)} agents and {len(skill_names)} skills "
        "plus scoped instructions."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
