"""Resolve the staged writable application root, never installed code paths."""

import os
from pathlib import Path

_asset_root: Path | None = None


def configure_asset_root(source_adapter: str | None = None) -> Path:
    global _asset_root
    if _asset_root is not None:
        return _asset_root
    configured = os.environ.get("CHAINLIT_APP_ROOT")
    source_root = Path(source_adapter).resolve().parent if source_adapter else None
    if configured:
        root = Path(configured).resolve()
    elif source_root is not None and (source_root / "chainlit.config.yaml").is_file():
        root = source_root
    else:
        root = Path.cwd().resolve()
    os.environ["CHAINLIT_APP_ROOT"] = str(root)
    _asset_root = root
    return root


def get_asset_root() -> Path:
    return configure_asset_root()
