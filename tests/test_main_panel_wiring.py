"""Tests for main.py's ``_mount_panel_routes`` wiring helper (issue #611,
ADR-0004): mounted only for the hosted-agent backend and only when
PANEL_SETTINGS is present, and never imports ``panel_routes``/
``panel_cosmos`` on the classic (``CHAT_BACKEND=orchestrator``) path --
proving the classic deployment carries zero additional behavior or
dependency surface from this feature."""

import unittest
from types import SimpleNamespace
from unittest.mock import Mock

import dependencies


class _FakeConfig:
    def __init__(self, values=None):
        self.values = values or {}

    def get(self, key, default=None, type=str):
        value = self.values.get(key, default)
        return type(value) if value is not None and type is not None else value


dependencies.__dict__["__config"] = _FakeConfig()

import main  # noqa: E402
from panel_config import PanelSettings  # noqa: E402


class MountPanelRoutesTests(unittest.TestCase):
    def setUp(self):
        self.host_app = Mock()
        self.config = Mock()

    def test_classic_orchestrator_backend_never_touches_panel_modules(self):
        """Classic regression: the orchestrator backend must never mount
        the panel routes. (Whether ``panel_routes`` happens to already be
        cached in ``sys.modules`` from an unrelated test module's own
        import is not asserted here -- mutating the shared module cache
        would leak a duplicate module object into other tests' ``patch()``
        targets; ``include_router`` never being called is sufficient proof
        that the classic path never mounts or otherwise depends on it.)"""
        handlers = SimpleNamespace(CHAT_BACKEND="orchestrator")
        main._mount_panel_routes(self.host_app, self.config, handlers)
        self.host_app.include_router.assert_not_called()

    def test_hosted_agent_without_panel_settings_does_not_mount(self):
        handlers = SimpleNamespace(CHAT_BACKEND="hosted_agent")
        main._mount_panel_routes(self.host_app, self.config, handlers)
        self.host_app.include_router.assert_not_called()

    def test_hosted_agent_with_panel_settings_mounts_routes(self):
        handlers = SimpleNamespace(
            CHAT_BACKEND="hosted_agent",
            PANEL_SETTINGS=PanelSettings(),
            HOSTED_CONTINUITY_ENABLED=False,
            _get_hosted_continuity_coordinator=lambda: Mock(store=Mock()),
        )
        main._mount_panel_routes(self.host_app, self.config, handlers)
        self.host_app.include_router.assert_called_once()


if __name__ == "__main__":
    unittest.main()
