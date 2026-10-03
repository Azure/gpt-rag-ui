"""Agent Landing Zone dual-read: new names win, legacy GPT-RAG names still resolve."""

import os
import unittest
from unittest.mock import patch

from gpt_rag_ui.config import appconfig
from gpt_rag_ui.telemetry.monitoring import Telemetry


class DualReadTests(unittest.TestCase):
    def client(self, values):
        with patch.dict(os.environ, {}, clear=True):
            client = appconfig.AppConfigClient()
        client.client = values
        return client

    def test_agentlz_key_wins_over_legacy_key(self):
        client = self.client({"AGENTLZ_SETTING": "new", "GPT_RAG_SETTING": "old"})
        self.assertEqual("new", client.get("GPT_RAG_SETTING"))
        self.assertEqual("new", client.get("AGENTLZ_SETTING"))

    def test_legacy_key_used_when_agentlz_key_absent(self):
        client = self.client({"GPT_RAG_SETTING": "old"})
        self.assertEqual("old", client.get("AGENTLZ_SETTING"))
        self.assertEqual("old", client.get("GPT_RAG_SETTING"))

    def test_default_when_neither_key_present(self):
        client = self.client({})
        self.assertEqual("fallback", client.get("AGENTLZ_SETTING", "fallback"))

    def test_unprefixed_keys_are_not_aliased(self):
        self.assertEqual(["LOG_LEVEL"], appconfig.candidate_keys("LOG_LEVEL"))
        self.assertEqual(["AGENTLZ_X", "GPT_RAG_X"], appconfig.candidate_keys("GPT_RAG_X"))

    def test_agentlz_label_selected_after_legacy_label_so_it_wins(self):
        with (
            patch.dict(os.environ, {"APP_CONFIG_ENDPOINT": "https://config.example.invalid"}, clear=True),
            patch.object(appconfig, "load", return_value={}) as provider,
        ):
            appconfig.AppConfigClient()
        labels = [s.label_filter for s in provider.call_args.kwargs["selects"]]
        self.assertLess(labels.index("gpt-rag"), labels.index("agent-lz"))

    def test_tracer_names_use_agentlz_prefix(self):
        with patch("gpt_rag_ui.telemetry.monitoring.trace.get_tracer") as get_tracer:
            Telemetry.get_tracer("gpt_rag_ui.services.chat")
            Telemetry.get_tracer("agentlz.already")
        self.assertEqual(
            ["agentlz.gpt_rag_ui.services.chat", "agentlz.already"],
            [c.args[0] for c in get_tracer.call_args_list],
        )


if __name__ == "__main__":
    unittest.main()
