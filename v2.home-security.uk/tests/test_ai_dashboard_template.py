"""Verify the AI dashboard template matches security-ai's emitted record schema."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("create_dashboards", ROOT / "scripts" / "create-dashboards.py")
create_dashboards = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(create_dashboards)


class AiDashboardTemplateTests(unittest.TestCase):
    def test_ai_panels_use_worker_fields_and_supported_histogram(self):
        creator = create_dashboards.OpenObserveDashboardCreator("http://unused", "user", "password", "default")
        captured = {}

        def capture_dashboard(title, description, panels):
            captured.update(title=title, description=description, panels=panels)
            return True

        with patch.object(creator, "create_dashboard", side_effect=capture_dashboard):
            self.assertTrue(creator.create_ai_recommendations_dashboard())

        self.assertEqual(captured["title"], "AI Recommendations Dashboard")
        panels = captured["panels"]
        self.assertEqual(len(panels), 6)
        queries = [panel["queries"][0]["query"] for panel in panels]
        self.assertTrue(any("histogram(_timestamp, '1 hour')" in query for query in queries))
        for emitted_field in (
            "event_count", "analysis_overall_severity", "analysis_confidence",
            "coverage_warnings", "sources", "event_types", "analysis_summary",
            "model", "event_refs",
        ):
            self.assertTrue(any(emitted_field in query for query in queries), emitted_field)
        for stale_field in ("finding_type", "status"):
            self.assertFalse(any(stale_field in query for query in queries), stale_field)
        self.assertTrue(all(panel["queries"][0]["fields"]["stream"] == "ai_recommendations"
                            for panel in panels))


if __name__ == "__main__":
    unittest.main()