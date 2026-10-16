"""Focused tests for review-only artifact and same-host playbook generation."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


artifact_writer = load_module("artifact_writer", ROOT / "security-ai" / "artifact_writer.py")
playbook_generator = load_module("playbook_generator", ROOT / "ansible-ai" / "playbook_generator.py")


def record(severity: str = "high") -> dict:
    rule = ('alert tcp $EXTERNAL_NET any -> $HOME_NET 22 '
            '(msg:"AI-REC: SSH brute force"; flow:to_server,established; '
            'classtype:attempted-admin; sid:1000001; rev:1;)')
    return {
        "timestamp": "2026-10-16T00:00:00Z",
        "event_count": 1,
        "event_refs": ["event-1"],
        "analysis": {
            "overall_severity": severity,
            "proposed_changes": [
                {"target": "suricata", "rule": rule},
                {"target": "firewalld", "block_type": "ip", "blocked_ip": "8.8.8.8"},
                {"target": "firewalld", "block_type": "ip", "blocked_ip": "192.168.1.2"},
                {"target": "firewalld", "block_type": "ip", "blocked_ip": "203.0.113.25"},
            ],
        },
    }


class ArtifactWriterTests(unittest.TestCase):
    def test_filters_block_ips_and_produces_non_executable_draft(self):
        outputs = artifact_writer.build_artifacts(record("critical"))
        self.assertIn("sid:1000001", outputs["home-security.rules"])
        self.assertIn("8.8.8.8", outputs["blocked-ips.txt"])
        self.assertNotIn("192.168.1.2", outputs["blocked-ips.txt"])
        self.assertNotIn("203.0.113.25", outputs["blocked-ips.txt"])
        self.assertIn("Never execute", outputs["firewall-draft.sh"])
        self.assertNotIn("--set-default-zone", outputs["firewall-draft.sh"])

    def test_low_severity_never_emits_block_requests(self):
        outputs = artifact_writer.build_artifacts(record("low"))
        self.assertIn("No eligible", outputs["blocked-ips.txt"])
        self.assertNotIn("firewall-cmd --permanent", outputs["firewall-draft.sh"])

    def test_manifest_committed_last_and_only_selects_real_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = artifact_writer.write_artifacts(record("high"), directory)
            self.assertTrue((Path(directory) / "manifest.json").is_file())
            self.assertEqual([item["name"] for item in manifest["deployable_artifacts"]],
                             ["suricata", "fail2ban", "firewalld"])
            self.assertTrue(all(item["source"].startswith(directory) for item in manifest["deployable_artifacts"]))


class PlaybookGeneratorTests(unittest.TestCase):
    def manifest(self, severity: str, rule_count: int = 1, ip_count: int = 1):
        record_value = record(severity)
        outputs = artifact_writer.build_artifacts(record_value)
        manifest = json.loads(outputs["manifest.json"])
        manifest["artifacts"]["suricata"]["rule_count"] = rule_count
        manifest["artifacts"]["fail2ban"]["ip_count"] = ip_count
        manifest["artifacts"]["firewalld"]["ip_count"] = ip_count
        return manifest

    def test_severity_selects_correct_artifacts_and_is_guarded(self):
        expected = {"informational": [], "low": [], "medium": ["suricata"],
                    "high": ["suricata", "fail2ban", "firewalld"],
                    "critical": ["suricata", "fail2ban", "firewalld"]}
        for severity, names in expected.items():
            with self.subTest(severity=severity):
                plays, metadata = playbook_generator.build_playbook(self.manifest(severity))
                playbook_generator.validate_playbook(plays)
                self.assertEqual([item["name"] for item in metadata["selected_artifacts"]], names)
                self.assertFalse(plays[0]["vars"]["apply_generated_artifacts"])
                self.assertEqual(plays[0]["hosts"], "localhost")
                self.assertEqual(plays[0]["connection"], "local")
                self.assertEqual(plays[0]["vars_prompt"][0]["private"], False)

    def test_suricata_health_check_and_rollback_are_present(self):
        plays, _ = playbook_generator.build_playbook(self.manifest("medium"))
        block = plays[0]["tasks"][0]["block"]
        rescue = plays[0]["tasks"][0]["rescue"]
        self.assertIn("sleep 150", [task.get("ansible.builtin.command", {}).get("cmd") for task in block])
        self.assertTrue(any("journalctl" in task.get("ansible.builtin.command", {}).get("argv", [""])[0]
                            for task in block))
        self.assertTrue(any(task.get("ansible.builtin.service", {}).get("state") == "reloaded"
                            for task in rescue))

    def test_invalid_or_automatic_manifest_is_rejected(self):
        manifest = self.manifest("high")
        manifest["status"] = "approved"
        with self.assertRaises(ValueError):
            playbook_generator.build_playbook(manifest)
        plays, _ = playbook_generator.build_playbook(self.manifest("medium"))
        plays[0]["tasks"][0]["when"] = "true"
        with self.assertRaises(ValueError):
            playbook_generator.validate_playbook(plays)

    def test_failed_suricata_validation_rolls_back_files(self):
        plays, _ = playbook_generator.build_playbook(self.manifest("high"))
        block = plays[0]["tasks"][0]["block"]
        rescue = plays[0]["tasks"][0]["rescue"]
        validate_index = next(i for i, task in enumerate(block)
                              if task.get("ansible.builtin.command", {}).get("cmd", "").startswith("suricata -T"))
        self.assertGreater(validate_index, next(i for i, task in enumerate(block)
                                               if task.get("name") == "Stage suricata draft"))
        self.assertTrue(any(task.get("name", "").startswith("Restore previous suricata") for task in rescue))


if __name__ == "__main__":
    unittest.main()