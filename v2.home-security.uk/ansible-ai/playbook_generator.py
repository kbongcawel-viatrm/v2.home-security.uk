"""Create a deterministic, guarded same-host Ansible deployment draft."""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml

SEVERITY_ORDER = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
TARGETS = {
    "suricata": "/etc/suricata/rules/home-security.rules",
    "fail2ban": "/etc/fail2ban/blocked-ips.txt",
    "firewalld": "/etc/firewalld/firewall-draft.sh",
}
ARTIFACT_ROOT = "{{ security_artifacts_dir }}"


def _copy_task(name: str, source: str, destination: str, mode: str) -> dict[str, Any]:
    return {"name": name, "ansible.builtin.copy": {
        "src": f"{ARTIFACT_ROOT}/{source}", "dest": destination,
        "owner": "root", "group": "root", "mode": mode, "backup": True,
    }}


def build_playbook(manifest: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    if manifest.get("agent") != "security-ai" or manifest.get("status") != "draft_only":
        raise ValueError("input must be a draft-only security-ai manifest")
    severity = str(manifest.get("severity", "low")).strip().lower()
    if severity not in SEVERITY_ORDER:
        severity = "low"
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict):
        raise ValueError("manifest artifacts must be a mapping")
    suricata = artifacts.get("suricata", {})
    fail2ban = artifacts.get("fail2ban", {})
    firewalld = artifacts.get("firewalld", {})
    rule_count = int(suricata.get("rule_count", 0))
    ip_count = max(int(fail2ban.get("ip_count", 0)), int(firewalld.get("ip_count", 0)))
    if min(rule_count, ip_count) < 0 or rule_count > 100 or ip_count > 100:
        raise ValueError("artifact counts are outside permitted bounds")

    selected: list[dict[str, str]] = []
    if rule_count and severity in ("medium", "high", "critical"):
        selected.append({"name": "suricata", "source": "home-security.rules", "dest": TARGETS["suricata"], "mode": "0644"})
    if ip_count and severity in ("high", "critical"):
        selected.extend([
            {"name": "fail2ban", "source": "blocked-ips.txt", "dest": TARGETS["fail2ban"], "mode": "0600"},
            {"name": "firewalld", "source": "firewall-draft.sh", "dest": TARGETS["firewalld"], "mode": "0600"},
        ])

    preflight: list[dict[str, Any]] = []
    backups: list[dict[str, Any]] = []
    stages: list[dict[str, Any]] = []
    rollback: list[dict[str, Any]] = []
    for item in selected:
        name, dest, mode = item["name"], item["dest"], item["mode"]
        register = f"{name}_before"
        backup_path = dest + ".security-ai.bak"
        preflight.append({"name": f"Check existing {name} file", "ansible.builtin.stat": {"path": dest}, "register": register})
        backups.append({"name": f"Back up existing {name} file", "ansible.builtin.copy": {
            "src": dest, "dest": backup_path, "remote_src": True, "owner": "root", "group": "root", "mode": mode,
        }, "when": f"{register}.stat.exists"})
        stages.append(_copy_task(f"Stage {name} draft", item["source"], dest, mode))
        rollback.extend([
            {"name": f"Restore previous {name} file", "ansible.builtin.copy": {
                "src": backup_path, "dest": dest, "remote_src": True,
                "owner": "root", "group": "root", "mode": mode,
            }, "when": f"{register}.stat.exists", "ignore_errors": True},
            {"name": f"Remove new {name} file if no previous file existed", "ansible.builtin.file": {
                "path": dest, "state": "absent",
            }, "when": f"not {register}.stat.exists", "ignore_errors": True},
        ])

    deploy = preflight + backups + stages
    has_suricata = any(item["name"] == "suricata" for item in selected)
    if has_suricata:
        deploy.extend([
            {"name": "Validate Suricata configuration before reload", "ansible.builtin.command": {
                "cmd": "suricata -T -c /etc/suricata/suricata.yaml",
            }, "changed_when": False},
            {"name": "Mark start of the Suricata health observation window", "ansible.builtin.command": {
                "cmd": "date +%s",
            }, "register": "suricata_reload_epoch", "changed_when": False},
            {"name": "Reload Suricata after successful validation", "ansible.builtin.service": {
                "name": "suricata", "state": "reloaded",
            }},
            {"name": "Observe Suricata for two and a half minutes", "ansible.builtin.command": {
                "cmd": "sleep 150",
            }, "changed_when": False},
            {"name": "Verify Suricata remains active", "ansible.builtin.command": {
                "cmd": "systemctl is-active suricata",
            }, "register": "suricata_health", "changed_when": False},
            {"name": "Check Suricata errors must be checked after the observation window", "ansible.builtin.command": {
                "argv": ["journalctl", "-u", "suricata", "--since", "@{{ suricata_reload_epoch.stdout }}", "--priority=err", "--no-pager"],
            }, "register": "suricata_recent_errors", "changed_when": False},
            {"name": "Fail when Suricata is inactive or logged post-reload errors", "ansible.builtin.assert": {
                "that": ["suricata_health.rc == 0", "suricata_health.stdout == 'active'",
                         "suricata_recent_errors.rc == 0", "suricata_recent_errors.stdout == ''"],
                "fail_msg": "Suricata is unhealthy or logged errors; restoring previous files.",
            }},
        ])
        rollback.append({"name": "Reload Suricata after restoring previous rules", "ansible.builtin.service": {
            "name": "suricata", "state": "reloaded",
        }, "ignore_errors": True})
    if not deploy:
        deploy.append({"name": "No artifacts meet severity threshold", "ansible.builtin.debug": {
            "msg": "No files will be copied and no services will be reloaded.",
        }})
    if not rollback:
        rollback.append({"name": "Report no changes to roll back", "ansible.builtin.debug": {
            "msg": "No deployment artifacts met the severity threshold.",
        }})
    rollback.append({"name": "Stop after rollback and report failure", "ansible.builtin.fail": {
        "msg": "Artifact deployment failed; previous files were restored where available.",
    }})

    play = {
        "name": "Draft-controlled security artifact deployment",
        "hosts": "localhost",
        "connection": "local",
        "gather_facts": False,
        "become": True,
        "vars_prompt": [{"name": "confirm_security_artifact_apply",
                         "prompt": "Type APPLY to stage reviewed security artifacts on this host",
                         "private": False}],
        "vars": {"apply_generated_artifacts": False,
                 "security_artifacts_dir": "{{ playbook_dir }}/../security-ai"},
        "tasks": [
            {"name": "Apply reviewed generated artifacts with explicit opt-in",
             "block": deploy,
             "rescue": rollback,
             "when": "apply_generated_artifacts | bool and confirm_security_artifact_apply == 'APPLY'"},
            {"name": "Report this draft deployment", "ansible.builtin.debug": {"msg": [
                f"Security severity: {severity}",
                f"Selected artifacts: {', '.join(item['name'] for item in selected) or 'none'}",
                "Fail2ban blocked-ips.txt is a draft; no Fail2ban jail currently consumes it.",
                "firewall-draft.sh is copied only as inert text and this playbook will never execute it.",
                "Default is no-op; staging needs apply_generated_artifacts=true and an interactive APPLY confirmation.",
            ]}},
        ],
    }
    metadata = {
        "version": 1,
        "agent": "ansible-ai",
        "status": "draft_only",
        "severity": severity,
        "source_analysis_id": manifest.get("analysis_id"),
        "target_inventory": "localhost (current host)",
        "selected_artifacts": selected,
        "policy": {
            "informational_or_low": "no host changes",
            "medium": "stage Suricata alert rules only",
            "high_or_critical": "stage Suricata rules plus inert Fail2ban and Firewalld drafts",
            "automatic_execution": False,
            "explicit_apply_flag": "apply_generated_artifacts=true",
            "human_confirmation": "type APPLY",
            "firewalld_script_executed": False,
            "fail2ban_integration_configured": False,
            "suricata_observation_seconds": 150,
            "rollback_on_validation_or_health_error": True,
        },
    }
    return [play], metadata


def validate_playbook(plays: list[dict[str, Any]]) -> None:
    if len(plays) != 1:
        raise ValueError("exactly one play is required")
    play = plays[0]
    if play.get("hosts") != "localhost" or play.get("connection") != "local" or play.get("become") is not True:
        raise ValueError("play must target the local host with privilege escalation")
    if play.get("vars", {}).get("apply_generated_artifacts") is not False:
        raise ValueError("apply flag must default to false")
    prompts = play.get("vars_prompt", [])
    if not any(isinstance(p, dict) and p.get("name") == "confirm_security_artifact_apply" and p.get("private") is False for p in prompts):
        raise ValueError("interactive human confirmation is required")
    tasks = play.get("tasks")
    guard = "apply_generated_artifacts | bool and confirm_security_artifact_apply == 'APPLY'"
    if not isinstance(tasks, list) or len(tasks) != 2 or tasks[0].get("when") != guard:
        raise ValueError("deployment requires both explicit apply guards")
    block, rescue = tasks[0].get("block", []), tasks[0].get("rescue", [])
    if not block or not rescue:
        raise ValueError("deployment and rollback tasks are required")

    allowed_modules = {"ansible.builtin.assert", "ansible.builtin.command", "ansible.builtin.copy",
                       "ansible.builtin.debug", "ansible.builtin.fail", "ansible.builtin.file",
                       "ansible.builtin.service", "ansible.builtin.stat"}
    allowed_commands = {"suricata -T -c /etc/suricata/suricata.yaml", "date +%s", "sleep 150", "systemctl is-active suricata"}
    destinations = set(TARGETS.values()) | {path + ".security-ai.bak" for path in TARGETS.values()}

    def check(task: dict[str, Any]) -> None:
        modules = [key for key in task if key.startswith("ansible.builtin.")]
        if len(modules) != 1 or modules[0] not in allowed_modules:
            raise ValueError("task uses an unsupported module")
        module, args = modules[0], task[modules[0]]
        if module == "ansible.builtin.command":
            if "argv" in args:
                expected = ["journalctl", "-u", "suricata", "--since", "@{{ suricata_reload_epoch.stdout }}", "--priority=err", "--no-pager"]
                if args["argv"] != expected:
                    raise ValueError("journal inspection arguments are not approved")
            elif args.get("cmd") not in allowed_commands:
                raise ValueError("command is not in the defensive allow-list")
        elif module == "ansible.builtin.copy":
            if args.get("dest") not in destinations:
                raise ValueError("copy destination is outside approved artifact paths")
            source = args.get("src", "")
            if args.get("remote_src"):
                if source not in set(TARGETS.values()) | {path + ".security-ai.bak" for path in TARGETS.values()}:
                    raise ValueError("backup source is outside approved host paths")
            elif not source.startswith(ARTIFACT_ROOT + "/") or source.rsplit("/", 1)[-1] not in {
                "home-security.rules", "blocked-ips.txt", "firewall-draft.sh"
            }:
                raise ValueError("copy source is outside the shared generated artifact directory")
        elif module == "ansible.builtin.file":
            if args.get("path") not in TARGETS.values() or args.get("state") != "absent":
                raise ValueError("rollback may remove only an approved generated file")
        elif module == "ansible.builtin.service":
            if args.get("name") != "suricata" or args.get("state") != "reloaded":
                raise ValueError("only Suricata reloads are allowed")

    def check_section(items: list[dict[str, Any]]) -> None:
        for task in items:
            if "block" in task:
                for section in ("block", "rescue", "always"):
                    check_section(task.get(section, []))
            else:
                check(task)

    check_section(tasks)
    if any("firewall-draft.sh" in str(task.get("ansible.builtin.command", {})) for task in block + rescue):
        raise ValueError("firewall draft execution is forbidden")
    report = tasks[1].get("ansible.builtin.debug", {}).get("msg", [])
    if not any("firewall-draft.sh" in str(line) and "never execute" in str(line) for line in report):
        raise ValueError("firewall execution prohibition must be documented")
    if any(task.get("ansible.builtin.command", {}).get("cmd") == "sleep 150" for task in block):
        if not any(task.get("ansible.builtin.command", {}).get("argv", [""])[0] == "journalctl" for task in block):
            raise ValueError("Suricata errors must be checked after the observation window")


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_playbook(manifest_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    plays, metadata = build_playbook(manifest)
    validate_playbook(plays)
    content = "# Draft only; applying requires apply_generated_artifacts=true and typing APPLY.\n"
    content += yaml.safe_dump(plays, sort_keys=False, allow_unicode=True)
    output = Path(output_dir)
    _atomic_write(output / "deploy-security-artifacts.yml", content)
    _atomic_write(output / "manifest.json", json.dumps(metadata, indent=2) + "\n")
    return metadata
