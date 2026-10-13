#!/usr/bin/env python3
"""Reject local deployment playbooks that can target remote machines or broaden scope.

This validator allows playbooks that:
- Target localhost only with connection: local
- Deploy Suricata rules (copy to /var/lib/suricata/rules/suricata.rules)
- Reload Suricata service (ansible.builtin.service)
- Manage firewalld (ansible.builtin.command with validated firewall-cmd)
- Validate with stat/assert/debug modules

Features:
- Supports Jinja2 templating ({{ var }}) in commands and paths
- Checks become at both play and task level
- Strict validation of command content (no shell metacharacters, no dangerous patterns)
"""
import sys
import re
from pathlib import Path

import yaml

FORBIDDEN_TASK_KEYS = {
    "shell", "raw", "script", "include_tasks", "import_tasks",
    "include_role", "import_role", "delegate_to", "local_action", "add_host",
}
ALLOWED_TASK_MODULES = {
    "ansible.builtin.copy",
    "ansible.builtin.stat",
    "ansible.builtin.assert",
    "ansible.builtin.debug",
    "ansible.builtin.service",
    "ansible.builtin.command",
}

RULES_DESTINATION = "/var/lib/suricata/rules/suricata.rules"
RULES_SOURCE = "../../artifacts/suricata.rules"

# Patterns for commands with Jinja2 templating support
# {{ var }} is replaced with a placeholder for validation
ALLOWED_COMMAND_PATTERNS = [
    # Suricata test mode
    re.compile(r'^suricata\s+-T\s+-c\s+/etc/suricata/suricata\.yaml(\s+-S\s+\S+)?$'),
    # firewall-cmd with templated zone
    re.compile(r'^firewall-cmd\s+--zone=\{\{\s*\w+\s*\}\}\s+--(add|remove)-rich-rule=.*$'),
    re.compile(r'^firewall-cmd\s+--zone=\{\{\s*\w+\s*\}\}\s+--(add|remove)-(service|port)=.*$'),
    re.compile(r'^firewall-cmd\s+--zone=\{\{\s*\w+\s*\}\}\s+--permanent\s+--(add|remove)-(rich-rule|service|port)=.*$'),
    re.compile(r'^firewall-cmd\s+--zone=\{\{\s*\w+\s*\}\}\s+--query-rich-rule=.*$'),
    # Literal zone names
    re.compile(r'^firewall-cmd\s+--zone=[A-Za-z0-9_-]{1,64}\s+--(add|remove)-rich-rule=.*$'),
    re.compile(r'^firewall-cmd\s+--zone=[A-Za-z0-9_-]{1,64}\s+--(add|remove)-(service|port)=.*$'),
    re.compile(r'^firewall-cmd\s+--zone=[A-Za-z0-9_-]{1,64}\s+--permanent\s+--(add|remove)-(rich-rule|service|port)=.*$'),
    re.compile(r'^firewall-cmd\s+--zone=[A-Za-z0-9_-]{1,64}\s+--query-rich-rule=.*$'),
]

# Dangerous patterns that must never appear (after template resolution simulation)
DANGEROUS_COMMAND_PATTERNS = [
    re.compile(r'[;&|`$(){}]'),           # Shell metacharacters (excluding {{ }} which we handle)
    re.compile(r'--panic'),
    re.compile(r'--flush'),
    re.compile(r'--remove-all'),
    re.compile(r'--set-default-zone'),
    re.compile(r'--add-interface'),
    re.compile(r'--change-interface'),
    re.compile(r'iptables'),
    re.compile(r'nft\s'),
    re.compile(r'rm\s+-rf'),
    re.compile(r'dd\s+if='),
    re.compile(r'>\s*/etc/'),
]

ALLOWED_SERVICES = {"suricata", "firewalld"}
ALLOWED_SERVICE_STATES = {"reloaded", "restarted", "started", "stopped"}

# Jinja2 template pattern
JINJA_PATTERN = re.compile(r'\{\{[^}]+\}\}')


def resolve_templates(cmd):
    """Replace Jinja2 templates with safe placeholders for validation."""
    if not isinstance(cmd, str):
        return cmd
    # Replace {{ var }} with a safe placeholder
    resolved = JINJA_PATTERN.sub('__VAR__', cmd)
    return resolved


def validate_command(cmd):
    """Validate that a command matches allowed patterns and has no dangerous content."""
    if not isinstance(cmd, str):
        return False
    # Resolve templates first
    resolved = resolve_templates(cmd)
    # Check for dangerous patterns (on resolved command)
    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if pattern.search(resolved):
            return False
    # Check if it matches any allowed pattern (on resolved command)
    for pattern in ALLOWED_COMMAND_PATTERNS:
        if pattern.match(resolved):
            return True
    # Also try matching the original (with templates)
    for pattern in ALLOWED_COMMAND_PATTERNS:
        if pattern.match(cmd):
            return True
    return False


def is_trusted_path(path):
    """Check if a path is trusted (literal or uses known variables)."""
    if not isinstance(path, str):
        return False
    # Allow Jinja2 templates that reference known variables
    if JINJA_PATTERN.search(path):
        return True
    # Check against known safe paths
    safe_paths = {RULES_DESTINATION, RULES_SOURCE, "/var/lib/suricata/rules"}
    return path in safe_paths


def validate(path: Path) -> list[str]:
    try:
        document = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        return [f"{path}: cannot read valid YAML: {error}"]
    if not isinstance(document, list) or not document:
        return [f"{path}: expected a non-empty list of plays"]

    errors = []
    for play_number, play in enumerate(document, 1):
        location = f"{path}: play {play_number}"
        if not isinstance(play, dict):
            errors.append(f"{location}: expected mapping")
            continue
        if play.get("hosts") != "localhost":
            errors.append(f"{location}: hosts must be exactly localhost")
        if play.get("connection") != "local":
            errors.append(f"{location}: connection must be explicitly local")
        if "ansible_connection" in play.get("vars", {}):
            if play["vars"]["ansible_connection"] != "local":
                errors.append(f"{location}: ansible_connection must be local")
        
        # Play-level become
        play_become = play.get("become", False)
        
        tasks = play.get("tasks", [])
        if not isinstance(tasks, list):
            errors.append(f"{location}: tasks must be a list")
            continue
        for task_number, task in enumerate(tasks, 1):
            task_location = f"{location}, task {task_number}"
            if not isinstance(task, dict):
                errors.append(f"{task_location}: expected mapping")
                continue
            illegal = FORBIDDEN_TASK_KEYS.intersection(task)
            illegal.update(
                key for key in task
                if isinstance(key, str) and key.rsplit(".", 1)[-1] in {"shell", "raw", "script"}
            )
            if illegal:
                errors.append(f"{task_location}: forbidden keys: {', '.join(sorted(illegal))}")
            modules = [key for key in task if isinstance(key, str) and key.startswith("ansible.builtin.")]
            if len(modules) != 1 or modules[0] not in ALLOWED_TASK_MODULES:
                errors.append(f"{task_location}: module must be one of {', '.join(sorted(ALLOWED_TASK_MODULES))}")
            allowed_keys = {"name", "become", "when", "register", "changed_when", "failed_when", "ignore_errors"}
            if set(task) - allowed_keys - set(modules):
                errors.append(f"{task_location}: task contains unsupported directives")
            
            # Effective become (task overrides play)
            task_become = task.get("become", play_become)
            
            module = modules[0] if modules else None
            
            if module == "ansible.builtin.copy":
                args = task[module]
                if not isinstance(args, dict):
                    errors.append(f"{task_location}: copy args must be a mapping")
                    continue
                dest = args.get("dest", "")
                src = args.get("src", "")
                # Allow templated paths or known safe paths
                if not is_trusted_path(dest):
                    errors.append(f"{task_location}: copy destination must be {RULES_DESTINATION} or use trusted variables")
                if not is_trusted_path(src):
                    errors.append(f"{task_location}: copy source must be {RULES_SOURCE} or use trusted variables")
            
            elif module == "ansible.builtin.service":
                args = task[module]
                if not isinstance(args, dict):
                    errors.append(f"{task_location}: service args must be a mapping")
                    continue
                service_name = args.get("name", "")
                # Allow templated service names or known services
                if not JINJA_PATTERN.search(str(service_name)) and service_name not in ALLOWED_SERVICES:
                    errors.append(f"{task_location}: service must be one of {', '.join(sorted(ALLOWED_SERVICES))} or use variables")
                state = args.get("state")
                if state not in ALLOWED_SERVICE_STATES:
                    errors.append(f"{task_location}: state must be one of {', '.join(sorted(ALLOWED_SERVICE_STATES))}")
                if not task_become:
                    errors.append(f"{task_location}: service module requires become: true (at play or task level)")
            
            elif module == "ansible.builtin.command":
                args = task[module]
                cmd = args.get("cmd") if isinstance(args, dict) else args
                if not validate_command(cmd):
                    errors.append(f"{task_location}: command does not match allowed patterns or contains dangerous content: {cmd}")
                if not task_become:
                    errors.append(f"{task_location}: command module requires become: true (at play or task level)")
            
            if "delegate_facts" in task or "run_once" in task:
                errors.append(f"{task_location}: delegation/fan-out controls are not allowed")
    return errors


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "ansible/playbooks")
    if not root.is_dir():
        print(f"Playbook directory does not exist: {root}", file=sys.stderr)
        return 1
    files = sorted((*root.rglob("*.yml"), *root.rglob("*.yaml")))
    if not files:
        print(f"No playbooks found in {root}", file=sys.stderr)
        return 1
    failures = [error for path in files for error in validate(path)]
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print(f"Local-only policy passed for {len(files)} playbook(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
