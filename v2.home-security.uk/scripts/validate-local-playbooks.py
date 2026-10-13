#!/usr/bin/env python3
"""Reject local deployment playbooks that can target remote machines or broaden scope."""
import sys
from pathlib import Path

import yaml

FORBIDDEN_TASK_KEYS = {
    "shell", "command", "raw", "script", "include_tasks", "import_tasks",
    "include_role", "import_role", "delegate_to", "local_action", "add_host",
}
ALLOWED_TASK_MODULES = {"ansible.builtin.copy", "ansible.builtin.stat", "ansible.builtin.assert"}
RULES_DESTINATION = "/var/lib/suricata/rules/suricata.rules"


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
                if isinstance(key, str) and key.rsplit(".", 1)[-1] in {"shell", "command", "raw", "script"}
            )
            if illegal:
                errors.append(f"{task_location}: forbidden keys: {', '.join(sorted(illegal))}")
            modules = [key for key in task if isinstance(key, str) and key.startswith("ansible.builtin.")]
            if len(modules) != 1 or modules[0] not in ALLOWED_TASK_MODULES:
                errors.append(f"{task_location}: module must be one of {', '.join(sorted(ALLOWED_TASK_MODULES))}")
            if set(task) - {"name", "become", *modules}:
                errors.append(f"{task_location}: task contains unsupported directives")
            if modules == ["ansible.builtin.copy"]:
                args = task[modules[0]]
                if not isinstance(args, dict) or set(args) != {"src", "dest"} or args.get("dest") != RULES_DESTINATION:
                    errors.append(f"{task_location}: copy destination must be exactly {RULES_DESTINATION}")
                elif args.get("src") != "../../artifacts/suricata.rules":
                    errors.append(f"{task_location}: copy source must be exactly ../../artifacts/suricata.rules")
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