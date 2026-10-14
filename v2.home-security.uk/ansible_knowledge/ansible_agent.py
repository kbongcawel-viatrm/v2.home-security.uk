"""Constrained Ansible proposal authoring and syntax validation; never runs plays."""
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml


KNOWLEDGE_PATH = Path(__file__).with_name("ansible_knowledge.md")
MAX_PLAYBOOK_BYTES = 8000
ALLOWED_MODULES = {
    "ansible.builtin.copy", "ansible.builtin.stat", "ansible.builtin.assert",
    "ansible.builtin.debug",
}
FORBIDDEN_KEYS = {
    "shell", "command", "raw", "script", "include_tasks", "import_tasks",
    "include_role", "import_role", "delegate_to", "lookup", "with_file",
}


def _load_knowledge():
    return KNOWLEDGE_PATH.read_text(encoding="utf-8")


def _validate_structure(playbook_text):
    if not isinstance(playbook_text, str) or len(playbook_text.encode("utf-8")) > MAX_PLAYBOOK_BYTES:
        raise ValueError("playbook is missing or exceeds the size limit")
    if any(token in playbook_text for token in ("!python", "!vault", "!!python", "\x00", "{{", "{%")):
        raise ValueError("unsupported YAML tags, templating, or control characters")
    try:
        plays = yaml.safe_load(playbook_text)
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid YAML: {exc}") from exc
    if not isinstance(plays, list) or not plays or len(plays) > 5:
        raise ValueError("playbook must be a non-empty list of at most five plays")
    for play in plays:
        if not isinstance(play, dict) or not isinstance(play.get("name"), str):
            raise ValueError("each play must have a descriptive name")
        if set(play) - {"name", "hosts", "connection", "gather_facts", "become", "tasks", "vars"}:
            raise ValueError("play contains unsupported directives")
        if "vars" in play and (not isinstance(play["vars"], dict) or len(play["vars"]) > 20):
            raise ValueError("play vars must be a bounded mapping")
        if play.get("hosts") != "localhost":
            raise ValueError("every play must target localhost only")
        if play.get("connection") != "local":
            raise ValueError("every play must explicitly use connection: local")
        if play.get("gather_facts", False) not in (False, True):
            raise ValueError("gather_facts must be boolean")
        tasks = play.get("tasks")
        if not isinstance(tasks, list) or len(tasks) > 20:
            raise ValueError("each play needs a bounded tasks list")
        for task in tasks:
            if not isinstance(task, dict) or not isinstance(task.get("name"), str):
                raise ValueError("each task must have a descriptive name")
            if set(task) - {"name", "become", "when", "register", "changed_when", "failed_when"} - ALLOWED_MODULES:
                raise ValueError("task contains unsupported directives or modules")
            if any(key in task for key in ("when", "register", "changed_when", "failed_when")):
                raise ValueError("conditional and result directives require manual authoring")
            if task.get("become", play.get("become", False)) not in (False, True):
                raise ValueError("become must be boolean")
            if FORBIDDEN_KEYS.intersection(task):
                raise ValueError("playbook contains a forbidden task key")
            modules = [key for key in task if key.startswith("ansible.")]
            modules += [key for key in task if "." not in key and key in {
                "shell", "command", "raw", "script", "copy", "template", "stat",
                "assert", "debug", "service", "firewalld",
            }]
            if len(modules) != 1 or modules[0] not in ALLOWED_MODULES:
                raise ValueError("task module is not in the permitted built-in module allowlist")
            if any(key in task for key in ("environment", "vars", "loop_control")):
                raise ValueError("task-level environment, vars, and custom loop controls require manual authoring")
    return plays


def _ansible_syntax_check(playbook_text):
    command = shutil.which("ansible-playbook")
    if not command:
        return {"status": "not_run", "reason": "ansible-playbook executable is unavailable"}
    with tempfile.TemporaryDirectory(prefix="security-ai-ansible-") as temp_dir:
        root = Path(temp_dir)
        playbook = root / "proposal.yml"
        inventory = root / "inventory.ini"
        config = root / "ansible.cfg"
        playbook.write_text(playbook_text, encoding="utf-8")
        inventory.write_text("localhost ansible_connection=local\n", encoding="utf-8")
        config.write_text("[defaults]\ninterpreter_python=auto_silent\n", encoding="utf-8")
        env = {"PATH": str(Path(command).parent), "HOME": temp_dir,
               "ANSIBLE_CONFIG": str(config), "ANSIBLE_LOCAL_TEMP": str(root / "local-tmp"),
               "ANSIBLE_REMOTE_TEMP": str(root / "remote-tmp"), "PYTHONNOUSERSITE": "1"}
        try:
            result = subprocess.run(
                [command, "-i", str(inventory), "--syntax-check", str(playbook)],
                cwd=temp_dir, env=env, capture_output=True, text=True, timeout=20, check=False,
            )
        except subprocess.TimeoutExpired:
            return {"status": "failed", "reason": "Ansible syntax check timed out"}
        if result.returncode:
            return {"status": "failed", "reason": (result.stderr or result.stdout)[-2000:]}
        return {"status": "passed", "output": result.stdout[-1000:]}


def validate_playbook(playbook_text):
    _validate_structure(playbook_text)
    return _ansible_syntax_check(playbook_text)


def finalize_proposals(proposals, events, ollama_url, model, request_json):
    """Use a dedicated Ansible-focused generation pass; only return syntax-valid drafts."""
    valid_refs = {event.get("event_ref") for event in events if event.get("event_ref")}
    finalized = []
    for proposal in proposals[:5]:
        if not isinstance(proposal, dict) or proposal.get("target") != "ansible":
            continue
        if (not str(proposal.get("rationale", "")).strip()
                or not str(proposal.get("risk", "")).strip()
                or not isinstance(proposal.get("validation_steps"), list)
                or not proposal["validation_steps"]
                or not isinstance(proposal.get("rollback_steps"), list)
                or not proposal["rollback_steps"]):
            continue
        proposal_refs = proposal.get("event_refs", [])
        if not isinstance(proposal_refs, list):
            continue
        refs = [ref for ref in proposal_refs if isinstance(ref, str) and ref in valid_refs]
        if not refs:
            continue
        prompt = (
            "You are the Ansible playbook authoring agent for a defensive home security stack. "
            "Use this guidance:\n" + _load_knowledge() + "\n"
            "Given a draft and evidence, return JSON with exactly one key playbook_yaml containing "
            "a complete YAML playbook. Do not claim it was run. Use the specified evidence only.\n"
            "Draft:\n" + json.dumps(proposal, ensure_ascii=False)[:6000] + "\n"
            "Evidence:\n" + json.dumps([e for e in events if e.get("event_ref") in refs], ensure_ascii=False)[:8000]
        )
        try:
            response = request_json(f"{ollama_url}/api/generate",
                                    {"model": model, "prompt": prompt, "stream": False, "format": "json",
                                     "options": {"temperature": 0.1}}, timeout=240)
            final = json.loads(response.get("response", "{}"))
            playbook_text = final.get("playbook_yaml") if isinstance(final, dict) else None
            check = validate_playbook(playbook_text)
            if check["status"] != "passed":
                continue
        except (ValueError, json.JSONDecodeError, OSError, TimeoutError):
            continue
        finalized.append({
            "target": "ansible", "rationale": str(proposal.get("rationale", ""))[:1000],
            "event_refs": refs[:20], "risk": str(proposal.get("risk", ""))[:500],
            "false_positive_risk": str(proposal.get("false_positive_risk", ""))[:500],
            "validation_steps": ["Ansible syntax-check passed in the authoring container.",
                                 "Review inventory and run --check --diff in a test environment before approval."],
            "rollback_steps": [str(step)[:500] for step in proposal.get("rollback_steps", [])[:8]],
            "playbook_yaml": playbook_text,
            "validation": {"policy": "passed", "ansible_syntax": check["status"]},
            "status": "validated_draft_not_applied",
        })
    return finalized