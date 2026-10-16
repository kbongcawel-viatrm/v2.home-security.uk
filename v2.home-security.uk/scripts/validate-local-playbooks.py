#!/usr/bin/env python3
"""Validate reviewed deployment playbooks with a narrow task allow-list."""
import re
import sys
from pathlib import Path
import yaml

FORBIDDEN = {"shell", "raw", "script", "include_tasks", "import_tasks", "include_role", "import_role", "delegate_to", "local_action", "add_host"}
MODULES = {"ansible.builtin.copy", "ansible.builtin.stat", "ansible.builtin.assert", "ansible.builtin.debug", "ansible.builtin.file", "ansible.builtin.fail", "ansible.builtin.service", "ansible.builtin.command"}
SAFE_PATHS = {
    "../../artifacts/suricata.rules", "/var/lib/suricata/rules/suricata.rules", "/var/lib/suricata/rules",
    "/etc/suricata/rules/home-security.rules", "/etc/suricata/rules/home-security.rules.security-ai.bak",
    "/etc/fail2ban/blocked-ips.txt", "/etc/fail2ban/blocked-ips.txt.security-ai.bak",
    "/etc/firewalld/firewall-draft.sh", "/etc/firewalld/firewall-draft.sh.security-ai.bak",
    "{{ security_artifacts_dir }}/home-security.rules", "{{ security_artifacts_dir }}/blocked-ips.txt",
    "{{ security_artifacts_dir }}/firewall-draft.sh",
}
JINJA = re.compile(r"\{\{[^}]+\}\}")
DANGEROUS = [re.compile(pattern) for pattern in (r"[;&|`$(){}]", r"--panic", r"--flush", r"--remove-all", r"--set-default-zone", r"--add-interface", r"--change-interface", r"iptables", r"nft\s", r"rm\s+-rf", r"dd\s+if=", r">\s*/etc/")]
COMMANDS = [re.compile(pattern) for pattern in (
    r"^suricata\s+-T\s+-c\s+/etc/suricata/suricata\.yaml(\s+-S\s+\S+)?$",
    r"^date\s+\+%s$", r"^sleep\s+150$", r"^systemctl\s+is-active\s+suricata$",
    r"^firewall-cmd\s+--zone=[A-Za-z0-9_-]{1,64}\s+--(add|remove)-rich-rule=.*$",
    r"^firewall-cmd\s+--zone=[A-Za-z0-9_-]{1,64}\s+--(add|remove)-(service|port)=.*$",
    r"^firewall-cmd\s+--zone=[A-Za-z0-9_-]{1,64}\s+--permanent\s+--(add|remove)-(rich-rule|service|port)=.*$",
    r"^firewall-cmd\s+--zone=[A-Za-z0-9_-]{1,64}\s+--query-rich-rule=.*$",
)]
TASK_KEYS = {"name", "become", "when", "register", "changed_when", "failed_when", "ignore_errors", "until", "retries", "delay", "args"}


def trusted(path): return isinstance(path, str) and path in SAFE_PATHS


def allowed_command(command):
    if not isinstance(command, str): return False
    normalized = JINJA.sub("__VAR__", command)
    return not any(pattern.search(normalized) for pattern in DANGEROUS) and any(pattern.match(normalized) for pattern in COMMANDS)


def task_errors(task, location, generated=False):
    errors=[]
    if not isinstance(task, dict): return [f"{location}: expected a task mapping"]
    forbidden=FORBIDDEN.intersection(task)
    if forbidden: errors.append(f"{location}: forbidden task directives: {sorted(forbidden)}")
    modules=[key for key in task if isinstance(key,str) and key.startswith("ansible.builtin.")]
    if len(modules)!=1 or modules[0] not in MODULES: return errors+[f"{location}: unsupported module"]
    module=modules[0]; args=task[module]
    if set(task)-TASK_KEYS-{module}: errors.append(f"{location}: unsupported directives")
    if module=="ansible.builtin.command":
        if not isinstance(args,dict): return errors+[f"{location}: command args must be a mapping"]
        expected=["journalctl","-u","suricata","--since","@{{ suricata_reload_epoch.stdout }}","--priority=err","--no-pager"]
        if args.get("argv") != expected and not allowed_command(args.get("cmd")): errors.append(f"{location}: command not allowed")
    elif module=="ansible.builtin.copy":
        if not isinstance(args,dict) or not trusted(args.get("dest")): return errors+[f"{location}: copy destination not allowed"]
        source=args.get("src")
        if args.get("remote_src"):
            if source not in SAFE_PATHS or not source.startswith("/etc/"): errors.append(f"{location}: backup source not allowed")
        elif not trusted(source): errors.append(f"{location}: artifact source not allowed")
    elif module=="ansible.builtin.file":
        if not isinstance(args,dict) or not trusted(args.get("path")) or args.get("state")!="absent": errors.append(f"{location}: file task outside rollback scope")
    elif module=="ansible.builtin.service":
        if not isinstance(args,dict) or args.get("name")!="suricata" or args.get("state")!="reloaded": errors.append(f"{location}: service action not allowed")
    return errors


def nested_errors(task, location):
    errors=[]
    if "block" not in task: return task_errors(task,location,True)
    expected="apply_generated_artifacts | bool and confirm_security_artifact_apply == 'APPLY'"
    if task.get("when")!=expected: errors.append(f"{location}: explicit apply guard missing")
    for section in ("block","rescue","always"):
        children=task.get(section,[])
        if not isinstance(children,list): errors.append(f"{location}: {section} must be a list"); continue
        for number,child in enumerate(children,1): errors.extend(task_errors(child,f"{location} {section}[{number}]",True))
    return errors


def validate(path: Path):
    try: plays=yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError,yaml.YAMLError) as exc: return [f"{path}: invalid YAML: {exc}"]
    if not isinstance(plays,list) or not plays: return [f"{path}: expected a non-empty play list"]
    generated=path.name=="deploy-security-artifacts.yml" and "ansible-ai" in path.parts
    errors=[]
    for pno,play in enumerate(plays,1):
        loc=f"{path}: play {pno}"
        if not isinstance(play,dict): errors.append(f"{loc}: expected a mapping"); continue
        host=play.get("hosts")
        if host not in ("localhost","target"): errors.append(f"{loc}: hosts must be localhost or target")
        if host=="localhost" and play.get("connection")!="local": errors.append(f"{loc}: localhost requires connection local")
        tasks=play.get("tasks",[])
        if not isinstance(tasks,list): errors.append(f"{loc}: tasks must be a list"); continue
        if not generated:
            for n,task in enumerate(tasks,1): errors.extend(task_errors(task,f"{loc}: task {n}"))
            continue
        if host!="localhost" or play.get("connection")!="local" or play.get("become") is not True: errors.append(f"{loc}: must target same host with become")
        if play.get("vars",{}).get("apply_generated_artifacts") is not False: errors.append(f"{loc}: apply must default false")
        if not any(isinstance(prompt,dict) and prompt.get("name")=="confirm_security_artifact_apply" and prompt.get("private") is False for prompt in play.get("vars_prompt",[])): errors.append(f"{loc}: interactive APPLY prompt missing")
        guard="apply_generated_artifacts | bool and confirm_security_artifact_apply == 'APPLY'"
        if len(tasks)!=2 or tasks[0].get("when")!=guard: errors.append(f"{loc}: both apply controls required")
        for n,task in enumerate(tasks,1): errors.extend(nested_errors(task,f"{loc}: task {n}"))
        text=path.read_text(encoding="utf-8")
        if "sleep 150" not in text or "journalctl" not in text: errors.append(f"{loc}: Suricata observation and post-reload error check required")
        report=tasks[-1].get("ansible.builtin.debug",{}).get("msg",[]) if tasks and isinstance(tasks[-1],dict) else []
        if not any("firewall-draft.sh" in str(line) and "never execute" in str(line) for line in report): errors.append(f"{loc}: firewall execution prohibition missing")
    return errors


def main():
    root=Path(sys.argv[1] if len(sys.argv)>1 else "ansible/playbooks")
    if not root.is_dir(): print(f"Playbook directory does not exist: {root}",file=sys.stderr); return 1
    files=sorted((*root.rglob("*.yml"),*root.rglob("*.yaml")))
    if not files: print(f"No playbooks found in {root}",file=sys.stderr); return 1
    errors=[err for path in files for err in validate(path)]
    if errors: print("\n".join(errors),file=sys.stderr); return 1
    print(f"Playbook policy passed for {len(files)} playbook(s)"); return 0

if __name__=="__main__": raise SystemExit(main())
