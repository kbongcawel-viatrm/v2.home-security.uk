#!/usr/bin/env python3
"""Turn security-ai manifests into validated, draft-only Ansible playbooks."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from playbook_generator import write_playbook


SECURITY_DIR = Path(os.getenv("SECURITY_ARTIFACTS_DIR", "/artifacts/generated/security-ai"))
OUTPUT_DIR = Path(os.getenv("ANSIBLE_ARTIFACTS_DIR", "/artifacts/generated/ansible-ai"))
INTERVAL = max(10, int(os.getenv("PLAYBOOK_INTERVAL_SECONDS", "30")))
STATE_FILE = Path(os.getenv("PLAYBOOK_STATE_FILE", "/tmp/ansible-ai-manifest.sha256"))


def process_manifest() -> bool:
    source = SECURITY_DIR / "manifest.json"
    if not source.is_file():
        return False
    try:
        text = source.read_text(encoding="utf-8")
        manifest = json.loads(text)
        fingerprint = str(manifest.get("analysis_id", ""))
        if not fingerprint:
            return False
        if STATE_FILE.exists() and STATE_FILE.read_text(encoding="utf-8").strip() == fingerprint:
            return False
        metadata = write_playbook(source, OUTPUT_DIR)
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = STATE_FILE.with_suffix(".tmp")
        temporary.write_text(fingerprint, encoding="utf-8")
        temporary.replace(STATE_FILE)
        print(
            "wrote draft-only Ansible playbook "
            f"severity={metadata['severity']} selected={len(metadata['selected_artifacts'])} "
            f"path={OUTPUT_DIR / 'deploy-security-artifacts.yml'}",
            flush=True,
        )
        return True
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"playbook draft generation failed: {type(exc).__name__}: {exc}", flush=True)
        return False


def main() -> None:
    print(
        f"ansible-ai draft worker started; interval={INTERVAL}s; "
        f"source={SECURITY_DIR}; output={OUTPUT_DIR}",
        flush=True,
    )
    while True:
        process_manifest()
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()