#!/usr/bin/env python3
"""Process firewalld block requests from artifacts/firewalld-blocks.json.

This script is called by the GitHub Actions workflow to apply firewalld
changes (block IPs, services, or ports) using Ansible playbooks.

Usage:
    python3 scripts/process-firewalld-blocks.py [--check] [--inventory inventory.ini]

Options:
    --check              Run in dry-run mode (check mode only, no changes)
    --inventory FILE     Ansible inventory file (default: localhost, with local connection)
    --limit GROUP        Limit to specific host group (default: target)

Examples:
    # Local execution (dry-run)
    python3 scripts/process-firewalld-blocks.py --check

    # Remote execution via SSH (dry-run)
    python3 scripts/process-firewalld-blocks.py --check --inventory inventory.ini

    # Remote execution via SSH (apply)
    python3 scripts/process-firewalld-blocks.py --inventory inventory.ini
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description='Process firewalld block requests using Ansible playbooks'
    )
    parser.add_argument(
        '--check',
        action='store_true',
        help='Run in check mode (dry-run, no changes)'
    )
    parser.add_argument(
        '--inventory',
        default=None,
        help='Ansible inventory file (default: localhost, with local connection)'
    )
    parser.add_argument(
        '--limit',
        default='target',
        help='Host group to limit execution to (default: target)'
    )
    args = parser.parse_args()

    check_only = args.check
    inventory = args.inventory
    limit = args.limit

    blocks_file = Path('artifacts/firewalld-blocks.json')
    if not blocks_file.exists():
        print(f"No firewalld blocks file found: {blocks_file}")
        return 0

    with open(blocks_file) as f:
        data = json.load(f)

    blocks = data.get('blocks', [])
    print(f"Found {len(blocks)} block(s) to process")
    print(f"Mode: {'CHECK (dry-run)' if check_only else 'APPLY'}")
    print(f"Inventory: {inventory or 'localhost (local connection)'}")
    print(f"Limit: {limit}")
    print("")

    failed = False
    for i, block in enumerate(blocks, 1):
        block_type = block.get('block_type')
        zone = block.get('zone', 'public')
        target = block.get('target')
        reason = block.get('reason', 'AI-recommended block')

        if not target:
            print(f"Block {i}: missing target, skipping")
            failed = True
            continue

        if block_type == 'ip':
            playbook = 'ansible/playbooks/block-ip-firewalld.yml'
            extra_vars = f"block_ip={target} zone={zone} reason='{reason}'"
        elif block_type == 'service':
            playbook = 'ansible/playbooks/block-service-firewalld.yml'
            extra_vars = f"service_name={target} zone={zone}"
        elif block_type == 'port':
            playbook = 'ansible/playbooks/block-service-firewalld.yml'
            extra_vars = f"port={target} zone={zone}"
        else:
            print(f"Block {i}: unknown block type '{block_type}', skipping")
            failed = True
            continue

        mode = "CHECK MODE (dry-run)" if check_only else "APPLY"
        print(f"=== Block {i}: {block_type} {target} in zone {zone} [{mode}] ===")

        cmd = [
            'ansible-playbook',
            '--become',
        ]
        if inventory:
            cmd.extend(['--inventory', inventory])
            cmd.extend(['--limit', limit])
        else:
            cmd.extend(['--inventory', 'localhost,', '--connection', 'local'])
        if check_only:
            cmd.extend(['--check', '--diff'])
        cmd.extend(['--extra-vars', extra_vars, playbook])

        print(f"Command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            failed = True
        print("")

    if failed:
        print("=== Some blocks failed ===")
        return 1

    print("=== All blocks processed successfully ===")
    return 0


if __name__ == '__main__':
    sys.exit(main())
