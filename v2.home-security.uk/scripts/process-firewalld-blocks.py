#!/usr/bin/env python3
"""Process firewalld block requests from artifacts/firewalld-blocks.json.

This script is called by the GitHub Actions workflow to apply firewalld
changes (block IPs, services, or ports) using Ansible playbooks.

Usage:
    python3 scripts/process-firewalld-blocks.py [--check]

The --check flag runs in dry-run mode (check mode only).
"""
import json
import subprocess
import sys
from pathlib import Path

def main():
    check_only = '--check' in sys.argv
    
    blocks_file = Path('artifacts/firewalld-blocks.json')
    if not blocks_file.exists():
        print(f"No firewalld blocks file found: {blocks_file}")
        return 0
    
    with open(blocks_file) as f:
        data = json.load(f)
    
    blocks = data.get('blocks', [])
    print(f"Found {len(blocks)} block(s) to process")
    
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
        print(f"\n=== Block {i}: {block_type} {target} in zone {zone} [{mode}] ===")
        
        cmd = [
            'ansible-playbook',
            '--inventory', 'localhost,',
            '--connection', 'local',
            '--limit', 'localhost',
            '--become',
        ]
        if check_only:
            cmd.extend(['--check', '--diff'])
        cmd.extend(['--extra-vars', extra_vars, playbook])
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        print(result.stdout)
        if result.returncode != 0:
            print(result.stderr, file=sys.stderr)
            failed = True
    
    if failed:
        print("\n=== Some blocks failed ===")
        return 1
    
    print("\n=== All blocks processed successfully ===")
    return 0

if __name__ == '__main__':
    sys.exit(main())
