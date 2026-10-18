# Generated Security Artifacts

The two agents exchange files under `artifacts/generated/`. These outputs are drafts and do not modify host configuration by themselves.

## Agent responsibilities

- `security-ai` analyzes OpenObserve events and atomically writes `artifacts/generated/security-ai/{home-security.rules,blocked-ips.txt,firewall-draft.sh,manifest.json}`. The manifest is published last and is the handoff marker.
- `ansible-ai` reads a new manifest and writes `artifacts/generated/ansible-ai/{deploy-security-artifacts.yml,manifest.json}`. It deterministically generates a restricted same-host playbook; it does not use an LLM-generated task list and never runs Ansible.
- The older files in the root of `artifacts/` are not overwritten by either worker. In particular, the untracked legacy `artifacts/firewall.sh` is not read or executed.

## Severity policy

| Severity | Drafts selected by Ansible |
|---|---|
| Informational / low | No host files |
| Medium | Suricata alert rules only |
| High / critical | Suricata alert rules and IP-block draft files, if non-empty |

Only `alert` Suricata rules with local SIDs `1000000–1999999` are emitted. Duplicate SIDs are removed. Firewalld candidates are observed public IPv4 addresses only; private, reserved, documentation, IPv6, service, and port requests are excluded. Firewall output contains narrow source-address rich rules and never changes the default zone or policy.

## Drafted host paths

- Suricata: `/etc/suricata/rules/home-security.rules`
- Fail2ban: `/etc/fail2ban/blocked-ips.txt`
- Firewalld: `/etc/firewalld/firewall-draft.sh`

Fail2ban is deliberately a text draft only: this host currently has no active Fail2ban configuration consuming `blocked-ips.txt`. The playbook does not claim that staging the list creates bans. Firewalld shell content is staged as inert text only and the playbook never executes it.

## Explicit manual apply (not automated)

Generated playbooks default to no changes. A human must review the manifest, all artifact contents, and the playbook. Staging requires both the `apply_generated_artifacts=true` extra variable and typing `APPLY` at Ansible's interactive prompt. For example, from the generated playbook directory:

```sh
ansible-playbook -i localhost, -c local --ask-become-pass \
  -e apply_generated_artifacts=true deploy-security-artifacts.yml
```

Review `--check --diff` first; interactive confirmation may be supplied with `--extra-vars` only by an operator intentionally choosing to apply. The current playbook validates the Suricata config, reloads Suricata, waits 150 seconds, checks service status and error-priority journal records since reload, and attempts to restore backed-up files/reload Suricata if a guarded deployment task fails. This path has not been exercised against the live host.

No generated playbook is automatically executed by Compose or either worker. No live rules have been changed by this code task.

---

## Files

### suricata.rules
AI-generated Suricata detection rules with CVE/attack metadata.

**Format:**
- Single-line `alert` rules only
- SID range: 1000000-1999999 (local rules)
- Required metadata: `cve`, `attack_type`, `source_id`, `created_at`

**Example:**
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"AI-REC: SSH brute force"; flow:to_server,established; detection_filter:track by_src, count 5, seconds 60; classtype:attempted-admin; sid:1000001; rev:1; metadata:cve CVE-2024-6387, attack_type brute_force, source_id AI-REC, created_at 2026-01-01;)
```

**Deployment:**
- Copied to `/var/lib/suricata/rules/suricata.rules` by `ansible/playbooks/deploy-suricata-rules.yml`
- Suricata is reloaded automatically after deployment

### firewalld-blocks.json
AI-generated firewalld block requests.

**Format:**
```json
{
  "version": "1.0",
  "blocks": [
    {
      "block_type": "ip|service|port",
      "target": "192.0.2.100|telnet|4444/tcp",
      "zone": "public",
      "reason": "Description of why this block is recommended",
      "cve_ids": ["CVE-2024-XXXX"],
      "attack_types": ["brute_force"],
      "mitre_techniques": ["T1110"],
      "event_refs": ["abc123"],
      "confidence": "high|medium|low",
      "expires_at": "2026-01-08T00:00:00Z"
    }
  ]
}
```

**Deployment:**
- Processed by `scripts/process-firewalld-blocks.py`
- Applied via `ansible/playbooks/block-ip-firewalld.yml` or `ansible/playbooks/block-service-firewalld.yml`

## Workflow

1. AI worker generates recommendations → OpenObserve `ai_recommendations` stream
2. Human reviews recommendations and creates artifacts in this directory
3. Human commits artifacts to repository
4. `apply-host-security-changes.yml` workflow deploys artifacts via SSH:
   - Runs on GitHub-hosted runner (`ubuntu-latest`)
   - Connects to target host via SSH using GitHub secrets
   - Validates playbooks and artifacts
   - Runs check mode (dry-run)
   - Applies with `--become` over SSH
5. Verify on target host:
   ```bash
   ssh user@target-host 'sudo systemctl status suricata'
   ssh user@target-host 'sudo firewall-cmd --list-all'
   ssh user@target-host 'sudo tail -f /var/log/suricata/suricata.log'
   ```

### GitHub Secrets Required

Configure these in **Settings → Secrets and variables → Actions**:

| Secret | Description | Example |
|--------|-------------|---------|
| `TARGET_HOST` | Target Fedora host IP/hostname | `192.168.1.100` |
| `TARGET_USER` | SSH user | `kim` |
| `TARGET_SSH_KEY` | SSH private key | `-----BEGIN OPENSSH...` |
| `TARGET_SUDO_PASSWORD` | Sudo password for --become | `your-sudo-password` |

### Generating SSH Key

```bash
# On your local machine or target host
ssh-keygen -t ed25519 -C "github-actions" -f ~/.ssh/github_actions

# Copy public key to target host
ssh-copy-id -i ~/.ssh/github_actions.pub user@target-host

# Add private key to GitHub secrets as TARGET_SSH_KEY
cat ~/.ssh/github_actions
```

### SSH Hardening

The workflow uses a hardened SSH configuration (`scripts/ssh_config.hardened`)
generated by `scripts/setup-ssh.sh`. Security features include:

| Feature | Setting | Purpose |
|---------|---------|---------|
| **Ciphers** | ChaCha20, AES-GCM, AES-CTR | Modern, fast, secure encryption |
| **Key Exchange** | Curve25519, DH-GEX-SHA256 | Forward secrecy, strong DH |
| **MACs** | HMAC-SHA2-512/256-ETM | Encrypt-then-MAC, no weak hashes |
| **Host Keys** | Ed25519, RSA-SHA2 | No DSA, no SHA1 |
| **Auth** | Public key only | No passwords, no keyboard-interactive |
| **Forwarding** | Disabled | No agent/X11 forwarding |
| **Host Check** | Strict + HashKnownHosts | MITM protection |

**Hardened SSH config location:** `~/.ssh/config` (on GitHub-hosted runner)

**Script:** `scripts/setup-ssh.sh` - Automates SSH setup with hardening

## Rollback

- Suricata rules: Restore from backup at `/var/lib/suricata/rules/suricata.rules.bak` and reload
- Firewalld: Use `ansible/playbooks/rollback-firewalld.yml` or manual `firewall-cmd` commands

## Security

- **Review all artifacts before committing**
- Never commit secrets or credentials
- Validate rule syntax with `suricata -T` before deployment
- Test in a non-production environment first
