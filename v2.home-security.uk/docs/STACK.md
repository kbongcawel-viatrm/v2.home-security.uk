# Minimal AI Security Lab

A small Podman/Compose stack built around host journald and native Suricata logs, Fluent Bit, OpenObserve, and Ollama. A small Python worker reads recent security logs from OpenObserve, sends a bounded batch to Ollama, and stores recommendations in OpenObserve.

## Services

| Service | Purpose | Published port |
|---|---|---|
| Native `suricata.service` | Host-interface IDS sensor; emits EVE JSON | Managed by host systemd |
| `fluent-bit` | Forwards Suricata EVE JSON and host journal records | None |
| `openobserve` | Search, dashboards and log storage | `127.0.0.1:5080` |
| `ollama` | Local LLM inference | Internal network only |
| `security-ai` | Periodically analyzes new security, kernel, and OS boot-log events and stores recommendations | None |

OpenObserve streams used by the current stack:
- `security_logs` receives host-journal and Suricata records from Fluent Bit, including `/var/log/boot.log` lines when that host file exists.
- `kernel_logs` receives journald records marked with `_TRANSPORT=kernel` (the host's kernel message stream, comparable to `dmesg`).
- `firewall_logs` receives a routed copy of journald records whose `_SYSTEMD_UNIT` is `firewalld.service`.
- `container_logs` receives a routed copy of journald records with Podman's `CONTAINER_ID_FULL` field. This depends on Podman using journald for container logs; the default log driver can vary by host configuration.
- `security_log_archive` is a persistent Podman named volume receiving a local file-output copy of records processed by Fluent Bit, including Suricata and journald records.
- `ai_recommendations` is the configured destination for successful AI analysis writes. OpenObserve creates it only after the worker successfully submits its first recommendation; it may not exist yet.

An existing `wazuh_alerts` stream may remain in the OpenObserve data volume from the former Wazuh setup. It is historical data: the current Compose stack does not ingest Wazuh alerts or write to that stream. The former Wazuh volumes were preserved separately.

## AI rule-draft handoff

`security-ai` now writes review-only files under `artifacts/generated/security-ai/`. A separate `ansible-ai` Compose service watches its manifest and writes a deterministic, policy-validated same-host playbook under `artifacts/generated/ansible-ai/`. Both containers use UID mapping and writable mounts limited to that generated-artifacts tree; neither receives host `/etc` mounts or host service sockets.

Severity policy: informational/low produces no selected host artifacts; medium selects Suricata alert rules; high/critical can additionally select the public IPv4 block-list and an inert Firewalld draft. The Firewalld script is never run. `blocked-ips.txt` is not yet connected to a Fail2ban jail/action, so staging it does not create a ban. Ansible drafts default to no-op and require both an explicit `apply_generated_artifacts=true` and interactive `APPLY` confirmation. If Suricata rules are selected, the playbook validates the config, reloads Suricata, observes for 150 seconds, checks the service and post-reload error journal, and attempts file/service rollback on failure. A human must review all generated files before any manual apply.

## Event pipeline

1. Native Suricata captures traffic on the configured host interface and writes `/var/log/suricata/eve.json`; host services and kernel messages are available from journald. Fluent Bit tails EVE JSON, Suricata text logs, and `/var/log/boot.log` if present.
2. Fluent Bit reads host journal records, routes `_TRANSPORT=kernel` records to `kernel_logs`, and sends `/var/log/boot.log` records to `security_logs` with `source=host-bootlog`. Suricata records are marked `source=suricata`, while general host-journal records also flow to `security_logs`; journald records matching firewalld or Podman's container metadata are rerouted to `firewall_logs` or `container_logs` respectively. Records processed by Fluent Bit are also copied to `security_log_archive`.
3. `security-ai` queries each configured OpenObserve stream independently with a small overlapping time window, deduplicates repeated results using stable event references, and applies a per-stream quota before producing a bounded batch for Ollama. The overlap reduces boundary misses; recommendations include per-stream and combined-limit warnings if query results reach their caps. Cursor state and recent references live in `security_ai_state`. The model examines Suricata, host boot and kernel records for supported trends, startup changes, and telemetry-integrity indicators, with explicit caution not to treat missing records alone as proof of tampering.
4. The worker writes the model's structured findings and proposed rule/configuration changes to the `ai_recommendations` stream.
5. A human reviews proposed changes, tests them in a controlled environment, commits approved changes to version control, deploys them, and verifies the resulting events.

The AI worker generates recommendations correlated to CVEs and cyber attacks. It does not modify or reload live security rules, run response actions, or execute Ansible. Recommendations include:
1. **Suricata rules** with CVE, attack_type, source_id, community_id metadata - deployed to `/var/lib/suricata/rules/suricata.rules` and Suricata is reloaded
2. **Firewall-cmd rules** to block IPs, services, or ports - applied via firewalld rich rules

### Deployment Architecture

Security changes are deployed by a **two-stage workflow**:

**Stage 1: deploy-v2-stack.yml** (Toolbox runner: `[self-hosted, fedora]`)
- Deploys the container stack (OpenObserve, Ollama, Fluent Bit, security-ai)
- The AI worker runs inside containers and generates recommendations
- Recommendations are stored in OpenObserve `ai_recommendations` stream

**Stage 2: apply-host-security-changes.yml** (GitHub-hosted runner: `ubuntu-latest`)
- Runs on GitHub-hosted runner (no self-hosted runner needed for security)
- Connects to target Fedora host via SSH with hardened configuration
- Uses `scripts/setup-ssh.sh` for secure SSH setup
- Uses GitHub secrets: `TARGET_HOST`, `TARGET_USER`, `TARGET_SSH_KEY`
- Validates playbooks with `scripts/validate-local-playbooks.py`
- Runs check mode (dry-run) with `--check --diff`
- Applies changes with `--become` over SSH for root permissions
- Deploys Suricata rules and reloads suricata.service
- Applies firewalld rich rules to block IPs/services/ports

**Required GitHub Secrets:**
- `TARGET_HOST` - IP or hostname of the Fedora target host
- `TARGET_USER` - SSH user on target host
- `TARGET_SSH_KEY` - SSH private key for authentication
- `TARGET_SUDO_PASSWORD` - Sudo password for privilege escalation (--become)

### Ansible Playbooks

Playbooks in `ansible/playbooks/` are restricted to localhost only:
- `deploy-suricata-rules.yml` - Deploy rules and reload Suricata
- `block-ip-firewalld.yml` - Block IP with firewalld rich rule
- `block-service-firewalld.yml` - Block service or port
- `rollback-firewalld.yml` - Rollback firewall changes

### Artifacts

Reviewed artifacts in `artifacts/`:
- `suricata.rules` - AI-generated Suricata detection rules
- `firewalld-blocks.json` - AI-generated firewalld block requests

### GitHub-Hosted Runner Requirements

The `apply-host-security-changes.yml` workflow runs on GitHub-hosted runners (`ubuntu-latest`).
No self-hosted runner is required for security deployments.

**GitHub Secrets:**
- `TARGET_HOST` - IP or hostname of the Fedora target host
- `TARGET_USER` - SSH user on target host (with sudo access)
- `TARGET_SSH_KEY` - SSH private key for authentication

**Target Host Requirements:**
- SSH server running and accessible
- User with sudo access (password stored in TARGET_SUDO_PASSWORD secret)
- Suricata installed with `/var/lib/suricata/rules/` directory
- firewalld installed and active
- No sudoers modifications needed - uses password-based sudo

A human must review artifacts, commit them to the repository, and trigger the
workflow. The worker never executes changes directly.

The optional `.github/workflows/ansible-local.yml` workflow operates only on reviewed playbooks committed under `ansible/playbooks/` and requires the non-empty reviewed artifact `artifacts/suricata.rules`; it does not import AI recommendations automatically. This workflow's allowed deployment action is copying that artifact to `/var/lib/suricata/rules/suricata.rules`. It does not alter Suricata configuration or reload/restart Suricata; after apply, a human must review the deployed rules and manually reload Suricata on the host later. Firewall-cmd rules are not applied by the workflow; any approved firewall commands must be reviewed and run manually with `sudo` on the host. Workflow dispatch defaults to simulation (policy, syntax, and check-mode preview only). Applying requires explicitly disabling simulation and approving the configured `ansible-local-apply` GitHub Environment; the apply command uses `--become` on the Fedora self-hosted runner, so the runner account must have suitable non-interactive sudo authorization. Playbooks are repeated on each apply run and should be idempotent to correct drift. No reviewed rules artifact/playbook is currently available, so no deployment or runner simulation has been verified.

### Persistent log archive and dashboards

`security_log_archive` is mounted into Fluent Bit at `/var/log/security-archive`. Fluent Bit's file output writes all routed records to `fluent-bit-events.jsonl` in its built-in file-output format; the filename is for identification and does not promise strict JSON Lines encoding. Its named volume survives ordinary Compose stop/remove and container recreation. OpenObserve independently retains its indexed data in `openobserve_data`. These two stores serve different purposes: OpenObserve is the interactive search/dashboard store, and the archive is a local copy for recovery or offline processing. Both can grow over time; monitor free disk and back up important data. `podman-compose down -v` deletes named volumes, including both stores.

The `fluent-bit` service mounts `${BOOT_LOG_PATH:-/var/log/boot.log}` read-only at `/host/boot.log` and tails it into `security_logs`. `/var/log/boot.log` is distro- and configuration-dependent; on systems without the file the input will be idle and no boot.log events will appear. Kernel messages are collected from the mounted system journal where accessible and routed from `_TRANSPORT=kernel` to `kernel_logs`; this is not an invocation of `dmesg`, and access/history depends on journald configuration and permissions. Both streams are included in AI analysis.

In OpenObserve, choose the `security_logs` stream and create panels from queries such as:

```sql
-- Event volume over time (set the panel interval to 1 minute or 5 minutes)
SELECT histogram(_timestamp, '5 minutes') AS time, count(*) AS events
FROM "security_logs"
WHERE source = 'suricata'
GROUP BY time ORDER BY time

-- Event-type distribution
SELECT event_type, count(*) AS events
FROM "security_logs"
WHERE source = 'suricata'
GROUP BY event_type ORDER BY events DESC

-- Alerts by signature and severity
SELECT alert.signature AS signature, alert.severity AS severity, count(*) AS events
FROM "security_logs"
WHERE source = 'suricata' AND event_type = 'alert'
GROUP BY signature, severity ORDER BY events DESC

-- Suricata stats snapshots (EVE event_type=stats)
SELECT * FROM "security_logs"
WHERE source = 'suricata' AND event_type = 'stats'
ORDER BY _timestamp DESC
```

Use OpenObserve's SQL editor to validate queries against the actual schema, then add each result as a panel and save them into a dashboard. Suricata `stats` events are the primary performance/traffic counters; the Fluent Bit configuration also enables its internal storage metrics, but does not currently export a Prometheus endpoint. Exact panel API provisioning is not included, to avoid coupling to a particular OpenObserve release's dashboard JSON format.

## Prerequisites and important limitations

- Run from a directory containing `compose.yaml`, `.env`, `fluent-bit/fluent-bit.conf`, and `security-ai/`.
- Suricata is already installed and managed natively on the Fedora host as `suricata.service`, not by this Compose project. The deployment workflow only verifies the existing service and its EVE log; it does not install or configure Suricata.
- Fluent Bit bind-mounts `${SURICATA_LOG_DIR:-/var/log/suricata}` and `/run/log/journal` read-only. The journal mount is deliberately not relabeled with `:Z` because rootless Podman cannot relabel the host journal directory; verify Fluent Bit can read it under host permissions and SELinux policy. Do not blindly relabel host log directories, which can interfere with host services.
- OpenObserve is bound to localhost by default. Access it through a local browser at `http://127.0.0.1:5080`. Do not expose it directly to the Internet.
- Ollama's API is not published on the host. Only containers on the private Compose network can access it.
- Set a unique OpenObserve password in the host env file `/etc/v2.home-security.uk/minimal-ai-security-lab.env` before first start. OpenObserve initializes root credentials on first start; changing environment variables later may not change an existing account password.
- `OPENOBSERVE_USER` must be a valid email address, not the literal `admin`. The sample value is `dummykevin08@gmail.com`; set it in the protected host environment file or deployment secret source as appropriate. Preserve the `openobserve_data` volume; do not remove it to troubleshoot credentials because it contains stored data. If OpenObserve is already initialized, follow the version-matched account/password recovery procedure rather than assuming environment changes reset it.
- The worker queries the last `OPENOBSERVE_QUERY_INTERVAL_MINUTES` (default 5) on its first run, then advances its saved query time after each successful cycle. It caps each batch at `MAX_EVENTS_PER_BATCH` (default 30). Initial historical logs are not backfilled into AI analysis.
- The worker stores offsets in `security_ai_state`. Fluent Bit stores independent tail offsets in `fluent_bit_state`.
- The named volumes in this standalone file are distinct from similarly named volumes in an existing Compose project unless explicitly declared as external. Do not run this alongside your existing stack without reviewing port conflicts, duplicate service names, and which volumes contain your existing data.

## Host Suricata prerequisite

Suricata is already installed and managed on the host as `suricata.service`. This repository does not install, configure, enable, or start it. The deployment workflow only checks that the existing service is enabled and active, validates the current configuration, and checks that the EVE log is readable and valid. For host-side maintenance, use your normal system administration process. Useful read-only checks include:

```bash
rpm -ql suricata | grep -E 'systemd|suricata.yaml|rules'
systemctl cat suricata
suricata --build-info
```

Verify that `/var/log/suricata/eve.json` is updating before relying on the sensor.

## Install the Compose stack

The host-managed environment file is `/etc/v2.home-security.uk/minimal-ai-security-lab.env`. It holds secrets, so it should be owned by your user with mode `600`. Do not copy it into the repository. Set a long, unique `OPENOBSERVE_PASSWORD` in that file before first start, then copy it into the project directory for a manual run:

```bash
install -m 600 /etc/v2.home-security.uk/minimal-ai-security-lab.env .env
```

The CI workflow does the same copy automatically and deletes `.env` when the job ends.

Review the Compose file and confirm the host interface name:

```bash
ip -brief link
```

Validate the rendered Compose configuration:

```bash
podman-compose -f compose.yaml config
```

Start the services:

```bash
CONTAINERS_POLICY_JSON="$PWD/containers-policy.json" podman build --signature-policy "$PWD/containers-policy.json" -t localhost/minimal-ai-security-worker:1.0 ./security-ai
podman-compose -f compose.yaml up -d --no-build
```

If your installed `podman-compose` version does not support `config`, use the available Compose validation command and inspect the rendered configuration before deployment. Do not use `sudo` blindly: rootful Podman has a separate container/volume store from rootless Podman.

Pull the selected Ollama model once:

```bash
podman exec ollama ollama pull qwen2.5:3b
```

Check status and logs (run the host service checks with sufficient privileges if required):

```bash
podman ps
podman logs --tail 100 fluent-bit
podman logs --tail 100 openobserve
podman logs --tail 100 security-ai
run0 systemctl is-active suricata.service
run0 suricata -T -c /etc/suricata/suricata.yaml
run0 tail -n 5 /var/log/suricata/eve.json
```

### Boot-time diagnostic log

An optional read-only user systemd unit captures Podman status, configured log drivers, the last 100 Fluent Bit and AI-worker log lines, and Suricata service status after a 30-second boot delay. It appends to `$XDG_STATE_HOME/v2-home-security/boot-diagnostics.log` (normally `~/.local/state/v2-home-security/boot-diagnostics.log`) with mode `600`, keeping one rotated copy when the current file reaches 5 MiB. Container logs can contain sensitive data; protect this file.

Install and enable it for the account that owns the rootless Podman containers:

```bash
install -Dm755 scripts/collect-boot-logs.sh "$HOME/.local/bin/collect-v2-home-security-boot-logs"
install -Dm644 scripts/systemd/v2-home-security-boot-diagnostics.service \
  "$HOME/.config/systemd/user/v2-home-security-boot-diagnostics.service"
systemctl --user daemon-reload
systemctl --user enable v2-home-security-boot-diagnostics.service
```

For the user unit to run at system boot before interactive login, enable lingering for the account using the host's administrative mechanism (for example, `sudo loginctl enable-linger "$USER"`). Review output with `less "$HOME/.local/state/v2-home-security/boot-diagnostics.log"` or `journalctl --user -u v2-home-security-boot-diagnostics.service`.

Open `http://127.0.0.1:5080` and sign in with the credentials in `.env`.

## Verify ingestion

To manually inject a clearly labeled synthetic Suricata-style event for testing, start the Compose stack and run this from the repository root:

```bash
./scripts/emit-synthetic-security-event.sh
```

The script uses the running `security-ai` container's OpenObserve connection settings, writes one event to `security_logs`, and prints the OpenObserve HTTP status. The event is marked `test_event: true` and uses documentation-range IP addresses; it is not real traffic and does not change security rules. Repeat the command whenever you want to trigger another test event.

1. Confirm native Suricata is active and emitting EVE JSON:
   ```bash
   systemctl is-active suricata.service
   tail -n 5 /var/log/suricata/eve.json
   ```
2. Confirm Fluent Bit is running and can read the Suricata log:
   ```bash
   podman ps --filter name=fluent-bit
   podman exec fluent-bit sh -c 'test -r /var/log/suricata/eve.json && echo readable'
   ```
3. In OpenObserve, inspect `security_logs` for `source=suricata` and `source=host-journal`; inspect `firewall_logs` for `source=firewalld` and `container_logs` for `source=podman-container`. Each stream is created upon first ingestion. Container log routing requires journald-backed Podman logs with the `CONTAINER_ID_FULL` field; other log drivers are not tailed by this stack.
4. The worker only creates `ai_recommendations` after it successfully queries new events from its input streams, completes an Ollama analysis, and writes the result. Its bounded input includes Suricata EVE/text and kernel records; `/var/log/boot.log` is included if the file exists and is readable. Check `podman logs --tail 100 security-ai` for `submitted AI analysis...`; `no new security logs to analyze` means there was no analysis to write in that cycle. An `analysis cycle failed` message means the query or analysis could not complete; resolve the logged OpenObserve/Ollama connectivity or authentication error and check again after a successful cycle.

## Operations and maintenance

- Keep `.env` out of version control, and keep the host env file in `/etc/v2.home-security.uk/` with mode `600`.
- Pin image tags or digests after testing; avoid unattended production upgrades from `latest`.
- Back up named volumes and test restores.
- Monitor disk usage; log and model volumes can grow substantially.
- Test proposed detection-rule changes before deployment. Keep a known-good revision and rollback procedure.

## Stop

```bash
podman-compose -f compose.yaml down
```

This stops and removes the Compose-managed containers while leaving named volumes intact. The former Wazuh container has been removed, but its named volumes were deliberately preserved and are not part of this Compose file. Do not run `down -v` unless you intentionally want to destroy the current stack's stored logs, OpenObserve data, Ollama models, and worker state.
