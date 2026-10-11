# Minimal AI Security Lab

A small Podman/Compose stack built around host journald and native Suricata logs, Fluent Bit, OpenObserve, and Ollama. A small Python worker reads recent security logs from OpenObserve, sends a bounded batch to Ollama, and stores recommendations in OpenObserve.

## Services

| Service | Purpose | Published port |
|---|---|---|
| Native `suricata.service` | Host-interface IDS sensor; emits EVE JSON | Managed by host systemd |
| `fluent-bit` | Forwards Suricata EVE JSON and host journal records | None |
| `openobserve` | Search, dashboards and log storage | `127.0.0.1:5080` |
| `ollama` | Local LLM inference | Internal network only |
| `security-ai` | Periodically analyzes new alerts and stores recommendations | None |

OpenObserve streams used by the current stack:
- `security_logs` receives host-journal and Suricata records from Fluent Bit.
- `ai_recommendations` is the configured destination for successful AI analysis writes. OpenObserve creates it only after the worker successfully submits its first recommendation; it may not exist yet.

An existing `wazuh_alerts` stream may remain in the OpenObserve data volume from the former Wazuh setup. It is historical data: the current Compose stack does not ingest Wazuh alerts or write to that stream. The former Wazuh volumes were preserved separately.

## Event pipeline

1. Native Suricata captures traffic on the configured host interface and writes `/var/log/suricata/eve.json`; host services write to journald.
2. Fluent Bit tails Suricata EVE JSON and reads host journal records, tagging events with their source and forwarding both to `security_logs`.
3. `security-ai` queries a bounded recent time window from OpenObserve and submits new records to Ollama.
4. The worker writes the model's structured findings and proposed rule/configuration changes to the `ai_recommendations` stream.
5. A human reviews proposed changes, tests them in a controlled environment, commits approved changes to version control, deploys them, and verifies the resulting events.

The AI worker is advisory only. It does not modify or reload live security rules, or run response actions. This lightweight setup is log collection and analysis, not Wazuh-equivalent endpoint monitoring or agent management.

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
3. In OpenObserve, inspect the `security_logs` stream for records with `source=suricata` or `source=host-journal`. The stream is created upon first ingestion.
4. The worker only creates `ai_recommendations` after it successfully queries new `security_logs`, completes an Ollama analysis, and writes the result. Check `podman logs --tail 100 security-ai` for `submitted AI analysis...`; `no new security logs to analyze` means there was no analysis to write in that cycle. An `analysis cycle failed` message means the stream will not be created by that attempt; resolve the logged OpenObserve/Ollama connectivity or authentication error and check again after a successful cycle.

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
