# Completed validation

- [x] Confirmed `fluent-bit`, `openobserve`, `ollama`, and `security-ai` containers are running with healthy status and zero restarts.
- [x] Configured Fluent Bit systemd inputs for kernel messages (`host.kernel`), journald-service boot records (`host.boot`), and general host journal records (`host.journal`).
- [x] Configured the `suricata.eve` JSON tail input for `/var/log/suricata-export/eve.json`, with a persistent offset database and `source=suricata` label.
- [x] Configured the `security.auditd` tail input for `/var/log/audit/audit.log`, with rotation handling, a persistent offset database, and `source=auditd` label.
- [x] Mounted the host journal, Suricata export, auditd, and AIDE directories read-only into Fluent Bit.
- [x] Routed all Fluent Bit inputs to OpenObserve's `security_logs` stream through the `_multi` ingestion endpoint.
- [x] Confirmed OpenObserve health at `http://127.0.0.1:5080/healthz`.
- [x] Confirmed the configured Ollama model, `qwen2.5:3b`, is installed and loads through `llamacpp`.
- [x] Corrected the Ollama healthcheck to use `/bin/ollama` and validate model availability without running an inference every 30 seconds.
- [x] Recreated Ollama and confirmed its corrected healthcheck reports healthy.
- [x] Confirmed `security-ai` is configured to read the `security_logs` stream and use `qwen2.5:3b` with a 600-second request timeout.
- [x] Confirmed `security-ai` can query OpenObserve, invoke Ollama, write review-only draft artifacts, and submit an AI analysis record to `ai_recommendations`.
- [x] Observed a completed AI analysis of 10 events; Ollama completed the request in about 136 seconds, within the configured timeout.
- [x] Confirmed the worker state file `/state/offsets.json` is readable.
- [x] Checked container resource usage and configured limits; Ollama is the primary consumer at roughly 2.3 GiB of its 4 GiB allocation.
- [x] Validated the rendered Compose configuration with `./scripts/podman-compose-host.sh -f compose.yaml config`.