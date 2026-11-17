# Security AI Ollama tracing

The `security-ai` worker sends OpenTelemetry traces for its Ollama inference requests to the OpenObserve instance in this Compose stack. Ollama remains the local model provider; this integration does not switch inference to OpenAI or change Ollama's service, API, model, or request format.

## How tracing works

The worker currently calls Ollama's HTTP `POST /api/generate` endpoint directly using Python's standard-library `urllib`. The Ollama Python-client auto-instrumentor would not observe that code path, so the worker creates a manual OpenTelemetry span around the existing HTTP request instead. The span is named `ollama.generate` and uses the tracer `security-ai.ollama`.

The span records the model, operation, Ollama server address, temperature, Ollama-reported duration, input/output token counts when present, and the completion `done` flag. Request failures are recorded as exceptions and mark the span as an error. Prompt and response bodies are not added as span attributes.

The OpenObserve SDK is initialized when the worker starts. It exports traces (not logs or metrics) to the configured traces stream, with `service.name=security-ai`. In Compose, the worker reaches OpenObserve at `http://openobserve:5080` over the internal `security` network.

## Configuration

The following variables are configured for `security-ai` in `compose.yaml` and supplied through the repository's `.env` where applicable:

| Variable | Default | Purpose |
|---|---|---|
| `OPENOBSERVE_URL` | `http://openobserve:5080` | OpenObserve base URL reachable from the worker container. |
| `OPENOBSERVE_USER` | Required | OpenObserve username used for trace export. |
| `OPENOBSERVE_PASSWORD` | Required | OpenObserve password used for trace export. Keep this in the ignored, private `.env`; do not commit it. |
| `OPENOBSERVE_ORG` | `default` | OpenObserve organization. |
| `OPENOBSERVE_TRACES_STREAM_NAME` | `default` | Destination trace stream. |
| `OLLAMA_URL` | `http://ollama:11434` | Existing Ollama HTTP service URL; unchanged by tracing. |
| `OLLAMA_MODEL` | `qwen2.5:3b` | Model used for local inference. |

Trace export is initialized with OpenObserve authentication and resource metadata in `security-ai/worker.py`. The SDK dependency is installed by `security-ai/Dockerfile`; the shared Compose worker image includes that dependency and both worker applications.

## Build and run

From the repository root, build the shared worker image locally, then recreate the workers using the repository's host-aware Podman wrappers:

```bash
./scripts/host-exec.sh env -u CONTAINER_HOST podman build \
  --signature-policy "$PWD/containers-policy.json" \
  -t demo.goharbor.io/home-security-uk/worker-template:1.2 \
  -f worker-image/Dockerfile .

./scripts/podman-compose-host.sh -f compose.yaml up -d security-ai ansible-ai
```

Both worker services reference `worker-template:1.2` and use `pull_policy: never`, so the locally built image is used. The build does not rebuild OpenObserve or Ollama. Confirm worker status with:

```bash
./scripts/podman-host.sh ps
./scripts/podman-host.sh logs --tail 100 security-ai
```

After the worker successfully analyzes an event batch, look under **Traces** in OpenObserve, selecting the configured organization and trace stream. If no inference request runs, there will be no Ollama inference span to inspect. The security worker's separate OpenObserve queries and analysis records are not themselves inference spans.

## Privacy note

Prompts contain security-event data. This integration deliberately avoids recording prompt or response text in span attributes. Span metadata still reveals operational details such as model name, timing, and token counts. Protect OpenObserve credentials and access to stored traces accordingly.