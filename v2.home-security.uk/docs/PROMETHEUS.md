# Prometheus endpoints and usage

This guide describes the Prometheus service in `compose.yaml`, its configured endpoints, and how it sends metrics to OpenObserve.

## Endpoints

| Endpoint | Address | Purpose |
|---|---|---|
| Prometheus web UI and HTTP API | `http://127.0.0.1:9090` | Local access to Prometheus queries, status, and API. The port is bound to loopback only. |
| Prometheus scrape target | `http://localhost:9090/metrics` (from the Prometheus container) | Prometheus scrapes its own instrumentation metrics every 30 seconds. The scrape job is named `prometheus`. |
| Prometheus readiness | `http://localhost:9090/-/ready` (from the Prometheus container) | Prometheus readiness endpoint; the Compose health check currently runs an instant `up` query using `promtool`. |
| OpenObserve remote-write receiver | `http://openobserve:5080/api/${OPENOBSERVE_ORG:-default}/prometheus/api/v1/write` (from the Prometheus container) | Receives scraped samples in the configured OpenObserve organization. `openobserve` resolves on the Compose `security` network. |

The OpenObserve receiver uses HTTP Basic Authentication with `OPENOBSERVE_USER` and `OPENOBSERVE_PASSWORD` from `.env`. Keep `.env` private and do not put credential values in this file or in `prometheus/prometheus.yml`. `PROMETHEUS_USER` and `PROMETHEUS_PW` are not used for this remote-write configuration.

## Start Prometheus

From the repository root, with `.env` configured and OpenObserve running:

```bash
./scripts/podman-compose-host.sh -f compose.yaml up -d prometheus
```

Prometheus configuration is in `prometheus/prometheus.yml`. It enables environment expansion, scrapes Prometheus itself every 30 seconds, and queues up to 10,000 samples per remote-write batch. Its local TSDB is retained in the `prometheus_data` named volume; the default retention is 15 days and can be changed with `PROMETHEUS_RETENTION`.

## Check Prometheus

Open the UI at `http://127.0.0.1:9090`, or query the HTTP API:

```bash
# Scrape target status
curl -fsS http://127.0.0.1:9090/api/v1/targets

# Confirm the self-scrape is returning a series
curl -fsS 'http://127.0.0.1:9090/api/v1/query?query=up'

# Check container health
podman inspect --format '{{.State.Health.Status}}' prometheus
```

The `up` query should include the `prometheus` job with value `1` when its self-scrape succeeds. A successful local scrape does not by itself prove that remote write reached OpenObserve; check the destination separately.

## Check OpenObserve ingestion

In OpenObserve, select the organization configured by `OPENOBSERVE_ORG` (default `default`), open the Metrics/Prometheus metrics explorer, and query `up`. The `prometheus` job should appear after Prometheus has scraped and delivered samples. Metrics are stored as metric data, not in a logs stream.

The endpoint path follows OpenObserve's Prometheus remote-write API: `POST /api/{organization}/prometheus/api/v1/write`. From inside Prometheus, use the Compose hostname `openobserve`, not `127.0.0.1`; loopback inside the container refers to Prometheus itself.

If data does not appear, check `podman logs --tail 100 prometheus` for configuration, authentication, network, or remote-write errors. Confirm `OPENOBSERVE_USER`, `OPENOBSERVE_PASSWORD`, and `OPENOBSERVE_ORG` match the OpenObserve account and organization. The Compose health check tests the local Prometheus query endpoint; it does not validate OpenObserve connectivity.