import base64
import time
from opentelemetry import metrics
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.prometheus_remote_write import PrometheusRemoteWriteMetricsExporter

# 1. Setup your OpenObserve credentials
username = "dummykevin08@gmail.com"
password = "o2oi_KrLrA4mQBEEWDALosxKj6ziXsBF4TpoW"

# Create the standard Base64 HTTP Basic Auth string
raw_credentials = f"{username}:{password}"
encoded_credentials = base64.b64encode(raw_credentials.encode("utf-8")).decode("utf-8")

# 2. Configure the Remote Write Exporter with your OpenObserve endpoint
exporter = PrometheusRemoteWriteMetricsExporter(
    endpoint="http://localhost:5080/api/default/prometheus/api/v1/write",
    headers={
        "Authorization": f"Basic {encoded_credentials}"
    }
)

# 3. Setup the Metric Reader (Exports data to OpenObserve every 15 seconds)
reader = PeriodicExportingMetricReader(exporter, export_interval_millis=15000)

# 4. Register the Meter Provider
provider = MeterProvider(metric_readers=[reader])
metrics.set_meter_provider(provider)

# 5. Create a metric generator
meter = metrics.get_meter("openobserve.python.exporter")
counter = meter.create_counter(
    name="python_ingest_test_total",
    description="Tracks metrics successfully exported to local OpenObserve",
    unit="1"
)

# 6. Run application loop
print("🚀 OpenTelemetry script started.")
print("Streaming metrics to OpenObserve at http://localhost:5080... (Ctrl+C to exit)")

try:
    while True:
        # Increment counter by 1 with tracking tags
        counter.add(1, {"env": "local", "exporter": "otel-remote-write"})
        time.sleep(1)
except KeyboardInterrupt:
    print("\nStopping metrics ingestion.")

