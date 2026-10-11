#!/usr/bin/env bash
set -euo pipefail

# Send a clearly marked, harmless Suricata-style test event to OpenObserve via
# the running security-ai container, reusing its configured OpenObserve URL and
# credentials without exposing secrets in this script or in cron arguments.
if ! podman container exists security-ai; then
    echo "security-ai container does not exist; start the Compose stack first" >&2
    exit 1
fi

podman exec -i security-ai python - <<'PY'
import base64
import json
import os
import urllib.request
from datetime import datetime, timezone

base = os.environ.get("OPENOBSERVE_URL", "http://openobserve:5080").rstrip("/")
org = os.environ.get("OPENOBSERVE_ORG", "default")
user = os.environ["OPENOBSERVE_USER"]
password = os.environ["OPENOBSERVE_PASSWORD"]
timestamp = datetime.now(timezone.utc).isoformat()
event_id = "synthetic-cron-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

event = {
    "timestamp": timestamp,
    "source": "suricata",
    "event_type": "alert",
    "alert": {
        "signature": "Synthetic test: repeated suspicious outbound connection",
        "category": "Potentially Bad Traffic",
        "severity": 2,
    },
    "src_ip": "192.0.2.25",
    "dest_ip": "198.51.100.77",
    "dest_port": 4444,
    "proto": "TCP",
    "flow_id": event_id,
    "test_event": True,
    "note": "Synthetic validation event only; documentation-range IPs, not a real intrusion.",
}
token = base64.b64encode(f"{user}:{password}".encode()).decode()
url = f"{base}/api/{org}/security_logs/_json"
request = urllib.request.Request(
    url,
    data=(json.dumps(event) + "\n").encode(),
    headers={"Content-Type": "application/json", "Authorization": f"Basic {token}"},
)
with urllib.request.urlopen(request, timeout=30) as response:
    response.read()
    print(f"Submitted synthetic event {event_id}; OpenObserve HTTP {response.status}")
PY