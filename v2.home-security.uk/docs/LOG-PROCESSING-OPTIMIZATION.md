# Log Processing Optimization Strategy

## Problem Analysis

### Current Issues

1. **Single Stream Bottleneck**
   - All 527k+ log lines ingest into one `security_logs` stream
   - Mixes high-priority alerts with low-priority metrics
   - No prioritization for security events

2. **Data Volume Waste**
   - `stats.log`: 271k lines (periodic metrics every second)
   - `suricata.log`: 222k lines (debug logs)
   - `eve.json`: 32k lines (contains stats events mixed with alerts)
   - Suricata EVE JSON has 200+ fields per event, most irrelevant

3. **Inefficient Flushing**
   - `Flush=1` sends data every second
   - Creates many small HTTP requests (high overhead)
   - OpenObserve logs show slow requests (5-8s per batch)

4. **No Data Reduction**
   - Full field ingestion for all events
   - No sampling for high-volume periodic data
   - No filtering of noise events

## Optimization Strategy

### 1. Stream Segregation

Split logs into priority-based streams:

| Stream | Purpose | Priority | Volume |
|--------|---------|----------|--------|
| `security_alerts` | Alerts, malware, integrity violations | High | Low |
| `security_metrics` | Suricata stats, debug logs | Low | High |
| `host_logs` | Kernel, boot, systemd journal | Low | Medium |
| `audit_logs` | Auditd records | Medium | High |

**Benefits:**
- Security alerts get dedicated stream for real-time analysis
- Metrics can be sampled without affecting alert visibility
- Stream-level retention policies (alerts: 90d, metrics: 7d)
- Reduced memory pressure on OpenObserve (separate memory tables)

### 2. Field Reduction

Suricata EVE JSON has 200+ fields. Keep only security-relevant fields:

```json
{
  "timestamp": "...",
  "event_type": "alert",
  "src_ip": "...",
  "src_port": "...",
  "dest_ip": "...",
  "dest_port": "...",
  "proto": "tcp",
  "alert": {...},
  "dns": {...},
  "http": {...},
  "tls": {...},
  "ssh": {...}
}
```

**Benefits:**
- 70-80% reduction in payload size
- Faster ingestion and querying
- Lower storage costs

### 3. Sampling

High-volume periodic data doesn't need 100% fidelity:

| Source | Current | Optimized | Sampling Rate |
|--------|---------|-----------|---------------|
| `stats.log` | 271k lines | ~27k lines | 1:10 |
| `suricata.log` | 222k lines | ~22k lines | 1:10 |
| `audit.log` | Full | ~20% | 1:5 |

**Benefits:**
- 80-90% reduction in metrics volume
- Trends still visible with sampling
- Security events (alerts) unchanged

### 4. Batching

Change flush interval from 1s to 5s:

```diff
- Flush 1
+ Flush 5
```

**Benefits:**
- 5x fewer HTTP requests
- Better network efficiency
- Reduced CPU overhead in Fluent Bit

### 5. Compression

Enable gzip compression for all outputs:

```diff
[OUTPUT]
  ...
+ compress gzip
```

**Benefits:**
- 60-80% reduction in network bandwidth
- Faster transmission on slower networks

### 6. Event Filtering

Exclude stats events from `eve.json` (they're already in `stats.log`):

```diff
[FILTER]
  Name              grep
  Match             suricata.eve
  Exclude           event_type stats
```

**Benefits:**
- Remove duplicate stats data
- Cleaner alert stream
- Reduced confusion in analysis

## Expected Impact

### Resource Reduction

| Metric | Current | Optimized | Reduction |
|--------|---------|-----------|-----------|
| Events/second | ~150 | ~15-20 | 85-90% |
| HTTP requests/min | ~180 | ~36 | 80% |
| Payload size/event | ~2KB | ~400-600B | 70-80% |
| Network bandwidth | ~300KB/s | ~30KB/s | 90% |

### OpenObserve Memory

- Current: MemoryTableOverflowError at 1600m
- Optimized: Should run comfortably at 1024-1280m
- Memory pressure reduced by 85-90%

### Security AI Worker

- Current: Queries single stream with 500k+ events
- Optimized: Queries `security_alerts` stream with ~5k events
- Analysis cycle time: 60s → 5-10s
- Better signal-to-noise ratio

## Implementation Steps

1. **Deploy optimized Fluent Bit config**
   ```bash
   cp fluent-bit/fluent-bit.conf.optimized fluent-bit/fluent-bit.conf
   podman-compose restart fluent-bit
   ```

2. **Update security-ai worker**
   - Change `OPENOBSERVE_INPUT_STREAMS` from `security_logs` to `security_alerts`
   - Update analysis prompt to reference correct stream

3. **Monitor new streams**
   ```bash
   curl -u user:pass "http://localhost:5080/api/default/security_alerts/_stats"
   curl -u user:pass "http://localhost:5080/api/default/security_metrics/_stats"
   ```

4. **Set stream retention policies** (optional)
   - security_alerts: 90 days
   - security_metrics: 7 days
   - host_logs: 30 days
   - audit_logs: 30 days

5. **Verify log coverage**
   - Check that alerts still flow
   - Verify sampling doesn't miss critical events
   - Confirm field reduction doesn't break analysis

## Rollback Plan

If issues occur:

```bash
# Restore original config
git checkout HEAD -- fluent-bit/fluent-bit.conf
podman-compose restart fluent-bit

# Reset security-ai worker
# .env: OPENOBSERVE_INPUT_STREAMS=security_logs
```

## Next Steps

1. Test optimized config in non-production
2. Compare alert detection rates before/after
3. Tune sampling rates based on requirements
4. Add retention policies to OpenObserve
5. Consider Loki for high-volume metrics (if needed)
