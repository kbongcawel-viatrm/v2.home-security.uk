# OpenObserve Dashboards

## Overview

Three comprehensive dashboards have been created for the v2.home-security.uk project to provide real-time monitoring and visualization of your security infrastructure.

## Dashboards Created

### 1. **Security Logs Dashboard** (ID: 7516224856958959616)

Real-time visibility into security events:
- Suricata Alerts Timeline - Event count over time
- Top Source IPs (Suricata) - Top 10 source IPs
- Top Destination IPs (Suricata) - Top 10 target IPs
- Firewall Events Timeline - firewalld activity
- Kernel Logs Timeline - System kernel messages
- Alert Severity Distribution - Severity breakdown (pie chart)

### 2. **Metrics Dashboard** (ID: 7516224858145947648)

Aggregated security metrics and statistics:
- Total Events (Last 24h) - Overall event count
- Unique Source IPs (24h) - Count of distinct sources
- Unique Destination IPs (24h) - Count of distinct destinations
- Event Rate Over Time - Frequency trends
- Top Destination Ports - Most targeted ports (bar chart)
- Top Protocols - Network protocols used (pie chart)
- Top Alert Rules - Frequently triggered rules
- Top Source IPs by Request Count - Detailed IP statistics (table)

### 3. **AI Recommendations Dashboard** (ID: 7516224858221445120)

AI-generated security insights:
- AI Analysis Events Timeline - Analysis cycle frequency
- Analysis Events per Day - Daily analysis count (last 30 days)
- Recommendation Status Distribution - Status breakdown (pie chart)
- Top Finding Types - Most common findings
- Recent AI Recommendations - Latest insights (table)

## Data Streams

| Stream | Source | Description |
|--------|--------|-------------|
| `security_logs` | Suricata + Host Journal | Primary security events |
| `firewall_logs` | firewalld | Firewall rule matches |
| `kernel_logs` | Kernel messages | System events |
| `ai_recommendations` | security-ai worker | AI analysis results |

## Accessing Dashboards

1. Open `http://127.0.0.1:5080` in browser
2. Sign in with credentials from `.env`
3. Navigate to **Dashboards** → Select any dashboard

## Creating Dashboards

To create all dashboards:

```bash
cd /home/kbongcawel/workspace/v2.home-security.uk/v2.home-security.uk
python3 scripts/create-dashboards.py
```

The script uses environment variables from `.env`:
- `OPENOBSERVE_URL` - API endpoint
- `OPENOBSERVE_USER` - Login email
- `OPENOBSERVE_PASSWORD` - Login password
- `OPENOBSERVE_ORG` - Organization (default: "default")

## Modifying Dashboards

1. Open dashboard in OpenObserve UI
2. Click **Edit** in top-right
3. Modify SQL queries, panel types, or layout
4. Click **Save Dashboard**

## Example Queries

**Top IPs (Last Hour):**
```sql
SELECT src_ip, COUNT(*) as count FROM security_logs 
WHERE source='suricata' AND src_ip IS NOT NULL 
AND _timestamp > now() - interval 1 hour
GROUP BY src_ip ORDER BY count DESC LIMIT 20
```

**Alert Severity Breakdown:**
```sql
SELECT alert_severity, COUNT(*) as count FROM security_logs 
WHERE source='suricata' AND _timestamp > now() - interval 24 hour
GROUP BY alert_severity
```

## Related Files

- **Script**: `scripts/create-dashboards.py`
- **Configuration**: `.env`
- **Documentation**: `STACK.md`
- **Compose**: `compose.yaml`
