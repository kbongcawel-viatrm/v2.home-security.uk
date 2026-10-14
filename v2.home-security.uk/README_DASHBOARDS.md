# OpenObserve Dashboards - Quick Start Guide

## 🎉 Dashboards Successfully Created!

Three comprehensive OpenObserve dashboards have been created for your v2.home-security.uk project:

### 📊 Dashboard Summary

| Dashboard | ID | Panels | Focus |
|-----------|----|---------| ----|
| **Security Logs Dashboard** | `7516224856958959616` | 6 | Real-time Suricata alerts, firewall logs, kernel events |
| **Metrics Dashboard** | `7516224858145947648` | 8 | Top IPs, ports, protocols, event statistics |
| **AI Recommendations Dashboard** | `7516224858221445120` | 5 | AI analysis insights, findings, recommendations |

## 🚀 Getting Started

### Access the Dashboards

1. **Open OpenObserve UI:**
   ```
   http://127.0.0.1:5080
   ```

2. **Sign In:**
   - Email: `dummykevin08@gmail.com`
   - Password: (from your `.env` file)

3. **Navigate to Dashboards:**
   - Click **Dashboards** in the left sidebar
   - Select any of the three dashboards to view

## 📈 What Each Dashboard Shows

### 1️⃣ Security Logs Dashboard
Monitors active threats in real-time:
- **Suricata Alerts Timeline** - See when attacks are detected
- **Top Source IPs** - Identify attacking IPs
- **Top Destination IPs** - See which systems are targeted
- **Firewall Events** - Monitor firewall rule matches
- **Kernel Logs** - Track system-level events
- **Alert Severity Distribution** - Understand threat severity

**Best for:** Security analysts monitoring ongoing threats

### 2️⃣ Metrics Dashboard
Provides high-level security analytics:
- **Event Counts** - Total security events (last 24h)
- **Unique IPs** - How many source/destination IPs seen
- **Event Rate Trends** - Attack frequency over time
- **Top Ports** - Which ports are being targeted
- **Protocol Breakdown** - What types of traffic detected
- **Alert Rules** - Which security rules are triggering
- **IP Request Table** - Detailed per-IP statistics

**Best for:** Security leadership, trend analysis, capacity planning

### 3️⃣ AI Recommendations Dashboard
Shows AI-powered security insights:
- **Analysis Timeline** - When AI review cycles run
- **Daily Analysis Count** - Historical analysis frequency
- **Recommendation Status** - How many pending vs. approved
- **Finding Types** - Categories of issues discovered
- **Recent Recommendations** - Latest AI-generated suggestions

**Best for:** Security engineers implementing AI-suggested improvements

## 🔧 Customizing Dashboards

### Edit a Dashboard

1. Open any dashboard
2. Click **Edit** (pencil icon) in top-right
3. Modify:
   - **SQL Queries** - Change data filtering
   - **Panel Types** - Switch between line/bar/pie/table
   - **Layout** - Drag panels to reposition
4. Click **Save Dashboard**

### Add Custom Queries

You can write custom SQL queries. Example:

```sql
-- Find top IPs in last hour
SELECT src_ip, COUNT(*) as count 
FROM security_logs 
WHERE source='suricata' 
AND src_ip IS NOT NULL 
AND _timestamp > now() - interval 1 hour
GROUP BY src_ip 
ORDER BY count DESC 
LIMIT 20
```

## 📝 Data Streams Reference

The dashboards pull from these streams:

| Stream | Contains | Source |
|--------|----------|--------|
| `security_logs` | Suricata EVE JSON + Host Journal | Fluent Bit ingestion |
| `firewall_logs` | Firewall rule matches | firewalld journald entries |
| `kernel_logs` | Kernel messages | Linux kernel via journald |
| `ai_recommendations` | Security analysis results | security-ai worker service |

## 🔄 Recreating Dashboards

If you need to recreate the dashboards (e.g., after OpenObserve reset):

```bash
cd /home/kbongcawel/workspace/v2.home-security.uk/v2.home-security.uk

# Run the dashboard creation script
python3 scripts/create-dashboards.py
```

The script will:
- Connect to OpenObserve API
- Create all three dashboards
- Display new dashboard IDs
- Report success/failure for each

## ⚙️ Configuration

The dashboards use environment variables from `.env`:

```bash
OPENOBSERVE_URL=http://127.0.0.1:5080
OPENOBSERVE_USER=dummykevin08@gmail.com
OPENOBSERVE_PASSWORD=your_password
OPENOBSERVE_ORG=default
```

## 📚 Additional Resources

- **Full Documentation:** See `DASHBOARDS.md` in this directory
- **Architecture:** See `STACK.md` for system overview
- **Script Source:** `scripts/create-dashboards.py`

## ✅ Verification Checklist

- [x] Security Logs Dashboard created with 6 panels
- [x] Metrics Dashboard created with 8 panels
- [x] AI Recommendations Dashboard created with 5 panels
- [x] All panels configured with SQL queries
- [x] All dashboards accessible via web UI
- [x] Data streams properly mapped

## 🆘 Troubleshooting

### Dashboard Shows No Data?
1. Check if OpenObserve is running: `podman ps | grep openobserve`
2. Verify Fluent Bit is sending data: `podman ps | grep fluent-bit`
3. Check time range in dashboard (adjust to "Last 24h" or "Last 7d")
4. Verify data streams exist: Look in OpenObserve "Streams" section

### Can't Access UI?
1. Verify OpenObserve is running: `podman ps --filter name=openobserve`
2. Check network: `curl http://127.0.0.1:5080/`
3. Check firewall: Ensure port 5080 is accessible
4. Check logs: `podman logs openobserve | tail -50`

### Script Creation Failed?
1. Verify credentials in `.env` are correct
2. Ensure OpenObserve is fully initialized (wait a minute after startup)
3. Check network connectivity
4. Run script with verbose output for details

## 🎯 Next Steps

1. **Explore the Data:** Browse each dashboard to understand your security events
2. **Set Alerts:** Use OpenObserve to create alerts for suspicious patterns
3. **Customize Views:** Modify dashboards to match your monitoring needs
4. **Export Reports:** Use OpenObserve reports feature for regular snapshots
5. **Integrate Webhooks:** Set up notifications for critical events

---

**Created:** October 2026  
**Script:** `scripts/create-dashboards.py`  
**OpenObserve Version:** Latest (from `compose.yaml`)
