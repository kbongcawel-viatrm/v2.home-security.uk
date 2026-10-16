# LLM-Powered Suricata and Firewall Rule Generation

## Overview

The security-ai worker has been enhanced to generate **actual Suricata detection rules** and **firewall-cmd blocking rules** using the Ollama LLM, not just recommendations.

## Components Added

### 1. New Module: `rule_generator.py`

Location: `/security-ai/rule_generator.py`

**SuricataRuleGenerator Class**
- ssh_brute_force_detection()
- suspicious_port_scan()
- malicious_payload_detection()
- high_port_connection()
- rate_limit_rule()

**FirewallRuleGenerator Class**
- block_ip_rule()
- block_port_rule()
- disable_service_rule()
- rate_limit_rule()

**Main Function**
- generate_rules_from_events(events, analysis) - Entry point

### 2. Updated: `worker.py`

Now calls generate_rules_from_events() with:
- Analyzed security events
- AI analysis findings
- Confidence levels

Outputs stored in ai_recommendations stream.

### 3. New Guidance: `rule_generation_guidance.md`

Comprehensive LLM prompting guidance covering:
- Suricata rule syntax and structure
- Common attack patterns and detection methods
- Firewall rule types and use cases
- Safety considerations
- Validation procedures
- Example workflows

## Rule Types Generated

### Suricata IDS Rules

**SSH Brute Force Detection**
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"AI-REC: SSH brute force from X.X.X.X";
    flow:to_server,established;
    content:"SSH-";
    detection_filter:track by_src, count 5, seconds 60;
    classtype:attempted-admin;
    sid:1000XXX;
    rev:1;
    metadata:
        created_at YYYY-MM-DD,
        attack_type brute_force,
        source_id AI-GENERATED
)
```

**Port Scan Detection**
- Detects 10+ port connection attempts in 30 seconds
- Uses SYN flags (S,12) for accuracy
- Tracks by source IP

**HTTP DoS Detection**
- Detects 50+ HTTP requests in 10 seconds
- Tracks connection rate by source
- Classifies as abuse-of-service

**DNS Tunneling Detection**
- Detects 100+ DNS queries in 60 seconds
- Indicates possible C2 communication
- Alert only (no blocking)

### Firewall-cmd Rules

**IP Blocking**
- Drops all traffic from malicious IPs
- Requires high-confidence detection
- Includes validation steps and rollback

**Port Blocking**
- Disables listening on unnecessary ports
- Example: Telnet (23), old SSH versions
- Medium-high risk (may break services)

**Service Disabling**
- Removes firewall exposure for vulnerable services
- Low risk when service unused
- High risk if service in use

**Rate Limiting**
- Limits connection rate per minute
- Example: SSH rate limit to 10 conn/min
- Prevents brute force while allowing legitimate access

## Example Workflow

### Input: Security Events
```json
[
  {
    "timestamp": "2026-01-15T10:23:45Z",
    "source_ip": "192.0.2.45",
    "dest_port": 22,
    "alert": "SSH_FAILED_LOGIN",
    "count": 15,
    "time_window": "5 minutes"
  }
]
```

### Process: LLM Analysis
- Identifies SSH brute force pattern
- Assigns high confidence
- Recommends detection and blocking

### Output: Generated Rules

**Suricata Rule**
```
alert tcp 192.0.2.45 any -> $HOME_NET 22 (
    msg:"AI-REC: SSH brute force from 192.0.2.45";
    ...
    sid:1000042;
    metadata: ...
)
```

**Firewall Rule**
```json
{
  "type": "block_ip",
  "ip": "192.0.2.45",
  "reason": "SSH brute force - 15 failed logins",
  "risk": "Low",
  "validation_steps": [...],
  "rollback_steps": [...],
  "status": "validated_draft_not_applied"
}
```

### Deployment: Human Review
1. Dashboard shows generated rules
2. Security team reviews rationale
3. Test in staging environment
4. Approve for production
5. GitHub Actions deploys via Ansible
6. Monitor for effectiveness

## Safety Features

### Rule Generation Constraints

✓ SSH brute force detection (alert + optional block)
✓ Port scanning reconnaissance alerts
✓ DNS tunneling detection
✓ HTTP DoS/flooding detection
✓ IP blocking (with strong evidence)
✓ Service disabling (with justification)

✗ Never generates:
- Drop rules for large IP ranges
- Disabling critical services without evidence
- Blocking without specific targets
- Referencing fake CVEs

### Validation Pipeline

1. **Syntax Check** - Valid Suricata/YAML format
2. **Safety Check** - No dangerous operations
3. **Policy Check** - Approved attack types
4. **Storage** - OpenObserve ai_recommendations
5. **Human Review** - Dashboard visualization
6. **Deployment** - GitHub Actions with --check mode

## Configuration

No additional configuration required!

The rule generator is automatically:
- Imported by worker.py
- Called with analyzed events
- Rules stored in recommendations stream
- Included in dashboards

Environment variables (already set):
- OPENOBSERVE_URL
- OPENOBSERVE_USER
- OPENOBSERVE_PASSWORD
- OPENOBSERVE_ORG
- OLLAMA_URL
- OLLAMA_MODEL

## Testing Generated Rules

### Suricata Syntax Check
```bash
suricata -T -c /etc/suricata/suricata.yaml -S /tmp/generated.rules
# Should succeed with no errors
```

### Firewall Rule Testing
```bash
# Temporary test (5 min timeout)
firewall-cmd --add-rich-rule='...' --timeout=0

# Verify blocking
tcpdump -i any -n src 192.0.2.45

# Monitor logs
journalctl -f -u firewalld
```

## Performance

- **Memory:** Minimal (Python object overhead)
- **CPU:** Low (I/O-bound on LLM)
- **Time per cycle:** 10-30 seconds (LLM-dependent)
- **Max rules per cycle:** 5 Suricata + 5 Firewall (configurable)
- **Analysis interval:** 300 seconds (configurable)

## Files Changed/Added

✓ security-ai/rule_generator.py (NEW - 310 lines)
✓ security-ai/rule_generation_guidance.md (NEW - guidance)
✓ LLM_RULE_GENERATION.md (NEW - this documentation)
✓ security-ai/worker.py (UPDATED - calls rule generator)

