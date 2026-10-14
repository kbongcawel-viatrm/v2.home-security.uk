"""
Static security knowledge base for CVE correlation, MITRE ATT&CK mapping,
IOC pattern libraries, and threat intelligence context used to enrich
the LLM's analysis prompt.

This module never calls any external API — it is purely reference data
embedded as Python dicts and strings so it works fully offline.
"""

from __future__ import annotations
from typing import Dict, List, Any

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique reference (sub-set most relevant to a home-lab IDS)
# ---------------------------------------------------------------------------
MITRE_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "T1110": {
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversary-in-the-middle or automated password guessing against SSH, RDP, HTTP.",
        "detection_hint": "High failed-auth rate from same source IP within a short window.",
        "mitigations": "Account lockout, fail2ban, MFA, key-based SSH auth only.",
    },
    "T1110.001": {
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "description": "Systematic guessing of common/weak passwords.",
        "detection_hint": "Repeated auth failures for many usernames or known default accounts.",
        "mitigations": "Disable password auth; enforce SSH key auth.",
    },
    "T1046": {
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Port scanning to identify open services.",
        "detection_hint": "SYN packets to many ports in rapid succession from a single source.",
        "mitigations": "Host-based firewall, default-deny egress, honeypot ports.",
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": "C2 traffic using legitimate protocols (HTTP/S, DNS, SMTP).",
        "detection_hint": "Unusual volume/frequency of DNS queries, periodic beaconing patterns.",
        "mitigations": "DNS filtering, TLS inspection, protocol anomaly detection.",
    },
    "T1071.004": {
        "name": "DNS",
        "tactic": "Command and Control",
        "description": "DNS used as C2 channel (tunneling, DGA queries).",
        "detection_hint": "High-entropy sub-domain queries, NXDOMAIN floods, txt record abuse.",
        "mitigations": "DNS-over-HTTPS enforcement, RPZ, DNSSEC.",
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Exploitation of internet-facing software vulnerabilities.",
        "detection_hint": "HTTP 40x/50x spikes, abnormal request payloads, CVE-specific patterns.",
        "mitigations": "Timely patching, WAF, network segmentation.",
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Use of shell, Python, PowerShell etc. for execution after exploitation.",
        "detection_hint": "Unexpected shell invocations, encoded commands, child processes of web servers.",
        "mitigations": "Application allowlisting, process auditing (auditd/sysdig).",
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Lateral movement via SSH, RDP, SMB, or VNC.",
        "detection_hint": "Unusual lateral SSH connections, non-standard source IPs for service accounts.",
        "mitigations": "Zero-trust network, privileged access workstations, jump hosts.",
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Data exfiltration over the same channel used for C2.",
        "detection_hint": "Unusually large outbound DNS/HTTP payloads, encrypted channels with atypical timing.",
        "mitigations": "DLP controls, egress filtering, anomaly detection on outbound volume.",
    },
    "T1498": {
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Volumetric or protocol-level DoS attacks.",
        "detection_hint": "Traffic spikes exceeding baseline by 3x+, SYN floods, ICMP floods.",
        "mitigations": "Rate limiting, traffic scrubbing, BGP blackhole routing.",
    },
    "T1562": {
        "name": "Impair Defenses",
        "tactic": "Defense Evasion",
        "description": "Disabling security tools, firewall rules, or audit logs.",
        "detection_hint": "Unexpected service stop commands, iptables flush, auditd stop.",
        "mitigations": "Immutable logging, separate SIEM, monitor critical service state changes.",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "description": "Use of stolen or legitimate credentials to gain persistent access.",
        "detection_hint": "Login from unusual geo/IP, off-hours sessions, service account interactive logins.",
        "mitigations": "MFA, anomalous login alerting, privileged account monitoring.",
    },
}

# ---------------------------------------------------------------------------
# CVE reference library — high-impact CVEs frequently seen in home-lab scans
# ---------------------------------------------------------------------------
CVE_LIBRARY: Dict[str, Dict[str, Any]] = {
    "CVE-2021-44228": {
        "alias": "Log4Shell",
        "cvss": 10.0,
        "description": "JNDI injection in Apache Log4j 2 allows unauthenticated RCE.",
        "affected_products": ["Apache Log4j 2.x < 2.17.1", "Any Java app using Log4j 2"],
        "mitre_techniques": ["T1190", "T1059"],
        "detection_patterns": [
            "${jndi:", "${${::-j}${::-n}${::-d}${::-i}:", "Base64-encoded JNDI in User-Agent"
        ],
        "suricata_hints": [
            'content:"${jndi:"; http.header;',
            'content:"${jndi:"; http.uri;',
        ],
        "remediation": "Patch Log4j to 2.17.1+; disable JNDI lookup if patching not possible immediately.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    },
    "CVE-2024-6387": {
        "alias": "regreSSHion",
        "cvss": 8.1,
        "description": "Race condition in OpenSSH sshd (glibc systems) allows unauthenticated RCE as root.",
        "affected_products": ["OpenSSH 8.5p1 – 9.7p1 on glibc Linux"],
        "mitre_techniques": ["T1190", "T1059"],
        "detection_patterns": [
            "Repeated incomplete SSH handshakes (LoginGraceTime exploitation)",
            "SSH banner exchange without auth completion"
        ],
        "suricata_hints": [
            "flow:to_server,established; content:\"SSH-\"; detection_filter:track by_src, count 5, seconds 60;",
        ],
        "remediation": "Upgrade OpenSSH to 9.8p1+; set LoginGraceTime 0 as short-term mitigation.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-6387"],
    },
    "CVE-2023-44487": {
        "alias": "HTTP/2 Rapid Reset",
        "cvss": 7.5,
        "description": "HTTP/2 RST_STREAM flood enables high-scale DoS against web servers.",
        "affected_products": ["nginx < 1.25.3", "Apache httpd < 2.4.58", "Any HTTP/2 server"],
        "mitre_techniques": ["T1498"],
        "detection_patterns": [
            "High rate of HTTP/2 RST_STREAM frames",
            "Connection count spike without corresponding data transfer"
        ],
        "suricata_hints": [
            'alert tcp $EXTERNAL_NET any -> $HOME_NET 443 (msg:"AI-REC: HTTP/2 rapid reset DoS candidate";',
            "detection_filter:track by_src, count 100, seconds 10;",
        ],
        "remediation": "Patch web server; enable HTTP/2 connection limits; deploy rate-limiting at reverse proxy.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-44487"],
    },
    "CVE-2021-3156": {
        "alias": "Heap-Based Buffer Overflow in Sudo (Baron Samedit)",
        "cvss": 7.8,
        "description": "Sudo heap overflow allows local privilege escalation to root.",
        "affected_products": ["sudo 1.8.2 – 1.8.31p2", "sudo 1.9.0 – 1.9.5p1"],
        "mitre_techniques": ["T1059", "T1078"],
        "detection_patterns": [
            "sudoedit invocation with malformed arguments",
            "Unexpected UID changes in audit logs"
        ],
        "suricata_hints": [],
        "remediation": "Upgrade sudo to 1.9.5p2+.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3156"],
    },
    "CVE-2022-0847": {
        "alias": "Dirty Pipe",
        "cvss": 7.8,
        "description": "Linux kernel pipe privilege escalation allowing overwrite of read-only files.",
        "affected_products": ["Linux kernel 5.8 – 5.16.11"],
        "mitre_techniques": ["T1059", "T1078"],
        "detection_patterns": [
            "Unexpected write to proc or read-only mounts",
            "SUID binary overwrite attempts"
        ],
        "suricata_hints": [],
        "remediation": "Upgrade kernel to 5.16.11+, 5.15.25+, or 5.10.102+.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-0847"],
    },
    "CVE-2021-41773": {
        "alias": "Apache Path Traversal",
        "cvss": 7.5,
        "description": "Path traversal and RCE in Apache HTTP Server 2.4.49 via URL-encoded paths.",
        "affected_products": ["Apache httpd 2.4.49"],
        "mitre_techniques": ["T1190"],
        "detection_patterns": [
            "/../ or /.%2e/ in HTTP URI",
            "/cgi-bin/sh or /bin/sh in HTTP request body"
        ],
        "suricata_hints": [
            'content:"/.%2e/"; http.uri;',
            'content:"/cgi-bin/"; http.uri; content:"sh"; http.uri;',
        ],
        "remediation": "Upgrade Apache to 2.4.51+; disable mod_cgi if not needed.",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
    },
}

# ---------------------------------------------------------------------------
# Attack pattern → CVE/technique correlation map
# ---------------------------------------------------------------------------
ATTACK_PATTERN_MAP: Dict[str, Dict[str, Any]] = {
    "ssh_brute_force": {
        "keywords": ["ssh", "brute", "auth fail", "invalid user", "connection reset by peer"],
        "cve_candidates": ["CVE-2024-6387"],
        "mitre": ["T1110", "T1110.001"],
        "severity_floor": "medium",
        "recommended_action": "Rate-limit SSH; alert on 5+ failures in 60s; consider key-only auth.",
    },
    "port_scan": {
        "keywords": ["scan", "syn flood", "network recon", "nmap", "masscan", "port sweep"],
        "cve_candidates": [],
        "mitre": ["T1046"],
        "severity_floor": "low",
        "recommended_action": "Alert on 10+ SYN packets to different ports in 30s from same source.",
    },
    "log4shell": {
        "keywords": ["jndi", "log4j", "${", "ldap://", "rmi://", "dns://"],
        "cve_candidates": ["CVE-2021-44228"],
        "mitre": ["T1190", "T1059"],
        "severity_floor": "critical",
        "recommended_action": "Block source IP immediately; inspect all HTTP headers not just URI.",
    },
    "rce_exploit": {
        "keywords": ["rce", "remote code", "command inject", "shell upload", "webshell", "reverse shell"],
        "cve_candidates": ["CVE-2021-41773"],
        "mitre": ["T1190", "T1059"],
        "severity_floor": "high",
        "recommended_action": "Block source IP; review web server logs; inspect uploaded files.",
    },
    "c2_beacon": {
        "keywords": ["beacon", "c2", "command and control", "periodic", "dga", "cobalt strike", "metasploit"],
        "cve_candidates": [],
        "mitre": ["T1071", "T1071.004", "T1041"],
        "severity_floor": "high",
        "recommended_action": "Block destination IP/domain; capture full packet for forensics; isolate host.",
    },
    "dns_tunneling": {
        "keywords": ["dns tunnel", "dns flood", "excessive dns", "nxdomain flood", "dnscat", "iodine"],
        "cve_candidates": [],
        "mitre": ["T1071.004"],
        "severity_floor": "medium",
        "recommended_action": "Alert on 100+ DNS queries/min per host; block suspicious domains.",
    },
    "dos_attack": {
        "keywords": ["dos", "flood", "syn flood", "http flood", "rapid reset", "volumetric"],
        "cve_candidates": ["CVE-2023-44487"],
        "mitre": ["T1498"],
        "severity_floor": "medium",
        "recommended_action": "Rate-limit at perimeter; tune detection thresholds; alert on baseline deviation.",
    },
    "lateral_movement": {
        "keywords": ["lateral", "smb", "psexec", "wmi", "ssh lateral", "pass the hash"],
        "cve_candidates": [],
        "mitre": ["T1021"],
        "severity_floor": "high",
        "recommended_action": "Alert on east-west SSH from unexpected sources; segment network.",
    },
    "credential_theft": {
        "keywords": ["credential", "mimikatz", "lsass", "pass the hash", "golden ticket", "kerberoast"],
        "cve_candidates": ["CVE-2021-3156"],
        "mitre": ["T1078"],
        "severity_floor": "high",
        "recommended_action": "Alert on LSASS access; enforce MFA; monitor privileged accounts.",
    },
    "privilege_escalation": {
        "keywords": ["privilege", "sudo", "suid", "dirty pipe", "setuid", "privilege escalation"],
        "cve_candidates": ["CVE-2021-3156", "CVE-2022-0847"],
        "mitre": ["T1059", "T1078"],
        "severity_floor": "high",
        "recommended_action": "Audit sudo rules; monitor SUID binary execution; restrict sudo access.",
    },
}

# ---------------------------------------------------------------------------
# IOC pattern validators (regex patterns for quick field-level checks)
# ---------------------------------------------------------------------------
IOC_PATTERNS = {
    "ipv4": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
    "ipv6": r"^[0-9a-fA-F:]{2,39}$",
    "cve": r"^CVE-\d{4}-\d{4,7}$",
    "mitre_technique": r"^T\d{4}(?:\.\d{3})?$",
    "sha256": r"^[0-9a-fA-F]{64}$",
    "md5": r"^[0-9a-fA-F]{32}$",
    "domain": r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
    "url": r"^https?://",
}

# ---------------------------------------------------------------------------
# Helper: build enriched context block for the LLM prompt
# ---------------------------------------------------------------------------

def build_knowledge_context(detected_keywords: List[str]) -> str:
    """
    Given a list of keywords extracted from raw events, return a formatted
    knowledge block to prepend to the LLM prompt with:
    - Matched attack patterns and their MITRE/CVE correlations
    - CVE details for the candidates
    - MITRE technique descriptions

    Args:
        detected_keywords: Lower-cased tokens found in event data.

    Returns:
        A multi-line string to embed in the LLM prompt.
    """
    kw_set = set(kw.lower() for kw in detected_keywords)
    matched_patterns: Dict[str, Dict[str, Any]] = {}
    for pattern_name, pattern_info in ATTACK_PATTERN_MAP.items():
        for kw in pattern_info["keywords"]:
            if any(kw in event_kw for event_kw in kw_set):
                matched_patterns[pattern_name] = pattern_info
                break

    lines: List[str] = ["## Security Knowledge Context\n"]

    if matched_patterns:
        lines.append("### Detected Attack Patterns")
        for pname, pinfo in matched_patterns.items():
            lines.append(f"\n**{pname.replace('_', ' ').title()}**")
            lines.append(f"- MITRE ATT&CK: {', '.join(pinfo['mitre'])}")
            if pinfo["cve_candidates"]:
                lines.append(f"- Candidate CVEs: {', '.join(pinfo['cve_candidates'])}")
            lines.append(f"- Minimum Severity: {pinfo['severity_floor']}")
            lines.append(f"- Recommended Action: {pinfo['recommended_action']}")

    # Include CVE details for all candidates
    cve_candidates: set = set()
    for p in matched_patterns.values():
        cve_candidates.update(p.get("cve_candidates", []))

    if cve_candidates:
        lines.append("\n### Relevant CVE Details")
        for cve_id in sorted(cve_candidates):
            if cve_id in CVE_LIBRARY:
                cve = CVE_LIBRARY[cve_id]
                lines.append(f"\n**{cve_id}** ({cve.get('alias', 'N/A')}) — CVSS {cve.get('cvss', 'N/A')}")
                lines.append(f"- {cve['description']}")
                lines.append(f"- Affected: {'; '.join(cve['affected_products'])}")
                lines.append(f"- Detection: {'; '.join(cve['detection_patterns'][:2])}")
                lines.append(f"- Remediation: {cve['remediation']}")

    # Include MITRE technique descriptions for all matched techniques
    mitre_ids: set = set()
    for p in matched_patterns.values():
        mitre_ids.update(p.get("mitre", []))

    if mitre_ids:
        lines.append("\n### MITRE ATT&CK Technique Details")
        for tid in sorted(mitre_ids):
            if tid in MITRE_TECHNIQUES:
                tech = MITRE_TECHNIQUES[tid]
                lines.append(f"\n**{tid}: {tech['name']}** [{tech['tactic']}]")
                lines.append(f"- {tech['description']}")
                lines.append(f"- Detection: {tech['detection_hint']}")
                lines.append(f"- Mitigations: {tech['mitigations']}")

    if not matched_patterns:
        lines.append("No specific attack patterns matched; apply general security baseline analysis.")

    return "\n".join(lines) + "\n"


def extract_keywords_from_events(events: List[Dict[str, Any]]) -> List[str]:
    """
    Extract text tokens from raw event dicts that can be matched against
    the ATTACK_PATTERN_MAP keyword lists.

    Args:
        events: List of raw event dicts from OpenObserve.

    Returns:
        Flat list of lower-cased string tokens.
    """
    tokens: List[str] = []
    interesting_fields = (
        "alert_signature", "event_type", "app_proto", "http_url",
        "http_user_agent", "http_hostname", "dns_query_name", "tls_sni",
        "log_message", "message", "msg", "reason", "description",
        "attack_type", "category", "severity",
    )
    for event in events:
        for field in interesting_fields:
            value = event.get(field)
            if isinstance(value, str):
                tokens.extend(value.lower().split())
        # Recurse one level for nested alert dicts (Suricata EVE format)
        alert = event.get("alert") or event.get("alert_data")
        if isinstance(alert, dict):
            for field in ("signature", "category"):
                v = alert.get(field)
                if isinstance(v, str):
                    tokens.extend(v.lower().split())
    return tokens
