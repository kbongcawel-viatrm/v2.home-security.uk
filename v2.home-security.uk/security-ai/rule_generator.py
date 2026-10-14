"""
Generate Suricata rules and firewall-cmd rules from security events.

This module provides functions to create syntactically valid and practical
Suricata detection rules and firewall blocking rules based on analyzed events.
"""

import json
import re
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple


class SuricataRuleGenerator:
    """Generate Suricata detection rules from security events."""
    
    # Available SIDs in the AI-generated range (1000000-1999999)
    MIN_SID = 1000000
    MAX_SID = 1999999
    
    def __init__(self, next_sid: int = MIN_SID):
        self.next_sid = next_sid
    
    def _increment_sid(self) -> int:
        """Get next available SID."""
        current = self.next_sid
        self.next_sid += 1
        if self.next_sid > self.MAX_SID:
            self.next_sid = self.MIN_SID
        return current
    
    def _format_metadata(self, cve: Optional[str] = None, attack_type: str = "suspicious_traffic",
                        created_at: Optional[str] = None) -> str:
        """Format Suricata metadata section."""
        if not created_at:
            created_at = datetime.utcnow().strftime("%Y-%m-%d")
        
        metadata = f"        created_at {created_at}"
        if cve:
            metadata += f",\n        cve {cve}"
        metadata += f",\n        attack_type {attack_type},\n        source_id AI-GENERATED"
        return metadata
    
    def ssh_brute_force_detection(self, source_ip: str, threshold: int = 5, 
                                   time_window: int = 60) -> str:
        """Generate rule for SSH brute force detection."""
        sid = self._increment_sid()
        return f"""alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (
    msg:"AI-REC: SSH brute force attempt from {source_ip}";
    flow:to_server,established;
    content:"SSH-";
    detection_filter:track by_src, count {threshold}, seconds {time_window};
    classtype:attempted-admin;
    sid:{sid};
    rev:1;
    metadata:
{self._format_metadata(attack_type="brute_force")}
)
"""
    
    def suspicious_port_scan(self, target_port: int = 22) -> str:
        """Generate rule for port scanning detection."""
        sid = self._increment_sid()
        return f"""alert tcp $EXTERNAL_NET any -> $HOME_NET {target_port} (
    msg:"AI-REC: Potential port scan targeting port {target_port}";
    flags:S,12;
    flow:to_server,no_stream;
    detection_filter:track by_src, count 10, seconds 30;
    classtype:network-scan;
    sid:{sid};
    rev:1;
    metadata:
{self._format_metadata(attack_type="port_scan")}
)
"""
    
    def malicious_payload_detection(self, pattern: str, payload_type: str = "shellcode") -> str:
        """Generate rule for malicious payload detection."""
        sid = self._increment_sid()
        # Escape pattern for safe inclusion in rule
        safe_pattern = pattern.replace('"', '\\"')
        return f"""alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"AI-REC: Suspicious {payload_type} pattern detected";
    flow:established;
    content:"{safe_pattern}";
    classtype:suspicious-login;
    sid:{sid};
    rev:1;
    metadata:
{self._format_metadata(attack_type="malicious_payload")}
)
"""
    
    def high_port_connection(self, src_ip: str, ports: List[int]) -> str:
        """Generate rule for suspicious high-port outbound connections."""
        sid = self._increment_sid()
        port_list = ",".join(str(p) for p in sorted(set(ports)))
        return f"""alert tcp $HOME_NET any -> $EXTERNAL_NET [{port_list}] (
    msg:"AI-REC: Suspicious outbound connection to high ports from {src_ip}";
    flow:to_server,established;
    classtype:unusual-protocol;
    sid:{sid};
    rev:1;
    metadata:
{self._format_metadata(attack_type="c2_beacon")}
)
"""
    
    def rate_limit_rule(self, source_net: str = "$EXTERNAL_NET", 
                       dest_port: int = 80, threshold: int = 100) -> str:
        """Generate rule for rate-limiting traffic."""
        sid = self._increment_sid()
        return f"""alert http {source_net} any -> $HOME_NET {dest_port} (
    msg:"AI-REC: Excessive HTTP requests from {source_net} to port {dest_port}";
    flow:to_server,established;
    detection_filter:track by_src, count {threshold}, seconds 60;
    classtype:abuse-of-service;
    sid:{sid};
    rev:1;
    metadata:
{self._format_metadata(attack_type="dos")}
)
"""


class FirewallRuleGenerator:
    """Generate firewall-cmd rules for blocking and service management."""
    
    @staticmethod
    def block_ip_rule(ip: str, reason: str = "AI-detected threat", zone: str = "public") -> Dict[str, Any]:
        """Generate firewall-cmd rule to block an IP."""
        return {
            "type": "block_ip",
            "target": "firewall-cmd",
            "ip": ip,
            "zone": zone,
            "reason": reason,
            "rationale": f"Block IP {ip} due to suspicious activity: {reason}",
            "risk": "Low - IP blocking has minimal false positive risk if properly scoped",
            "false_positive_risk": "Medium - May block legitimate users sharing an IP (proxies, corporate NAT)",
            "validation_steps": [
                "Verify IP is not in whitelist before blocking",
                "Test with: firewall-cmd --query-rich-rule='rule family=\"ipv4\" source address=\"{ip}\" drop'",
                "Verify connections from {ip} are dropped: tcpdump -i any -n src {ip}"
            ],
            "rollback_steps": [
                f"firewall-cmd --permanent --remove-rich-rule='rule family=\"ipv4\" source address=\"{ip}\" drop'",
                "firewall-cmd --reload"
            ],
            "event_refs": []
        }
    
    @staticmethod
    def block_port_rule(port: int, protocol: str = "tcp", 
                       reason: str = "Unnecessary service", zone: str = "public") -> Dict[str, Any]:
        """Generate firewall-cmd rule to block a port."""
        return {
            "type": "block_port",
            "target": "firewall-cmd",
            "port": port,
            "protocol": protocol,
            "zone": zone,
            "reason": reason,
            "rationale": f"Block {protocol.upper()}/{port} - {reason}",
            "risk": "Medium - May block legitimate services if port is unexpectedly used",
            "false_positive_risk": "High - Blocking a port globally affects all users",
            "validation_steps": [
                f"Test in safe environment: firewall-cmd --remove-port={port}/{protocol} --timeout=0",
                f"Verify with: netstat -tlnp | grep :{port}",
                f"Monitor logs for blocked connections: journalctl -f -u firewalld"
            ],
            "rollback_steps": [
                f"firewall-cmd --permanent --add-port={port}/{protocol}",
                "firewall-cmd --reload"
            ],
            "event_refs": []
        }
    
    @staticmethod
    def disable_service_rule(service: str, reason: str = "Unnecessary service", 
                            zone: str = "public") -> Dict[str, Any]:
        """Generate firewall-cmd rule to disable a service."""
        return {
            "type": "disable_service",
            "target": "firewall-cmd",
            "service": service,
            "zone": zone,
            "reason": reason,
            "rationale": f"Disable {service} from firewall - {reason}",
            "risk": "Medium - May affect services that depend on exposed ports",
            "false_positive_risk": "High - Disabling services affects all users",
            "validation_steps": [
                f"Check current services: firewall-cmd --list-services",
                f"Test removal: firewall-cmd --remove-service={service} --timeout=0",
                f"Verify with: firewall-cmd --query-service={service}"
            ],
            "rollback_steps": [
                f"firewall-cmd --permanent --add-service={service}",
                "firewall-cmd --reload"
            ],
            "event_refs": []
        }
    
    @staticmethod
    def rate_limit_rule(port: int, protocol: str = "tcp", 
                       connections_per_minute: int = 10,
                       zone: str = "public") -> Dict[str, Any]:
        """Generate firewall-cmd rate limiting rule."""
        return {
            "type": "rate_limit",
            "target": "firewall-cmd",
            "port": port,
            "protocol": protocol,
            "connections_per_minute": connections_per_minute,
            "zone": zone,
            "rationale": f"Rate limit {protocol.upper()}/{port} to {connections_per_minute} connections/minute",
            "risk": "Medium - May affect legitimate rapid connections",
            "false_positive_risk": "Medium - Legitimate clients with bursty traffic may be rate-limited",
            "validation_steps": [
                "Create test traffic: while true; do nc -zv target:port; done",
                "Monitor with: firewall-cmd --query-rich-rule='...'",
                "Check rejection logs: journalctl -f -u firewalld"
            ],
            "rollback_steps": [
                f"firewall-cmd --permanent --remove-rich-rule='rule family=\"ipv4\" port protocol={protocol} port={port} limit value=\"{connections_per_minute}/m\" drop'",
                "firewall-cmd --reload"
            ],
            "event_refs": []
        }

def generate_rules_from_events(events: List[Dict[str, Any]], analysis: Dict[str, Any]) -> Tuple[List[str], List[Dict[str, Any]]]:
    """
    Generate Suricata rules and firewall rules from events and AI analysis.
    
    Args:
        events: List of security events from OpenObserve
        analysis: AI analysis result with findings and confidence
        
    Returns:
        Tuple of (suricata_rules, firewall_rules)
    """
    suricata_gen = SuricataRuleGenerator()
    firewall_gen = FirewallRuleGenerator()
    
    suricata_rules = []
    firewall_rules = []
    
    # Extract key indicators from events
    source_ips = set()
    target_ports = set()
    attack_types = set()
    
    for event in events:
        if event.get("source"):
            source_ips.add(event.get("src_ip"))
        if event.get("dest_port"):
            target_ports.add(event.get("dest_port"))
        if event.get("alert_severity"):
            attack_types.add("suspicious")
    
    # Generate Suricata rules based on findings
    findings = analysis.get("findings", [])
    
    for finding in findings[:5]:  # Limit to 5 rules
        finding_type = finding.get("type", "").lower()
        
        # SSH brute force detection
        if "brute" in finding_type or "ssh" in finding_type:
            for ip in list(source_ips)[:3]:  # Limit to top 3 IPs
                if ip:
                    rule = suricata_gen.ssh_brute_force_detection(ip)
                    suricata_rules.append(rule)
        
        # Port scan detection
        elif "scan" in finding_type or "port" in finding_type:
            for port in list(target_ports)[:2]:  # Limit to top 2 ports
                if port and 1 <= int(port) <= 65535:
                    rule = suricata_gen.suspicious_port_scan(int(port))
                    suricata_rules.append(rule)
        
        # Rate limiting
        elif "dos" in finding_type or "flood" in finding_type or "rate" in finding_type:
            rule = suricata_gen.rate_limit_rule()
            suricata_rules.append(rule)
        
        # Malicious payload
        elif "payload" in finding_type or "exploit" in finding_type:
            rule = suricata_gen.malicious_payload_detection("suspicious_pattern")
            suricata_rules.append(rule)
    
    # Generate firewall rules
    confidence = analysis.get("confidence", "low").lower()
    
    # Block high-confidence suspicious IPs
    if confidence in ("high", "critical"):
        for ip in list(source_ips)[:5]:  # Limit to top 5 IPs
            if ip and ip != "0.0.0.0":
                rule = firewall_gen.block_ip_rule(ip, "AI-detected suspicious activity")
                firewall_rules.append(rule)
    
    # Disable unnecessary services based on findings
    for finding in findings[:3]:
        finding_desc = finding.get("description", "").lower()
        if "telnet" in finding_desc:
            rule = firewall_gen.disable_service_rule("telnet", "Insecure protocol")
            firewall_rules.append(rule)
        elif "ssh" in finding_desc and "open" in finding_desc:
            # Rate limit SSH if brute force detected
            rule = firewall_gen.rate_limit_rule(22, "tcp", connections_per_minute=10)
            firewall_rules.append(rule)
    
    return suricata_rules, firewall_rules

