"""
Enhanced Suricata rule and firewall-cmd rule generator.

Improvements over v1:
- Strict single-line rule output (compliant with worker.py validation)
- CVE-aware metadata embedding
- MITRE ATT&CK technique tagging
- Community ID and source_id support
- Input sanitisation helpers
- New attack-pattern generators: Log4Shell, DNS tunnelling, RCE, C2 beacon,
  HTTP/2 rapid-reset, lateral movement
- FirewallRuleGenerator: structured IP/service/port blocks with Ansible-ready output
"""

from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MIN_SID = 1_000_000
MAX_SID = 1_999_999
_VALID_PORT = re.compile(r"^\d{1,5}(?:-\d{1,5})?$")
_VALID_IP   = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$")
_VALID_ZONE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _today() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _sanitise_content(pattern: str) -> str:
    """Escape double-quotes inside a Suricata content string."""
    return pattern.replace('"', '\\"')


def _build_metadata(
    *,
    cve: Optional[str] = None,
    attack_type: str = "suspicious_traffic",
    mitre: Optional[List[str]] = None,
    source_id: str = "AI-RECOMMENDATION",
    community_id: str = "",
    created_at: Optional[str] = None,
) -> str:
    """Build a compact single-line Suricata metadata string."""
    parts = [f"created_at {created_at or _today()}"]
    if cve:
        # Accept either a single CVE string or the first of a list
        cve_str = cve if isinstance(cve, str) else cve[0] if cve else ""
        if cve_str:
            parts.append(f"cve {cve_str}")
    parts.append(f"attack_type {attack_type}")
    if mitre:
        parts.append(f"mitre {' '.join(mitre)}")
    parts.append(f"source_id {source_id}")
    if community_id:
        parts.append(f"community_id {community_id}")
    return ", ".join(parts)


# ---------------------------------------------------------------------------
# Suricata rule generator
# ---------------------------------------------------------------------------

class SuricataRuleGenerator:
    """
    Generate syntactically valid Suricata *alert* rules as single-line strings.

    Each rule is self-contained and validated with a regex before being
    returned so that worker.py's validate_proposals() will not reject it.
    """

    def __init__(self, next_sid: int = MIN_SID):
        if not (MIN_SID <= next_sid <= MAX_SID):
            next_sid = MIN_SID
        self._sid = next_sid

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _alloc_sid(self) -> int:
        sid = self._sid
        self._sid = self._sid + 1 if self._sid < MAX_SID else MIN_SID
        return sid

    @staticmethod
    def _one_liner(
        *,
        proto: str,
        src: str,
        src_port: str,
        dst: str,
        dst_port: str,
        msg: str,
        options: List[str],
        classtype: str,
        sid: int,
        metadata: str,
        rev: int = 1,
    ) -> str:
        """Assemble a valid single-line Suricata rule."""
        msg_escaped = _sanitise_content(msg)
        body = (
            f'msg:"{msg_escaped}"; '
            + " ".join(o.rstrip(";") + ";" for o in options if o)
            + f" classtype:{classtype}; sid:{sid}; rev:{rev}; metadata:{metadata};"
        )
        return f"alert {proto} {src} {src_port} -> {dst} {dst_port} ({body})"

    @staticmethod
    def validate(rule: str) -> bool:
        """Return True if the rule passes the worker.py shape checks."""
        return (
            isinstance(rule, str)
            and rule.lstrip().startswith("alert ")
            and len(rule) <= 2000
            and "\n" not in rule
            and "\r" not in rule
        )

    # ------------------------------------------------------------------
    # Public rule generators
    # ------------------------------------------------------------------

    def ssh_brute_force(
        self,
        *,
        src_ip: str = "$EXTERNAL_NET",
        threshold: int = 5,
        window: int = 60,
        cve: str = "CVE-2024-6387",
    ) -> str:
        """SSH brute-force / regreSSHion detection rule."""
        sid = self._alloc_sid()
        return self._one_liner(
            proto="tcp",
            src=src_ip, src_port="any",
            dst="$HOME_NET", dst_port="22",
            msg="AI-REC: SSH brute force / regreSSHion candidate",
            options=[
                "flow:to_server,established",
                'content:"SSH-"',
                f"detection_filter:track by_src, count {threshold}, seconds {window}",
            ],
            classtype="attempted-admin",
            sid=sid,
            metadata=_build_metadata(
                cve=cve,
                attack_type="brute_force",
                mitre=["T1110", "T1110.001"],
            ),
        )

    def port_scan(
        self,
        *,
        dst_ports: str = "22,80,443,445,3306,5432,27017",
        threshold: int = 10,
        window: int = 30,
    ) -> str:
        """Network reconnaissance / port scan detection rule."""
        sid = self._alloc_sid()
        return self._one_liner(
            proto="tcp",
            src="$EXTERNAL_NET", src_port="any",
            dst="$HOME_NET", dst_port=f"[{dst_ports}]",
            msg="AI-REC: Network reconnaissance port scan",
            options=[
                "flags:S,12",
                "flow:to_server,no_stream",
                f"detection_filter:track by_src, count {threshold}, seconds {window}",
            ],
            classtype="network-scan",
            sid=sid,
            metadata=_build_metadata(
                attack_type="port_scan",
                mitre=["T1046"],
            ),
        )

    def log4shell(self, *, proto: str = "http") -> str:
        """Log4Shell (CVE-2021-44228) JNDI injection detection rule."""
        sid = self._alloc_sid()
        return self._one_liner(
            proto=proto,
            src="$EXTERNAL_NET", src_port="any",
            dst="$HOME_NET", dst_port="any",
            msg="AI-REC: Log4Shell JNDI injection attempt CVE-2021-44228",
            options=[
                "flow:to_server,established",
                'content:"${jndi:"', "nocase",
                "http.header",
            ],
            classtype="web-application-attack",
            sid=sid,
            metadata=_build_metadata(
                cve="CVE-2021-44228",
                attack_type="rce_exploit",
                mitre=["T1190", "T1059"],
            ),
        )

    def http_path_traversal(self, *, cve: str = "CVE-2021-41773") -> str:
        """Apache path-traversal / RCE detection rule."""
        sid = self._alloc_sid()
        return self._one_liner(
            proto="http",
            src="$EXTERNAL_NET", src_port="any",
            dst="$HOME_NET", dst_port="any",
            msg="AI-REC: HTTP path traversal attempt",
            options=[
                "flow:to_server,established",
                'content:"/.%2e/"', "nocase",
                "http.uri",
            ],
            classtype="web-application-attack",
            sid=sid,
            metadata=_build_metadata(
                cve=cve,
                attack_type="rce_exploit",
                mitre=["T1190"],
            ),
        )

    def dns_tunneling(
        self,
        *,
        threshold: int = 100,
        window: int = 60,
    ) -> str:
        """DNS tunneling / C2 beacon via excessive DNS queries."""
        sid = self._alloc_sid()
        return self._one_liner(
            proto="dns",
            src="$HOME_NET", src_port="any",
            dst="$EXTERNAL_NET", dst_port="53",
            msg="AI-REC: Possible DNS tunneling or C2 via excessive DNS",
            options=[
                "flow:to_server",
                f"detection_filter:track by_src, count {threshold}, seconds {window}",
            ],
            classtype="protocol-command-decode",
            sid=sid,
            metadata=_build_metadata(
                attack_type="c2_beacon",
                mitre=["T1071.004"],
            ),
        )

    def http_flood(
        self,
        *,
        dst_port: str = "any",
        threshold: int = 50,
        window: int = 10,
        cve: str = "CVE-2023-44487",
    ) -> str:
        """HTTP flood / HTTP/2 rapid-reset DoS detection rule."""
        sid = self._alloc_sid()
        return self._one_liner(
            proto="http",
            src="$EXTERNAL_NET", src_port="any",
            dst="$HOME_NET", dst_port=dst_port,
            msg="AI-REC: HTTP flood or rapid-reset DoS candidate",
            options=[
                "flow:to_server,established",
                f"detection_filter:track by_src, count {threshold}, seconds {window}",
            ],
            classtype="abuse-of-service",
            sid=sid,
            metadata=_build_metadata(
                cve=cve,
                attack_type="dos_attack",
                mitre=["T1498"],
            ),
        )

    def c2_high_port_outbound(
        self,
        *,
        ports: List[int],
        src_ip: str = "$HOME_NET",
    ) -> str:
        """Suspicious outbound C2 beacon to unusual high ports."""
        sid = self._alloc_sid()
        port_spec = ",".join(str(p) for p in sorted(set(ports)) if 1 <= p <= 65535)
        if not port_spec:
            port_spec = "4444,5555,8888,9999"
        return self._one_liner(
            proto="tcp",
            src=src_ip, src_port="any",
            dst="$EXTERNAL_NET", dst_port=f"[{port_spec}]",
            msg="AI-REC: Suspicious outbound connection on atypical high port (possible C2)",
            options=[
                "flow:to_server,established",
            ],
            classtype="trojan-activity",
            sid=sid,
            metadata=_build_metadata(
                attack_type="c2_beacon",
                mitre=["T1071"],
            ),
        )

    def suspicious_user_agent(self, *, user_agent: str) -> str:
        """Detect a known malicious or scanner User-Agent string."""
        sid = self._alloc_sid()
        safe_ua = _sanitise_content(user_agent)[:80]
        return self._one_liner(
            proto="http",
            src="$EXTERNAL_NET", src_port="any",
            dst="$HOME_NET", dst_port="any",
            msg=f"AI-REC: Known malicious/scanner User-Agent: {safe_ua[:40]}",
            options=[
                "flow:to_server,established",
                f'content:"{safe_ua}"', "nocase",
                "http.user_agent",
            ],
            classtype="web-application-attack",
            sid=sid,
            metadata=_build_metadata(
                attack_type="web_attack",
                mitre=["T1190"],
            ),
        )

    def lateral_ssh(self, *, threshold: int = 5, window: int = 60) -> str:
        """East-west (lateral movement) SSH connection alert."""
        sid = self._alloc_sid()
        return self._one_liner(
            proto="tcp",
            src="$HOME_NET", src_port="any",
            dst="$HOME_NET", dst_port="22",
            msg="AI-REC: Possible lateral movement via internal SSH",
            options=[
                "flow:to_server,established",
                'content:"SSH-"',
                f"detection_filter:track by_src, count {threshold}, seconds {window}",
            ],
            classtype="unusual-client-port-connection",
            sid=sid,
            metadata=_build_metadata(
                attack_type="lateral_movement",
                mitre=["T1021"],
            ),
        )


# ---------------------------------------------------------------------------
# Firewall rule generator  (structured output for worker.py validate_proposals)
# ---------------------------------------------------------------------------

class FirewallRuleGenerator:
    """
    Build structured firewall proposal dicts that pass worker.py's
    validate_proposals() schema checks for the 'firewalld' target.

    The output format matches the worker's expected fields:
      block_type, blocked_ip / blocked_service / blocked_port, zone,
      rationale, risk, false_positive_risk, validation_steps, rollback_steps.
    """

    @staticmethod
    def _base(
        *,
        rationale: str,
        risk: str,
        fp_risk: str,
        validation_steps: List[str],
        rollback_steps: List[str],
        event_refs: Optional[List[str]] = None,
        cve_ids: Optional[List[str]] = None,
        attack_types: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        proposal: Dict[str, Any] = {
            "target": "firewalld",
            "rationale": rationale,
            "risk": risk,
            "false_positive_risk": fp_risk,
            "validation_steps": validation_steps,
            "rollback_steps": rollback_steps,
            "event_refs": event_refs or [],
        }
        if cve_ids:
            proposal["cve_ids"] = cve_ids
        if attack_types:
            proposal["attack_types"] = attack_types
        if mitre_techniques:
            proposal["mitre_techniques"] = mitre_techniques
        return proposal

    def block_ip(
        self,
        ip: str,
        *,
        zone: str = "public",
        reason: str = "AI-detected suspicious activity",
        event_refs: Optional[List[str]] = None,
        cve_ids: Optional[List[str]] = None,
        attack_types: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Propose an IP block; returns None if ip/zone fail validation."""
        if not _VALID_IP.match(ip) or not _VALID_ZONE.match(zone):
            return None
        proposal = self._base(
            rationale=f"Block source IP {ip} — {reason}",
            risk="Low — targeted IP block with narrow scope",
            fp_risk=(
                "Medium — may block legitimate users behind NAT, shared hosting, "
                "or commercial proxies. Verify the IP is not in a known safe list."
            ),
            validation_steps=[
                f"Confirm {ip} is not an internal, CDN, or allowlisted address",
                f"firewall-cmd --query-rich-rule='rule family=ipv4 source address={ip} drop'",
                f"Monitor with: tcpdump -i any -n src {ip} -c 50",
            ],
            rollback_steps=[
                f"firewall-cmd --permanent --remove-rich-rule='rule family=ipv4 source address={ip} drop'",
                "firewall-cmd --reload",
                f"# Verify removal: firewall-cmd --query-rich-rule='rule family=ipv4 source address={ip} drop'",
            ],
            event_refs=event_refs,
            cve_ids=cve_ids,
            attack_types=attack_types,
            mitre_techniques=mitre_techniques,
        )
        proposal["block_type"] = "ip"
        proposal["blocked_ip"] = ip
        proposal["zone"] = zone
        return proposal

    def block_port(
        self,
        port_spec: str,
        *,
        zone: str = "public",
        reason: str = "Unnecessary or exploited service",
        event_refs: Optional[List[str]] = None,
        cve_ids: Optional[List[str]] = None,
        attack_types: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Propose a port block.
        port_spec must match ``\\d{1,5}(?:-\\d{1,5})?/(tcp|udp|sctp|dccp)``.
        """
        if not re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?/(?:tcp|udp|sctp|dccp)", port_spec):
            return None
        if not _VALID_ZONE.match(zone):
            return None
        port_num, proto = port_spec.split("/")
        proposal = self._base(
            rationale=f"Block {port_spec} — {reason}",
            risk="Medium — removing a port affects all traffic on that port/protocol",
            fp_risk=(
                "High — verify no legitimate internal services depend on this port "
                "before applying globally."
            ),
            validation_steps=[
                f"List current open ports: firewall-cmd --list-ports --zone={zone}",
                f"Test in timeout mode: firewall-cmd --remove-port={port_spec} --timeout=120",
                f"Verify blocked: nmap -p {port_num} <host>",
                f"Monitor: journalctl -f -u firewalld",
            ],
            rollback_steps=[
                f"firewall-cmd --permanent --add-port={port_spec}",
                "firewall-cmd --reload",
                f"# Verify: firewall-cmd --query-port={port_spec} --zone={zone}",
            ],
            event_refs=event_refs,
            cve_ids=cve_ids,
            attack_types=attack_types,
            mitre_techniques=mitre_techniques,
        )
        proposal["block_type"] = "port"
        proposal["blocked_port"] = port_spec
        proposal["zone"] = zone
        return proposal

    def block_service(
        self,
        service: str,
        *,
        zone: str = "public",
        reason: str = "Insecure or unnecessary service",
        event_refs: Optional[List[str]] = None,
        cve_ids: Optional[List[str]] = None,
        attack_types: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Propose removal of a named firewalld service."""
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", service):
            return None
        if not _VALID_ZONE.match(zone):
            return None
        proposal = self._base(
            rationale=f"Remove service '{service}' from zone '{zone}' — {reason}",
            risk="Medium — affects all hosts in the firewalld zone",
            fp_risk=(
                "High — confirm no legitimate internal traffic requires this service "
                "before removing."
            ),
            validation_steps=[
                f"firewall-cmd --list-services --zone={zone}",
                f"firewall-cmd --remove-service={service} --timeout=120",
                f"firewall-cmd --query-service={service} --zone={zone}",
            ],
            rollback_steps=[
                f"firewall-cmd --permanent --add-service={service} --zone={zone}",
                "firewall-cmd --reload",
                f"# Verify: firewall-cmd --query-service={service} --zone={zone}",
            ],
            event_refs=event_refs,
            cve_ids=cve_ids,
            attack_types=attack_types,
            mitre_techniques=mitre_techniques,
        )
        proposal["block_type"] = "service"
        proposal["blocked_service"] = service
        proposal["zone"] = zone
        return proposal


# ---------------------------------------------------------------------------
# Event-driven rule synthesis  (called from worker.py after LLM analysis)
# ---------------------------------------------------------------------------

def synthesize_rules_from_analysis(
    events: List[Dict[str, Any]],
    analysis: Dict[str, Any],
    *,
    existing_sids: Optional[List[int]] = None,
) -> Tuple[List[str], List[Dict[str, Any]]]:
    """
    Derive concrete Suricata rules and firewall proposals from the LLM's
    structured analysis.  This is the post-LLM synthesis pass that turns
    high-confidence findings into validated artefacts.

    Args:
        events:        Raw events passed to the LLM.
        analysis:      LLM analysis dict (findings, proposed_changes, confidence).
        existing_sids: SIDs already in use — next_sid starts after the max.

    Returns:
        (suricata_rules, firewall_proposals) — both already validated.
    """
    start_sid = MIN_SID
    if existing_sids:
        start_sid = min(MAX_SID, max(existing_sids) + 1)

    sg = SuricataRuleGenerator(next_sid=start_sid)
    fg = FirewallRuleGenerator()

    suricata_rules: List[str] = []
    fw_proposals: List[Dict[str, Any]] = []

    # Extract IOCs from events
    src_ips: List[str] = []
    dst_ports: List[int] = []
    user_agents: List[str] = []

    for ev in events:
        ip = ev.get("src_ip") or ev.get("source_ip")
        if isinstance(ip, str) and _VALID_IP.match(ip):
            src_ips.append(ip)
        port = ev.get("dest_port") or ev.get("dst_port")
        if isinstance(port, int) and 1 <= port <= 65535:
            dst_ports.append(port)
        ua = ev.get("http_user_agent") or ev.get("user_agent")
        if isinstance(ua, str) and len(ua) > 4:
            user_agents.append(ua)

    findings = analysis.get("findings", []) if isinstance(analysis, dict) else []
    confidence = str(analysis.get("confidence", "low")).lower() if isinstance(analysis, dict) else "low"

    for finding in findings[:8]:
        if not isinstance(finding, dict):
            continue
        severity    = str(finding.get("severity", "")).lower()
        rec         = str(finding.get("recommendation", "")).lower()
        f_types     = [str(a).lower() for a in finding.get("attack_types", [])]
        cve_ids     = finding.get("cve_ids", [])
        mitre_ids   = finding.get("mitre_techniques", [])
        ev_refs     = finding.get("event_refs", [])

        # --- Suricata rules ---
        if "brute" in rec or "ssh" in rec or "brute_force" in f_types:
            rule = sg.ssh_brute_force(
                cve=cve_ids[0] if cve_ids else "CVE-2024-6387",
            )
            if SuricataRuleGenerator.validate(rule):
                suricata_rules.append(rule)

        if "scan" in rec or "port_scan" in f_types or "recon" in rec:
            rule = sg.port_scan(
                dst_ports=",".join(str(p) for p in dst_ports[:6]) if dst_ports else "22,80,443,445",
            )
            if SuricataRuleGenerator.validate(rule):
                suricata_rules.append(rule)

        if "log4" in rec or "jndi" in rec or "CVE-2021-44228" in cve_ids:
            rule = sg.log4shell()
            if SuricataRuleGenerator.validate(rule):
                suricata_rules.append(rule)

        if "path traversal" in rec or "CVE-2021-41773" in cve_ids:
            rule = sg.http_path_traversal(
                cve=cve_ids[0] if cve_ids else "CVE-2021-41773",
            )
            if SuricataRuleGenerator.validate(rule):
                suricata_rules.append(rule)

        if "dns tunnel" in rec or "dns" in f_types or "c2_beacon" in f_types:
            rule = sg.dns_tunneling()
            if SuricataRuleGenerator.validate(rule):
                suricata_rules.append(rule)

        if "dos" in rec or "flood" in rec or "dos_attack" in f_types:
            rule = sg.http_flood(
                cve=cve_ids[0] if cve_ids else "CVE-2023-44487",
            )
            if SuricataRuleGenerator.validate(rule):
                suricata_rules.append(rule)

        if "lateral" in rec or "lateral_movement" in f_types:
            rule = sg.lateral_ssh()
            if SuricataRuleGenerator.validate(rule):
                suricata_rules.append(rule)

        high_ports = [p for p in dst_ports if p > 1024 and p not in (3306, 5432, 8080, 8443, 27017)]
        if high_ports and ("c2" in rec or "beacon" in rec or "c2_beacon" in f_types):
            rule = sg.c2_high_port_outbound(ports=high_ports[:5])
            if SuricataRuleGenerator.validate(rule):
                suricata_rules.append(rule)

        # --- Firewall proposals (only for medium/high/critical severity) ---
        if severity in ("high", "critical") and confidence in ("medium", "high"):
            for ip in src_ips[:3]:
                prop = fg.block_ip(
                    ip,
                    reason=finding.get("recommendation", "AI-detected threat")[:200],
                    event_refs=ev_refs[:10],
                    cve_ids=[c for c in cve_ids if re.match(r"^CVE-\d{4}-\d{4,7}$", c)][:5],
                    attack_types=f_types[:5],
                    mitre_techniques=[m for m in mitre_ids if re.match(r"^T\d{4}(\.\d{3})?$", m)][:5],
                )
                if prop:
                    fw_proposals.append(prop)

        if "telnet" in rec:
            prop = fg.block_service("telnet", reason="Insecure plaintext protocol", event_refs=ev_refs[:10])
            if prop:
                fw_proposals.append(prop)

        if "ftp" in rec and "sftp" not in rec:
            prop = fg.block_service("ftp", reason="Insecure plaintext protocol", event_refs=ev_refs[:10])
            if prop:
                fw_proposals.append(prop)

    # De-duplicate rules by stripped content
    seen_rules: set = set()
    unique_rules: List[str] = []
    for rule in suricata_rules:
        key = re.sub(r"sid:\d+;", "sid:X;", rule)
        if key not in seen_rules:
            seen_rules.add(key)
            unique_rules.append(rule)

    return unique_rules[:10], fw_proposals[:10]
