#!/usr/bin/env python3
"""
Create comprehensive OpenObserve dashboards for home security monitoring.
Generates:
1. Security Logs Dashboard - Suricata alerts, firewall logs, kernel logs
2. Metrics Dashboard - Top requests, top IPs, event counts
3. AI Recommendations Dashboard - Security AI analysis results
"""

import os
import json
import requests
import sys
from typing import Dict, Any
from datetime import datetime

# Configuration from environment
OPENOBSERVE_URL = os.getenv("OPENOBSERVE_URL", "http://127.0.0.1:5080")
OPENOBSERVE_USER = os.getenv("OPENOBSERVE_USER", "dummykevin08@gmail.com")
OPENOBSERVE_PASSWORD = os.getenv("OPENOBSERVE_PASSWORD", "P4ssword!1P4ssword")
OPENOBSERVE_ORG = os.getenv("OPENOBSERVE_ORG", "default")

class OpenObserveDashboardCreator:
    def __init__(self, base_url: str, user: str, password: str, org: str):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self.org = org
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.headers.update({
            "Content-Type": "application/json",
        })

    def _api_request(self, method: str, endpoint: str, data: Dict[str, Any] = None) -> requests.Response:
        """Make an API request to OpenObserve."""
        url = f"{self.base_url}/api/{self.org}/{endpoint}"
        print(f"[{method}] {url}")
        
        if method == "GET":
            response = self.session.get(url)
        elif method == "POST":
            response = self.session.post(url, json=data)
        elif method == "PUT":
            response = self.session.put(url, json=data)
        else:
            raise ValueError(f"Unsupported method: {method}")
        
        return response

    def create_dashboard(self, dashboard_name: str, dashboard_description: str, panels: list) -> bool:
        """Create a dashboard in OpenObserve using v8 format."""
        dashboard_data = {
            "version": 8,
            "title": dashboard_name,
            "description": dashboard_description,
            "folder_id": "default",
            "tabs": [{
                "tabId": "default",
                "name": "Default",
                "panels": panels
            }]
        }
        
        # Create dashboard
        response = self._api_request(
            "POST",
            "dashboards",
            dashboard_data
        )
        
        if response.status_code in [200, 201]:
            print(f"✓ Dashboard '{dashboard_name}' created successfully")
            result = response.json()
            dashboard_id = result.get("v8", {}).get("dashboardId", "unknown")
            print(f"  Dashboard ID: {dashboard_id}")
            return True
        else:
            print(f"✗ Failed to create dashboard '{dashboard_name}'")
            print(f"  Status: {response.status_code}")
            print(f"  Response: {response.text}")
            return False

    def get_dashboards(self) -> list:
        """List all dashboards."""
        response = self._api_request("GET", "dashboards")
        if response.status_code == 200:
            return response.json().get("dashboards", [])
        return []

    def _create_panel(self, panel_id: str, title: str, chart_type: str, sql_query: str, 
                     stream: str, x: int, y: int, w: int = 12, h: int = 8) -> dict:
        """Helper method to create a panel with proper v8 format."""
        return {
            "id": panel_id,
            "type": chart_type,
            "title": title,
            "description": "",
            "queryType": "sql",
            "queries": [{
                "query": sql_query,
                "customQuery": False,
                "fields": {
                    "stream": stream,
                    "stream_type": "logs",
                    "x": [],
                    "y": [],
                    "filter": {
                        "filterType": "group",
                        "logicalOperator": "AND",
                        "conditions": []
                    }
                },
                "config": {}
            }],
            "config": {},
            "layout": {
                "x": x,
                "y": y,
                "w": w,
                "h": h,
                "i": panel_id
            }
        }

    def create_security_logs_dashboard(self) -> bool:
        """Create Security Logs Dashboard with Suricata, firewall, and kernel logs."""
        panels = [
            self._create_panel("suricata_alerts", "Suricata Alerts Timeline", "line",
                              "SELECT COUNT(*) as count FROM security_logs WHERE source='suricata' GROUP BY _timestamp ORDER BY _timestamp DESC",
                              "security_logs", 0, 0),
            self._create_panel("top_src_ips", "Top Source IPs (Suricata)", "bar",
                              "SELECT src_ip, COUNT(*) as count FROM security_logs WHERE source='suricata' AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY count DESC LIMIT 10",
                              "security_logs", 12, 0),
            self._create_panel("top_dest_ips", "Top Destination IPs (Suricata)", "bar",
                              "SELECT dest_ip, COUNT(*) as count FROM security_logs WHERE source='suricata' AND dest_ip IS NOT NULL GROUP BY dest_ip ORDER BY count DESC LIMIT 10",
                              "security_logs", 24, 0),
            self._create_panel("firewall_logs", "Firewall Events Timeline", "line",
                              "SELECT COUNT(*) as count FROM firewall_logs GROUP BY _timestamp ORDER BY _timestamp DESC",
                              "firewall_logs", 0, 10),
            self._create_panel("kernel_logs", "Kernel Logs Timeline", "line",
                              "SELECT COUNT(*) as count FROM kernel_logs GROUP BY _timestamp ORDER BY _timestamp DESC",
                              "kernel_logs", 12, 10),
            self._create_panel("alert_severity", "Alert Severity Distribution", "pie",
                              "SELECT alert_severity, COUNT(*) as count FROM security_logs WHERE source='suricata' AND alert_severity IS NOT NULL GROUP BY alert_severity",
                              "security_logs", 24, 10)
        ]
        
        return self.create_dashboard(
            "Security Logs Dashboard",
            "Real-time view of Suricata alerts, firewall logs, and kernel messages",
            panels
        )

    def create_metrics_dashboard(self) -> bool:
        """Create Metrics Dashboard with top requests, IPs, and event statistics."""
        panels = [
            self._create_panel("total_events", "Total Events (Last 24h)", "stat",
                              "SELECT COUNT(*) as total FROM security_logs WHERE _timestamp > now() - interval 24 hour",
                              "security_logs", 0, 0, 6, 8),
            self._create_panel("unique_src_ips", "Unique Source IPs (24h)", "stat",
                              "SELECT COUNT(DISTINCT src_ip) as unique_ips FROM security_logs WHERE source='suricata' AND src_ip IS NOT NULL AND _timestamp > now() - interval 24 hour",
                              "security_logs", 6, 0, 6, 8),
            self._create_panel("unique_dest_ips", "Unique Destination IPs (24h)", "stat",
                              "SELECT COUNT(DISTINCT dest_ip) as unique_ips FROM security_logs WHERE source='suricata' AND dest_ip IS NOT NULL AND _timestamp > now() - interval 24 hour",
                              "security_logs", 12, 0, 6, 8),
            self._create_panel("event_rate", "Event Rate Over Time", "line",
                              "SELECT COUNT(*) as count FROM security_logs WHERE source='suricata' GROUP BY _timestamp ORDER BY _timestamp DESC",
                              "security_logs", 18, 0, 12, 8),
            self._create_panel("top_ports", "Top Destination Ports", "bar",
                              "SELECT dest_port, COUNT(*) as count FROM security_logs WHERE source='suricata' AND dest_port IS NOT NULL GROUP BY dest_port ORDER BY count DESC LIMIT 15",
                              "security_logs", 0, 8),
            self._create_panel("top_protocols", "Top Protocols", "pie",
                              "SELECT proto, COUNT(*) as count FROM security_logs WHERE source='suricata' AND proto IS NOT NULL GROUP BY proto",
                              "security_logs", 12, 8),
            self._create_panel("top_alert_rules", "Top Alert Rules", "bar",
                              "SELECT alert_msg, COUNT(*) as count FROM security_logs WHERE source='suricata' AND alert_msg IS NOT NULL GROUP BY alert_msg ORDER BY count DESC LIMIT 12",
                              "security_logs", 24, 8),
            self._create_panel("src_ip_request_count", "Top Source IPs by Request Count", "table",
                              "SELECT src_ip, COUNT(*) as requests FROM security_logs WHERE source='suricata' AND src_ip IS NOT NULL GROUP BY src_ip ORDER BY requests DESC LIMIT 20",
                              "security_logs", 0, 16, 12, 8)
        ]
        
        return self.create_dashboard(
            "Metrics Dashboard",
            "High-level metrics: top IPs, ports, protocols, event rates, and request counts",
            panels
        )

    def create_ai_recommendations_dashboard(self) -> bool:
        """Create AI Recommendations Dashboard showing security analysis results."""
        panels = [
            self._create_panel("recommendations_timeline", "AI Analysis Events Timeline", "line",
                              "SELECT COUNT(*) as count FROM ai_recommendations GROUP BY _timestamp ORDER BY _timestamp DESC",
                              "ai_recommendations", 0, 0),
            self._create_panel("analysis_events_daily", "Analysis Events per Day", "bar",
                              "SELECT COUNT(*) as count FROM ai_recommendations GROUP BY date_trunc('day', _timestamp) ORDER BY date_trunc('day', _timestamp) DESC LIMIT 30",
                              "ai_recommendations", 12, 0),
            self._create_panel("recommendation_status", "Recommendation Status Distribution", "pie",
                              "SELECT status, COUNT(*) as count FROM ai_recommendations GROUP BY status",
                              "ai_recommendations", 24, 0, 12, 8),
            self._create_panel("top_findings", "Top Finding Types", "bar",
                              "SELECT finding_type, COUNT(*) as count FROM ai_recommendations WHERE finding_type IS NOT NULL GROUP BY finding_type ORDER BY count DESC LIMIT 10",
                              "ai_recommendations", 0, 8),
            self._create_panel("recent_recommendations", "Recent AI Recommendations", "table",
                              "SELECT * FROM ai_recommendations ORDER BY _timestamp DESC LIMIT 50",
                              "ai_recommendations", 0, 16, 36, 10)
        ]
        
        return self.create_dashboard(
            "AI Recommendations Dashboard",
            "View AI-generated security analysis and recommendations from Ollama",
            panels
        )


def main():
    """Main entry point."""
    print(f"\n=== OpenObserve Dashboard Creator ===")
    print(f"OpenObserve URL: {OPENOBSERVE_URL}")
    print(f"Organization: {OPENOBSERVE_ORG}")
    print(f"User: {OPENOBSERVE_USER}\n")
    
    creator = OpenObserveDashboardCreator(
        OPENOBSERVE_URL,
        OPENOBSERVE_USER,
        OPENOBSERVE_PASSWORD,
        OPENOBSERVE_ORG
    )
    
    # Check connection
    try:
        dashboards = creator.get_dashboards()
        print(f"✓ Connected to OpenObserve")
        print(f"  Existing dashboards: {len(dashboards)}")
        if dashboards:
            for db in dashboards:
                print(f"    - {db.get('name', 'Unknown')}")
        print()
    except Exception as e:
        print(f"✗ Failed to connect to OpenObserve: {e}")
        sys.exit(1)
    
    # Create dashboards
    results = []
    
    print("Creating Security Logs Dashboard...")
    results.append(creator.create_security_logs_dashboard())
    print()
    
    print("Creating Metrics Dashboard...")
    results.append(creator.create_metrics_dashboard())
    print()
    
    print("Creating AI Recommendations Dashboard...")
    results.append(creator.create_ai_recommendations_dashboard())
    print()
    
    # Summary
    print("=== Summary ===")
    print(f"Total dashboards created: {sum(results)}/{len(results)}")
    if all(results):
        print("✓ All dashboards created successfully!")
        print(f"\nAccess OpenObserve at: {OPENOBSERVE_URL}")
        return 0
    else:
        print("✗ Some dashboards failed to create")
        return 1


if __name__ == "__main__":
    sys.exit(main())
