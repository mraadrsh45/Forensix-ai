import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class GTICDatabaseService:
    def __init__(self):
        self._threat_events: List[Dict[str, Any]] = []
        self._country_stats: Dict[str, Dict[str, Any]] = {}
        self._init_seed_data()

    def _init_seed_data(self):
        # Initial seed of global threat statistics & hotspots
        self._country_stats = {
            "US": {"country": "United States", "code": "US", "threat_count": 4820, "lat": 37.0902, "lon": -95.7129, "risk_level": "CRITICAL", "top_vector": "Phishing & Ransomware"},
            "DE": {"country": "Germany", "code": "DE", "threat_count": 2340, "lat": 51.1657, "lon": 10.4515, "risk_level": "HIGH", "top_vector": "Botnet & C2"},
            "CN": {"country": "China", "code": "CN", "threat_count": 3910, "lat": 35.8617, "lon": 104.1954, "risk_level": "CRITICAL", "top_vector": "Credential Theft & APT"},
            "RU": {"country": "Russia", "code": "RU", "threat_count": 4120, "lat": 61.5240, "lon": 105.3188, "risk_level": "CRITICAL", "top_vector": "Ransomware & C2"},
            "GB": {"country": "United Kingdom", "code": "GB", "threat_count": 1890, "lat": 55.3781, "lon": -3.4360, "risk_level": "HIGH", "top_vector": "Malware & Phishing"},
            "BR": {"country": "Brazil", "code": "BR", "threat_count": 1540, "lat": -14.2350, "lon": -51.9253, "risk_level": "MEDIUM", "top_vector": "Banking Trojans"},
            "IN": {"country": "India", "code": "IN", "threat_count": 2780, "lat": 20.5937, "lon": 78.9629, "risk_level": "HIGH", "top_vector": "DDoS & Cryptojacking"},
            "NL": {"country": "Netherlands", "code": "NL", "threat_count": 1420, "lat": 52.1326, "lon": 5.2913, "risk_level": "MEDIUM", "top_vector": "Malicious Hosting"},
            "JP": {"country": "Japan", "code": "JP", "threat_count": 980, "lat": 36.2048, "lon": 138.2529, "risk_level": "MEDIUM", "top_vector": "Supply Chain"}
        }

    def add_threat_event(self, event: Dict[str, Any]):
        event["id"] = event.get("id") or f"GTIC-EVT-{len(self._threat_events) + 1:06d}"
        event["timestamp"] = event.get("timestamp") or datetime.utcnow().isoformat()
        self._threat_events.insert(0, event)
        # Keep capped log of recent 500 events
        if len(self._threat_events) > 500:
            self._threat_events.pop()

        # Update country stat
        country_code = event.get("country_code", "US")
        if country_code in self._country_stats:
            self._country_stats[country_code]["threat_count"] += 1

    def get_recent_events(self, limit: int = 50, category: Optional[str] = None) -> List[Dict[str, Any]]:
        events = self._threat_events
        if category and category.lower() != "all":
            events = [e for e in events if e.get("category", "").lower() == category.lower()]
        return events[:limit]

    def get_country_stats(self) -> List[Dict[str, Any]]:

        return list(self._country_stats.values())

    def get_stats_summary(self) -> Dict[str, Any]:
        return {
            "active_threats": 18490 + len(self._threat_events),
            "malicious_domains": 4210,
            "blacklisted_ips": 6890,
            "malware_samples": 3410,
            "phishing_urls": 2840,
            "critical_cves": 114,
            "active_campaigns": 28,
            "high_risk_countries": len([c for c in self._country_stats.values() if c["risk_level"] == "CRITICAL"]),
            "investigation_alerts": 84
        }

gtic_db_service = GTICDatabaseService()
