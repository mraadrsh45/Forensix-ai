import logging
import asyncio
import datetime
import httpx
from typing import Dict, Any, List, Optional
from app.config import settings
from app.services.gtic_db_service import gtic_db_service
from app.services.ai_service import generate_forensic_ai_response

logger = logging.getLogger(__name__)

# Existing platform case records for IOC correlation
EXISTING_PLATFORM_CASES = [
    {
        "case_id": "CASE-2401",
        "case_name": "Ransomware Incident – Finance Dept",
        "related_ips": ["185.234.219.45", "185.220.101.5"],
        "related_domains": ["phish-login-bank.com", "login-secure-bank.tk"],
        "related_malware": ["AgentTesla.exe", "WannaCry_variant.bin"],
        "related_emails": ["executive_phish@finance-portal.com"]
    },
    {
        "case_id": "CASE-2400",
        "case_name": "Phishing Campaign – Executive Spear",
        "related_ips": ["45.142.214.10", "192.168.1.105"],
        "related_domains": ["paypa1-secure.com", "verify-account-update.info"],
        "related_malware": ["Invoice_7741.pdf.js"],
        "related_emails": ["ceo-alert@executive-verify.org"]
    }
]

class GTICService:
    def __init__(self):
        self._is_polling = False
        self._seed_initial_feed()

    def _seed_initial_feed(self):
        # Initial seed threat events
        seed_events = [
            {"indicator": "185.234.219.45", "type": "ip", "category": "Command & Control", "severity": "CRITICAL", "source": "ThreatFox", "country": "Russia", "country_code": "RU", "lat": 61.5240, "lon": 105.3188, "first_seen": "2026-07-20T12:00:00Z", "last_updated": "2026-07-20T19:30:00Z"},
            {"indicator": "phish-login-bank.com", "type": "domain", "category": "Phishing", "severity": "HIGH", "source": "URLhaus", "country": "Germany", "country_code": "DE", "lat": 51.1657, "lon": 10.4515, "first_seen": "2026-07-20T13:10:00Z", "last_updated": "2026-07-20T19:32:00Z"},
            {"indicator": "CVE-2024-21626", "type": "cve", "category": "Exploitation", "severity": "CRITICAL", "source": "CISA KEV", "country": "United States", "country_code": "US", "lat": 37.0902, "lon": -95.7129, "first_seen": "2026-07-19T08:00:00Z", "last_updated": "2026-07-20T18:00:00Z"},
            {"indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "type": "hash", "category": "Ransomware", "severity": "CRITICAL", "source": "MalwareBazaar", "country": "China", "country_code": "CN", "lat": 35.8617, "lon": 104.1954, "first_seen": "2026-07-20T10:15:00Z", "last_updated": "2026-07-20T19:00:00Z"},
            {"indicator": "185.220.101.5", "type": "ip", "category": "Botnet", "severity": "HIGH", "source": "AbuseIPDB", "country": "Germany", "country_code": "DE", "lat": 51.1657, "lon": 10.4515, "first_seen": "2026-07-20T11:00:00Z", "last_updated": "2026-07-20T19:35:00Z"},
            {"indicator": "https://secure-login-verify.online/auth", "type": "url", "category": "Credential Theft", "severity": "HIGH", "source": "PhishTank", "country": "Brazil", "country_code": "BR", "lat": -14.2350, "lon": -51.9253, "first_seen": "2026-07-20T14:20:00Z", "last_updated": "2026-07-20T19:25:00Z"},
            {"indicator": "CVE-2024-1709", "type": "cve", "category": "Exploitation", "severity": "CRITICAL", "source": "NVD CVE Feed", "country": "United States", "country_code": "US", "lat": 37.0902, "lon": -95.7129, "first_seen": "2026-07-18T16:00:00Z", "last_updated": "2026-07-20T17:15:00Z"},
            {"indicator": "45.142.214.10", "type": "ip", "category": "DDoS", "severity": "MEDIUM", "source": "AlienVault OTX", "country": "Netherlands", "country_code": "NL", "lat": 52.1326, "lon": 5.2913, "first_seen": "2026-07-20T15:00:00Z", "last_updated": "2026-07-20T19:10:00Z"}
        ]
        for evt in seed_events:
            gtic_db_service.add_threat_event(evt)

    async def fetch_cisa_kev_feed(self) -> List[Dict[str, Any]]:

        """Fetch live Known Exploited Vulnerabilities from CISA KEV Feed."""
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        events = []
        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.get(url)
                if res.status_code == 200:
                    data = res.json()
                    vulns = data.get("vulnerabilities", [])[:5]
                    for v in vulns:
                        events.append({
                            "indicator": v.get("cveID"),
                            "type": "cve",
                            "category": "Exploitation",
                            "severity": "CRITICAL",
                            "source": "CISA KEV Feed",
                            "country": "United States",
                            "country_code": "US",
                            "lat": 37.0902,
                            "lon": -95.7129,
                            "description": v.get("shortDescription", ""),
                            "first_seen": v.get("dateAdded", datetime.datetime.utcnow().isoformat()),
                            "last_updated": datetime.datetime.utcnow().isoformat()
                        })
        except Exception as e:
            logger.warning(f"CISA KEV live feed fetch fallback: {e}")
        return events

    async def collect_and_normalize(self) -> List[Dict[str, Any]]:
        """Aggregates from threat feeds, normalizes, deduplicates, and updates GTIC database."""
        cisa_events = await self.fetch_cisa_kev_feed()
        for evt in cisa_events:
            gtic_db_service.add_threat_event(evt)
        return gtic_db_service.get_recent_events(limit=30)

    async def generate_ai_threat_summary(self) -> str:
        """Generates AI global threat summary describing trends, top categories, and priorities."""
        stats = gtic_db_service.get_stats_summary()
        recent = gtic_db_service.get_recent_events(limit=10)
        
        prompt = (
            f"Generate a C-Suite Global Threat Intelligence Center (GTIC) Executive Summary.\n"
            f"Active Threats: {stats['active_threats']}, Phishing URLs: {stats['phishing_urls']}, Malicious IPs: {stats['blacklisted_ips']}, Critical CVEs: {stats['critical_cves']}.\n"
            f"Recent Threat Events: {[r['indicator'] + ' (' + r['category'] + ')' for r in recent[:5]]}.\n"
            f"Provide global trend analysis, top affected threat vectors, and 3 recommended investigation priorities."
        )
        return await generate_forensic_ai_response(prompt)

    def correlate_ioc_with_cases(self, indicator: str) -> Dict[str, Any]:
        """Links GTIC threat indicators with existing investigation cases in the platform."""
        ind_clean = indicator.strip().lower()
        matched_cases = []

        for case in EXISTING_PLATFORM_CASES:
            is_match = False
            all_entities = case["related_ips"] + case["related_domains"] + case["related_malware"] + case["related_emails"]
            for entity in all_entities:
                if ind_clean in entity.lower() or entity.lower() in ind_clean:
                    is_match = True
                    break
            
            if is_match:
                matched_cases.append(case)

        return {
            "query_indicator": indicator,
            "has_correlation": len(matched_cases) > 0,
            "correlated_case_count": len(matched_cases),
            "matched_cases": matched_cases,
            "related_entities": {
                "domains": list(set([d for c in matched_cases for d in c["related_domains"]])),
                "ips": list(set([ip for c in matched_cases for ip in c["related_ips"]])),
                "malware": list(set([m for c in matched_cases for m in c["related_malware"]])),
                "emails": list(set([e for c in matched_cases for e in c["related_emails"]]))
            }
        }

gtic_service = GTICService()
