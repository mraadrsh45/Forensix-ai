import httpx
import logging
from typing import Dict, Any
from app.config import settings

logger = logging.getLogger(__name__)

async def query_viewdns(domain: str) -> Dict[str, Any]:
    api_key = settings.VIEWDNS_API_KEY
    subdomain_count = 0
    host_provider = "Unknown"
    
    # Clean domain name
    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    if api_key:
        # 1. Query ViewDNS Subdomain Discovery API
        try:
            url_subs = f"https://api.viewdns.info/subdomains/?domain={clean_domain}&apikey={api_key}&output=json"
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(url_subs)
                if res.status_code == 200:
                    data = res.json()
                    subdomains = data.get("response", {}).get("subdomains", [])
                    if isinstance(subdomains, list):
                        subdomain_count = len(subdomains)
        except Exception as e:
            logger.warning(f"Error querying ViewDNS subdomains: {e}")

        # 2. Query ViewDNS IP History API to resolve host provider (owner field)
        try:
            url_hist = f"https://api.viewdns.info/iphistory/?domain={clean_domain}&apikey={api_key}&output=json"
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(url_hist)
                if res.status_code == 200:
                    data = res.json()
                    records = data.get("response", {}).get("records", [])
                    if isinstance(records, list) and len(records) > 0:
                        host_provider = records[0].get("owner", "Unknown")
        except Exception as e:
            logger.warning(f"Error querying ViewDNS iphistory: {e}")

        return {
            "alexa_rank": None,
            "subdomain_count": subdomain_count,
            "host_provider": host_provider
        }

    # Mock Fallback Behavior when API key is missing
    is_phish = any(term in clean_domain.lower() for term in ["phish", "login", "paypa", "secure"])
    return {
        "alexa_rank": None if is_phish else 1420,
        "subdomain_count": 4 if is_phish else 48,
        "host_provider": "Offshore Bulletproof Hosting" if is_phish else "Cloudflare, Inc."
    }
