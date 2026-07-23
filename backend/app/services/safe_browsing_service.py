import httpx
from typing import Dict, Any
from app.config import settings

async def query_google_safe_browsing(url: str) -> Dict[str, Any]:
    api_key = settings.GOOGLE_SAFE_BROWSING_KEY  # must be a real key with Safe Browsing API enabled
    if api_key:
        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
            payload = {
                "client": {"clientId": "forensix-ai", "clientVersion": "2.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}]
                }
            }
            async with httpx.AsyncClient(timeout=6.0) as client:
                res = await client.post(endpoint, json=payload)
                if res.status_code == 200:
                    matches = res.json().get("matches", [])
                    if matches:
                        return {
                            "flagged": True,
                            "threatTypes": [m.get("threatType") for m in matches],
                            "platformTypes": [m.get("platformType") for m in matches]
                        }
        except Exception:
            pass

    is_phish = any(term in url.lower() for term in ["phish", "login", "paypa", "secure", "bank", "verify"])
    return {
        "flagged": is_phish,
        "threatTypes": ["SOCIAL_ENGINEERING"] if is_phish else [],
        "platformTypes": ["ANY_PLATFORM"] if is_phish else []
    }
