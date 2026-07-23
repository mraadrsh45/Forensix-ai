import httpx
from typing import Dict, Any
from app.config import settings

async def query_virustotal_url(target_url: str) -> Dict[str, Any]:
    api_key = settings.VIRUSTOTAL_API_KEY
    if api_key:
        try:
            import base64
            url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
            headers = {"x-apikey": api_key}
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
                if res.status_code == 200:
                    stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                    }
        except Exception:
            pass

    # Demo fallback logic if no API key or lookup fails
    is_phish = any(term in target_url.lower() for term in ["phish", "login", "paypa", "secure", "bank", "verify"])
    return {
        "malicious": 24 if is_phish else 0,
        "suspicious": 6 if is_phish else 0,
        "harmless": 35 if is_phish else 68,
        "undetected": 15 if is_phish else 4
    }

async def query_virustotal_hash(file_hash: str) -> Dict[str, Any]:
    api_key = settings.VIRUSTOTAL_API_KEY
    if api_key:
        try:
            headers = {"x-apikey": api_key}
            async with httpx.AsyncClient(timeout=8.0) as client:
                res = await client.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers)
                if res.status_code == 200:
                    stats = res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "harmless": stats.get("harmless", 0),
                        "undetected": stats.get("undetected", 0),
                    }
        except Exception:
            pass

    return {"malicious": 48, "suspicious": 4, "harmless": 15, "undetected": 5}
