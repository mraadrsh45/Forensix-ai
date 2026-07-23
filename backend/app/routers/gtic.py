import asyncio
import logging
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, HTTPException
from app.services.gtic_service import gtic_service
from app.services.gtic_db_service import gtic_db_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/gtic", tags=["Global Threat Intelligence Center"])

@router.get("/stats")
async def get_gtic_stats() -> Dict[str, Any]:
    """Returns live GTIC dashboard statistics."""
    return gtic_db_service.get_stats_summary()

@router.get("/map")
async def get_threat_map_data() -> Dict[str, Any]:
    """Returns country-wise threat hotspots and map marker data."""
    return {
        "hotspots": gtic_db_service.get_country_stats(),
        "recent_threat_markers": gtic_db_service.get_recent_events(limit=20)
    }

@router.get("/feed")
async def get_threat_feed(
    category: Optional[str] = Query(None, description="Category filter (Phishing, Ransomware, Botnet, C2, etc.)"),
    limit: int = Query(30, ge=1, le=100)
) -> Dict[str, Any]:
    """Returns live real-time threat feed events."""
    events = gtic_db_service.get_recent_events(limit=limit, category=category)
    return {
        "count": len(events),
        "category_filter": category or "All",
        "events": events
    }

@router.get("/categories")
async def get_threat_categories() -> Dict[str, Any]:
    """Returns categorized threat distribution metrics."""
    return {
        "categories": [
            {"name": "Phishing", "count": 2840, "color": "#eab308"},
            {"name": "Malware", "count": 3410, "color": "#ef4444"},
            {"name": "Ransomware", "count": 1920, "color": "#dc2626"},
            {"name": "Botnet", "count": 2150, "color": "#f97316"},
            {"name": "DDoS", "count": 1280, "color": "#8b5cf6"},
            {"name": "Credential Theft", "count": 1740, "color": "#06b6d4"},
            {"name": "Command & Control", "count": 1590, "color": "#ec4899"},
            {"name": "Supply Chain", "count": 620, "color": "#3b82f6"},
            {"name": "Exploitation", "count": 1140, "color": "#10b981"},
            {"name": "Cryptojacking", "count": 890, "color": "#6366f1"}
        ]
    }

@router.get("/timeline")
async def get_threat_timeline(limit: int = Query(20, ge=1, le=50)) -> List[Dict[str, Any]]:
    """Returns chronological history of threat events."""
    return gtic_db_service.get_recent_events(limit=limit)

@router.get("/ai-summary")
async def get_ai_threat_summary() -> Dict[str, Any]:
    """Generates automated AI global threat summary & priority recommendations."""
    summary_text = await gtic_service.generate_ai_threat_summary()
    return {
        "timestamp": gtic_db_service.get_stats_summary(),
        "ai_summary": summary_text
    }

@router.get("/search")
async def search_gtic_threats(
    q: str = Query(..., description="Domain, URL, IP, Hash, CVE, Country, or ASN"),
    type: Optional[str] = Query(None)
) -> Dict[str, Any]:
    """Searches GTIC threat database across indicators."""
    all_events = gtic_db_service.get_recent_events(limit=200)
    q_clean = q.strip().lower()
    
    matches = [
        e for e in all_events
        if q_clean in e.get("indicator", "").lower()
        or q_clean in e.get("category", "").lower()
        or q_clean in e.get("country", "").lower()
        or q_clean in e.get("source", "").lower()
    ]
    
    return {
        "query": q,
        "total_matches": len(matches),
        "results": matches
    }

@router.get("/ioc-correlation")
async def correlate_ioc(indicator: str = Query(..., description="IOC indicator to correlate with platform cases")):
    """Correlates GTIC threat indicator with existing investigation cases in the platform."""
    return gtic_service.correlate_ioc_with_cases(indicator)

@router.websocket("/ws")
async def websocket_threat_stream(websocket: WebSocket):
    """Real-time WebSocket endpoint broadcasting live threat updates."""
    await websocket.accept()
    try:
        while True:
            # Periodically collect & stream live events
            events = await gtic_service.collect_and_normalize()
            stats = gtic_db_service.get_stats_summary()
            
            await websocket.send_json({
                "type": "GTIC_LIVE_UPDATE",
                "stats": stats,
                "latest_event": events[0] if events else None
            })
            await asyncio.sleep(5)
    except WebSocketDisconnect:
        logger.info("GTIC WebSocket client disconnected")
    except Exception as e:
        logger.error(f"GTIC WebSocket error: {e}")
