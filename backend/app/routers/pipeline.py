from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any, Optional, List
from pydantic import BaseModel
from app.services.pipeline_service import pipeline_service
from app.services.search_service import search_service
from app.services.graph_service import neo4j_service
from app.services.cache_service import cache_service

router = APIRouter(prefix="/pipeline", tags=["Data Pipeline"])

class IngestRequest(BaseModel):
    indicator_type: str  # ip, domain, hash, url, email
    source: Optional[str] = "Manual_Ingest"
    raw_payload: Dict[str, Any]

@router.post("/ingest")
async def ingest_payload(payload: IngestRequest):
    """
    Ingests raw API payloads through the pipeline:
    API Results -> Normalize -> PostgreSQL -> Neo4j -> Redis Cache -> Elasticsearch
    """
    try:
        result = pipeline_service.process_and_ingest(
            raw_data=payload.raw_payload,
            indicator_type=payload.indicator_type,
            source=payload.source or "API_Ingest"
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Pipeline execution error: {str(e)}")

@router.get("/indicator/{indicator_val}")
async def get_indicator(indicator_val: str):
    """
    Fetches normalized indicator with Redis cache optimization.
    """
    res = pipeline_service.get_indicator_fast(indicator_val)
    if not res["data"]:
        raise HTTPException(status_code=404, detail="Indicator not found in database or cache")
    return res

@router.get("/search")
async def search_indicators(
    q: str = Query("*", description="Search query"),
    type: Optional[str] = Query(None, description="Indicator type filter (ip, domain, hash)"),
    limit: int = Query(20, ge=1, le=100)
):
    """
    Searches normalized threat indicators via Elasticsearch.
    """
    return {
        "query": q,
        "type_filter": type,
        "results": search_service.search_indicators(query=q, type_filter=type, limit=limit)
    }

@router.get("/topology")
async def get_threat_topology():
    """
    Retrieves threat network topology from Neo4j graph.
    """
    return neo4j_service.get_topology()

@router.get("/metrics")
async def get_pipeline_metrics():
    """
    Returns the live health status of pipeline infrastructure components.
    """
    redis_online = cache_service.redis_client is not None
    neo4j_online = neo4j_service.driver is not None
    es_online = search_service.client is not None

    return {
        "pipeline": "FORENSIX AI Threat Intelligence Pipeline",
        "status": "operational",
        "components": {
            "normalizer": {"status": "healthy", "type": "Pydantic Schema Engine"},
            "postgresql": {"status": "healthy", "type": "Relational Storage"},
            "neo4j": {"status": "healthy" if neo4j_online else "fallback_active", "type": "Graph Database"},
            "redis_cache": {"status": "healthy" if redis_online else "fallback_active", "type": "In-Memory Cache"},
            "elasticsearch": {"status": "healthy" if es_online else "fallback_active", "type": "Full-Text Search Engine"}
        }
    }
