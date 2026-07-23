import logging
from typing import Dict, Any, Optional
from app.services.normalizer import DataNormalizer, NormalizedIndicator
from app.services.db_service import postgres_service
from app.services.graph_service import neo4j_service
from app.services.cache_service import cache_service
from app.services.search_service import search_service

logger = logging.getLogger(__name__)

class PipelineOrchestrator:
    @staticmethod
    def process_and_ingest(raw_data: Dict[str, Any], indicator_type: str, source: str = "API_Ingest") -> Dict[str, Any]:
        """
        Full Data Pipeline Execution:
        API Results -> Normalize -> PostgreSQL -> Neo4j -> Redis Cache -> Elasticsearch
        """
        # 1. Normalize API Results
        normalized: NormalizedIndicator
        itype = indicator_type.lower()
        if itype == "ip":
            normalized = DataNormalizer.normalize_ip(raw_data, source=source)
        elif itype == "domain":
            normalized = DataNormalizer.normalize_domain(raw_data, source=source)
        elif itype == "hash":
            normalized = DataNormalizer.normalize_file_hash(raw_data, source=source)
        else:
            normalized = DataNormalizer.normalize_generic(raw_data, indicator_type=indicator_type, source=source)

        # 2. Persist to PostgreSQL
        pg_result = postgres_service.save_indicator(normalized)

        # 3. Ingest into Neo4j Graph
        graph_result = neo4j_service.ingest_indicator(normalized)

        # 4. Cache in Redis
        cache_key = f"indicator:{normalized.indicator}"
        cache_service.set(cache_key, normalized.dict(), ttl=3600)

        # 5. Index in Elasticsearch
        es_result = search_service.index_indicator(normalized)

        logger.info(f"Pipeline executed for [{normalized.type.value}:{normalized.indicator}]")

        return {
            "indicator": normalized.indicator,
            "type": normalized.type.value,
            "normalized_data": normalized.dict(),
            "pipeline_status": {
                "normalization": "success",
                "postgresql": "saved",
                "neo4j": graph_result.get("status"),
                "redis_cache": "cached",
                "elasticsearch": es_result.get("status")
            }
        }

    @staticmethod
    def get_indicator_fast(indicator_val: str) -> Dict[str, Any]:
        """
        Fast lookup with Redis cache first, falling back to PostgreSQL.
        """
        cache_key = f"indicator:{indicator_val}"
        cached = cache_service.get(cache_key)
        if cached:
            return {"source": "redis_cache", "data": cached}

        db_result = postgres_service.get_indicator(indicator_val)
        if db_result:
            cache_service.set(cache_key, db_result, ttl=3600)
            return {"source": "postgresql", "data": db_result}

        return {"source": "none", "data": None}

pipeline_service = PipelineOrchestrator()
