import logging
from typing import Dict, Any, List
from app.config import settings
from app.services.normalizer import NormalizedIndicator

logger = logging.getLogger(__name__)

class ElasticCloudSearchService:
    def __init__(self):
        self.client = None
        self.index_name = "forensix_indicators"
        self._in_memory_docs: List[Dict[str, Any]] = []
        if settings.ELASTICSEARCH_URL:
            try:
                from elasticsearch import Elasticsearch
                kw: Dict[str, Any] = {"request_timeout": 3}
                if settings.ELASTICSEARCH_API_KEY:
                    kw["api_key"] = settings.ELASTICSEARCH_API_KEY
                
                self.client = Elasticsearch(settings.ELASTICSEARCH_URL, **kw)
                if not self.client.ping():
                    self.client = None
                    logger.warning("Elastic Cloud ping failed, active fallback.")
                else:
                    logger.info("Elastic Cloud connected successfully.")
            except Exception as e:
                logger.warning(f"Elastic Cloud connection fallback mode: {e}")
                self.client = None

    def index_indicator(self, indicator: NormalizedIndicator) -> Dict[str, Any]:
        doc = indicator.dict()
        doc_id = f"{indicator.type.value}_{indicator.indicator}"
        
        # Memory store fallback
        self._in_memory_docs = [d for d in self._in_memory_docs if d.get("id") != doc_id]
        doc["id"] = doc_id
        self._in_memory_docs.append(doc)

        if not self.client:
            return {"status": "indexed_memory", "count": len(self._in_memory_docs)}

        try:
            res = self.client.index(index=self.index_name, id=doc_id, document=doc)
            return {"status": "indexed_elastic_cloud", "result": res.get("result")}
        except Exception as e:
            logger.error(f"Elastic Cloud indexing error: {e}")
            return {"status": "indexed_memory_fallback", "error": str(e)}

    def search_indicators(self, query: str, type_filter: str = None, limit: int = 20) -> List[Dict[str, Any]]:
        if self.client:
            try:
                must_clause = []
                if query and query.strip() != "*":
                    must_clause.append({"multi_match": {"query": query, "fields": ["indicator^3", "threat_category", "reputation", "tags", "metadata.*"]}})
                else:
                    must_clause.append({"match_all": {}})

                if type_filter:
                    must_clause.append({"term": {"type.keyword": type_filter.lower()}})

                es_query = {"query": {"bool": {"must": must_clause}}, "size": limit}
                res = self.client.search(index=self.index_name, body=es_query)
                hits = res.get("hits", {}).get("hits", [])
                return [h["_source"] for h in hits]
            except Exception as e:
                logger.error(f"Elastic Cloud search error: {e}")

        # Memory fallback search
        results = []
        q_lower = query.lower() if query else "*"
        for doc in self._in_memory_docs:
            if type_filter and doc.get("type") != type_filter.lower():
                continue
            if q_lower == "*" or q_lower in doc.get("indicator", "").lower() or q_lower in doc.get("threat_category", "").lower():
                results.append(doc)
            if len(results) >= limit:
                break
        return results

search_service = ElasticCloudSearchService()
