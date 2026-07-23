import logging
from typing import Dict, Any, List
from app.config import settings
from app.services.normalizer import NormalizedIndicator

logger = logging.getLogger(__name__)

class Neo4jAuraService:
    def __init__(self):
        self.driver = None
        self._in_memory_nodes: Dict[str, Dict[str, Any]] = {}
        self._in_memory_edges: List[Dict[str, Any]] = []
        if settings.NEO4J_URI:
            try:
                from neo4j import GraphDatabase
                self.driver = GraphDatabase.driver(
                    settings.NEO4J_URI,
                    auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD)
                )
                logger.info("Neo4j AuraDB cloud graph connection established.")
            except Exception as e:
                logger.warning(f"Neo4j AuraDB cloud fallback mode active: {e}")
                self.driver = None

    def ingest_indicator(self, indicator: NormalizedIndicator) -> Dict[str, Any]:
        node_label = indicator.type.value.upper()
        ind_val = indicator.indicator
        
        # Save to memory fallback
        self._in_memory_nodes[ind_val] = {
            "id": ind_val,
            "label": node_label,
            "risk_score": indicator.risk_score,
            "reputation": indicator.reputation,
            "category": indicator.threat_category
        }

        for rel in indicator.relationships:
            self._in_memory_edges.append({
                "source": rel.source,
                "target": rel.target,
                "type": rel.relation_type
            })

        if not self.driver:
            return {"status": "ingested_memory", "nodes": len(self._in_memory_nodes), "edges": len(self._in_memory_edges)}

        query = f"""
        MERGE (n:{node_label} {{name: $name}})
        SET n.risk_score = $risk_score,
            n.reputation = $reputation,
            n.threat_category = $category,
            n.updated_at = datetime()
        """
        try:
            with self.driver.session() as session:
                session.run(
                    query,
                    name=ind_val,
                    risk_score=indicator.risk_score,
                    reputation=indicator.reputation,
                    category=indicator.threat_category
                )

                for rel in indicator.relationships:
                    rel_query = f"""
                    MERGE (a {{name: $source}})
                    MERGE (b {{name: $target}})
                    MERGE (a)-[r:{rel.relation_type}]->(b)
                    """
                    session.run(rel_query, source=rel.source, target=rel.target)

            return {"status": "ingested_neo4j_auradb", "indicator": ind_val}
        except Exception as e:
            logger.error(f"Neo4j AuraDB ingestion error: {e}")
            return {"status": "ingested_memory_fallback", "error": str(e)}

    def get_topology(self) -> Dict[str, Any]:
        if self.driver:
            try:
                with self.driver.session() as session:
                    res_nodes = session.run("MATCH (n) RETURN n.name as name, labels(n)[0] as label, n.risk_score as score LIMIT 50")
                    nodes = [{"id": r["name"], "label": r["label"], "score": r["score"]} for r in res_nodes]
                    
                    res_edges = session.run("MATCH (a)-[r]->(b) RETURN a.name as source, b.name as target, type(r) as type LIMIT 100")
                    edges = [{"source": r["source"], "target": r["target"], "type": r["type"]} for r in res_edges]
                    
                    return {"nodes": nodes, "edges": edges}
            except Exception as e:
                logger.error(f"Neo4j topology query failed: {e}")

        # Return memory fallback topology
        nodes = [{"id": k, "label": v["label"], "score": v["risk_score"]} for k, v in self._in_memory_nodes.items()]
        return {"nodes": nodes, "edges": self._in_memory_edges}

neo4j_service = Neo4jAuraService()
