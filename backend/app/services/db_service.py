import json
import logging
from datetime import datetime
from typing import List, Optional, Dict, Any
from sqlalchemy import create_engine, Column, String, Float, DateTime, Text, Integer, JSON
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings
from app.services.normalizer import NormalizedIndicator

logger = logging.getLogger(__name__)

Base = declarative_base()

class IndicatorModel(Base):
    __tablename__ = "indicators"

    id = Column(String, primary_key=True)
    indicator = Column(String, index=True, nullable=False)
    type = Column(String, index=True, nullable=False)
    risk_score = Column(Float, default=0.0)
    threat_category = Column(String, default="Uncategorized")
    reputation = Column(String, default="unknown")
    sources = Column(JSON, default=list)
    tags = Column(JSON, default=list)
    metadata_json = Column(JSON, default=dict)
    relationships_json = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)

class PostgresService:
    def __init__(self):
        self.engine = None
        self.SessionLocal = None
        self._in_memory_store: Dict[str, Dict[str, Any]] = {}
        try:
            self.engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)
            Base.metadata.create_all(bind=self.engine)
            self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
            logger.info("PostgreSQL database initialized successfully.")
        except Exception as e:
            logger.warning(f"PostgreSQL connection fallback mode: {e}")

    def save_indicator(self, indicator: NormalizedIndicator) -> Dict[str, Any]:
        indicator_dict = indicator.dict()
        ind_id = f"{indicator.type.value}:{indicator.indicator}"
        indicator_dict["id"] = ind_id

        if self.SessionLocal:
            db = self.SessionLocal()
            try:
                existing = db.query(IndicatorModel).filter(IndicatorModel.id == ind_id).first()
                if existing:
                    existing.risk_score = indicator.risk_score
                    existing.reputation = indicator.reputation
                    existing.metadata_json = indicator.metadata
                    existing.relationships_json = [r.dict() for r in indicator.relationships]
                    existing.sources = list(set(existing.sources + indicator.sources))
                else:
                    db_obj = IndicatorModel(
                        id=ind_id,
                        indicator=indicator.indicator,
                        type=indicator.type.value,
                        risk_score=indicator.risk_score,
                        threat_category=indicator.threat_category,
                        reputation=indicator.reputation,
                        sources=indicator.sources,
                        tags=indicator.tags,
                        metadata_json=indicator.metadata,
                        relationships_json=[r.dict() for r in indicator.relationships]
                    )
                    db.add(db_obj)
                db.commit()
                return indicator_dict
            except Exception as e:
                db.rollback()
                logger.error(f"Postgres insert failed, falling back to memory: {e}")
            finally:
                db.close()

        self._in_memory_store[ind_id] = indicator_dict
        return indicator_dict

    def get_indicator(self, indicator_val: str) -> Optional[Dict[str, Any]]:
        if self.SessionLocal:
            db = self.SessionLocal()
            try:
                match = db.query(IndicatorModel).filter(IndicatorModel.indicator == indicator_val).first()
                if match:
                    return {
                        "id": match.id,
                        "indicator": match.indicator,
                        "type": match.type,
                        "risk_score": match.risk_score,
                        "threat_category": match.threat_category,
                        "reputation": match.reputation,
                        "sources": match.sources,
                        "tags": match.tags,
                        "metadata": match.metadata_json,
                        "relationships": match.relationships_json,
                        "created_at": match.created_at.isoformat() if match.created_at else ""
                    }
            except Exception as e:
                logger.error(f"Postgres query error: {e}")
            finally:
                db.close()

        for item in self._in_memory_store.values():
            if item["indicator"] == indicator_val:
                return item
        return None

postgres_service = PostgresService()
