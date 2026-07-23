import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

class IndicatorType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    EMAIL = "email"
    ASN = "asn"

class NormalizedRelationship(BaseModel):
    source: str
    target: str
    relation_type: str  # RESOLVES_TO, HOSTED_BY, DROPPED_BY, BELONGS_TO, ASSOCIATED_WITH

class NormalizedIndicator(BaseModel):
    id: Optional[str] = None
    indicator: str
    type: IndicatorType
    risk_score: float = Field(default=0.0, ge=0.0, le=100.0)
    threat_category: str = "Uncategorized"
    reputation: str = "unknown"  # clean, suspicious, malicious, unknown
    sources: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    relationships: List[NormalizedRelationship] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.datetime.utcnow().isoformat())

class DataNormalizer:
    @staticmethod
    def normalize_ip(raw_data: Dict[str, Any], source: str = "generic") -> NormalizedIndicator:
        indicator_val = raw_data.get("ip") or raw_data.get("ipAddress") or raw_data.get("query") or "0.0.0.0"
        score = float(raw_data.get("abuseConfidenceScore") or raw_data.get("score") or 0.0)
        
        rep = "clean"
        if score >= 70:
            rep = "malicious"
        elif score >= 30:
            rep = "suspicious"

        tags = raw_data.get("tags") or []
        country = raw_data.get("countryCode") or raw_data.get("country") or "Unknown"
        isp = raw_data.get("isp") or raw_data.get("owner") or "Unknown"
        asn = str(raw_data.get("asn") or "Unknown")

        rel = []
        if asn != "Unknown":
            rel.append(NormalizedRelationship(source=indicator_val, target=f"AS{asn}", relation_type="BELONGS_TO"))

        return NormalizedIndicator(
            indicator=indicator_val,
            type=IndicatorType.IP,
            risk_score=score,
            threat_category=raw_data.get("usageType") or "Network Indicator",
            reputation=rep,
            sources=[source],
            tags=tags,
            metadata={
                "country": country,
                "isp": isp,
                "asn": asn,
                "total_reports": raw_data.get("totalReports", 0),
                "last_reported": raw_data.get("lastReportedAt", "")
            },
            relationships=rel
        )

    @staticmethod
    def normalize_domain(raw_data: Dict[str, Any], source: str = "generic") -> NormalizedIndicator:
        indicator_val = raw_data.get("domain") or raw_data.get("name") or "unknown.com"
        score = float(raw_data.get("risk_score") or raw_data.get("score") or 0.0)
        
        rep = "clean"
        if score >= 60:
            rep = "malicious"
        elif score >= 20:
            rep = "suspicious"

        ip_resolutions = raw_data.get("ip_resolutions") or raw_data.get("a_records") or []
        rel = []
        for ip in ip_resolutions:
            if isinstance(ip, str):
                rel.append(NormalizedRelationship(source=indicator_val, target=ip, relation_type="RESOLVES_TO"))

        return NormalizedIndicator(
            indicator=indicator_val,
            type=IndicatorType.DOMAIN,
            risk_score=score,
            threat_category="Domain Intelligence",
            reputation=rep,
            sources=[source],
            tags=raw_data.get("categories") or [],
            metadata={
                "registrar": raw_data.get("registrar", "Unknown"),
                "creation_date": raw_data.get("creation_date", ""),
                "dns_records": raw_data.get("dns_records", {})
            },
            relationships=rel
        )

    @staticmethod
    def normalize_file_hash(raw_data: Dict[str, Any], source: str = "generic") -> NormalizedIndicator:
        indicator_val = raw_data.get("sha256") or raw_data.get("md5") or raw_data.get("hash") or "unknown_hash"
        score = float(raw_data.get("positives") or raw_data.get("detection_rate") or 0.0)
        
        rep = "clean"
        if score > 10:
            rep = "malicious"
        elif score > 0:
            rep = "suspicious"

        rel = []
        c2_ips = raw_data.get("c2_ips") or []
        for ip in c2_ips:
            rel.append(NormalizedRelationship(source=indicator_val, target=ip, relation_type="CONNECTS_TO"))

        return NormalizedIndicator(
            indicator=indicator_val,
            type=IndicatorType.HASH,
            risk_score=min(score * 10, 100.0),
            threat_category=raw_data.get("meaningful_name") or "File Artifact",
            reputation=rep,
            sources=[source],
            tags=raw_data.get("tags") or [],
            metadata={
                "file_type": raw_data.get("file_type", "Unknown"),
                "file_size": raw_data.get("file_size", 0),
                "threat_name": raw_data.get("threat_name", "Clean/Unidentified")
            },
            relationships=rel
        )

    @staticmethod
    def normalize_generic(raw_data: Dict[str, Any], indicator_type: str, source: str) -> NormalizedIndicator:
        indicator_val = str(raw_data.get("query") or raw_data.get("indicator") or raw_data.get("target") or "unknown")
        itype = IndicatorType.IP
        try:
            itype = IndicatorType(indicator_type.lower())
        except ValueError:
            pass

        return NormalizedIndicator(
            indicator=indicator_val,
            type=itype,
            risk_score=float(raw_data.get("score", 0.0)),
            threat_category=str(raw_data.get("category", "General Intelligence")),
            reputation=str(raw_data.get("reputation", "unknown")),
            sources=[source],
            tags=raw_data.get("tags", []),
            metadata=raw_data.get("raw_attributes", raw_data),
            relationships=[]
        )
