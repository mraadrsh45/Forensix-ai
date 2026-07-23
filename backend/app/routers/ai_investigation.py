import uuid
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from app.services.investigation_pipeline_service import investigation_pipeline

router = APIRouter(prefix="/ai-investigation", tags=["AI Investigation Pipeline"])

investigation_db: Dict[str, Any] = {}

class InvestigationRequest(BaseModel):
    case_name: str
    target_subject: str
    evidence_modules: Optional[List[str]] = None

@router.post("/execute")
async def run_ai_investigation_pipeline(req: InvestigationRequest) -> Dict[str, Any]:
    analysis_id = f"INV-CASE-{uuid.uuid4().hex[:8].upper()}"
    report = await investigation_pipeline.run_pipeline(
        case_name=req.case_name,
        target_subject=req.target_subject
    )
    report["analysis_id"] = analysis_id
    investigation_db[analysis_id] = report
    return report

@router.get("/history")
async def get_investigation_history():
    return list(investigation_db.values())

