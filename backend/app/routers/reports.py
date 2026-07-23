from fastapi import APIRouter, Response, HTTPException
from pydantic import BaseModel
from typing import Dict, Any, Optional
from app.services.investigation_pipeline_service import investigation_pipeline
from app.services.pdf_report_service import pdf_report_generator

router = APIRouter(prefix="/reports", tags=["Report Generation"])

class PDFReportRequest(BaseModel):
    case_name: Optional[str] = "CASE-2401 Cyber Incident"
    target_subject: Optional[str] = "Corporate Infrastructure"

@router.post("/generate")
async def generate_report_meta(req: PDFReportRequest) -> Dict[str, Any]:
    return {
        "report_id": f"RPT-{req.case_name[:8].upper()}-9901",
        "case_name": req.case_name,
        "status": "ready",
        "download_url": "/api/v1/reports/pdf/download"
    }

@router.post("/pdf/download")
@router.get("/pdf/download")
async def download_pdf_report(case_name: str = "CASE-2401 Cyber Incident", target_subject: str = "Corporate Infrastructure"):
    """
    Executes the investigation pipeline and renders a publication-ready PDF report binary stream.
    """
    try:
        data = await investigation_pipeline.run_pipeline(
            case_name=case_name,
            target_subject=target_subject
        )
        pdf_bytes = pdf_report_generator.generate_pdf(data)
        
        filename = f"Forensic_Report_{case_name.replace(' ', '_')}.pdf"
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Generation Failed: {str(e)}")
