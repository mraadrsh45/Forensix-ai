from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

router = APIRouter(prefix="/cases", tags=["Case Management"])

class CaseCreate(BaseModel):
    title: str
    type: str = "General"
    priority: str = "High"
    investigator: str = "Admin User"

class Case(BaseModel):
    id: str
    title: str
    status: str
    priority: str
    type: str
    investigator: str
    created: str
    evidence_count: int

# In-memory case database store
cases_db = [
    { "id": "CASE-2401", "title": "Ransomware Incident – Finance Department", "status": "Active", "priority": "Critical", "type": "Malware", "investigator": "Alice Chen", "created": "2025-07-19", "evidence_count": 14 },
    { "id": "CASE-2400", "title": "Phishing Campaign – Executive Spear Attack", "status": "Active", "priority": "High", "type": "Email", "investigator": "Bob Smith", "created": "2025-07-18", "evidence_count": 8 },
    { "id": "CASE-2399", "title": "Suspicious Network Traffic – DMZ Zone", "status": "Review", "priority": "Medium", "type": "Network", "investigator": "Carol Davis", "created": "2025-07-17", "evidence_count": 22 },
    { "id": "CASE-2398", "title": "Data Exfiltration Attempt via USB", "status": "Closed", "priority": "High", "type": "Insider", "investigator": "David Lee", "created": "2025-07-15", "evidence_count": 35 },
]

@router.get("", response_model=List[Case])
async def get_cases():
    return cases_db

@router.post("", response_model=Case)
async def create_case(case_in: CaseCreate):
    new_id = f"CASE-{2400 + len(cases_db) + 2}"
    new_case = {
        "id": new_id,
        "title": case_in.title,
        "status": "Active",
        "priority": case_in.priority,
        "type": case_in.type,
        "investigator": case_in.investigator,
        "created": datetime.utcnow().strftime("%Y-%m-%d"),
        "evidence_count": 0
    }
    cases_db.insert(0, new_case)
    return new_case

@router.get("/{case_id}", response_model=Case)
async def get_case(case_id: str):
    for c in cases_db:
        if c["id"] == case_id:
            return c
    raise HTTPException(status_code=404, detail="Case not found")
