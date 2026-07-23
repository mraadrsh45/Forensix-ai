from fastapi import APIRouter
from pydantic import BaseModel
from app.services.ai_service import generate_forensic_ai_response

router = APIRouter(prefix="/ai-assistant", tags=["AI Assistant"])

class AIAskRequest(BaseModel):
    prompt: str

@router.post("/ask")
async def ask_ai(req: AIAskRequest):
    answer = await generate_forensic_ai_response(req.prompt)
    return {"prompt": req.prompt, "response": answer}
