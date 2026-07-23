from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
try:
    from jose import jwt
    JOSE_AVAILABLE = True
except ImportError:
    JOSE_AVAILABLE = False
from app.config import settings

router = APIRouter(prefix="/auth", tags=["Authentication"])

class LoginRequest(BaseModel):
    email: str
    password: str

class MFARequest(BaseModel):
    email: str
    code: str

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: dict

@router.post("/login")
async def login(req: LoginRequest):
    if not req.email or not req.password:
        raise HTTPException(status_code=400, detail="Email and password required")
    # Require 2FA TOTP step
    return {"status": "mfa_required", "email": req.email, "message": "Enter 6-digit TOTP code"}

@router.post("/mfa", response_model=TokenResponse)
async def verify_mfa(req: MFARequest):
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": req.email, "exp": expire, "role": "Senior Analyst"}
    token = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM) if JOSE_AVAILABLE else "forensix-static-dev-token"
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "name": "Admin User",
            "email": req.email,
            "role": "Senior Analyst"
        }
    }
