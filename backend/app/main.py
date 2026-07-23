from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.routers import (
    auth, cases, website_intel, domain_intel, ip_intel,
    threat_intel, ai_assistant, reports, email_forensics, file_analysis,
    malware_analysis, network_forensics, memory_forensics, mobile_forensics,
    osint, ai_investigation, pipeline, gtic
)


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="ForensiX AI – Enterprise Digital Forensics & Threat Intelligence Platform REST API"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(cases.router, prefix=settings.API_V1_STR)
app.include_router(website_intel.router, prefix=settings.API_V1_STR)
app.include_router(domain_intel.router, prefix=settings.API_V1_STR)
app.include_router(ip_intel.router, prefix=settings.API_V1_STR)
app.include_router(threat_intel.router, prefix=settings.API_V1_STR)
app.include_router(ai_assistant.router, prefix=settings.API_V1_STR)
app.include_router(reports.router, prefix=settings.API_V1_STR)
app.include_router(email_forensics.router, prefix=settings.API_V1_STR)
app.include_router(file_analysis.router, prefix=settings.API_V1_STR)
app.include_router(malware_analysis.router, prefix=settings.API_V1_STR)
app.include_router(network_forensics.router, prefix=settings.API_V1_STR)
app.include_router(memory_forensics.router, prefix=settings.API_V1_STR)
app.include_router(mobile_forensics.router, prefix=settings.API_V1_STR)
app.include_router(osint.router, prefix=settings.API_V1_STR)
app.include_router(ai_investigation.router, prefix=settings.API_V1_STR)
app.include_router(pipeline.router, prefix=settings.API_V1_STR)
app.include_router(gtic.router, prefix=settings.API_V1_STR)


@app.get("/")
async def root():
    return {
        "status": "online",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": "/docs"
    }

@app.get("/health")
async def health():
    return {"status": "healthy"}
