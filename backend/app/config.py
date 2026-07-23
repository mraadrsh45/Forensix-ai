import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "ForensiX AI Backend API"
    VERSION: str = "2.0.0"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "forensix-ai-super-secret-key-change-in-production-32bytes")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24

    # External Threat & Intelligence API Keys
    VIRUSTOTAL_API_KEY: str = os.getenv("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")
    URLSCAN_API_KEY: str = os.getenv("URLSCAN_API_KEY", "")
    SHODAN_API_KEY: str = os.getenv("SHODAN_API_KEY", "")
    VIEWDNS_API_KEY: str = os.getenv("VIEWDNS_API_KEY", "")
    WHOISXML_API_KEY: str = os.getenv("WHOISXML_API_KEY", "")
    GOOGLE_SAFE_BROWSING_KEY: str = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")

    # Cloud Managed Database & Infrastructure Configuration (Vercel, Railway, Render)
    # 1. PostgreSQL -> NeonDB
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        ""
    )

    # 2. Redis -> Upstash Redis (rediss://... or REST API)
    UPSTASH_REDIS_REST_URL: str = os.getenv("UPSTASH_REDIS_REST_URL", "")
    UPSTASH_REDIS_REST_TOKEN: str = os.getenv("UPSTASH_REDIS_REST_TOKEN", "")
    REDIS_URL: str = os.getenv("REDIS_URL", "")

    # 3. Neo4j -> Neo4j AuraDB (neo4j+s://...)
    NEO4J_URI: str = os.getenv("NEO4J_URI", "")
    NEO4J_USER: str = os.getenv("NEO4J_USER", "")
    NEO4J_PASSWORD: str = os.getenv("NEO4J_PASSWORD", "")

    # 4. Elasticsearch -> Elastic Cloud (https://...)
    ELASTICSEARCH_URL: str = os.getenv("ELASTICSEARCH_URL", "")
    ELASTICSEARCH_API_KEY: str = os.getenv("ELASTICSEARCH_API_KEY", "")

    # 5. File Storage -> Cloudflare R2 / AWS S3
    S3_ENDPOINT: str = os.getenv("S3_ENDPOINT", "")
    S3_ACCESS_KEY_ID: str = os.getenv("S3_ACCESS_KEY_ID", "")
    S3_SECRET_ACCESS_KEY: str = os.getenv("S3_SECRET_ACCESS_KEY", "")
    S3_BUCKET_NAME: str = os.getenv("S3_BUCKET_NAME", "forensix-evidence-bucket")

    # 6. Supabase Authentication & Database
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", os.getenv("NEXT_PUBLIC_SUPABASE_URL", ""))
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", os.getenv("NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY", ""))


    class Config:
        case_sensitive = True

settings = Settings()
