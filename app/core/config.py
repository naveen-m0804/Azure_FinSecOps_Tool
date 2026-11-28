import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    app_name: str = "Azure Cloud Governance & FinOps Platform"
    app_version: str = "2.0.0"
    app_env: str = os.getenv("APP_ENV", "production")
    app_host: str = os.getenv("APP_HOST", "127.0.0.1")
    app_port: int = int(os.getenv("APP_PORT", "8000"))
    frontend_url: str = os.getenv("FRONTEND_URL", "http://localhost:8000")
    
    job_ttl_minutes: int = int(os.getenv("JOB_TTL_MINUTES", "60"))
    report_ttl_minutes: int = int(os.getenv("REPORT_TTL_MINUTES", "30"))
    
    max_concurrent_subscriptions: int = int(os.getenv("MAX_CONCURRENT_SUBSCRIPTIONS", "5"))
    max_concurrent_assessments: int = int(os.getenv("MAX_CONCURRENT_ASSESSMENTS", "8"))
    
    azure_request_timeout_seconds: int = int(os.getenv("AZURE_REQUEST_TIMEOUT_SECONDS", "60"))
    azure_max_retries: int = int(os.getenv("AZURE_MAX_RETRIES", "4"))
    
    # --------------------------------------------------------------------------
    # Google Cloud Vertex AI Agentic Engine
    # --------------------------------------------------------------------------
    vertex_ai_api_key: str = os.getenv("VERTEX_AI_API_KEY", "")
    vertex_ai_model: str = os.getenv("VERTEX_AI_MODEL", "gemini-2.5-flash")
    vertex_ai_project: str = os.getenv("VERTEX_AI_PROJECT", "")
    vertex_ai_location: str = os.getenv("VERTEX_AI_LOCATION", "global")

    # Engine Execution Constraints
    ai_max_tokens: int = int(os.getenv("AI_MAX_TOKENS", "4096"))
    ai_max_tool_calls: int = int(os.getenv("AI_MAX_TOOL_CALLS", "10"))
    ai_max_concurrent_requests: int = int(os.getenv("AI_MAX_CONCURRENT_REQUESTS", "5"))
    ai_request_timeout_seconds: int = int(os.getenv("AI_REQUEST_TIMEOUT_SECONDS", "60"))
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
