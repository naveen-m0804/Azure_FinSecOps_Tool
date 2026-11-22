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
    # Genuine Dynamic Agentic AI Engine (Universal Multi-Provider Support)
    # Supported AI_PROVIDER values: groq | openai | gemini | claude | azure_openai
    # --------------------------------------------------------------------------
    ai_provider: str = os.getenv("AI_PROVIDER", "groq")

    # Groq Cloud Configuration
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    groq_model: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    groq_base_url: str = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")

    # OpenAI (ChatGPT) Configuration
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

    # Google Gemini Configuration (Official OpenAI-compatible endpoint)
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "")
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-1.5-pro")
    gemini_base_url: str = os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai")

    # Anthropic Claude Configuration
    anthropic_api_key: str = os.getenv("ANTHROPIC_API_KEY", "")
    claude_model: str = os.getenv("CLAUDE_MODEL", "claude-3-5-sonnet-20241022")
    anthropic_base_url: str = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")

    # Azure OpenAI Service Configuration
    azure_openai_api_key: str = os.getenv("AZURE_OPENAI_API_KEY", "")
    azure_openai_endpoint: str = os.getenv("AZURE_OPENAI_ENDPOINT", "")
    azure_openai_deployment_name: str = os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", "")
    azure_openai_api_version: str = os.getenv("AZURE_OPENAI_API_VERSION", "2024-06-01")

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
