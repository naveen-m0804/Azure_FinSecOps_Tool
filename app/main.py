import asyncio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.session_store import session_store
from app.api import connection, subscriptions, assessments, jobs, reports, ai_advisor_router

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Azure FinSecOps - Enterprise Cloud Financial & Security Posture Platform"
)

# CORS configuration for Vite Frontend
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    settings.frontend_url,
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow local Vite dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(connection.router)
app.include_router(subscriptions.router)
app.include_router(assessments.router)
app.include_router(jobs.router)
app.include_router(reports.router)
app.include_router(ai_advisor_router.router)

@app.on_event("startup")
async def startup_event():
    # Periodic TTL cleaner task
    async def cleanup_loop():
        while True:
            try:
                await session_store.cleanup_expired()
            except Exception:
                pass
            await asyncio.sleep(300) # Every 5 minutes

    asyncio.create_task(cleanup_loop())

@app.get("/")
async def root():
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "status": "online",
        "docs_url": "/docs"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
