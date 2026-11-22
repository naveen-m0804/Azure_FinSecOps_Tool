from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from app.core.session_store import session_store
from app.services.ai_advisor import AIAdvisorService

router = APIRouter(prefix="/api/ai", tags=["AI Advisor"])

class ChatRequest(BaseModel):
    connection_id: Optional[str] = None
    message: str
    history: Optional[List[Dict[str, Any]]] = None

@router.post("/chat")
async def chat_with_advisor(req: ChatRequest):
    if not req.message or not req.message.strip():
        raise HTTPException(status_code=400, detail="Message cannot be blank.")

    conn = None
    if req.connection_id:
        conn = await session_store.get_connection(req.connection_id)
    if not conn and session_store._connections:
        conn = list(session_store._connections.values())[-1]

    res = await AIAdvisorService.process_chat(
        user_message=req.message,
        connection_data=conn,
        chat_history=req.history
    )
    return res
