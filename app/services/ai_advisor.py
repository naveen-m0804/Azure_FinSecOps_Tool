"""
FinSecOps AI Advisor Service
Replaced old hardcoded question-to-answer mappings with genuine Agentic AI orchestrator.
Delegates dynamically to FinSecOpsAgentOrchestrator for intelligent tool calling,
real read-only Azure queries, assessment report analysis, and cloud knowledge reasoning.
"""
import logging
from typing import Dict, Any, List, Optional
from app.agent.orchestrator import FinSecOpsAgentOrchestrator
from app.agent.guardrails import FinSecOpsGuardrails

logger = logging.getLogger("azure_finsecops.services.ai_advisor")

class AIAdvisorService:
    POLICY_MESSAGE = FinSecOpsGuardrails.USAGE_POLICY_MESSAGE

    @classmethod
    def is_in_scope(cls, user_message: str) -> bool:
        """Determines if user message is within supported cloud / FinSecOps scope."""
        return FinSecOpsGuardrails.is_in_scope(user_message)

    @staticmethod
    def sanitize_credentials(text: str) -> str:
        """Sanitizes any secrets or sensitive tokens from output."""
        return FinSecOpsGuardrails.sanitize_credentials(text)

    @classmethod
    async def process_chat(
        cls,
        user_message: str,
        connection_data: Optional[Dict[str, Any]] = None,
        chat_history: Optional[List[Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Unified Agentic AI Chat Pipeline:
        Dynamically classifies intent, selects read-only Azure tools, queries live tenant,
        inspects session assessment reports, and synthesizes accurate responses using Groq.
        """
        return await FinSecOpsAgentOrchestrator.process_request(
            user_message=user_message,
            connection_data=connection_data,
            chat_history=chat_history
        )
