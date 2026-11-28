"""
Google Cloud Vertex AI Agentic Inference Engine.
Provides autonomous multi-step tool calling via the Vertex AI Gemini generateContent API
using an API key configured in .env (VERTEX_AI_API_KEY).
"""
import os
import json
import uuid
import logging
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import httpx
from app.core.config import settings

logger = logging.getLogger("azure_finsecops.agent.provider")


class AIProviderError(Exception):
    """Base exception for Vertex AI inference and configuration errors."""
    pass


class BaseLLMProvider(ABC):
    """Abstract Base Class for LLM inference providers."""

    @abstractmethod
    def is_configured(self) -> bool:
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        pass

    @abstractmethod
    def get_config_guidance(self) -> str:
        pass

    @abstractmethod
    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: float = 0.1,
    ) -> Dict[str, Any]:
        pass


class VertexAIInferenceProvider(BaseLLMProvider):
    """
    Google Cloud Vertex AI provider using the Vertex AI REST generateContent API.
    Supports full multi-step function/tool calling for the FinSecOps Agent Orchestrator.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        project_id: Optional[str] = None,
        location: Optional[str] = None,
        timeout: Optional[int] = None,
    ):
        self.api_key = (
            api_key
            if api_key is not None
            else (settings.vertex_ai_api_key or os.getenv("VERTEX_AI_API_KEY", "").strip())
        )
        self.model = (
            model
            or settings.vertex_ai_model
            or os.getenv("VERTEX_AI_MODEL", "gemini-2.5-flash").strip()
        )
        self.project_id = (
            project_id
            if project_id is not None
            else (settings.vertex_ai_project or os.getenv("VERTEX_AI_PROJECT", "").strip())
        )
        self.location = (
            location
            or settings.vertex_ai_location
            or os.getenv("VERTEX_AI_LOCATION", "global").strip()
        )
        self.timeout = timeout or settings.ai_request_timeout_seconds
        self.max_tokens = settings.ai_max_tokens

    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key.strip()) > 5)

    def get_provider_name(self) -> str:
        return "Google Cloud Vertex AI"

    def get_model_name(self) -> str:
        return self.model

    def get_config_guidance(self) -> str:
        return (
            "### Vertex AI API Key Required\n\n"
            "The **FinSecOps Agentic AI** uses **Google Cloud Vertex AI**, which requires a `VERTEX_AI_API_KEY`.\n\n"
            "**To configure Vertex AI**:\n"
            "1. Create or copy a Vertex AI API key in Google Cloud Console (**Vertex AI -> API Keys**).\n"
            "2. Open your `.env` file and set:\n"
            "   ```bash\n"
            "   VERTEX_AI_API_KEY=your_vertex_ai_api_key_here\n"
            f"   VERTEX_AI_MODEL={self.model}\n"
            "   ```\n"
            "3. Refresh or send your question again."
        )

    def _build_endpoint_url(self) -> str:
        if self.project_id:
            loc = self.location or "us-central1"
            host = "aiplatform.googleapis.com" if loc == "global" else f"{loc}-aiplatform.googleapis.com"
            return (
                f"https://{host}/v1/projects/{self.project_id}/locations/{loc}"
                f"/publishers/google/models/{self.model}:generateContent"
            )
        return f"https://aiplatform.googleapis.com/v1/publishers/google/models/{self.model}:generateContent"

    @staticmethod
    def _sanitize_schema(schema: Any) -> Any:
        """Recursively cleans JSON Schema fields for Vertex AI FunctionDeclaration compatibility."""
        if not isinstance(schema, dict):
            return schema
        cleaned: Dict[str, Any] = {}
        for k, v in schema.items():
            if k in ("additionalProperties", "$schema", "default"):
                continue
            if k == "properties" and isinstance(v, dict):
                cleaned[k] = {pk: VertexAIInferenceProvider._sanitize_schema(pv) for pk, pv in v.items()}
            elif k == "items" and isinstance(v, dict):
                cleaned[k] = VertexAIInferenceProvider._sanitize_schema(v)
            else:
                cleaned[k] = v
        return cleaned

    @classmethod
    def _convert_tools_to_vertex(cls, tools: Optional[List[Dict[str, Any]]]) -> Optional[List[Dict[str, Any]]]:
        if not tools:
            return None
        declarations = []
        for t in tools:
            fn = t.get("function", t)
            decl: Dict[str, Any] = {
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
            }
            params = fn.get("parameters")
            if params:
                decl["parameters"] = cls._sanitize_schema(params)
            declarations.append(decl)
        return [{"functionDeclarations": declarations}] if declarations else None

    @staticmethod
    def _convert_messages_to_vertex(messages: List[Dict[str, Any]]) -> tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        system_parts: List[Dict[str, str]] = []
        contents: List[Dict[str, Any]] = []

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content") or ""

            if role == "system":
                if content:
                    system_parts.append({"text": str(content)})
                continue

            if role == "user":
                contents.append({"role": "user", "parts": [{"text": str(content)}]})
            elif role == "assistant":
                parts: List[Dict[str, Any]] = []
                if content:
                    parts.append({"text": str(content)})
                for tc in msg.get("tool_calls") or []:
                    fn = tc.get("function", {})
                    raw_args = fn.get("arguments", "{}")
                    try:
                        args_obj = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                    except Exception:
                        args_obj = {}
                    parts.append({"functionCall": {"name": fn.get("name", ""), "args": args_obj}})
                if parts:
                    contents.append({"role": "model", "parts": parts})
            elif role == "tool":
                tool_name = msg.get("name", "tool")
                try:
                    resp_obj = json.loads(content) if isinstance(content, str) else content
                    if not isinstance(resp_obj, dict):
                        resp_obj = {"result": resp_obj}
                except Exception:
                    resp_obj = {"result": str(content)}
                contents.append({
                    "role": "user",
                    "parts": [{
                        "functionResponse": {
                            "name": tool_name,
                            "response": resp_obj,
                        }
                    }],
                })

        system_instruction = {"parts": system_parts} if system_parts else None
        return system_instruction, contents

    @staticmethod
    def _parse_vertex_response(data: Dict[str, Any], default_model: str) -> Dict[str, Any]:
        candidates = data.get("candidates") or []
        if not candidates:
            raise AIProviderError("Vertex AI returned 200 OK with no candidates.")

        cand = candidates[0]
        content_obj = cand.get("content", {})
        parts = content_obj.get("parts") or []

        text_segments: List[str] = []
        tool_calls: List[Dict[str, Any]] = []

        for part in parts:
            if "text" in part and part["text"]:
                text_segments.append(part["text"])
            elif "functionCall" in part:
                fc = part["functionCall"]
                tool_calls.append({
                    "id": f"call_{uuid.uuid4().hex[:12]}",
                    "type": "function",
                    "function": {
                        "name": fc.get("name", ""),
                        "arguments": json.dumps(fc.get("args") or {}),
                    },
                })

        usage_meta = data.get("usageMetadata") or {}
        usage = {
            "prompt_tokens": usage_meta.get("promptTokenCount", 0),
            "completion_tokens": usage_meta.get("candidatesTokenCount", 0),
            "total_tokens": usage_meta.get("totalTokenCount", 0),
        }

        message_out: Dict[str, Any] = {
            "role": "assistant",
            "content": "\n".join(text_segments).strip(),
        }
        if tool_calls:
            message_out["tool_calls"] = tool_calls

        return {
            "message": message_out,
            "finish_reason": cand.get("finishReason", "STOP"),
            "usage": usage,
            "model_used": data.get("modelVersion", default_model),
        }

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: float = 0.1,
    ) -> Dict[str, Any]:
        if not self.is_configured():
            raise AIProviderError(
                "Vertex AI API key is not configured. Please supply a valid VERTEX_AI_API_KEY in your .env file."
            )

        endpoint = self._build_endpoint_url()
        system_instruction, contents = self._convert_messages_to_vertex(messages)
        vertex_tools = self._convert_tools_to_vertex(tools)

        payload: Dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": self.max_tokens,
            },
        }
        if system_instruction:
            payload["systemInstruction"] = system_instruction
        if vertex_tools:
            payload["tools"] = vertex_tools
            mode = "NONE" if tool_choice == "none" else "AUTO"
            payload["toolConfig"] = {"functionCallingConfig": {"mode": mode}}

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        params = {"key": self.api_key}

        max_retries = 3
        last_error: Optional[Exception] = None

        for attempt in range(1, max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(endpoint, headers=headers, params=params, json=payload)

                    if resp.status_code == 200:
                        return self._parse_vertex_response(resp.json(), self.model)

                    if resp.status_code == 429:
                        retry_after = resp.headers.get("retry-after")
                        wait_sec = float(retry_after) if retry_after and retry_after.isdigit() else (2 ** attempt) + 1.0
                        logger.warning("Vertex AI HTTP 429 rate limit. Waiting %.1fs (attempt %d/%d)", wait_sec, attempt, max_retries)
                        if attempt < max_retries:
                            await asyncio.sleep(wait_sec)
                            continue
                        raise AIProviderError("Vertex AI rate limit exceeded (HTTP 429). Please wait a moment and try again.")

                    if resp.status_code in (401, 403):
                        raise AIProviderError(
                            f"Vertex AI authentication failed (HTTP {resp.status_code}). Please verify your VERTEX_AI_API_KEY."
                        )

                    if resp.status_code == 400:
                        raise AIProviderError(f"Vertex AI bad request (HTTP 400): {resp.text[:250]}")

                    if resp.status_code >= 500:
                        if attempt < max_retries:
                            await asyncio.sleep(2 * attempt)
                            continue
                        raise AIProviderError(f"Vertex AI server error (HTTP {resp.status_code}).")

                    raise AIProviderError(f"Vertex AI returned HTTP {resp.status_code}: {resp.text[:250]}")

            except (httpx.RequestError, httpx.TimeoutException) as ex:
                last_error = ex
                logger.warning("Network error communicating with Vertex AI (%s). Attempt %d/%d", ex, attempt, max_retries)
                if attempt < max_retries:
                    await asyncio.sleep(2 * attempt)
                else:
                    raise AIProviderError(f"Network error communicating with Vertex AI: {ex}")

        raise AIProviderError(f"Failed to connect to Vertex AI: {last_error}")


def get_ai_provider(provider_name: Optional[str] = None) -> BaseLLMProvider:
    """Returns the configured Google Cloud Vertex AI provider instance."""
    return VertexAIInferenceProvider()
