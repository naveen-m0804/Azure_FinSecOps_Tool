"""
Universal Multi-Provider AI Inference Engine
Supports plug-and-play LLM providers via .env configuration:
1. Groq Cloud (Default): High-speed tool-calling inference
2. NVIDIA Nemotron: nvidia/nemotron-3.5-super-vl-120b-a12b via NVIDIA NIM / OpenAI-compatible endpoint
3. OpenAI (ChatGPT): gpt-4o, gpt-4o-mini
4. Google Gemini: gemini-1.5-pro, gemini-1.5-flash via official OpenAI-compatible endpoint
5. Anthropic Claude: claude-3-5-sonnet, claude-3-5-haiku via native messages API
6. Azure OpenAI: Enterprise Azure OpenAI Service
"""
import os
import json
import logging
import asyncio
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
import httpx
from app.core.config import settings

logger = logging.getLogger("azure_finsecops.agent.provider")


class AIProviderError(Exception):
    """Base exception for all AI inference and provider errors."""
    pass


# Maintain backward compatibility alias
GroqProviderError = AIProviderError


class BaseLLMProvider(ABC):
    """Abstract Base Class for all LLM inference providers."""

    @abstractmethod
    def is_configured(self) -> bool:
        """Returns True if the provider has a valid API key configured."""
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Returns the human-readable name of the provider."""
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        """Returns the current model identifier."""
        pass

    @abstractmethod
    def get_config_guidance(self) -> str:
        """Returns markdown instructions on how to configure the API key for this provider."""
        pass

    @abstractmethod
    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: float = 0.1
    ) -> Dict[str, Any]:
        """
        Executes a chat completion with dynamic tool calling.
        Returns a dict:
        {
            "message": {"role": "assistant", "content": str, "tool_calls": [...]},
            "finish_reason": str,
            "usage": {"prompt_tokens": int, "completion_tokens": int, "total_tokens": int},
            "model_used": str
        }
        """
        pass


# ==============================================================================
# 1. Groq Inference Provider (Primary / Default)
# ==============================================================================
class GroqInferenceProvider(BaseLLMProvider):
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[int] = None
    ):
        self.api_key = api_key or settings.groq_api_key or os.getenv("GROQ_API_KEY", "").strip()
        self.model = model or settings.groq_model or os.getenv("GROQ_MODEL", "openai/gpt-oss-120b").strip()
        self.base_url = (base_url or settings.groq_base_url or os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")).rstrip("/")
        self.timeout = timeout or settings.ai_request_timeout_seconds
        self.max_tokens = settings.ai_max_tokens
        self._fallback_models = ["openai/gpt-oss-120b", "qwen/qwen3.8-27b", "openai/gpt-oss-20b"]

    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) > 5)

    def get_provider_name(self) -> str:
        return "Groq Cloud"

    def get_model_name(self) -> str:
        return self.model

    def get_config_guidance(self) -> str:
        return (
            "### ⚠️ Groq API Key Required\n\n"
            "The **FinSecOps Agentic AI** is configured to use **Groq Cloud**, which requires a valid Groq API key.\n\n"
            "**To configure Groq**:\n"
            "1. Sign up for free at [console.groq.com](https://console.groq.com).\n"
            "2. Generate an API key under **API Keys**.\n"
            "3. Open your `.env` file and set:\n"
            "   ```bash\n"
            "   AI_PROVIDER=groq\n"
            "   GROQ_API_KEY=gsk_your_actual_key_here\n"
            f"   GROQ_MODEL={self.model}\n"
            "   ```\n"
            "4. Refresh or send your question again."
        )

    async def _resolve_fallback_model(self, client: httpx.AsyncClient, headers: Dict[str, str], failed_model: str) -> Optional[str]:
        """Queries Groq /models to find an active supported chat/tool model in customer account."""
        try:
            m_resp = await client.get(f"{self.base_url}/models", headers=headers, timeout=10)
            if m_resp.status_code == 200:
                data = m_resp.json().get("data", [])
                available_ids = [m.get("id") for m in data if m.get("id")]
                for fb in self._fallback_models:
                    if fb in available_ids and fb != failed_model:
                        return fb
                for mid in available_ids:
                    if any(k in mid.lower() for k in ["gpt-oss", "qwen", "llama"]) and "guard" not in mid.lower() and "whisper" not in mid.lower() and mid != failed_model:
                        return mid
        except Exception as ex:
            logger.debug(f"Failed to auto-discover Groq models: {ex}")
        for fb in self._fallback_models:
            if fb != failed_model:
                return fb
        return None

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: float = 0.1
    ) -> Dict[str, Any]:
        if not self.is_configured():
            raise GroqProviderError(
                "Groq API key is not configured. Please supply a valid GROQ_API_KEY in your environment configuration (.env)."
            )

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.max_tokens
        }

        if tools and len(tools) > 0:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        max_retries = 3
        last_error = None

        for attempt in range(1, max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(endpoint, headers=headers, json=payload)

                    if resp.status_code == 200:
                        data = resp.json()
                        choices = data.get("choices", [])
                        if not choices:
                            raise GroqProviderError("Groq returned 200 OK but choices array is empty.")
                        
                        choice = choices[0]
                        return {
                            "message": choice.get("message", {}),
                            "finish_reason": choice.get("finish_reason"),
                            "usage": data.get("usage", {}),
                            "model_used": data.get("model", self.model)
                        }

                    # Handle 429 Rate Limit
                    if resp.status_code == 429:
                        err_body = resp.text
                        retry_after = resp.headers.get("retry-after")
                        wait_sec = float(retry_after) if retry_after and retry_after.isdigit() else (2 ** attempt) + 1.0
                        logger.warning(f"Groq API HTTP 429 rate limit reached. Waiting {wait_sec:.1f}s (attempt {attempt}/{max_retries}). Body: {err_body[:200]}")
                        if attempt < max_retries:
                            await asyncio.sleep(wait_sec)
                            continue
                        raise GroqProviderError(
                            "Groq API rate limit or TPM quota exceeded (HTTP 429). Please wait a moment before trying again."
                        )

                    # Handle 401 Unauthorized
                    if resp.status_code == 401:
                        raise GroqProviderError(
                            "Groq authentication failed (HTTP 401). Please verify that your GROQ_API_KEY is valid."
                        )

                    # Handle 404 Model Not Found -> Auto-recover with active account model
                    if resp.status_code == 404:
                        err_detail = resp.text
                        logger.warning(f"Groq model '{payload['model']}' not accessible (404). Attempting auto-fallback...")
                        fb = await self._resolve_fallback_model(client, headers, payload["model"])
                        if fb and fb != payload["model"]:
                            logger.info(f"Auto-switching Groq model to '{fb}'")
                            self.model = fb
                            payload["model"] = fb
                            continue
                        raise GroqProviderError(f"Groq model not accessible: {err_detail[:200]}")

                    # Handle 400 Bad Request
                    if resp.status_code == 400:
                        err_detail = resp.text
                        raise GroqProviderError(
                            f"Groq API bad request (HTTP 400): {err_detail[:250]}. Please verify model compatibility."
                        )

                    # Handle 5xx Server Errors
                    if resp.status_code >= 500:
                        logger.warning(f"Groq API temporary server error HTTP {resp.status_code}. Retrying...")
                        if attempt < max_retries:
                            await asyncio.sleep(2 * attempt)
                            continue
                        raise GroqProviderError(f"Groq upstream server error HTTP {resp.status_code}.")

                    raise GroqProviderError(f"Groq API returned HTTP {resp.status_code}: {resp.text[:200]}")

            except (httpx.RequestError, httpx.TimeoutException) as ex:
                last_error = ex
                logger.warning(f"Network error communicating with Groq API ({ex}). Attempt {attempt}/{max_retries}")
                if attempt < max_retries:
                    await asyncio.sleep(2 * attempt)
                else:
                    raise GroqProviderError(f"Network error communicating with Groq: {str(ex)}")

        if last_error:
            raise GroqProviderError(f"Failed to connect to Groq inference API: {str(last_error)}")
        raise GroqProviderError("Unknown Groq inference failure.")


# ==============================================================================
# 2. OpenAI Inference Provider (ChatGPT: gpt-4o, gpt-4o-mini)
# ==============================================================================
class OpenAIInferenceProvider(BaseLLMProvider):
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[int] = None
    ):
        self.api_key = api_key or settings.openai_api_key or os.getenv("OPENAI_API_KEY", "").strip()
        self.model = model or settings.openai_model or os.getenv("OPENAI_MODEL", "gpt-4o").strip()
        self.base_url = (base_url or settings.openai_base_url or os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")).rstrip("/")
        self.timeout = timeout or settings.ai_request_timeout_seconds
        self.max_tokens = settings.ai_max_tokens

    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) > 5)

    def get_provider_name(self) -> str:
        return "OpenAI (ChatGPT)"

    def get_model_name(self) -> str:
        return self.model

    def get_config_guidance(self) -> str:
        return (
            "### ⚠️ OpenAI API Key Required\n\n"
            "The **FinSecOps Agentic AI** is configured to use **OpenAI (ChatGPT)**, which requires a valid OpenAI API key.\n\n"
            "**To configure OpenAI**:\n"
            "1. Sign up or log in at [platform.openai.com](https://platform.openai.com/api-keys).\n"
            "2. Create a new secret key under **API Keys**.\n"
            "3. Open your `.env` file and set:\n"
            "   ```bash\n"
            "   AI_PROVIDER=openai\n"
            "   OPENAI_API_KEY=sk-proj-your_actual_key_here\n"
            f"   OPENAI_MODEL={self.model}\n"
            "   ```\n"
            "4. Refresh or send your question again."
        )

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: float = 0.1
    ) -> Dict[str, Any]:
        if not self.is_configured():
            raise AIProviderError(
                "OpenAI API key is not configured. Please supply a valid OPENAI_API_KEY in your .env file."
            )

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.max_tokens
        }

        if tools and len(tools) > 0:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(endpoint, headers=headers, json=payload)

                    if resp.status_code == 200:
                        data = resp.json()
                        choices = data.get("choices", [])
                        if not choices:
                            raise AIProviderError("OpenAI returned 200 OK but choices array is empty.")
                        choice = choices[0]
                        return {
                            "message": choice.get("message", {}),
                            "finish_reason": choice.get("finish_reason"),
                            "usage": data.get("usage", {}),
                            "model_used": data.get("model", self.model)
                        }

                    if resp.status_code == 429:
                        wait_sec = (2 ** attempt) + 1.0
                        logger.warning(f"OpenAI rate limit (HTTP 429). Retrying in {wait_sec}s...")
                        if attempt < max_retries:
                            await asyncio.sleep(wait_sec)
                            continue
                        raise AIProviderError("OpenAI rate limit exceeded (HTTP 429).")

                    if resp.status_code == 401:
                        raise AIProviderError("OpenAI authentication failed (HTTP 401). Please check OPENAI_API_KEY.")

                    if resp.status_code >= 500:
                        if attempt < max_retries:
                            await asyncio.sleep(2 * attempt)
                            continue
                        raise AIProviderError(f"OpenAI server error HTTP {resp.status_code}.")

                    raise AIProviderError(f"OpenAI API returned HTTP {resp.status_code}: {resp.text[:250]}")

            except (httpx.RequestError, httpx.TimeoutException) as ex:
                if attempt < max_retries:
                    await asyncio.sleep(2 * attempt)
                else:
                    raise AIProviderError(f"Network error communicating with OpenAI: {str(ex)}")

        raise AIProviderError("Unknown OpenAI inference failure.")


# ==============================================================================
# 3. Google Gemini Inference Provider (via Official OpenAI-Compatible Endpoint)
# ==============================================================================
class GeminiInferenceProvider(BaseLLMProvider):
    """
    Google Gemini uses Google's official OpenAI-compatible endpoint:
    https://generativelanguage.googleapis.com/v1beta/openai/chat/completions
    This enables full function calling with existing OpenAI tool definitions without extra SDKs.
    """
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[int] = None
    ):
        self.api_key = api_key or settings.gemini_api_key or os.getenv("GEMINI_API_KEY", "").strip()
        self.model = model or settings.gemini_model or os.getenv("GEMINI_MODEL", "gemini-1.5-pro").strip()
        self.base_url = (base_url or settings.gemini_base_url or os.getenv("GEMINI_BASE_URL", "https://generativelanguage.googleapis.com/v1beta/openai")).rstrip("/")
        self.timeout = timeout or settings.ai_request_timeout_seconds
        self.max_tokens = settings.ai_max_tokens

    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) > 5)

    def get_provider_name(self) -> str:
        return "Google Gemini"

    def get_model_name(self) -> str:
        return self.model

    def get_config_guidance(self) -> str:
        return (
            "### ⚠️ Google Gemini API Key Required\n\n"
            "The **FinSecOps Agentic AI** is configured to use **Google Gemini**, which requires a Google AI API key.\n\n"
            "**To configure Gemini**:\n"
            "1. Get a free API key at [aistudio.google.com](https://aistudio.google.com/app/apikey).\n"
            "2. Open your `.env` file and set:\n"
            "   ```bash\n"
            "   AI_PROVIDER=gemini\n"
            "   GEMINI_API_KEY=AIzaSy_your_actual_key_here\n"
            f"   GEMINI_MODEL={self.model}\n"
            "   ```\n"
            "3. Refresh or send your question again."
        )

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: float = 0.1
    ) -> Dict[str, Any]:
        if not self.is_configured():
            raise AIProviderError(
                "Gemini API key is not configured. Please supply a valid GEMINI_API_KEY in your .env file."
            )

        endpoint = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.max_tokens
        }

        if tools and len(tools) > 0:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(endpoint, headers=headers, json=payload)

                    if resp.status_code == 200:
                        data = resp.json()
                        choices = data.get("choices", [])
                        if not choices:
                            raise AIProviderError("Gemini returned 200 OK but choices array is empty.")
                        choice = choices[0]
                        return {
                            "message": choice.get("message", {}),
                            "finish_reason": choice.get("finish_reason"),
                            "usage": data.get("usage", {}),
                            "model_used": data.get("model", self.model)
                        }

                    if resp.status_code == 429:
                        wait_sec = (2 ** attempt) + 1.0
                        logger.warning(f"Gemini quota/rate limit (HTTP 429). Retrying in {wait_sec}s...")
                        if attempt < max_retries:
                            await asyncio.sleep(wait_sec)
                            continue
                        raise AIProviderError("Gemini rate limit exceeded (HTTP 429).")

                    if resp.status_code in [400, 401, 403]:
                        raise AIProviderError(f"Gemini API error (HTTP {resp.status_code}): {resp.text[:250]}")

                    if resp.status_code >= 500:
                        if attempt < max_retries:
                            await asyncio.sleep(2 * attempt)
                            continue
                        raise AIProviderError(f"Gemini server error HTTP {resp.status_code}.")

                    raise AIProviderError(f"Gemini API returned HTTP {resp.status_code}: {resp.text[:250]}")

            except (httpx.RequestError, httpx.TimeoutException) as ex:
                if attempt < max_retries:
                    await asyncio.sleep(2 * attempt)
                else:
                    raise AIProviderError(f"Network error communicating with Gemini: {str(ex)}")

        raise AIProviderError("Unknown Gemini inference failure.")


# ==============================================================================
# 4. Anthropic Claude Inference Provider (claude-3-5-sonnet, claude-3-5-haiku)
# ==============================================================================
class ClaudeInferenceProvider(BaseLLMProvider):
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[int] = None
    ):
        self.api_key = api_key or settings.anthropic_api_key or os.getenv("ANTHROPIC_API_KEY", "").strip()
        self.model = model or settings.claude_model or os.getenv("CLAUDE_MODEL", "claude-3-5-sonnet-20241022").strip()
        self.base_url = (base_url or settings.anthropic_base_url or os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1")).rstrip("/")
        self.timeout = timeout or settings.ai_request_timeout_seconds
        self.max_tokens = settings.ai_max_tokens

    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) > 5)

    def get_provider_name(self) -> str:
        return "Anthropic Claude"

    def get_model_name(self) -> str:
        return self.model

    def get_config_guidance(self) -> str:
        return (
            "### ⚠️ Anthropic Claude API Key Required\n\n"
            "The **FinSecOps Agentic AI** is configured to use **Anthropic Claude**, which requires a Claude API key.\n\n"
            "**To configure Claude**:\n"
            "1. Get an API key at [console.anthropic.com](https://console.anthropic.com/settings/keys).\n"
            "2. Open your `.env` file and set:\n"
            "   ```bash\n"
            "   AI_PROVIDER=claude\n"
            "   ANTHROPIC_API_KEY=sk-ant-your_actual_key_here\n"
            f"   CLAUDE_MODEL={self.model}\n"
            "   ```\n"
            "3. Refresh or send your question again."
        )

    def _convert_tools_to_anthropic(self, openai_tools: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Converts OpenAI JSON Schema tools to Anthropic tool definitions."""
        claude_tools = []
        for t in openai_tools:
            fn = t.get("function", {})
            claude_tools.append({
                "name": fn.get("name", ""),
                "description": fn.get("description", ""),
                "input_schema": fn.get("parameters", {"type": "object", "properties": {}})
            })
        return claude_tools

    def _convert_messages_to_anthropic(self, openai_messages: List[Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
        """Separates system prompt and adapts conversation turn history to Claude format."""
        system_prompt = ""
        claude_messages: List[Dict[str, Any]] = []

        pending_tool_results: List[Dict[str, Any]] = []

        for m in openai_messages:
            role = m.get("role")
            content = m.get("content")

            if role == "system":
                system_prompt = content or ""
                continue

            if role == "user":
                if pending_tool_results:
                    claude_messages.append({"role": "user", "content": pending_tool_results})
                    pending_tool_results = []
                claude_messages.append({"role": "user", "content": content or ""})

            elif role == "assistant":
                if pending_tool_results:
                    claude_messages.append({"role": "user", "content": pending_tool_results})
                    pending_tool_results = []

                blocks = []
                if content:
                    blocks.append({"type": "text", "text": str(content)})
                for tc in m.get("tool_calls") or []:
                    fn = tc.get("function", {})
                    raw_args = fn.get("arguments", "{}")
                    try:
                        args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
                    except Exception:
                        args = {}
                    blocks.append({
                        "type": "tool_use",
                        "id": tc.get("id", f"call_{len(blocks)}"),
                        "name": fn.get("name", ""),
                        "input": args
                    })
                claude_messages.append({"role": "assistant", "content": blocks if blocks else (content or "")})

            elif role == "tool":
                pending_tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": m.get("tool_call_id", ""),
                    "content": content or "{}"
                })

        if pending_tool_results:
            claude_messages.append({"role": "user", "content": pending_tool_results})

        return system_prompt, claude_messages

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: float = 0.1
    ) -> Dict[str, Any]:
        if not self.is_configured():
            raise AIProviderError(
                "Anthropic API key is not configured. Please supply ANTHROPIC_API_KEY in your .env file."
            )

        endpoint = f"{self.base_url}/messages"
        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }

        system_prompt, claude_msgs = self._convert_messages_to_anthropic(messages)
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": claude_msgs,
            "max_tokens": self.max_tokens,
            "temperature": temperature
        }

        if system_prompt:
            payload["system"] = system_prompt

        if tools and len(tools) > 0:
            payload["tools"] = self._convert_tools_to_anthropic(tools)

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(endpoint, headers=headers, json=payload)

                    if resp.status_code == 200:
                        data = resp.json()
                        content_blocks = data.get("content", [])
                        text_parts = [b["text"] for b in content_blocks if b.get("type") == "text"]
                        tool_calls = [
                            {
                                "id": b["id"],
                                "type": "function",
                                "function": {
                                    "name": b["name"],
                                    "arguments": json.dumps(b.get("input", {}))
                                }
                            }
                            for b in content_blocks if b.get("type") == "tool_use"
                        ]

                        usage = data.get("usage", {})
                        total_tok = usage.get("input_tokens", 0) + usage.get("output_tokens", 0)
                        return {
                            "message": {
                                "role": "assistant",
                                "content": "\n".join(text_parts) if text_parts else None,
                                "tool_calls": tool_calls if tool_calls else None
                            },
                            "finish_reason": data.get("stop_reason"),
                            "usage": {
                                "prompt_tokens": usage.get("input_tokens", 0),
                                "completion_tokens": usage.get("output_tokens", 0),
                                "total_tokens": total_tok
                            },
                            "model_used": data.get("model", self.model)
                        }

                    if resp.status_code == 429:
                        wait_sec = (2 ** attempt) + 1.0
                        logger.warning(f"Claude rate limit (HTTP 429). Retrying in {wait_sec}s...")
                        if attempt < max_retries:
                            await asyncio.sleep(wait_sec)
                            continue
                        raise AIProviderError("Anthropic rate limit exceeded (HTTP 429).")

                    if resp.status_code in [400, 401, 403]:
                        raise AIProviderError(f"Anthropic API error (HTTP {resp.status_code}): {resp.text[:250]}")

                    if resp.status_code >= 500:
                        if attempt < max_retries:
                            await asyncio.sleep(2 * attempt)
                            continue
                        raise AIProviderError(f"Anthropic server error HTTP {resp.status_code}.")

                    raise AIProviderError(f"Anthropic API returned HTTP {resp.status_code}: {resp.text[:250]}")

            except (httpx.RequestError, httpx.TimeoutException) as ex:
                if attempt < max_retries:
                    await asyncio.sleep(2 * attempt)
                else:
                    raise AIProviderError(f"Network error communicating with Anthropic: {str(ex)}")

        raise AIProviderError("Unknown Anthropic Claude inference failure.")


# ==============================================================================
# 5. Azure OpenAI Inference Provider (Enterprise)
# ==============================================================================
class AzureOpenAIInferenceProvider(BaseLLMProvider):
    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        deployment_name: Optional[str] = None,
        api_version: Optional[str] = None,
        timeout: Optional[int] = None
    ):
        self.api_key = api_key or settings.azure_openai_api_key or os.getenv("AZURE_OPENAI_API_KEY", "").strip()
        self.endpoint = (endpoint or settings.azure_openai_endpoint or os.getenv("AZURE_OPENAI_ENDPOINT", "")).rstrip("/")
        self.deployment_name = deployment_name or settings.azure_openai_deployment_name or os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME", "gpt-4o").strip()
        self.api_version = api_version or settings.azure_openai_api_version or os.getenv("AZURE_OPENAI_API_VERSION", "2024-06-01").strip()
        self.timeout = timeout or settings.ai_request_timeout_seconds
        self.max_tokens = settings.ai_max_tokens

    def is_configured(self) -> bool:
        return bool(self.api_key and self.endpoint and len(self.api_key) > 5)

    def get_provider_name(self) -> str:
        return "Azure OpenAI Service"

    def get_model_name(self) -> str:
        return self.deployment_name

    def get_config_guidance(self) -> str:
        return (
            "### ⚠️ Azure OpenAI Configuration Required\n\n"
            "The **FinSecOps Agentic AI** is configured to use **Azure OpenAI Service**.\n\n"
            "**To configure Azure OpenAI**:\n"
            "1. Find your Azure OpenAI resource in the Azure Portal.\n"
            "2. Under **Resource Management** → **Keys and Endpoint**, copy the Key and Endpoint.\n"
            "3. Open your `.env` file and set:\n"
            "   ```bash\n"
            "   AI_PROVIDER=azure_openai\n"
            "   AZURE_OPENAI_API_KEY=your_key_here\n"
            "   AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com\n"
            f"   AZURE_OPENAI_DEPLOYMENT_NAME={self.deployment_name}\n"
            "   ```\n"
            "4. Refresh or send your question again."
        )

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: float = 0.1
    ) -> Dict[str, Any]:
        if not self.is_configured():
            raise AIProviderError(
                "Azure OpenAI is not configured. Please supply AZURE_OPENAI_API_KEY and AZURE_OPENAI_ENDPOINT in .env."
            )

        url = f"{self.endpoint}/openai/deployments/{self.deployment_name}/chat/completions?api-version={self.api_version}"
        headers = {
            "api-key": self.api_key,
            "Content-Type": "application/json"
        }

        payload: Dict[str, Any] = {
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.max_tokens
        }

        if tools and len(tools) > 0:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        max_retries = 3
        for attempt in range(1, max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.post(url, headers=headers, json=payload)

                    if resp.status_code == 200:
                        data = resp.json()
                        choices = data.get("choices", [])
                        if not choices:
                            raise AIProviderError("Azure OpenAI returned 200 OK but choices array is empty.")
                        choice = choices[0]
                        return {
                            "message": choice.get("message", {}),
                            "finish_reason": choice.get("finish_reason"),
                            "usage": data.get("usage", {}),
                            "model_used": self.deployment_name
                        }

                    if resp.status_code == 429:
                        wait_sec = (2 ** attempt) + 1.0
                        if attempt < max_retries:
                            await asyncio.sleep(wait_sec)
                            continue
                        raise AIProviderError("Azure OpenAI rate limit exceeded (HTTP 429).")

                    if resp.status_code in [401, 403]:
                        raise AIProviderError(f"Azure OpenAI authentication failed (HTTP {resp.status_code}).")

                    if resp.status_code >= 500:
                        if attempt < max_retries:
                            await asyncio.sleep(2 * attempt)
                            continue
                        raise AIProviderError(f"Azure OpenAI server error HTTP {resp.status_code}.")

                    raise AIProviderError(f"Azure OpenAI returned HTTP {resp.status_code}: {resp.text[:250]}")

            except (httpx.RequestError, httpx.TimeoutException) as ex:
                if attempt < max_retries:
                    await asyncio.sleep(2 * attempt)
                else:
                    raise AIProviderError(f"Network error communicating with Azure OpenAI: {str(ex)}")

        raise AIProviderError("Unknown Azure OpenAI inference failure.")


# ==============================================================================
# 6. NVIDIA Nemotron Inference Provider (NVIDIA NIM / Open Platform)
# ==============================================================================
class NemotronInferenceProvider(BaseLLMProvider):
    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[int] = None
    ):
        if api_key is not None:
            self.api_key = api_key.strip()
        else:
            self.api_key = (settings.nemotron_api_key or os.getenv("NEMOTRON_API_KEY", os.getenv("NVIDIA_API_KEY", ""))).strip()
        self.model = model or settings.nemotron_model or os.getenv("NEMOTRON_MODEL", "nvidia/nemotron-3.5-super-vl-120b-a12b").strip()
        self.base_url = (base_url or settings.nemotron_base_url or os.getenv("NEMOTRON_BASE_URL", os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1"))).rstrip("/")
        self.timeout = timeout or settings.ai_request_timeout_seconds
        self.max_tokens = settings.ai_max_tokens
        self._fallback_models = [
            "nvidia/nemotron-3.5-super-vl-120b-a12b",
            "nvidia/nemotron-4-340b-instruct",
            "meta/llama-3.3-70b-instruct"
        ]

    def is_configured(self) -> bool:
        return bool(self.api_key and len(self.api_key) > 5)

    def get_provider_name(self) -> str:
        return "Nemotron (NVIDIA)"

    def get_model_name(self) -> str:
        return self.model

    def get_config_guidance(self) -> str:
        return (
            "### ⚠️ Nemotron (NVIDIA) API Key Configuration Required\n\n"
            f"The **FinSecOps Agentic AI** is configured to use the **Nemotron (NVIDIA)** provider (`{self.model}`).\n\n"
            "**To configure your Nemotron / NVIDIA API key**:\n"
            "1. Obtain an API key from [build.nvidia.com](https://build.nvidia.com/) (starts with `nvapi-`) or your enterprise NVIDIA NIM endpoint.\n"
            "2. Open your `.env` file and set:\n"
            "   ```bash\n"
            "   AI_PROVIDER=nemotron\n"
            "   NEMOTRON_API_KEY=nvapi-your-key-here\n"
            f"   NEMOTRON_MODEL={self.model}\n"
            f"   NEMOTRON_BASE_URL={self.base_url}\n"
            "   ```\n"
            "3. Ask your question or command again."
        )

    async def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: Optional[List[Dict[str, Any]]] = None,
        tool_choice: str = "auto",
        temperature: float = 0.1
    ) -> Dict[str, Any]:
        if not self.is_configured():
            raise AIProviderError(
                "Nemotron (NVIDIA) API key is missing. Set NEMOTRON_API_KEY or NVIDIA_API_KEY in .env."
            )

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": self.max_tokens
        }

        if tools and len(tools) > 0:
            payload["tools"] = tools
            payload["tool_choice"] = tool_choice

        models_to_try = [self.model] + [m for m in self._fallback_models if m != self.model]
        last_error = None
        max_retries = 3

        for current_model in models_to_try:
            payload["model"] = current_model
            for attempt in range(1, max_retries + 1):
                try:
                    async with httpx.AsyncClient(timeout=self.timeout) as client:
                        resp = await client.post(url, headers=headers, json=payload)

                        if resp.status_code == 200:
                            data = resp.json()
                            choices = data.get("choices", [])
                            if not choices:
                                raise AIProviderError("Nemotron API returned 200 OK but choices array is empty.")
                            choice = choices[0]
                            return {
                                "message": choice.get("message", {}),
                                "finish_reason": choice.get("finish_reason"),
                                "usage": data.get("usage", {}),
                                "model_used": current_model
                            }

                        if resp.status_code == 429:
                            wait_sec = (2 ** attempt) + 1.0
                            logger.warning(
                                f"Nemotron rate limit (429) on attempt {attempt}. Retrying in {wait_sec:.1f}s..."
                            )
                            if attempt < max_retries:
                                await asyncio.sleep(wait_sec)
                                continue
                            last_error = AIProviderError("Nemotron API rate limit exceeded (HTTP 429).")
                            break

                        if resp.status_code in [401, 403]:
                            raise AIProviderError(
                                f"Nemotron API authentication failed (HTTP {resp.status_code}). Please verify your NEMOTRON_API_KEY."
                            )

                        if resp.status_code in [404, 400] and "model" in resp.text.lower():
                            logger.warning(
                                f"Nemotron model '{current_model}' unavailable (HTTP {resp.status_code}): {resp.text[:150]}. Trying fallback..."
                            )
                            last_error = AIProviderError(f"Model {current_model} not available: {resp.text[:150]}")
                            break

                        if resp.status_code >= 500:
                            if attempt < max_retries:
                                await asyncio.sleep(2 * attempt)
                                continue
                            last_error = AIProviderError(f"Nemotron server error (HTTP {resp.status_code}).")
                            break

                        last_error = AIProviderError(
                            f"Nemotron API returned HTTP {resp.status_code}: {resp.text[:250]}"
                        )
                        break

                except (httpx.RequestError, httpx.TimeoutException) as ex:
                    logger.warning(f"Network error communicating with Nemotron ({current_model}) on attempt {attempt}: {ex}")
                    if attempt < max_retries:
                        await asyncio.sleep(2 * attempt)
                    else:
                        last_error = AIProviderError(f"Network error communicating with Nemotron: {str(ex)}")

        raise last_error or AIProviderError("All Nemotron inference attempts failed.")


# ==============================================================================
# Provider Factory Function
# ==============================================================================
def get_ai_provider(provider_name: Optional[str] = None) -> BaseLLMProvider:
    """
    Factory function returning the configured LLM provider instance.
    Supported provider names (case-insensitive):
    - 'groq' (default)
    - 'nemotron', 'nvidia', 'nemotron-3.5', 'nvidia_nemotron'
    - 'openai', 'chatgpt'
    - 'gemini', 'google'
    - 'claude', 'anthropic'
    - 'azure_openai', 'azure'
    """
    prov = (provider_name or settings.ai_provider or os.getenv("AI_PROVIDER", "groq")).strip().lower()

    if prov in ["nemotron", "nvidia", "nemotron-3.5", "nvidia_nemotron"]:
        return NemotronInferenceProvider()
    elif prov in ["openai", "chatgpt"]:
        return OpenAIInferenceProvider()
    elif prov in ["gemini", "google"]:
        return GeminiInferenceProvider()
    elif prov in ["claude", "anthropic"]:
        return ClaudeInferenceProvider()
    elif prov in ["azure_openai", "azure"]:
        return AzureOpenAIInferenceProvider()
    elif prov == "groq":
        return GroqInferenceProvider()
    else:
        logger.warning(f"Unrecognized AI_PROVIDER '{prov}'. Defaulting to Groq.")
        return GroqInferenceProvider()
