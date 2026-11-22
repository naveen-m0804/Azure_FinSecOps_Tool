import asyncio
import random
import httpx
from typing import Optional, Dict, Any
from app.core.config import settings

class AzureClientBase:
    def __init__(self, token: str, timeout: int = 60, max_retries: int = 5):
        self.token = token
        self.timeout = timeout
        self.max_retries = max_retries

    def get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def execute_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> httpx.Response:
        """
        Executes HTTP request with exponential backoff and jitter for 429 and 5xx errors.
        Mirrors the retry logic from the Azure assessment scripts.
        """
        req_headers = self.get_headers()
        if headers:
            req_headers.update(headers)

        last_exception = None
        for attempt in range(1, self.max_retries + 1):
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    resp = await client.request(
                        method=method,
                        url=url,
                        headers=req_headers,
                        json=json_data,
                        params=params
                    )

                    # Check for throttling or temporary server errors
                    if resp.status_code in (429, 500, 502, 503, 504) and attempt < self.max_retries:
                        # Extract Retry-After if available
                        retry_after_hdr = resp.headers.get("Retry-After")
                        if retry_after_hdr and retry_after_hdr.isdigit():
                            wait_seconds = int(retry_after_hdr)
                        else:
                            # Exponential backoff: attempt 1 -> 4s, attempt 2 -> 8s, attempt 3 -> 16s...
                            wait_seconds = (2 ** (attempt - 1)) * 4

                        # Add random jitter to prevent herd retries
                        wait_seconds = min(60, max(2, wait_seconds)) + random.uniform(0.5, 2.5)
                        await asyncio.sleep(wait_seconds)
                        continue

                    return resp
            except (httpx.RequestError, httpx.TimeoutException) as ex:
                last_exception = ex
                if attempt < self.max_retries:
                    wait_seconds = ((2 ** (attempt - 1)) * 4) + random.uniform(0.5, 2.5)
                    await asyncio.sleep(wait_seconds)
                else:
                    raise ex

        if last_exception:
            raise last_exception
        raise RuntimeError(f"Request failed after {self.max_retries} attempts: {url}")
