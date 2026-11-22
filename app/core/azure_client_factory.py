from typing import Optional, Dict
from app.core.authentication import AzureAuthService
from app.azure.client_base import AzureClientBase
from app.core.config import settings

class AzureClientFactory:
    def __init__(self):
        self._tokens: Dict[str, str] = {}

    async def get_client_for_session(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: Optional[str] = None
    ) -> AzureClientBase:
        if not client_secret:
            raise ValueError("Client secret is required to acquire Azure ARM token.")

        token, err = await AzureAuthService.acquire_arm_token(tenant_id, client_id, client_secret)
        if not token:
            raise RuntimeError(f"Authentication failed: {err}")

        return AzureClientBase(
            token=token,
            timeout=settings.azure_request_timeout_seconds,
            max_retries=settings.azure_max_retries
        )

azure_client_factory = AzureClientFactory()
