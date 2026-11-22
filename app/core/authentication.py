import msal
import httpx
from typing import Optional, Dict, Any, Tuple
from app.core.config import settings

ARM_RESOURCE = "https://management.azure.com"
ARM_DEFAULT_SCOPE = [f"{ARM_RESOURCE}/.default"]
GRAPH_RESOURCE = "https://graph.microsoft.com"
GRAPH_DEFAULT_SCOPE = [f"{GRAPH_RESOURCE}/.default"]

class AzureAuthService:
    @staticmethod
    def get_msal_app(tenant_id: str, client_id: str, client_secret: str) -> msal.ConfidentialClientApplication:
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        return msal.ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=authority
        )

    @staticmethod
    async def acquire_arm_token(tenant_id: str, client_id: str, client_secret: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Acquires ARM access token. Returns (token, error_message).
        Never leaks client_secret.
        """
        try:
            app = AzureAuthService.get_msal_app(tenant_id, client_id, client_secret)
            result = app.acquire_token_for_client(scopes=ARM_DEFAULT_SCOPE)
            
            if "access_token" in result:
                return result["access_token"], None
            else:
                err_desc = result.get("error_description", result.get("error", "Authentication failed"))
                return None, err_desc
        except Exception as ex:
            return None, str(ex)

    @staticmethod
    async def acquire_graph_token(tenant_id: str, client_id: str, client_secret: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Acquires Microsoft Graph access token for directory object lookups (users, groups, service principals).
        """
        try:
            app = AzureAuthService.get_msal_app(tenant_id, client_id, client_secret)
            result = app.acquire_token_for_client(scopes=GRAPH_DEFAULT_SCOPE)
            if "access_token" in result:
                return result["access_token"], None
            err_desc = result.get("error_description", result.get("error", "Graph authentication failed"))
            return None, err_desc
        except Exception as ex:
            return None, str(ex)

    @staticmethod
    async def test_credentials(tenant_id: str, client_id: str, client_secret: str) -> Tuple[bool, str, int]:
        """
        Tests whether the service principal can authenticate and query subscriptions.
        Returns (success, message, subscription_count).
        """
        token, err = await AzureAuthService.acquire_arm_token(tenant_id, client_id, client_secret)
        if not token:
            return False, f"Authentication failed: {err}", 0

        # Query subscriptions endpoint to verify ARM access
        url = f"{ARM_RESOURCE}/subscriptions?api-version=2022-12-01"
        headers = {"Authorization": f"Bearer {token}"}
        
        try:
            async with httpx.AsyncClient(timeout=settings.azure_request_timeout_seconds) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    subs = data.get("value", [])
                    enabled_subs = [s for s in subs if s.get("state") == "Enabled"]
                    return True, "Authentication and subscription access successful.", len(enabled_subs)
                else:
                    return False, f"ARM Subscriptions API returned HTTP {resp.status_code}: {resp.text}", 0
        except Exception as ex:
            return False, f"Failed to connect to Azure Resource Manager: {str(ex)}", 0
