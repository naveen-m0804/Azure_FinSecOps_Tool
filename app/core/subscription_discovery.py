import httpx
from typing import List, Optional, Dict, Any
from app.core.authentication import AzureAuthService, ARM_RESOURCE
from app.schemas.subscription import SubscriptionModel
from app.core.config import settings
from app.utils.validators import is_valid_guid

class SubscriptionDiscoveryService:
    @staticmethod
    async def validate_single_subscription(
        tenant_id: str,
        client_id: str,
        client_secret: Optional[str],
        subscription_id: str
    ) -> Dict[str, Any]:
        """Validate live accessibility and fetch metadata for a single Azure subscription."""
        clean_sub_id = subscription_id.strip() if subscription_id else ""
        if not clean_sub_id:
            return {
                "valid": False,
                "subscription_id": clean_sub_id,
                "error": "Subscription ID cannot be blank."
            }

        # Real Azure Service Principal Validation
        if not is_valid_guid(clean_sub_id):
            return {
                "valid": False,
                "subscription_id": clean_sub_id,
                "error": "Invalid GUID format."
            }

        token, err = await AzureAuthService.acquire_arm_token(tenant_id, client_id, client_secret)
        if not token:
            return {
                "valid": False,
                "subscription_id": clean_sub_id,
                "error": f"Azure authentication failed: {err}"
            }

        url = f"{ARM_RESOURCE}/subscriptions/{clean_sub_id}?api-version=2022-12-01"
        headers = {"Authorization": f"Bearer {token}"}

        try:
            async with httpx.AsyncClient(timeout=settings.azure_request_timeout_seconds) as client:
                resp = await client.get(url, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return {
                        "valid": True,
                        "subscription_id": data.get("subscriptionId", clean_sub_id),
                        "display_name": data.get("displayName", clean_sub_id),
                        "state": data.get("state", "Enabled"),
                        "message": "Verified & Accessible"
                    }
                elif resp.status_code == 403:
                    return {
                        "valid": False,
                        "subscription_id": clean_sub_id,
                        "error": "Access Denied (403) - Service Principal lacks Reader role."
                    }
                elif resp.status_code == 404:
                    return {
                        "valid": False,
                        "subscription_id": clean_sub_id,
                        "error": "Subscription Not Found (404) in this Azure Tenant."
                    }
                else:
                    return {
                        "valid": False,
                        "subscription_id": clean_sub_id,
                        "error": f"Azure API returned status {resp.status_code}."
                    }
        except Exception as ex:
            return {
                "valid": False,
                "subscription_id": clean_sub_id,
                "error": f"Connection error: {str(ex)}"
            }

    @staticmethod
    async def discover_subscriptions(
        tenant_id: str,
        client_id: str,
        client_secret: Optional[str] = None,
        target_subscription_ids: Optional[List[str]] = None
    ) -> List[SubscriptionModel]:
        # Filter target IDs if provided
        clean_target_ids = [s.strip().lower() for s in target_subscription_ids if s and s.strip()] if target_subscription_ids else []

        token, err = await AzureAuthService.acquire_arm_token(tenant_id, client_id, client_secret)
        if not token:
            raise ValueError(f"Could not authenticate to discover subscriptions: {err}")

        headers = {"Authorization": f"Bearer {token}"}
        subscriptions: List[SubscriptionModel] = []

        async with httpx.AsyncClient(timeout=settings.azure_request_timeout_seconds) as client:
            if clean_target_ids:
                # Target-specific validation mode: Only discover and retain entered, accessible subscription IDs
                for target_id in clean_target_ids:
                    url = f"{ARM_RESOURCE}/subscriptions/{target_id}?api-version=2022-12-01"
                    try:
                        resp = await client.get(url, headers=headers)
                        if resp.status_code == 200:
                            data = resp.json()
                            sub_id = data.get("subscriptionId", target_id)
                            subscriptions.append(
                                SubscriptionModel(
                                    id=data.get("id", f"/subscriptions/{sub_id}"),
                                    subscription_id=sub_id,
                                    display_name=data.get("displayName", sub_id),
                                    state=data.get("state", "Enabled"),
                                    tenant_id=tenant_id,
                                    authorization_source=data.get("authorizationSource", "RoleAssignment"),
                                    cost_permission=True,
                                    security_permission=True,
                                    monitor_permission=True,
                                )
                            )
                    except Exception:
                        continue
                return subscriptions

            # Full auto-discovery mode across the entire tenant
            url = f"{ARM_RESOURCE}/subscriptions?api-version=2022-12-01"
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                raise RuntimeError(f"Subscription discovery failed with HTTP {resp.status_code}: {resp.text}")
            
            data = resp.json()
            for item in data.get("value", []):
                if item.get("state") == "Enabled":
                    sub_id = item.get("subscriptionId", "")
                    subscriptions.append(
                        SubscriptionModel(
                            id=item.get("id", f"/subscriptions/{sub_id}"),
                            subscription_id=sub_id,
                            display_name=item.get("displayName", sub_id),
                            state=item.get("state", "Enabled"),
                            tenant_id=tenant_id,
                            authorization_source=item.get("authorizationSource", "RoleAssignment"),
                            cost_permission=True,
                            security_permission=True,
                            monitor_permission=True,
                        )
                    )

        return subscriptions
