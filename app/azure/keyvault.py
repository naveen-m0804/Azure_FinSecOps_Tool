from typing import Dict, Any, List, Optional
from app.azure.client_base import AzureClientBase

class KeyVaultAdapter:
    @staticmethod
    async def get_key_vaults(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves Key Vaults in the subscription with pagination.
        URI: /subscriptions/{sub}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.KeyVault/vaults?api-version=2023-07-01"
        all_vaults: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_vaults.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return all_vaults
