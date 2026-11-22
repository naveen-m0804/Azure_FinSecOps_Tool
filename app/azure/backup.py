from typing import Dict, Any, List
from app.azure.client_base import AzureClientBase

class BackupAdapter:
    @staticmethod
    async def get_recovery_vaults(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.RecoveryServices/vaults?api-version=2023-01-01"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                return resp.json().get("value", [])
            return []
        except Exception:
            return []

    @staticmethod
    async def get_backup_policies(client: AzureClientBase, vault_id: str) -> List[Dict[str, Any]]:
        clean_id = vault_id.lstrip("/")
        url = f"https://management.azure.com/{clean_id}/backupPolicies?api-version=2023-02-01"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                return resp.json().get("value", [])
            return []
        except Exception:
            return []
