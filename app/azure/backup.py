import logging
from typing import Dict, Any, List
from app.azure.client_base import AzureClientBase

logger = logging.getLogger("azure_finsecops.azure.backup")

class BackupAdapter:
    @staticmethod
    async def get_recovery_vaults(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Discovers all Recovery Services Vaults in a given subscription.
        Handles pagination and distinguishes permission/API errors from empty results.
        """
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.RecoveryServices/vaults?api-version=2023-01-01"
        vaults: List[Dict[str, Any]] = []

        while url:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                data = resp.json()
                vaults.extend(data.get("value", []))
                url = data.get("nextLink")
            elif resp.status_code in (401, 403):
                raise PermissionError(f"Permission denied ({resp.status_code}) accessing Recovery Services Vaults: {resp.text}")
            elif resp.status_code == 404:
                return []
            else:
                raise RuntimeError(f"Failed to fetch Recovery Services Vaults (HTTP {resp.status_code}): {resp.text}")

        return vaults

    @staticmethod
    async def get_backup_policies(client: AzureClientBase, vault_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves all backup protection policies configured within a specific Recovery Services Vault.
        """
        clean_id = vault_id.lstrip("/")
        url = f"https://management.azure.com/{clean_id}/backupPolicies?api-version=2023-02-01"
        policies: List[Dict[str, Any]] = []

        while url:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                data = resp.json()
                policies.extend(data.get("value", []))
                url = data.get("nextLink")
            elif resp.status_code in (401, 403):
                raise PermissionError(f"Permission denied ({resp.status_code}) accessing Backup Policies for vault '{clean_id}': {resp.text}")
            elif resp.status_code == 404:
                return []
            else:
                raise RuntimeError(f"Failed to fetch Backup Policies for vault '{clean_id}' (HTTP {resp.status_code}): {resp.text}")

        return policies

    @staticmethod
    async def get_backup_protected_items(client: AzureClientBase, vault_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves protected items in a vault to obtain actual backup storage volume where available.
        """
        clean_id = vault_id.lstrip("/")
        url = f"https://management.azure.com/{clean_id}/backupProtectedItems?api-version=2023-02-01"
        items: List[Dict[str, Any]] = []

        try:
            while url:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
        except Exception as ex:
            logger.debug("Failed to retrieve backup protected items for %s: %s", clean_id, ex)

        return items
