from typing import Dict, Any, List, Optional
from app.azure.client_base import AzureClientBase

class StorageAdapter:
    @staticmethod
    async def get_storage_accounts(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves storage accounts in the subscription with pagination.
        URI: /subscriptions/{sub}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"
        all_accounts: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_accounts.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return all_accounts

    @staticmethod
    async def get_lifecycle_policy(client: AzureClientBase, storage_account_id: str) -> Dict[str, Any]:
        """
        Retrieves lifecycle management policy for storage account.
        Mirrors Get-AzStorageAccountManagementPolicy from LCM_Status_Check_Top_Storageaccounts.txt.
        """
        clean_id = storage_account_id.lstrip("/")
        url = f"https://management.azure.com/{clean_id}/managementPolicies/default?api-version=2023-01-01"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                data = resp.json()
                props = data.get("properties", {})
                policy = props.get("policy", {})
                rules = policy.get("rules", [])
                total_rules = len(rules)
                enabled_rules = [r for r in rules if r.get("enabled", True)]
                
                if total_rules == 0:
                    status = "Configured - No Rules"
                elif len(enabled_rules) > 0:
                    status = "Configured"
                else:
                    status = "Configured - All Rules Disabled"

                rule_names = "; ".join([r.get("name", "Unnamed") for r in rules])
                enabled_rule_names = "; ".join([r.get("name", "Unnamed") for r in enabled_rules])

                return {
                    "success": True,
                    "status": status,
                    "total_rules": total_rules,
                    "enabled_rules_count": len(enabled_rules),
                    "rule_names": rule_names,
                    "enabled_rule_names": enabled_rule_names,
                    "last_modified": props.get("lastModifiedTime"),
                    "raw": data
                }
            elif resp.status_code == 404:
                return {
                    "success": True,
                    "status": "Not Configured",
                    "total_rules": 0,
                    "enabled_rules_count": 0,
                    "rule_names": "",
                    "enabled_rule_names": "",
                    "raw": None
                }
            return {
                "success": False,
                "error": f"HTTP {resp.status_code}: {resp.text}",
                "status": "Error"
            }
        except Exception as ex:
            return {"success": False, "error": str(ex), "status": "Error"}
