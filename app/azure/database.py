from typing import Dict, Any, List
from app.azure.client_base import AzureClientBase

class DatabaseAdapter:
    @staticmethod
    async def get_sql_servers(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Sql/servers?api-version=2021-11-01"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                return resp.json().get("value", [])
            return []
        except Exception:
            return []

    @staticmethod
    async def get_sql_databases(client: AzureClientBase, server_id: str) -> List[Dict[str, Any]]:
        clean_id = server_id.lstrip("/")
        url = f"https://management.azure.com/{clean_id}/databases?api-version=2021-11-01"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                return resp.json().get("value", [])
            return []
        except Exception:
            return []
