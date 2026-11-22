from typing import Dict, Any, List
from app.azure.client_base import AzureClientBase

class NetworkAdapter:
    @staticmethod
    async def get_public_ips(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/publicIPAddresses?api-version=2023-05-01"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                return resp.json().get("value", [])
            return []
        except Exception:
            return []

    @staticmethod
    async def get_network_interfaces(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/networkInterfaces?api-version=2023-05-01"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                return resp.json().get("value", [])
            return []
        except Exception:
            return []
