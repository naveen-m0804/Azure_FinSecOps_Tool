from typing import Dict, Any, List, Optional
from app.azure.client_base import AzureClientBase

class ResourcesAdapter:
    @staticmethod
    async def get_subscription_resources(client: AzureClientBase, subscription_id: str, filter_str: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieves resources in subscription with full pagination.
        URI: /subscriptions/{sub}/resources?api-version=2021-04-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/resources?api-version=2021-04-01"
        params = {}
        if filter_str:
            params["$filter"] = filter_str

        all_resources: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url, params=params if params and "?" not in url else None)
                if resp.status_code == 200:
                    data = resp.json()
                    all_resources.extend(data.get("value", []))
                    url = data.get("nextLink")
                    params = None # nextLink already contains query parameters
                else:
                    break
            except Exception:
                break

        return all_resources

    @staticmethod
    async def get_app_services(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves App Services (Web Apps) in the subscription with pagination.
        URI: /subscriptions/{sub}/providers/Microsoft.Web/sites?api-version=2022-09-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Web/sites?api-version=2022-09-01"
        all_sites: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_sites.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return all_sites

    @staticmethod
    async def get_app_service_plans(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves App Service Plans (serverfarms) in the subscription with pagination.
        URI: /subscriptions/{sub}/providers/Microsoft.Web/serverfarms?api-version=2022-09-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Web/serverfarms?api-version=2022-09-01"
        all_plans: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_plans.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return all_plans

    @staticmethod
    async def get_sql_servers(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves Azure SQL Servers in the subscription with pagination.
        URI: /subscriptions/{sub}/providers/Microsoft.Sql/servers?api-version=2022-05-01-preview
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Sql/servers?api-version=2022-05-01-preview"
        all_servers: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_servers.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return all_servers

    @staticmethod
    async def get_redis_caches(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves Azure Cache for Redis instances with pagination.
        URI: /subscriptions/{sub}/providers/Microsoft.Cache/Redis?api-version=2023-08-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Cache/Redis?api-version=2023-08-01"
        all_caches: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_caches.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return all_caches
