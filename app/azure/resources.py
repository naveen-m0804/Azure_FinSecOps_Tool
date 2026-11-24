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
        Retrieves App Services (Web Apps and Function Apps) in the subscription with pagination.
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

    @staticmethod
    async def get_cosmos_db_accounts(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves Azure Cosmos DB accounts with pagination.
        URI: /subscriptions/{sub}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2023-04-15
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=2023-04-15"
        items: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return items

    @staticmethod
    async def get_postgresql_flexible_servers(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves PostgreSQL Flexible Servers.
        URI: /subscriptions/{sub}/providers/Microsoft.DBforPostgreSQL/flexibleServers?api-version=2022-12-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.DBforPostgreSQL/flexibleServers?api-version=2022-12-01"
        items: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return items

    @staticmethod
    async def get_mysql_flexible_servers(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves MySQL Flexible Servers.
        URI: /subscriptions/{sub}/providers/Microsoft.DBforMySQL/flexibleServers?api-version=2021-05-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.DBforMySQL/flexibleServers?api-version=2021-05-01"
        items: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return items

    @staticmethod
    async def get_public_ip_addresses(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves all Public IP addresses in the subscription.
        URI: /subscriptions/{sub}/providers/Microsoft.Network/publicIPAddresses?api-version=2023-05-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/publicIPAddresses?api-version=2023-05-01"
        items: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return items

    @staticmethod
    async def get_load_balancers(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves all Load Balancers in the subscription.
        URI: /subscriptions/{sub}/providers/Microsoft.Network/loadBalancers?api-version=2023-05-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/loadBalancers?api-version=2023-05-01"
        items: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return items

    @staticmethod
    async def get_application_gateways(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves all Application Gateways in the subscription.
        URI: /subscriptions/{sub}/providers/Microsoft.Network/applicationGateways?api-version=2023-05-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Network/applicationGateways?api-version=2023-05-01"
        items: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return items

    @staticmethod
    async def get_managed_clusters(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves all AKS Managed Clusters in the subscription.
        URI: /subscriptions/{sub}/providers/Microsoft.ContainerService/managedClusters?api-version=2023-06-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.ContainerService/managedClusters?api-version=2023-06-01"
        items: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return items

    @staticmethod
    async def get_advisor_recommendations(client: AzureClientBase, subscription_id: str, category: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Retrieves real-time Azure Advisor recommendations for the subscription.
        URI: /subscriptions/{sub}/providers/Microsoft.Advisor/recommendations?api-version=2020-01-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Advisor/recommendations?api-version=2020-01-01"
        params = {}
        if category:
            params["$filter"] = f"Category eq '{category}'"

        items: List[Dict[str, Any]] = []
        while url:
            try:
                resp = await client.execute_request("GET", url, params=params if params and "?" not in url else None)
                if resp.status_code == 200:
                    data = resp.json()
                    items.extend(data.get("value", []))
                    url = data.get("nextLink")
                    params = None
                else:
                    break
            except Exception:
                break

        return items

    @staticmethod
    async def get_available_stacks(client: AzureClientBase, os_type: str = "Linux") -> List[Dict[str, Any]]:
        """
        Retrieves supported and deprecated runtime stacks directly from Azure App Service platform metadata.
        URI: /providers/Microsoft.Web/availableStacks?api-version=2022-09-01&osTypeSelected={os_type}
        """
        url = f"https://management.azure.com/providers/Microsoft.Web/availableStacks?api-version=2022-09-01&osTypeSelected={os_type}"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("value", [])
        except Exception:
            pass
        return []

    @staticmethod
    async def get_resource_health_events(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves Azure Service Health and Resource Health planned maintenance, retirement, and advisory events.
        URI: /subscriptions/{sub}/providers/Microsoft.ResourceHealth/events?api-version=2022-10-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.ResourceHealth/events?api-version=2022-10-01"
        items: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    items.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return items

