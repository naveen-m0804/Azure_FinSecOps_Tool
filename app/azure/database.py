import logging
from typing import Dict, Any, List, Optional
from app.azure.client_base import AzureClientBase

logger = logging.getLogger("azure_finsecops.database")


class DatabaseAdapter:
    @staticmethod
    async def get_sql_servers(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """Retrieves Azure SQL Servers in subscription with pagination."""
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Sql/servers?api-version=2021-11-01"
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
            except Exception as ex:
                logger.warning(f"Error fetching SQL servers for sub {subscription_id}: {ex}")
                break

        return all_servers

    @staticmethod
    async def get_sql_virtual_machines(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """Retrieves Azure SQL Virtual Machines (Microsoft.SqlVirtualMachine/sqlVirtualMachines) with pagination."""
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.SqlVirtualMachine/sqlVirtualMachines?api-version=2022-02-01"
        all_sql_vms: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_sql_vms.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return all_sql_vms

    @staticmethod
    async def get_sql_databases(client: AzureClientBase, server_id: str) -> List[Dict[str, Any]]:
        """Retrieves SQL databases under a server with pagination."""
        clean_id = server_id.lstrip("/")
        url: Optional[str] = f"https://management.azure.com/{clean_id}/databases?api-version=2021-11-01"
        all_databases: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_databases.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception as ex:
                logger.warning(f"Error fetching databases for server {server_id}: {ex}")
                break

        return all_databases

    @staticmethod
    async def get_postgres_flexible_servers(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """Retrieves PostgreSQL Flexible Servers with pagination."""
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.DBforPostgreSQL/flexibleServers?api-version=2022-12-01"
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
    async def get_mysql_flexible_servers(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """Retrieves MySQL Flexible Servers with pagination."""
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.DBforMySQL/flexibleServers?api-version=2021-05-01"
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
