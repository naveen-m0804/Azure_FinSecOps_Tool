import logging
import asyncio
from typing import Dict, Any, List, Optional
from app.azure.client_base import AzureClientBase
from app.core.authentication import AzureAuthService
from app.azure.compute import ComputeAdapter
from app.azure.resources import ResourcesAdapter

logger = logging.getLogger("azure_finsecops.ai_resource_querier")

class AzureAIResourceQuerier:
    @staticmethod
    async def get_client(tenant_id: str, client_id: str, client_secret: str) -> Optional[AzureClientBase]:
        try:
            token, err = await AzureAuthService.acquire_arm_token(tenant_id, client_id, client_secret)
            if not token:
                logger.warning(f"Could not acquire token for AI Querier: {err}")
                return None
            return AzureClientBase(token=token, timeout=45)
        except Exception as ex:
            logger.error(f"Error acquiring Azure client for AI querier: {ex}")
            return None

    @classmethod
    async def query_resource_graph(
        cls,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscriptions: List[Any],
        kql_query: str
    ) -> Dict[str, Any]:
        """
        Executes dynamic KQL query across subscriptions using Azure Resource Graph (ARG).
        Zero agent footprint - returns real-time tenant resources.
        """
        client = await cls.get_client(tenant_id, client_id, client_secret)
        if not client:
            return {"data": [], "count": 0, "error": "Could not authenticate with Azure"}

        sub_ids = []
        for s in subscriptions:
            s_id = getattr(s, "subscription_id", None) or s.get("subscription_id")
            if s_id:
                sub_ids.append(s_id)

        if not sub_ids:
            return {"data": [], "count": 0, "error": "No verified subscriptions in session"}

        url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
        payload = {
            "subscriptions": sub_ids,
            "query": kql_query,
            "options": {
                "resultFormat": "objectArray"
            }
        }

        try:
            resp = await client.execute_request("POST", url, json_data=payload)
            if resp.status_code == 200:
                data = resp.json()
                rows = data.get("data", [])
                total = data.get("totalRecords", len(rows))
                return {"data": rows, "count": total, "error": None}
            else:
                return {"data": [], "count": 0, "error": f"HTTP {resp.status_code}: {resp.text}"}
        except Exception as ex:
            logger.warning(f"ARG query failed ({ex}), falling back to ARM adapters.")
            return {"data": [], "count": 0, "error": str(ex)}

    @classmethod
    async def list_vms(
        cls,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscriptions: List[Any],
        sub_filter: Optional[str] = None,
        status_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Lists VMs across all accessible subscriptions with live PowerState and hardware specs.
        status_filter can be: 'deallocated', 'running', 'stopped', or None.
        """
        client = await cls.get_client(tenant_id, client_id, client_secret)
        if not client:
            return []

        all_vms = []

        target_subs = []
        for s in subscriptions:
            s_id = getattr(s, "subscription_id", None) or s.get("subscription_id")
            s_name = getattr(s, "display_name", None) or s.get("display_name", s_id)
            if sub_filter:
                flt = sub_filter.lower().strip()
                if flt not in s_name.lower() and flt not in s_id.lower():
                    continue
            target_subs.append((s_id, s_name))

        async def fetch_sub_vms(sub_id: str, sub_name: str):
            sub_results = []
            try:
                raw_vms = await ComputeAdapter.get_vms(client, sub_id, expand_instance_view=True)
                for vm in raw_vms:
                    vm_id = vm.get("id", "")
                    vm_name = vm.get("name", "Unknown-VM")
                    location = vm.get("location", "global")
                    rg = "Unknown"
                    if "/resourceGroups/" in vm_id:
                        rg = vm_id.split("/resourceGroups/")[1].split("/")[0]

                    # Hardware
                    hw = vm.get("properties", {}).get("hardwareProfile", {})
                    vm_size = hw.get("vmSize", "Unknown")

                    # Storage Profile & OS
                    storage_prof = vm.get("properties", {}).get("storageProfile", {})
                    image_ref = storage_prof.get("imageReference", {})
                    os_disk = storage_prof.get("osDisk", {})
                    os_type = os_disk.get("osType", "Unknown")
                    os_offer = image_ref.get("offer", "")
                    os_sku = image_ref.get("sku", "")
                    os_version = f"{os_offer} {os_sku}".strip() or os_type

                    # OS Disk details
                    os_disk_sku = os_disk.get("managedDisk", {}).get("storageAccountType", "Standard_LRS")
                    os_disk_size = os_disk.get("diskSizeGB", 30)

                    # Power State
                    instance_view = vm.get("properties", {}).get("instanceView", {})
                    statuses = instance_view.get("statuses", [])
                    power_state = "Unknown"
                    for st in statuses:
                        code = st.get("code", "")
                        if code.startswith("PowerState/"):
                            power_state = st.get("displayStatus", code.replace("PowerState/", "").capitalize())
                            break

                    if power_state == "Unknown" and vm_id:
                        try:
                            iv_res = await ComputeAdapter.get_vm_instance_view(client, vm_id)
                            if iv_res.get("success"):
                                power_state = iv_res.get("power_state", "Unknown")
                        except Exception:
                            pass

                    # Filter by status if requested
                    if status_filter:
                        sf = status_filter.lower()
                        ps = power_state.lower()
                        if sf == "deallocated" and "deallocated" not in ps and "stopped" not in ps:
                            continue
                        elif sf == "running" and "running" not in ps:
                            continue
                        elif sf == "stopped" and "stopped" not in ps and "deallocated" not in ps:
                            continue

                    sub_results.append({
                        "name": vm_name,
                        "id": vm_id,
                        "subscription_id": sub_id,
                        "subscription_name": sub_name,
                        "resource_group": rg,
                        "location": location,
                        "vm_size": vm_size,
                        "os_type": os_type,
                        "os_version": os_version,
                        "power_state": power_state,
                        "os_disk_sku": os_disk_sku,
                        "os_disk_size_gb": os_disk_size,
                        "tags": vm.get("tags") or {}
                    })
            except Exception as ex:
                logger.warning(f"Error fetching VMs for sub {sub_id}: {ex}")
            return sub_results

        tasks = [fetch_sub_vms(sid, sname) for sid, sname in target_subs]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                all_vms.extend(r)

        return all_vms

    @classmethod
    async def list_storage_accounts(
        cls,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscriptions: List[Any],
        sub_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        client = await cls.get_client(tenant_id, client_id, client_secret)
        if not client:
            return []

        all_storage = []
        for s in subscriptions:
            s_id = getattr(s, "subscription_id", None) or s.get("subscription_id")
            s_name = getattr(s, "display_name", None) or s.get("display_name", s_id)
            if sub_filter:
                flt = sub_filter.lower().strip()
                if flt not in s_name.lower() and flt not in s_id.lower():
                    continue

            url = f"https://management.azure.com/subscriptions/{s_id}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01"
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("value", []):
                        r_id = item.get("id", "")
                        rg = "Unknown"
                        if "/resourceGroups/" in r_id:
                            rg = r_id.split("/resourceGroups/")[1].split("/")[0]
                        all_storage.append({
                            "name": item.get("name"),
                            "subscription_id": s_id,
                            "subscription_name": s_name,
                            "resource_group": rg,
                            "location": item.get("location"),
                            "sku": item.get("sku", {}).get("name", "Standard_LRS"),
                            "tier": item.get("sku", {}).get("tier", "Standard"),
                            "kind": item.get("kind", "StorageV2"),
                            "https_only": item.get("properties", {}).get("supportsHttpsTrafficOnly", True),
                            "access_tier": item.get("properties", {}).get("accessTier", "Hot")
                        })
            except Exception as ex:
                logger.warning(f"Error querying storage accounts for sub {s_id}: {ex}")

        return all_storage

    @classmethod
    async def list_disks(
        cls,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscriptions: List[Any],
        unattached_only: bool = False
    ) -> List[Dict[str, Any]]:
        client = await cls.get_client(tenant_id, client_id, client_secret)
        if not client:
            return []

        all_disks = []
        for s in subscriptions:
            s_id = getattr(s, "subscription_id", None) or s.get("subscription_id")
            s_name = getattr(s, "display_name", None) or s.get("display_name", s_id)
            url = f"https://management.azure.com/subscriptions/{s_id}/providers/Microsoft.Compute/disks?api-version=2023-04-02"
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("value", []):
                        r_id = item.get("id", "")
                        rg = "Unknown"
                        if "/resourceGroups/" in r_id:
                            rg = r_id.split("/resourceGroups/")[1].split("/")[0]
                        
                        props = item.get("properties", {})
                        disk_state = props.get("diskState", "Unattached")
                        managed_by = item.get("managedBy")

                        is_unattached = disk_state.lower() == "unattached" or not managed_by
                        if unattached_only and not is_unattached:
                            continue

                        all_disks.append({
                            "name": item.get("name"),
                            "subscription_id": s_id,
                            "subscription_name": s_name,
                            "resource_group": rg,
                            "location": item.get("location"),
                            "sku": item.get("sku", {}).get("name", "Standard_LRS"),
                            "size_gb": props.get("diskSizeGB", 0),
                            "disk_state": disk_state,
                            "is_unattached": is_unattached,
                            "managed_by": managed_by or "None (Orphan)"
                        })
            except Exception as ex:
                logger.warning(f"Error querying disks for sub {s_id}: {ex}")

        return all_disks
