from typing import Dict, Any, List, Optional
from app.azure.client_base import AzureClientBase

class ComputeAdapter:
    @staticmethod
    async def get_vms(client: AzureClientBase, subscription_id: str, expand_instance_view: bool = False) -> List[Dict[str, Any]]:
        expand_param = "&$expand=instanceView" if expand_instance_view else ""
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01{expand_param}"
        all_vms: List[Dict[str, Any]] = []

        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                data = resp.json()
                all_vms.extend(data.get("value", []))
                url = data.get("nextLink")
            elif expand_instance_view and resp.status_code in (400, 403, 404):
                # Fallback without $expand=instanceView
                url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01"
            else:
                return []
        except Exception:
            if expand_instance_view:
                url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/virtualMachines?api-version=2023-09-01"
            else:
                return []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_vms.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return all_vms

    @staticmethod
    async def get_vm_patch_assessment_latest(client: AzureClientBase, subscription_id: str, resource_group: str, vm_name: str) -> Dict[str, Any]:
        """
        Retrieves the latest Azure Update Manager patch assessment results for a VM.
        URI: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.Compute/virtualMachines/{vm}/patchAssessmentResults/latest?api-version=2023-09-01
        """
        url = f"https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Compute/virtualMachines/{vm_name}/patchAssessmentResults/latest?api-version=2023-09-01"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                return {"success": True, "status_code": 200, "data": resp.json()}
            return {"success": False, "status_code": resp.status_code, "error": f"HTTP {resp.status_code}"}
        except Exception as ex:
            return {"success": False, "status_code": 500, "error": str(ex)}

    @staticmethod
    async def get_vm_instance_view(client: AzureClientBase, resource_id: str) -> Dict[str, Any]:
        """
        Retrieves VM instance view to determine exact PowerState.
        Mirrors Get-AzVM -Status from Check-AzureVM-AutoShutdownStatus.txt.
        """
        clean_id = resource_id.lstrip("/")
        url = f"https://management.azure.com/{clean_id}/instanceView?api-version=2023-03-01"
        try:
            resp = await client.execute_request("GET", url)
            if resp.status_code == 200:
                data = resp.json()
                statuses = data.get("statuses", [])
                power_state = "Unknown"
                for s in statuses:
                    code = s.get("code", "")
                    if code.startswith("PowerState/"):
                        power_state = s.get("displayStatus", code.split("/")[-1])
                        break
                return {
                    "success": True,
                    "power_state": power_state,
                    "statuses": statuses,
                    "patch_status": data.get("patchStatus", {}),
                    "raw": data
                }
            return {"success": False, "power_state": "Unknown"}
        except Exception as ex:
            return {"success": False, "power_state": "Unknown", "error": str(ex)}

    @staticmethod
    async def get_disks(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/disks?api-version=2023-04-02"
        all_disks: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_disks.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return all_disks

    @staticmethod
    async def get_snapshots(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Compute/snapshots?api-version=2023-04-02"
        all_snapshots: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_snapshots.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return all_snapshots

    @staticmethod
    async def get_devtest_schedules(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves DevTestLab schedules for auto-shutdown.
        Matches taskType == "ComputeVmShutdownTask" and targetResourceId.
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.DevTestLab/schedules?api-version=2018-09-15"
        all_schedules: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_schedules.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return all_schedules
