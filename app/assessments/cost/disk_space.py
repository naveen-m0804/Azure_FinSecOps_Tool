import datetime
import time
import re
from typing import List, Dict, Any, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.monitor import MonitorAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment, matches_target_tags


def _extract_resource_group(resource_id: str, fallback: Optional[str] = None) -> str:
    """Extracts valid resource group name from resource ID, avoiding 'Unknown'."""
    if fallback and fallback not in ("Unknown", "--", "", "Subscription Scope"):
        return fallback
    if resource_id:
        m = re.search(r"/resourceGroups/([^/]+)", resource_id, re.IGNORECASE)
        if m:
            return m.group(1)
        parsed = parse_azure_resource_id(resource_id)
        rg = parsed.get("resource_group")
        if rg and rg not in ("Unknown", "--", ""):
            return rg
    return fallback or "--"


class DiskSpaceAssessment(BaseAssessment):
    assessment_id = "disk_space"
    code = "COST-09"
    category = "cost"
    name = "Disk Space Alert"
    description = "Audit managed disk provisioned capacity against utilization thresholds to flag overprovisioned storage and capacity exhaustion risks."
    purpose = "Right-size grossly oversized managed disks, eliminate unattached storage costs, and prevent volume full downtime."
    required_permissions = ["Microsoft.Compute/disks/read", "Microsoft.Compute/virtualMachines/read", "Reader"]
    required_data_sources = ["Microsoft.Compute Disks API & Virtual Machines Storage Profiles"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()
        start_iso, end_iso = f"{cost_start}T00:00:00Z", f"{cost_end}T23:59:59Z"

        for sub in context.subscriptions:
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=cost_start,
                end_date=cost_end,
                resource_type_filter="Microsoft.Compute/disks"
            )

            # 1. Map VM storage profiles to associate disks with host VMs
            try:
                vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id)
            except Exception as ex:
                vms = []
                errors.append(f"Failed to fetch VMs for sub {sub.subscription_id}: {ex}")

            vm_disk_map: Dict[str, str] = {}
            vm_id_map: Dict[str, str] = {}
            vm_env_map: Dict[str, str] = {}
            for vm in vms:
                vm_name = vm.get("name", "")
                vm_id = vm.get("id", "")
                vm_tags = vm.get("tags") or {}
                rg_vm = _extract_resource_group(vm_id)
                env_vm = resolve_environment(tags=vm_tags, resource_name=vm_name, resource_group=rg_vm, prod_tags=context.prod_tags, test_tags=context.test_tags, target_tags=context.target_tags)

                props = vm.get("properties", {})
                storage_profile = props.get("storageProfile", {})
                os_disk = storage_profile.get("osDisk", {})
                if os_disk.get("managedDisk", {}).get("id"):
                    norm_os_id = normalize_resource_id(os_disk["managedDisk"]["id"])
                    vm_disk_map[norm_os_id] = vm_name
                    vm_id_map[norm_os_id] = vm_id
                    vm_env_map[norm_os_id] = env_vm

                for dd in storage_profile.get("dataDisks", []):
                    if dd.get("managedDisk", {}).get("id"):
                        norm_dd_id = normalize_resource_id(dd["managedDisk"]["id"])
                        vm_disk_map[norm_dd_id] = vm_name
                        vm_id_map[norm_dd_id] = vm_id
                        vm_env_map[norm_dd_id] = env_vm

            # 2. Query all managed disks in subscription
            try:
                disks = await ComputeAdapter.get_disks(context.client, sub.subscription_id)
            except Exception as ex:
                disks = []
                errors.append(f"Failed to fetch disks for sub {sub.subscription_id}: {ex}")

            for disk in disks:
                disk_tags = disk.get("tags") or {}
                if not matches_target_tags(disk_tags, context.target_tags):
                    continue
                resources_evaluated += 1
                disk_name = disk.get("name", "")
                disk_id = disk.get("id", "")
                norm_id = normalize_resource_id(disk_id)
                props = disk.get("properties", {})
                size_gb = int(props.get("diskSizeGB") or 128)
                sku_info = disk.get("sku", {})
                sku_name = sku_info.get("name", "Premium_LRS")
                disk_state = props.get("diskState", "Attached")
                managed_by = str(disk.get("managedBy") or props.get("managedBy") or "").strip()
                disk_state = str(props.get("diskState", "Attached")).strip()

                host_vm = (
                    vm_disk_map.get(norm_id)
                    or (managed_by.split("/")[-1] if managed_by else ("Unattached" if disk_state.lower() in ("unattached", "reserved") else "Attached VM"))
                )
                parent_vm_id = vm_id_map.get(norm_id) or managed_by or ""
                is_unattached = disk_state.lower() in ("unattached", "reserved") or (not managed_by and norm_id not in vm_disk_map)

                rg_name = _extract_resource_group(disk_id, disk.get("resourceGroup"))
                disk_tags = disk.get("tags") or {}
                env_name = vm_env_map.get(norm_id) or resolve_environment(
                    tags=disk_tags,
                    resource_name=disk_name,
                    resource_group=rg_name,
                    prod_tags=context.prod_tags,
                    test_tags=context.test_tags,
                    target_tags=context.target_tags
                )

                # Cost lookup
                cost_info = cost_map.get(norm_id, {})
                actual_cost = cost_info.get("cost")
                currency = cost_info.get("currency", context.currency)
                disk_region = disk.get("location", "")

                curr_cost: Optional[float] = float(actual_cost) if (actual_cost is not None and actual_cost > 0) else await PricingEngine.get_disk_monthly_price(sku_name, size_gb, disk_region, currency)

                # Calculate provisioned IOPS based on Azure Managed Disk specs
                prov_iops = int(props.get("diskIOPSReadWrite") or 0)
                if prov_iops <= 0:
                    sku_upper = sku_name.upper()
                    if "PREMIUM" in sku_upper:
                        prov_iops = 500 if size_gb <= 128 else (1100 if size_gb <= 256 else (2300 if size_gb <= 512 else 5000))
                    elif "STANDARDSSD" in sku_upper:
                        prov_iops = 500
                    else:
                        prov_iops = 500

                # 3. Determine real-time Disk Utilization using host hypervisor metrics
                # Mirrors Underutilized_OS_Disk_IOPS_Report.txt & Underutilized_Data_Disk_IOPS_Report.txt
                # Do NOT query in-guest diagnostics/extensions (WAD/AMA) which are often unconfigured or emit corrupt values.
                utilization_pct: Optional[float] = None
                consumed_iops: float = 0.0
                iops_utilization: float = 0.0

                if is_unattached:
                    utilization_pct = 0.0
                    consumed_iops = 0.0
                    iops_utilization = 0.0
                elif parent_vm_id:
                    # Query parent VM directly using PT1H hourly grain
                    metric_vm = await MonitorAdapter.get_metrics(
                        context.client,
                        resource_id=parent_vm_id,
                        metric_names="OS Disk Read Operations/Sec,OS Disk Write Operations/Sec,Data Disk Read Operations/Sec,Data Disk Write Operations/Sec",
                        start_time=start_iso,
                        end_time=end_iso,
                        time_grain="PT1H",
                        aggregation="Average"
                    )
                    if metric_vm.get("success"):
                        vm_m = metric_vm.get("metrics", {})
                        os_r = vm_m.get("os disk read operations/sec") or vm_m.get("OS Disk Read Operations/Sec") or 0.0
                        os_w = vm_m.get("os disk write operations/sec") or vm_m.get("OS Disk Write Operations/Sec") or 0.0
                        data_r = vm_m.get("data disk read operations/sec") or vm_m.get("Data Disk Read Operations/Sec") or 0.0
                        data_w = vm_m.get("data disk write operations/sec") or vm_m.get("Data Disk Write Operations/Sec") or 0.0

                        is_os_disk = ("os" in disk_name.lower() or "osdisk" in disk_name.lower() or props.get("osType"))
                        read_io = os_r if is_os_disk else data_r
                        write_io = os_w if is_os_disk else data_w
                        consumed_iops = round(read_io + write_io, 2)

                        if prov_iops > 0:
                            iops_utilization = round((consumed_iops / prov_iops) * 100.0, 2)

                # Per Savings Formula Guide (R10): Supporting evidence only; no standalone savings formula.
                if utilization_pct is not None:
                    utilization_pct = max(0.0, min(100.0, round(float(utilization_pct), 1)))
                    used_gb = round(size_gb * (utilization_pct / 100.0), 1)
                    free_gb = round(max(0.0, size_gb - used_gb), 1)
                else:
                    used_gb = None
                    free_gb = None

                # 4. Sizing & Capacity Alert Categorization (Supporting Evidence Only - 0 standalone savings)
                if is_unattached:
                    status_str = "Unattached Disk (100% Free)"
                    severity = "High"
                    recommendation = f"Managed disk '{disk_name}' ({size_gb} GB) is unattached. Refer to Orphan Resources for deletion savings."
                    calc_method = "Supporting evidence only; no standalone savings formula (avoid duplicate counting)"
                elif utilization_pct is not None and utilization_pct >= 90.0:
                    status_str = f"Critical Capacity ({utilization_pct:.1f}% Used)"
                    severity = "Critical"
                    recommendation = f"Disk '{disk_name}' on '{host_vm}' has reached {utilization_pct:.1f}% capacity. Expand disk volume immediately to prevent application failure."
                    calc_method = "Capacity expansion required to prevent downtime"
                elif utilization_pct is not None and utilization_pct >= 80.0:
                    status_str = f"High Capacity ({utilization_pct:.1f}% Used)"
                    severity = "High"
                    recommendation = f"Disk '{disk_name}' on '{host_vm}' is at {utilization_pct:.1f}% capacity ({free_gb:.1f} GB free). Monitor volume and plan expansion."
                    calc_method = "Capacity monitoring required"
                else:
                    status_str = f"Attached ({consumed_iops:.1f} Avg IOPS | {iops_utilization:.1f}% IOPS)"
                    severity = "Informational"
                    recommendation = f"Disk '{disk_name}' on '{host_vm}' ({size_gb} GB, {sku_name}). Guest filesystem space requires Azure Monitor Agent / Log Analytics; calculate any resize savings on Underutilized OS/Data Disk tabs."
                    calc_method = "Supporting evidence only; no standalone savings formula (avoid duplicate counting)"

                findings.append(
                    FindingModel(
                        finding_id=f"cost09-{disk_name[:16]}-{size_gb}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=rg_name,
                        resource_name=disk_name,
                        resource_type="Microsoft.Compute/disks",
                        resource_id=disk_id,
                        region=disk_region or "global",
                        severity=severity,
                        status=status_str,
                        current_configuration=f"Host: {host_vm} | Tier: {sku_name} | Capacity: {size_gb} GB | Avg IOPS: {consumed_iops}",
                        measured_value=f"{utilization_pct:.1f}% Used ({free_gb:.1f} GB Free)" if utilization_pct is not None else f"{consumed_iops:.1f} Avg IOPS ({iops_utilization:.1f}% of {prov_iops} IOPS)",
                        recommended_configuration="Use as supporting evidence; calculate approved resizing on Underutilized OS/Data Disk tabs",
                        recommendation=recommendation,
                        metric_period=f"Last Completed Month ({cost_month})",
                        data_source="Azure Monitor & Microsoft.Compute Disks API",
                        evidence={
                            "vm_name": host_vm,
                            "attached_vm": host_vm,
                            "total_capacity_gb": size_gb,
                            "used_space_gb": used_gb,
                            "free_space_gb": free_gb,
                            "utilization_pct": utilization_pct,
                            "consumed_iops": consumed_iops,
                            "iops_utilization": iops_utilization,
                            "environment": env_name,
                            "actual_cost_mtd": round(curr_cost, 2) if curr_cost is not None else None,
                            "disk_tier": sku_name,
                            "cost_month": cost_month
                        },
                        current_monthly_cost=round(curr_cost, 2) if curr_cost is not None else None,
                        estimated_monthly_savings=None,
                        estimated_annual_savings=None,
                        currency=currency,
                        savings_type="Supporting Evidence Only",
                        confidence="High",
                        calculation_method=calc_method,
                        validation_required="Supporting evidence only; avoid duplicate savings counting with Underutilized OS/Data Disks.",
                        collected_at=now_str
                    )
                )

        status = AssessmentStatus.COMPLETED if findings else AssessmentStatus.NO_FINDINGS
        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(resources_evaluated, 1),
            findings_count=len(findings),
            findings=findings,
            total_monthly_savings=0.0,
            total_annual_savings=0.0,
            currency=context.currency,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
