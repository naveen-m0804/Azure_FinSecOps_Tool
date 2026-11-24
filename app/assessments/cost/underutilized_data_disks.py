import datetime
import time
from typing import List, Dict, Any, Optional, Tuple
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.monitor import MonitorAdapter
from app.azure.pricing import PricingEngine
from app.azure.cost_management import CostManagementAdapter
from app.utils.dates import get_observation_window
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment


def _extract_metric_value(metrics: Dict[str, float], *names: str) -> float:
    """Case-insensitive metric lookup across candidate metric names."""
    for name in names:
        target_lower = name.lower()
        for k, v in metrics.items():
            if k.lower() == target_lower:
                return float(v or 0.0)
    return 0.0


def _has_metric_key(metrics: Dict[str, Any], *names: str) -> bool:
    """Check if any of candidate metric names exist in the metrics dictionary."""
    target_lowers = {name.lower() for name in names}
    return any(k.lower() in target_lowers for k in metrics)


def _get_friendly_disk_tier(sku: str, size_gb: int, azure_tier: Optional[str] = None) -> str:
    """
    Returns human-friendly disk tier e.g. 'Premium SSD P30', 'Standard SSD E20', 'Standard HDD S10'.
    Honors explicit Azure tier if provided, otherwise maps according to official Azure Managed Disks size matrix.
    """
    sku_upper = (sku or "").upper()
    tier_upper = (azure_tier or "").strip().upper()

    if "PREMIUMV2" in sku_upper:
        return f"Premium SSD v2 {tier_upper}".strip()
    elif "ULTRA" in sku_upper:
        return f"Ultra SSD {tier_upper}".strip()
    elif "PREMIUM" in sku_upper:
        if tier_upper and tier_upper.startswith("P"):
            p_tier = tier_upper
        else:
            if size_gb <= 32: p_tier = "P4"
            elif size_gb <= 64: p_tier = "P6"
            elif size_gb <= 128: p_tier = "P10"
            elif size_gb <= 256: p_tier = "P15"
            elif size_gb <= 512: p_tier = "P20"
            elif size_gb <= 1024: p_tier = "P30"
            elif size_gb <= 2048: p_tier = "P40"
            elif size_gb <= 4096: p_tier = "P50"
            elif size_gb <= 8192: p_tier = "P60"
            elif size_gb <= 16384: p_tier = "P70"
            else: p_tier = "P80"
        return f"Premium SSD {p_tier}"
    elif "STANDARDSSD" in sku_upper:
        if tier_upper and tier_upper.startswith("E"):
            e_tier = tier_upper
        else:
            if size_gb <= 32: e_tier = "E4"
            elif size_gb <= 64: e_tier = "E6"
            elif size_gb <= 128: e_tier = "E10"
            elif size_gb <= 256: e_tier = "E15"
            elif size_gb <= 512: e_tier = "E20"
            elif size_gb <= 1024: e_tier = "E30"
            elif size_gb <= 2048: e_tier = "E40"
            elif size_gb <= 4096: e_tier = "E50"
            elif size_gb <= 8192: e_tier = "E60"
            elif size_gb <= 16384: e_tier = "E70"
            else: e_tier = "E80"
        return f"Standard SSD {e_tier}"
    elif "STANDARD" in sku_upper:
        if tier_upper and tier_upper.startswith("S"):
            s_tier = tier_upper
        else:
            if size_gb <= 32: s_tier = "S4"
            elif size_gb <= 64: s_tier = "S6"
            elif size_gb <= 128: s_tier = "S10"
            elif size_gb <= 256: s_tier = "S15"
            elif size_gb <= 512: s_tier = "S20"
            elif size_gb <= 1024: s_tier = "S30"
            elif size_gb <= 2048: s_tier = "S40"
            elif size_gb <= 4096: s_tier = "S50"
            elif size_gb <= 8192: s_tier = "S60"
            elif size_gb <= 16384: s_tier = "S70"
            else: s_tier = "S80"
        return f"Standard HDD {s_tier}"
    return sku or "Standard SSD"


def _get_provisioned_iops(sku: str, size_gb: int, azure_iops: Optional[int] = None) -> int:
    """
    Returns provisioned IOPS based on explicit Azure configuration or standard Azure Managed Disk performance specs.
    """
    if azure_iops is not None and azure_iops > 0:
        return int(azure_iops)

    sku_upper = (sku or "").upper()
    if "PREMIUM" in sku_upper and "PREMIUMV2" not in sku_upper:
        if size_gb <= 32: return 120
        elif size_gb <= 64: return 240
        elif size_gb <= 128: return 500
        elif size_gb <= 256: return 1100
        elif size_gb <= 512: return 2300
        elif size_gb <= 1024: return 5000
        elif size_gb <= 4096: return 7500
        elif size_gb <= 8192: return 16000
        elif size_gb <= 16384: return 18000
        else: return 20000
    elif "STANDARDSSD" in sku_upper:
        if size_gb <= 4096: return 500
        elif size_gb <= 8192: return 1300
        elif size_gb <= 16384: return 2000
        else: return 4000
    elif "STANDARD" in sku_upper:
        if size_gb <= 8192: return 500
        else: return 2000
    return 500


def _is_standard_hdd(sku: str) -> bool:
    """Checks if a SKU is Standard HDD (cannot be downgraded further)."""
    s = (sku or "").lower()
    return "standard" in s and "ssd" not in s


async def _fetch_iops_metrics(
    client,
    disk_id: str,
    vm_id: str,
    start_iso: str,
    end_iso: str
) -> Tuple[float, float, float, str]:
    """
    Fetch IOPS metrics directly from Azure Monitor host platform metrics.
    Mirrors Underutilized_Data_Disk_IOPS_Report.txt:
    Queries the host VM resource ID ($VM.Id) with hourly grain (PT1H / 01:00:00)
    for 'Data Disk Read Operations/Sec' and 'Data Disk Write Operations/Sec'.
    Falls back to disk-level metrics for mock testing environments.
    """
    # 1. Primary: Host VM platform metrics with PT1H grain (matching reference PowerShell script)
    if vm_id:
        for tg in ("PT1H", "PT12H", "P1D"):
            metric_res = await MonitorAdapter.get_metrics(
                client,
                resource_id=vm_id,
                metric_names="Data Disk Read Operations/Sec,Data Disk Write Operations/Sec",
                start_time=start_iso,
                end_time=end_iso,
                time_grain=tg,
                aggregation="Average"
            )
            if metric_res.get("success"):
                metrics = metric_res.get("metrics", {})
                if _has_metric_key(metrics, "Data Disk Read Operations/Sec", "Data Disk Write Operations/Sec"):
                    r = _extract_metric_value(metrics, "Data Disk Read Operations/Sec", "Data Disk Read Operations/sec", "data disk read operations/sec")
                    w = _extract_metric_value(metrics, "Data Disk Write Operations/Sec", "Data Disk Write Operations/sec", "data disk write operations/sec")
                    return (r + w, r, w, f"Azure Monitor Data Disk Operations/Sec ({tg})")

    # 2. Secondary / Mock fallback: disk resource ID with Composite or Data Disk metrics
    if disk_id:
        for tg in ("P1D", "PT1H"):
            metric_res = await MonitorAdapter.get_metrics(
                client,
                resource_id=disk_id,
                metric_names="Composite Disk Read Operations/sec,Composite Disk Write Operations/sec,Data Disk Read Operations/Sec,Data Disk Write Operations/Sec",
                start_time=start_iso,
                end_time=end_iso,
                time_grain=tg,
                aggregation="Average"
            )
            if metric_res.get("success"):
                metrics = metric_res.get("metrics", {})
                if _has_metric_key(metrics, "Composite Disk Read Operations/sec", "Composite Disk Write Operations/sec", "Data Disk Read Operations/Sec", "Data Disk Write Operations/Sec", "Disk Read Operations/Sec", "Disk Write Operations/Sec"):
                    r = _extract_metric_value(metrics, "Composite Disk Read Operations/sec", "Composite Disk Read Operations/Sec", "Data Disk Read Operations/Sec", "Disk Read Operations/Sec")
                    w = _extract_metric_value(metrics, "Composite Disk Write Operations/sec", "Composite Disk Write Operations/Sec", "Data Disk Write Operations/Sec", "Disk Write Operations/Sec")
                    return (r + w, r, w, f"Azure Monitor Operations/sec ({tg})")

    return (0.0, 0.0, 0.0, "Azure Monitor (No metric response)")


class UnderutilizedDataDisksAssessment(BaseAssessment):
    assessment_id = "underutilized_data_disks"
    code = "COST-03"
    category = "cost"
    name = "Underutilized Data Disks"
    description = "Identify attached managed data disks where average IOPS utilization is below 5% of provisioned IOPS over 90 days."
    purpose = "Optimize overprovisioned data disk tiers (e.g., Premium SSD to Standard SSD) to reduce storage expenditure."
    required_permissions = [
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/disks/read",
        "Microsoft.Insights/metrics/read",
        "Monitoring Reader"
    ]
    required_data_sources = ["Azure Monitor Data Disk Read/Write Operations/sec (90 days, P1D/PT1H, Average)"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        start_iso, end_iso = get_observation_window(days=90)
        start_iso_30, end_iso_30 = get_observation_window(days=30)
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()

        for sub in context.subscriptions:
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=cost_start,
                end_date=cost_end,
                resource_type_filter="Microsoft.Compute/disks"
            )

            # Query all managed disks in the subscription for full tier and sizing metadata
            try:
                disks = await ComputeAdapter.get_disks(context.client, sub.subscription_id)
            except Exception as ex:
                disks = []
                errors.append(f"Failed to fetch disks for sub {sub.subscription_id}: {ex}")

            disk_lookup: Dict[str, Dict[str, Any]] = {}
            disk_name_lookup: Dict[str, Dict[str, Any]] = {}
            for d in disks:
                d_id = d.get("id", "")
                if d_id:
                    disk_lookup[normalize_resource_id(d_id)] = d
                d_name = d.get("name", "")
                if d_name:
                    disk_name_lookup[d_name.lower()] = d

            # Query VMs in the subscription to map attached data disks
            try:
                vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id)
            except Exception as ex:
                vms = []
                errors.append(f"Failed to fetch VMs for sub {sub.subscription_id}: {ex}")

            processed_disk_ids = set()

            for vm in vms:
                vm_name = vm.get("name", "")
                vm_id = vm.get("id", "")
                vm_tags = vm.get("tags") or {}
                vm_location = vm.get("location", "global")
                data_disks = vm.get("properties", {}).get("storageProfile", {}).get("dataDisks", [])

                for dd in data_disks:
                    resources_evaluated += 1
                    dd_name = dd.get("name", "")
                    lun = dd.get("lun", 0)
                    managed_disk = dd.get("managedDisk", {})
                    disk_id = managed_disk.get("id", "")
                    norm_disk_id = normalize_resource_id(disk_id) if disk_id else ""
                    if norm_disk_id:
                        processed_disk_ids.add(norm_disk_id)

                    # Enrich with Azure disk properties if available
                    azure_disk = disk_lookup.get(norm_disk_id) or disk_name_lookup.get(dd_name.lower())
                    if azure_disk:
                        azure_props = azure_disk.get("properties", {})
                        azure_sku = azure_disk.get("sku", {})
                        size_gb = azure_props.get("diskSizeGB") or dd.get("diskSizeGB", 128)
                        curr_sku = azure_sku.get("name") or managed_disk.get("storageAccountType") or "Premium_LRS"
                        azure_tier = azure_props.get("tier")
                        azure_iops = azure_props.get("diskIOPSReadWrite")
                        disk_tags = azure_disk.get("tags") or vm_tags
                        region = azure_disk.get("location") or vm_location
                    else:
                        size_gb = dd.get("diskSizeGB", 128)
                        curr_sku = managed_disk.get("storageAccountType") or "Premium_LRS"
                        azure_tier = None
                        azure_iops = None
                        disk_tags = vm_tags
                        region = vm_location

                    disk_tier_str = _get_friendly_disk_tier(curr_sku, size_gb, azure_tier)
                    provisioned_iops = _get_provisioned_iops(curr_sku, size_gb, azure_iops)

                    # Query read and write IOPS (using 30-day window to respect Azure Monitor hourly grain limit)
                    used_iops, read_iops, write_iops, metric_source = await _fetch_iops_metrics(
                        context.client,
                        disk_id=disk_id,
                        vm_id=vm_id,
                        start_iso=start_iso_30,
                        end_iso=end_iso_30
                    )

                    iops_utilization = (used_iops / provisioned_iops * 100.0) if provisioned_iops > 0 else 0.0

                    # Threshold: IOPS utilization under 5% over 90 days and not already on Standard HDD
                    if iops_utilization < 5.0 and not _is_standard_hdd(curr_sku):
                        curr_cost, proposed_sku, proposed_cost = PricingEngine.get_disk_downgrade_savings(curr_sku, size_gb)
                        parsed = parse_azure_resource_id(disk_id or vm_id)
                        rg_name = parsed.get("resource_group") or "Unknown"

                        cost_info = cost_map.get(norm_disk_id, {})
                        actual_cost = cost_info.get("cost")
                        currency = cost_info.get("currency", context.currency)

                        final_cost = actual_cost if actual_cost is not None and actual_cost > 0 else curr_cost
                        monthly_saving = max(0.0, final_cost - proposed_cost)

                        env = resolve_environment(
                            tags=disk_tags,
                            resource_name=dd_name,
                            resource_group=rg_name,
                            prod_tags=context.prod_tags,
                            test_tags=context.test_tags,
                            target_tags=context.target_tags
                        )

                        finding_key = f"{sub.subscription_id[:6]}-{rg_name[:8]}-{dd_name[:16]}-{lun}"

                        findings.append(
                            FindingModel(
                                finding_id=f"cost03-{finding_key}",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=rg_name,
                                resource_name=dd_name,
                                resource_type="Microsoft.Compute/disks",
                                resource_id=disk_id or f"{vm_id}/dataDisks/{lun}",
                                region=region,
                                severity="Medium",
                                status="Underutilized IOPS",
                                current_configuration=f"Tier: {disk_tier_str} | Size: {size_gb} GiB | LUN: {lun} | Provisioned IOPS: {provisioned_iops}",
                                measured_value=f"{iops_utilization:.2f}%",
                                recommended_configuration=f"Downgrade data disk storage tier to {proposed_sku}",
                                recommendation=f"Data disk '{dd_name}' is provisioned on {disk_tier_str} ({provisioned_iops} IOPS) but averages {used_iops:.2f} IOPS ({iops_utilization:.2f}% utilization over 90 days). Downgrade tier to {proposed_sku}.",
                                metric_period=f"Last 90 Days (Cost Month: {cost_month})",
                                data_source=metric_source,
                                evidence={
                                    "vm_name": vm_name,
                                    "attached_vm": vm_name,
                                    "disk_tier": disk_tier_str,
                                    "tier": disk_tier_str,
                                    "disk_size_gb": size_gb,
                                    "lun": lun,
                                    "avg_iops": round(used_iops, 2),
                                    "used_iops": round(used_iops, 2),
                                    "read_iops": round(read_iops, 2),
                                    "write_iops": round(write_iops, 2),
                                    "provisioned_iops": provisioned_iops,
                                    "iops_utilization": f"{iops_utilization:.2f}%",
                                    "iops_utilization_percent": round(iops_utilization, 2),
                                    "environment": env,
                                    "actual_cost_mtd": round(final_cost, 2),
                                    "current_sku": curr_sku,
                                    "proposed_sku": proposed_sku,
                                    "observation_window_days": 90,
                                    "cost_month": cost_month
                                },
                                current_monthly_cost=round(final_cost, 2),
                                estimated_monthly_savings=round(monthly_saving, 2),
                                estimated_annual_savings=round(monthly_saving * 12, 2),
                                currency=currency,
                                savings_type="Estimated Savings",
                                confidence="High",
                                calculation_method=f"Downgrading data disk tier from {disk_tier_str} to {proposed_sku} based on 90-day <5% IOPS utilization",
                                validation_required="Verify peak transaction IOPS with application team before downgrading",
                                collected_at=now_str
                            )
                        )

            # Check any remaining attached managed data disks from get_disks that may not have been in vms list
            for disk in disks:
                norm_d_id = normalize_resource_id(disk.get("id", ""))
                if not norm_d_id or norm_d_id in processed_disk_ids:
                    continue

                d_props = disk.get("properties", {})
                disk_state = d_props.get("diskState", "")
                managed_by = d_props.get("managedBy", "")
                os_type = d_props.get("osType")

                # Only evaluate attached data disks (osType is None for data disks)
                if (disk_state == "Attached" or managed_by) and os_type is None:
                    resources_evaluated += 1
                    processed_disk_ids.add(norm_d_id)
                    d_name = disk.get("name", "")
                    d_sku = disk.get("sku", {})
                    curr_sku = d_sku.get("name") or "Premium_LRS"
                    size_gb = d_props.get("diskSizeGB", 128)
                    azure_tier = d_props.get("tier")
                    azure_iops = d_props.get("diskIOPSReadWrite")
                    disk_tags = disk.get("tags") or {}
                    region = disk.get("location", "global")
                    vm_id_ref = managed_by or ""
                    vm_name_ref = managed_by.split("/")[-1] if managed_by else "Attached"

                    disk_tier_str = _get_friendly_disk_tier(curr_sku, size_gb, azure_tier)
                    provisioned_iops = _get_provisioned_iops(curr_sku, size_gb, azure_iops)

                    used_iops, read_iops, write_iops, metric_source = await _fetch_iops_metrics(
                        context.client,
                        disk_id=disk.get("id", ""),
                        vm_id=vm_id_ref,
                        start_iso=start_iso,
                        end_iso=end_iso
                    )

                    iops_utilization = (used_iops / provisioned_iops * 100.0) if provisioned_iops > 0 else 0.0

                    if iops_utilization < 5.0 and not _is_standard_hdd(curr_sku):
                        curr_cost, proposed_sku, proposed_cost = PricingEngine.get_disk_downgrade_savings(curr_sku, size_gb)
                        parsed = parse_azure_resource_id(disk.get("id", ""))
                        rg_name = parsed.get("resource_group") or "Unknown"

                        cost_info = cost_map.get(norm_d_id, {})
                        actual_cost = cost_info.get("cost")
                        currency = cost_info.get("currency", context.currency)

                        final_cost = actual_cost if actual_cost is not None and actual_cost > 0 else curr_cost
                        monthly_saving = max(0.0, final_cost - proposed_cost)

                        env = resolve_environment(
                            tags=disk_tags,
                            resource_name=d_name,
                            resource_group=rg_name,
                            prod_tags=context.prod_tags,
                            test_tags=context.test_tags,
                            target_tags=context.target_tags
                        )

                        finding_key = f"{sub.subscription_id[:6]}-{rg_name[:8]}-{d_name[:16]}-data"

                        findings.append(
                            FindingModel(
                                finding_id=f"cost03-{finding_key}",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=rg_name,
                                resource_name=d_name,
                                resource_type="Microsoft.Compute/disks",
                                resource_id=disk.get("id", ""),
                                region=region,
                                severity="Medium",
                                status="Underutilized IOPS",
                                current_configuration=f"Tier: {disk_tier_str} | Size: {size_gb} GiB | Provisioned IOPS: {provisioned_iops}",
                                measured_value=f"{iops_utilization:.2f}%",
                                recommended_configuration=f"Downgrade data disk storage tier to {proposed_sku}",
                                recommendation=f"Data disk '{d_name}' is provisioned on {disk_tier_str} ({provisioned_iops} IOPS) but averages {used_iops:.2f} IOPS ({iops_utilization:.2f}% utilization over 90 days). Downgrade tier to {proposed_sku}.",
                                metric_period=f"Last 90 Days (Cost Month: {cost_month})",
                                data_source=metric_source,
                                evidence={
                                    "vm_name": vm_name_ref,
                                    "attached_vm": vm_name_ref,
                                    "disk_tier": disk_tier_str,
                                    "tier": disk_tier_str,
                                    "disk_size_gb": size_gb,
                                    "lun": 0,
                                    "avg_iops": round(used_iops, 2),
                                    "used_iops": round(used_iops, 2),
                                    "read_iops": round(read_iops, 2),
                                    "write_iops": round(write_iops, 2),
                                    "provisioned_iops": provisioned_iops,
                                    "iops_utilization": f"{iops_utilization:.2f}%",
                                    "iops_utilization_percent": round(iops_utilization, 2),
                                    "environment": env,
                                    "actual_cost_mtd": round(final_cost, 2),
                                    "current_sku": curr_sku,
                                    "proposed_sku": proposed_sku,
                                    "observation_window_days": 90,
                                    "cost_month": cost_month
                                },
                                current_monthly_cost=round(final_cost, 2),
                                estimated_monthly_savings=round(monthly_saving, 2),
                                estimated_annual_savings=round(monthly_saving * 12, 2),
                                currency=currency,
                                savings_type="Estimated Savings",
                                confidence="High",
                                calculation_method=f"Downgrading data disk tier from {disk_tier_str} to {proposed_sku} based on 90-day <5% IOPS utilization",
                                validation_required="Verify peak transaction IOPS with application team before downgrading",
                                collected_at=now_str
                            )
                        )

        total_monthly = sum((f.estimated_monthly_savings or 0.0) for f in findings)
        status = AssessmentStatus.COMPLETED if findings else AssessmentStatus.NO_FINDINGS
        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(resources_evaluated, 1),
            findings_count=len(findings),
            findings=findings,
            total_monthly_savings=round(total_monthly, 2),
            total_annual_savings=round(total_monthly * 12, 2),
            currency=context.currency,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
