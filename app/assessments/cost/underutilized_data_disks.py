import datetime
import time
from typing import List
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.monitor import MonitorAdapter
from app.azure.pricing import PricingEngine
from app.azure.cost_management import CostManagementAdapter
from app.utils.dates import get_observation_window, get_current_month_to_date
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id

class UnderutilizedDataDisksAssessment(BaseAssessment):
    assessment_id = "underutilized_data_disks"
    code = "COST-03"
    category = "cost"
    name = "Underutilized Data Disks"
    description = "Identify attached managed data disks where average IOPS utilization is below 5% of provisioned IOPS over 30 days."
    purpose = "Optimize overprovisioned data disk tiers (e.g., Premium SSD to Standard SSD) to reduce storage expenditure."
    required_permissions = [
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/disks/read",
        "Microsoft.Insights/metrics/read",
        "Monitoring Reader"
    ]
    required_data_sources = ["Azure Monitor Data Disk Read/Write Operations/sec (30 days, PT1H, Average)"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        start_iso, end_iso = get_observation_window(days=30)
        mtd_start, mtd_end = get_current_month_to_date()

        for sub in context.subscriptions:
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=mtd_start,
                end_date=mtd_end,
                resource_type_filter="Microsoft.Compute/disks"
            )

            vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id)
            for vm in vms:
                vm_name = vm.get("name", "")
                vm_id = vm.get("id", "")
                data_disks = vm.get("properties", {}).get("storageProfile", {}).get("dataDisks", [])

                for dd in data_disks:
                    resources_evaluated += 1
                    dd_name = dd.get("name", "")
                    lun = dd.get("lun", 0)
                    managed_disk = dd.get("managedDisk", {})
                    disk_id = managed_disk.get("id", "")
                    
                    # Query read and write IOPS
                    metric_target = disk_id if disk_id else vm_id
                    metric_res = await MonitorAdapter.get_metrics(
                        context.client,
                        resource_id=metric_target,
                        metric_names="Composite Disk Read Operations/sec,Composite Disk Write Operations/sec" if disk_id else "Data Disk Read Operations/sec,Data Disk Write Operations/sec",
                        start_time=start_iso,
                        end_time=end_iso,
                        time_grain="PT1H",
                        aggregation="Average"
                    )

                    if not metric_res.get("success"):
                        # Fallback to VM-level query if disk-level metrics return 400/404
                        metric_res = await MonitorAdapter.get_metrics(
                            context.client,
                            resource_id=vm_id,
                            metric_names="Data Disk Read Operations/sec,Data Disk Write Operations/sec",
                            start_time=start_iso,
                            end_time=end_iso,
                            time_grain="PT1H",
                            aggregation="Average"
                        )

                    read_iops = (
                        metric_res.get("metrics", {}).get("Composite Disk Read Operations/sec")
                        or metric_res.get("metrics", {}).get("Data Disk Read Operations/sec", 0.0)
                    )
                    write_iops = (
                        metric_res.get("metrics", {}).get("Composite Disk Write Operations/sec")
                        or metric_res.get("metrics", {}).get("Data Disk Write Operations/sec", 0.0)
                    )
                    used_iops = read_iops + write_iops

                    size_gb = dd.get("diskSizeGB", 128)
                    curr_sku = managed_disk.get("storageAccountType") or "Premium_LRS"

                    if "Standard_LRS" in curr_sku:
                        provisioned_iops = 500
                    elif "StandardSSD" in curr_sku:
                        provisioned_iops = 500
                    else:
                        if size_gb >= 1024:
                            provisioned_iops = 5000
                        elif size_gb >= 512:
                            provisioned_iops = 2300
                        elif size_gb >= 256:
                            provisioned_iops = 1100
                        elif size_gb >= 128:
                            provisioned_iops = 500
                        else:
                            provisioned_iops = 240

                    iops_utilization = (used_iops / provisioned_iops * 100.0) if provisioned_iops > 0 else 0.0

                    # Threshold: < 5% and not already on Standard HDD
                    if iops_utilization < 5.0 and curr_sku != "Standard_LRS":
                        curr_cost, proposed_sku, proposed_cost = PricingEngine.get_disk_downgrade_savings(curr_sku, size_gb)
                        monthly_saving = max(0.0, curr_cost - proposed_cost)
                        parsed = parse_azure_resource_id(disk_id or vm_id)

                        norm_id = normalize_resource_id(disk_id) if disk_id else ""
                        cost_info = cost_map.get(norm_id, {})
                        actual_cost = cost_info.get("cost")
                        currency = cost_info.get("currency", context.currency)

                        final_cost = actual_cost if actual_cost is not None and actual_cost > 0 else curr_cost

                        findings.append(
                            FindingModel(
                                finding_id=f"cost03-{dd_name[:12]}",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=parsed.get("resource_group") or "Unknown",
                                resource_name=dd_name,
                                resource_type="Microsoft.Compute/disks",
                                resource_id=disk_id or f"{vm_id}/dataDisks/{lun}",
                                region=vm.get("location", "global"),
                                severity="Medium",
                                status="Underutilized IOPS",
                                current_configuration=f"SKU: {curr_sku} | Size: {size_gb} GB | LUN: {lun} | Provisioned IOPS: {provisioned_iops}",
                                measured_value=f"Average {used_iops:.1f} IOPS ({iops_utilization:.2f}% of provisioned) over 30 days",
                                recommended_configuration=f"Downgrade data disk storage tier to {proposed_sku}",
                                recommendation=f"Data disk '{dd_name}' is provisioned on {curr_sku} but averages {used_iops:.1f} IOPS. Downgrade tier.",
                                metric_period="Previous 30 days hourly grain",
                                data_source="Azure Monitor Data Disk Read/Write Operations/sec",
                                evidence={
                                    "avg_iops": round(used_iops, 2),
                                    "iops_utilization_percent": round(iops_utilization, 2),
                                    "size_gb": size_gb,
                                    "lun": lun,
                                    "actual_cost_mtd": round(final_cost, 2)
                                },
                                current_monthly_cost=round(final_cost, 2),
                                estimated_monthly_savings=monthly_saving,
                                estimated_annual_savings=round(monthly_saving * 12, 2),
                                currency=currency,
                                savings_type="Estimated Savings",
                                confidence="High",
                                calculation_method=f"Downgrading data disk tier from {curr_sku} to {proposed_sku}",
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
