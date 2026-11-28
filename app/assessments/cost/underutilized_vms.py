import datetime
import time
from typing import List, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.monitor import MonitorAdapter
from app.azure.pricing import PricingEngine
from app.azure.cost_management import CostManagementAdapter
from app.utils.dates import get_observation_window
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment, matches_target_tags


class UnderutilizedVmsAssessment(BaseAssessment):
    assessment_id = "underutilized_vms"
    code = "COST-01"
    category = "cost"
    name = "Underutilized Virtual Machines"
    description = "Identify virtual machines with average CPU utilization below 1% over the past 90 days."
    purpose = "Detect severely underutilized VM candidates for right-sizing, shutdown scheduling, or decommissioning."
    required_permissions = ["Microsoft.Compute/virtualMachines/read", "Microsoft.Insights/metrics/read", "Monitoring Reader"]
    required_data_sources = ["Azure Monitor 'Percentage CPU' (90 days, PT1H, Average)", "Azure Cost Management", "Azure Retail Prices API"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        start_iso, end_iso = get_observation_window(days=90)
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()

        for sub in context.subscriptions:
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=cost_start,
                end_date=cost_end,
                resource_type_filter="Microsoft.Compute/virtualMachines"
            )

            vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id)
            for vm in vms:
                if not matches_target_tags(vm.get("tags"), context.target_tags):
                    continue
                resources_evaluated += 1
                vm_name = vm.get("name", "")
                vm_id = vm.get("id", "")
                region = vm.get("location", "")
                props = vm.get("properties", {})
                hardware_profile = props.get("hardwareProfile", {})
                vm_size = hardware_profile.get("vmSize")
                os_type = props.get("storageProfile", {}).get("osDisk", {}).get("osType", "Linux")

                if not vm_size:
                    continue

                # Get CPU metrics (first try PT1H, fallback to P1D daily grain if 90-day PT1H is rejected)
                metric_res = await MonitorAdapter.get_metrics(
                    context.client,
                    resource_id=vm_id,
                    metric_names="Percentage CPU",
                    start_time=start_iso,
                    end_time=end_iso,
                    time_grain="PT1H",
                    aggregation="Average",
                    metric_namespace="Microsoft.Compute/virtualMachines"
                )

                if not metric_res.get("success"):
                    metric_res = await MonitorAdapter.get_metrics(
                        context.client,
                        resource_id=vm_id,
                        metric_names="Percentage CPU",
                        start_time=start_iso,
                        end_time=end_iso,
                        time_grain="P1D",
                        aggregation="Average",
                        metric_namespace="Microsoft.Compute/virtualMachines"
                    )

                if not metric_res.get("success"):
                    continue

                avg_cpu = metric_res.get("metrics", {}).get("Percentage CPU")
                if avg_cpu is None:
                    continue

                # Flag VMs where average CPU < 1.0%
                if avg_cpu < 1.0:
                    norm_id = normalize_resource_id(vm_id)
                    cost_item = cost_map.get(norm_id, {})
                    actual_cost = cost_item.get("cost")
                    currency = cost_item.get("currency", context.currency)

                    # Dynamic current VM compute cost: Cost Management ActualCost first, else Azure Retail Prices API
                    curr_cost: Optional[float] = None
                    pricing_src = "Azure Cost Management ActualCost"
                    if actual_cost is not None and actual_cost > 0:
                        curr_cost = float(actual_cost)
                    else:
                        vm_rates = await PricingEngine.get_vm_rates(vm_size, region, os_type=os_type, currency=currency)
                        if vm_rates and vm_rates.get("monthly") is not None:
                            curr_cost = vm_rates["monthly"]
                            pricing_src = "Azure Retail Prices API"

                    # Dynamic recommended smaller SKU & price from Azure Retail Prices API
                    rec_info = await PricingEngine.get_recommended_smaller_vm_sku(
                        vm_size, region, currency=currency, os_type=os_type
                    )
                    rec_sku = rec_info["recommended_sku"] if rec_info else None
                    rec_cost = rec_info["recommended_monthly_cost"] if rec_info else None

                    # Formula (R2): Monthly savings = current eligible VM compute cost - recommended VM compute cost
                    est_saving: Optional[float] = None
                    est_annual: Optional[float] = None
                    savings_pct: Optional[float] = None
                    savings_type = "Not Estimated"
                    if curr_cost is not None and curr_cost > 0 and rec_cost is not None:
                        est_saving = round(max(0.0, curr_cost - rec_cost), 2)
                        est_annual = round(est_saving * 12.0, 2)
                        savings_pct = round((est_saving / curr_cost) * 100.0, 2) if curr_cost > 0 else 0.0
                        savings_type = "Estimated Savings"

                    parsed = parse_azure_resource_id(vm_id)
                    rg_name = parsed.get("resource_group") or "Unknown"
                    env_val = resolve_environment(
                        tags=vm.get("tags") or {},
                        resource_name=vm_name,
                        resource_group=rg_name,
                        prod_tags=context.prod_tags,
                        test_tags=context.test_tags,
                        target_tags=context.target_tags,
                    )

                    rec_cfg = (
                        f"Right-size to {rec_sku} ({currency} {rec_cost:,.2f}/mo)"
                        if rec_sku and rec_cost is not None
                        else "Evaluate right-sizing to a smaller SKU or deallocating if idle (pricing comparison required)"
                    )

                    findings.append(
                        FindingModel(
                            finding_id=f"cost01-{vm_name[:12]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg_name,
                            resource_name=vm_name,
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_id=vm_id,
                            region=region or "global",
                            severity="High" if avg_cpu < 0.2 else "Medium",
                            status="Underutilized Candidate",
                            current_configuration=f"Size: {vm_size} | 90-Day Avg CPU: {avg_cpu:.2f}%",
                            measured_value=f"{avg_cpu:.2f}% Average CPU over 90 days (< 1% threshold)",
                            recommended_configuration=rec_cfg,
                            recommendation=f"VM average CPU utilization is {avg_cpu:.2f}%. {rec_cfg}.",
                            metric_period="Previous 90 days",
                            data_source="Azure Monitor Percentage CPU",
                            evidence={
                                "average_cpu_percent": round(avg_cpu, 2),
                                "avg_cpu": round(avg_cpu, 2),
                                "vm_size": vm_size,
                                "recommended_sku": rec_sku,
                                "recommended_monthly_cost": rec_cost,
                                "savings_pct": savings_pct,
                                "environment": env_val,
                                "actual_cost_mtd": round(curr_cost, 2) if curr_cost is not None else None,
                                "cost_month": cost_month,
                            },
                            current_monthly_cost=round(curr_cost, 2) if curr_cost is not None else None,
                            estimated_monthly_savings=est_saving,
                            estimated_annual_savings=est_annual,
                            currency=currency,
                            savings_type=savings_type,
                            confidence="High" if est_saving is not None else "Low",
                            pricing_source=pricing_src,
                            calculation_method="Monthly savings = current eligible VM compute cost - recommended VM compute cost; annual = monthly * 12",
                            validation_required="Validate CPU/RAM, workload, SKU, region and licensing; avoid overlap with shutdown savings.",
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
