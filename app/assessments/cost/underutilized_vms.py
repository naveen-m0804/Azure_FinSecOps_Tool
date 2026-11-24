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

class UnderutilizedVmsAssessment(BaseAssessment):
    assessment_id = "underutilized_vms"
    code = "COST-01"
    category = "cost"
    name = "Underutilized Virtual Machines"
    description = "Identify virtual machines with average CPU utilization below 1% over the past 90 days."
    purpose = "Detect severely underutilized VM candidates for right-sizing, shutdown scheduling, or decommissioning."
    required_permissions = ["Microsoft.Compute/virtualMachines/read", "Microsoft.Insights/metrics/read", "Monitoring Reader"]
    required_data_sources = ["Azure Monitor 'Percentage CPU' (90 days, PT1H, Average)"]

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
                resources_evaluated += 1
                vm_name = vm.get("name", "")
                vm_id = vm.get("id", "")
                hardware_profile = vm.get("properties", {}).get("hardwareProfile", {})
                vm_size = hardware_profile.get("vmSize", "Standard_D2s_v5")

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

                    rates = PricingEngine.get_vm_rates(vm_size)
                    curr_cost = actual_cost if actual_cost is not None and actual_cost > 0 else rates.get("monthly", 87.60)
                    # Estimated saving by downsizing to B-series or deallocating (~75% saving)
                    est_saving = round(curr_cost * 0.75, 2)
                    parsed = parse_azure_resource_id(vm_id)

                    findings.append(
                        FindingModel(
                            finding_id=f"cost01-{vm_name[:12]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=parsed.get("resource_group") or "Unknown",
                            resource_name=vm_name,
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_id=vm_id,
                            region=vm.get("location", "global"),
                            severity="High" if avg_cpu < 0.2 else "Medium",
                            status="Underutilized Candidate",
                            current_configuration=f"Size: {vm_size} | 90-Day Avg CPU: {avg_cpu:.2f}%",
                            measured_value=f"{avg_cpu:.2f}% Average CPU over 90 days (< 1% threshold)",
                            recommended_configuration="Evaluate downsizing to burstable B-series or deallocate if idle",
                            recommendation=f"VM average CPU utilization is {avg_cpu:.2f}%. Validate workload and right-size.",
                            metric_period="Previous 90 days hourly grain",
                            data_source="Azure Monitor Percentage CPU",
                            evidence={
                                "average_cpu_percent": round(avg_cpu, 2),
                                "vm_size": vm_size,
                                "actual_cost_mtd": round(curr_cost, 2),
                                "cost_month": cost_month
                            },
                            current_monthly_cost=round(curr_cost, 2),
                            estimated_monthly_savings=est_saving,
                            estimated_annual_savings=round(est_saving * 12, 2),
                            currency=currency,
                            savings_type="Estimated Savings",
                            confidence="High",
                            calculation_method="Approximate 75% compute cost reduction via right-sizing to B-series or scheduled deallocation",
                            validation_required="Verify business peak load and scheduled batch processing windows",
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
