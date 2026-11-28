import datetime
import re
import time
from typing import List, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.dates import get_current_month_to_date
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment, matches_target_tags

class AutoShutdownAssessment(BaseAssessment):
    assessment_id = "auto_shutdown"
    code = "COST-08"
    category = "cost"
    name = "Auto Shutdown Status"
    description = "Audit virtual machines lacking enabled daily auto-shutdown schedules based on evaluation scope."
    purpose = "Enforce off-hours shutdown policies on virtual machines to eliminate unnecessary compute runtime cost."
    required_permissions = [
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.DevTestLab/schedules/read",
        "Microsoft.CostManagement/query/action",
        "Reader"
    ]
    required_data_sources = ["Microsoft.Compute VirtualMachines & Microsoft.DevTestLab/schedules APIs"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()

        for sub in context.subscriptions:
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=cost_start,
                end_date=cost_end,
                resource_type_filter=None  # Query all resource types to aggregate VM + Disks + NICs + IPs
            )

            try:
                vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id)
                schedules = await ComputeAdapter.get_devtest_schedules(context.client, sub.subscription_id)
            except Exception as ex:
                errors.append(f"Failed to query compute/schedules for {sub.subscription_id}: {ex}")
                continue

            # Build map of schedules by normalized targetResourceId
            schedule_map = {}
            for sch in schedules:
                props = sch.get("properties", {})
                if props.get("taskType") == "ComputeVmShutdownTask":
                    target_id = normalize_resource_id(props.get("targetResourceId", ""))
                    if target_id:
                        schedule_map[target_id] = sch

            for vm in vms:
                vm_name = vm.get("name", "")
                vm_id = vm.get("id", "")
                tags = vm.get("tags") or {}
                parsed = parse_azure_resource_id(vm_id)
                rg = parsed.get("resource_group") or ""

                # Strict tag-based scoping: If user entered target_tags, match ONLY resources with matching tags.
                # If no target_tags entered, evaluate ALL VMs (tagged or untagged).
                if not matches_target_tags(tags, context.target_tags):
                    continue

                env_val = resolve_environment(tags, vm_name, rg, prod_tags=context.prod_tags, test_tags=context.test_tags, target_tags=context.target_tags)

                resources_evaluated += 1
                norm_vm_id = normalize_resource_id(vm_id)
                matched_sch = schedule_map.get(norm_vm_id)

                auto_shutdown_status = "Not Configured"
                scheduled_time_display = "Unavailable"
                sch_time = None
                sch_tz = None

                if matched_sch:
                    sch_props = matched_sch.get("properties", {})
                    sch_status = sch_props.get("status", "Disabled")
                    auto_shutdown_status = "Enabled" if sch_status.lower() == "enabled" else "Disabled"
                    daily_rec = sch_props.get("dailyRecurrence", {})
                    sch_time = daily_rec.get("time")
                    sch_tz = sch_props.get("timeZoneId", "UTC")
                    if sch_time:
                        scheduled_time_display = f"{sch_time} ({sch_tz})"

                # Check VM power state (running vs deallocated)
                props = vm.get("properties", {})
                inst_view = props.get("instanceView", {})
                statuses = inst_view.get("statuses", [])
                power_state = "Running"
                for st in statuses:
                    code = st.get("code", "")
                    if "PowerState/deallocated" in code:
                        power_state = "Deallocated"
                        break
                    elif "PowerState/running" in code:
                        power_state = "Running"

                # Identify genuinely wasteful resources:
                # Flag VMs where auto-shutdown is NOT enabled
                if auto_shutdown_status != "Enabled":
                    vm_size = props.get("hardwareProfile", {}).get("vmSize")
                    vm_region = vm.get("location", "")
                    os_type = props.get("storageProfile", {}).get("osDisk", {}).get("osType", "Linux")

                    # Per Savings Formula Guide (R9):
                    # Compute-only proxy; exclude disk, reserved-instance and other continuing charges.
                    cost_item = cost_map.get(norm_vm_id, {})
                    actual_compute_cost = cost_item.get("cost")
                    currency = cost_item.get("currency", context.currency)

                    vm_compute_cost: Optional[float] = None
                    if actual_compute_cost is not None and actual_compute_cost > 0:
                        vm_compute_cost = float(actual_compute_cost)
                    elif vm_size:
                        vm_rates = await PricingEngine.get_vm_rates(vm_size, vm_region, os_type=os_type, currency=currency)
                        if vm_rates and vm_rates.get("monthly") is not None:
                            vm_compute_cost = vm_rates["monthly"]

                    # Formula (R9): Savings % = scheduled stoppable hours/year / 8760
                    # Standard off-hours schedule: 12 hours/day (19:00-07:00) * 365 days = 4380 hours/year (or 2600 if weekday 10h*5d)
                    stoppable_hours_year = 4380.0
                    savings_ratio = stoppable_hours_year / 8760.0
                    savings_pct = round(savings_ratio * 100.0, 2)

                    monthly_compute_savings: Optional[float] = None
                    annual_savings: Optional[float] = None
                    if vm_compute_cost is not None and vm_compute_cost > 0:
                        monthly_compute_savings = round(vm_compute_cost * savings_ratio, 2)
                        annual_savings = round(monthly_compute_savings * 12.0, 2)

                    parsed = parse_azure_resource_id(vm_id)

                    findings.append(
                        FindingModel(
                            finding_id=f"cost08-{vm_name[:12]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=parsed.get("resource_group") or "Unknown",
                            resource_name=vm_name,
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_id=vm_id,
                            region=vm_region or "global",
                            severity="High" if auto_shutdown_status == "Not Configured" else "Medium",
                            status=f"Shutdown {auto_shutdown_status}",
                            current_configuration=f"Environment: {env_val} | Auto-Shutdown: {auto_shutdown_status} | Size: {vm_size or 'Unknown'} | Power: {power_state}",
                            measured_value=f"VM runs without active auto-shutdown schedule (State: {power_state})",
                            recommended_configuration="Enable automated daily auto-shutdown at 19:00 local time",
                            recommendation=(
                                f"VM '{vm_name}' does not have an active auto-shutdown schedule."
                                + (f" Eligible compute monthly cost: {currency} {vm_compute_cost:,.2f}." if vm_compute_cost is not None else "")
                            ),
                            metric_period=f"Last Completed Month ({cost_month})",
                            data_source="Microsoft.DevTestLab/schedules API & Azure Cost Management",
                            evidence={
                                "environment": env_val,
                                "vm_size": vm_size,
                                "deallocated_status": power_state,
                                "power_state": power_state,
                                "auto_shutdown_enabled": auto_shutdown_status == "Enabled",
                                "auto_shutdown_status": auto_shutdown_status,
                                "scheduled_shutdown_time": scheduled_time_display,
                                "shutdown_time": sch_time,
                                "timezone": sch_tz,
                                "vm_compute_cost": round(vm_compute_cost, 2) if vm_compute_cost is not None else None,
                                "stoppable_hours_year": stoppable_hours_year,
                                "savings_pct": savings_pct,
                                "actual_cost_mtd": round(vm_compute_cost, 2) if vm_compute_cost is not None else None,
                                "cost_month": cost_month
                            },
                            current_monthly_cost=round(vm_compute_cost, 2) if vm_compute_cost is not None else None,
                            estimated_monthly_savings=monthly_compute_savings,
                            estimated_annual_savings=annual_savings,
                            currency=currency,
                            savings_type="Estimated Savings" if monthly_compute_savings is not None else "Not Estimated",
                            confidence="High" if monthly_compute_savings is not None else "Low",
                            calculation_method="Savings % = scheduled stoppable hours/year (4380) / 8760; monthly estimate = eligible compute cost * savings %; annual = monthly * 12 (compute-only proxy)",
                            validation_required="Verify actual execution and exclude disk, reserved-instance and other continuing charges; may overlap Off-Hours Execution.",
                            collected_at=now_str
                        )
                    )

        total_monthly = sum((f.estimated_monthly_savings or 0.0) for f in findings)
        status = AssessmentStatus.COMPLETED if (findings or not errors) else AssessmentStatus.FAILED
        if not findings and not errors:
            status = AssessmentStatus.NO_FINDINGS

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
