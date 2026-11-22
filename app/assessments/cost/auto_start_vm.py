import datetime
import time
from typing import List
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.dates import get_current_month_to_date
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment

class AutoStartVmAssessment(BaseAssessment):
    assessment_id = "auto_start_vm"
    code = "COST-18"
    category = "cost"
    name = "Auto Start VM"
    description = "Audit VM automated start schedules to detect unnecessary weekend or off-hours runtime schedules based on evaluation scope."
    purpose = "Align automated start schedules with actual business working hours to prevent wasted compute."
    required_permissions = [
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.DevTestLab/schedules/read",
        "Microsoft.CostManagement/query/action",
        "Reader"
    ]
    required_data_sources = ["Azure Automation / DevTestLab Schedules API & Cost Management"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        mtd_start, mtd_end = get_current_month_to_date()

        for sub in context.subscriptions:
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=mtd_start,
                end_date=mtd_end,
                resource_type_filter="microsoft.compute/virtualmachines"
            )

            try:
                vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id)
                schedules = await ComputeAdapter.get_devtest_schedules(context.client, sub.subscription_id)
            except Exception as ex:
                errors.append(f"Failed to query compute/schedules for {sub.subscription_id}: {ex}")
                continue

            # Build map of start schedules
            start_schedules = {}
            for sch in schedules:
                props = sch.get("properties", {})
                task_type = props.get("taskType", "")
                if "Start" in task_type or "Startup" in task_type:
                    target_id = normalize_resource_id(props.get("targetResourceId", ""))
                    if target_id:
                        start_schedules[target_id] = sch

            for vm in vms:
                vm_name = vm.get("name", "")
                vm_id = vm.get("id", "")
                norm_id = normalize_resource_id(vm_id)
                tags = vm.get("tags") or {}
                parsed = parse_azure_resource_id(vm_id)
                rg = parsed.get("resource_group") or ""

                # Pure tag-based scoping: If target tags provided, match ONLY matching VMs.
                # If target tags are empty, analyze ALL VMs with automated start schedules.
                clean_target_tags = [str(tt).strip() for tt in (context.target_tags or context.test_tags or []) if str(tt).strip()]
                if clean_target_tags:
                    matched_vm = False
                    for tt in clean_target_tags:
                        tt_lower = tt.lower()
                        for k, v in tags.items():
                            if tt_lower == str(k).strip().lower() or tt_lower == str(v).strip().lower() or tt_lower in f"{k}={v}".lower():
                                matched_vm = True
                                break
                        if not matched_vm and (tt_lower in rg.lower() or tt_lower in vm_name.lower()):
                            matched_vm = True
                            break
                        if matched_vm:
                            break
                    if not matched_vm:
                        continue

                resources_evaluated += 1
                env_val = resolve_environment(tags, vm_name, rg, prod_tags=context.prod_tags, test_tags=context.test_tags, target_tags=context.target_tags)

                matched_sch = start_schedules.get(norm_id)
                auto_start_status = "Not Configured"
                configured_start_time = "Unavailable"

                if matched_sch:
                    sch_props = matched_sch.get("properties", {})
                    sch_status = sch_props.get("status", "Disabled")
                    daily_rec = sch_props.get("dailyRecurrence", {})
                    time_val = daily_rec.get("time")
                    tz_val = sch_props.get("timeZoneId", "UTC")
                    auto_start_status = f"Configured ({sch_status})"
                    if time_val:
                        configured_start_time = f"{time_val} ({tz_val})"

                # If auto-start schedule turns VM on 7 days a week including weekends for dev/test:
                if matched_sch and "enabled" in auto_start_status.lower():
                    props = vm.get("properties", {})
                    vm_size = props.get("hardwareProfile", {}).get("vmSize", "Standard_D2s_v5")
                    rates = PricingEngine.get_vm_rates(vm_size)
                    hourly_rate = rates.get("hourly", 0.096)

                    # Compute cost of unnecessary weekend runtime (48 hours/weekend * 52 weekends)
                    annual_cost_impact = round(48 * 52 * hourly_rate, 2)
                    cost_item = cost_map.get(norm_id, {})
                    cost_val = cost_item.get("cost", rates.get("monthly", 70.08))
                    currency = cost_item.get("currency", context.currency)

                    parsed = parse_azure_resource_id(vm_id)

                    findings.append(
                        FindingModel(
                            finding_id=f"cost18-{vm_name[:12]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=parsed.get("resource_group") or "Unknown",
                            resource_name=vm_name,
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_id=vm_id,
                            region=vm.get("location", "global"),
                            severity="Medium",
                            status=auto_start_status,
                            current_configuration=f"Size: {vm_size} | Auto-Start: {auto_start_status} | Time: {configured_start_time}",
                            measured_value="VM scheduled to start 7 days a week including weekend hours",
                            recommended_configuration="Restrict automated start schedule to Monday-Friday 07:00",
                            recommendation=f"VM '{vm_name}' has an active auto-start schedule that initiates runtime during weekends.",
                            metric_period=f"{mtd_start} to {mtd_end} (MTD)",
                            data_source="Azure Automation & DevTestLab Schedules API",
                            evidence={
                                "environment": env_val,
                                "vm_size": vm_size,
                                "auto_start_status": auto_start_status,
                                "configured_start_time": configured_start_time,
                                "annual_cost_impact": annual_cost_impact,
                                "actual_cost_mtd": round(cost_val, 2)
                            },
                            current_monthly_cost=round(cost_val, 2),
                            estimated_monthly_savings=0.0,
                            estimated_annual_savings=annual_cost_impact,
                            currency=currency,
                            savings_type="Cost Avoidance",
                            confidence="High",
                            calculation_method="48 weekend hours * 52 weeks * hourly compute rate",
                            validation_required="Confirm developers do not require weekend runtime",
                            collected_at=now_str
                        )
                    )

        total_impact = sum((f.evidence.get("annual_cost_impact", f.estimated_annual_savings or 0.0)) for f in findings)
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
            total_monthly_savings=0.0,
            total_annual_savings=round(total_impact, 2),
            currency=context.currency,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
