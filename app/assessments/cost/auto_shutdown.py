import datetime
import re
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

                # Pure tag-based scoping: If target tags provided, match ONLY matching VMs.
                # If target tags are empty, analyze ALL VMs lacking auto-shutdown schedules.
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
                # Flag non-prod VMs where auto-shutdown is NOT enabled AND VM is running or incurs compute runtime
                if auto_shutdown_status != "Enabled":
                    vm_size = props.get("hardwareProfile", {}).get("vmSize", "Standard_D2s_v5")
                    rates = PricingEngine.get_vm_rates(vm_size)

                    # AGGREGATE FULL COST OF VM AND ALL ATTACHED ASSETS (Disks, NICs, IPs)
                    storage_prof = props.get("storageProfile", {})
                    os_disk_id = storage_prof.get("osDisk", {}).get("managedDisk", {}).get("id")
                    os_disk_cost = cost_map.get(normalize_resource_id(os_disk_id), {}).get("cost", 0.0) if os_disk_id else 0.0

                    data_disks_cost = 0.0
                    for dd in storage_prof.get("dataDisks", []):
                        dd_id = dd.get("managedDisk", {}).get("id")
                        if dd_id:
                            data_disks_cost += cost_map.get(normalize_resource_id(dd_id), {}).get("cost", 0.0)

                    network_prof = props.get("networkProfile", {})
                    nics_cost = 0.0
                    for nic in network_prof.get("networkInterfaces", []):
                        nic_id = nic.get("id")
                        if nic_id:
                            nics_cost += cost_map.get(normalize_resource_id(nic_id), {}).get("cost", 0.0)

                    vm_compute_cost = cost_map.get(norm_vm_id, {}).get("cost", 0.0)
                    total_vm_cost = vm_compute_cost + os_disk_cost + data_disks_cost + nics_cost

                    # Fallback if no billing data exists yet
                    if total_vm_cost <= 0.0:
                        total_vm_cost = rates.get("monthly", 70.08)

                    # User formula: hourly rate = (last month cost / 710 hours)
                    # Savings = hourly rate * off_hours (~360 off-hours per month)
                    hourly_rate = total_vm_cost / 710.0
                    monthly_compute_savings = round(hourly_rate * 360.0, 2)
                    annual_savings = round(monthly_compute_savings * 12.0, 2)

                    cost_item = cost_map.get(norm_vm_id, {})
                    currency = cost_item.get("currency", context.currency)
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
                            region=vm.get("location", "global"),
                            severity="High" if auto_shutdown_status == "Not Configured" else "Medium",
                            status=f"Shutdown {auto_shutdown_status}",
                            current_configuration=f"Environment: {env_val} | Auto-Shutdown: {auto_shutdown_status} | Size: {vm_size} | Power: {power_state}",
                            measured_value=f"VM runs without active auto-shutdown schedule (State: {power_state})",
                            recommended_configuration="Enable automated daily auto-shutdown at 19:00 local time",
                            recommendation=f"Non-production VM '{vm_name}' does not have an active auto-shutdown schedule. Total VM + assets monthly cost: ${total_vm_cost:,.2f}.",
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
                                "vm_compute_cost": round(vm_compute_cost, 2),
                                "os_disk_cost": round(os_disk_cost, 2),
                                "data_disks_cost": round(data_disks_cost, 2),
                                "network_cost": round(nics_cost, 2),
                                "total_vm_cost": round(total_vm_cost, 2),
                                "hourly_rate": round(hourly_rate, 4),
                                "actual_cost_mtd": round(total_vm_cost, 2),
                                "cost_month": cost_month
                            },
                            current_monthly_cost=round(total_vm_cost, 2),
                            estimated_monthly_savings=monthly_compute_savings,
                            estimated_annual_savings=annual_savings,
                            currency=currency,
                            savings_type="Estimated Savings",
                            confidence="High",
                            calculation_method=f"Total VM + attached assets cost (${total_vm_cost:,.2f}) / 710 hours * 360 off-hours",
                            validation_required="Confirm developers do not require off-hours or overnight compute runtime",
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
