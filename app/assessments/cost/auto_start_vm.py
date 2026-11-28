import datetime
import time
from typing import List, Dict, Any, Optional, Tuple
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.monitor import MonitorAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment, matches_target_tags


def _parse_iso_datetime(dt_val: Any) -> Optional[datetime.datetime]:
    if not dt_val or not isinstance(dt_val, str):
        return None
    try:
        clean_str = dt_val.strip().replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        return None


def _is_event_in_off_hours(ts_str: str, shutdown_hour: int, shutdown_minute: int = 0) -> bool:
    """Checks whether an event timestamp falls into off-hours (between scheduled shutdown and 07:00 AM, or weekend)."""
    dt = _parse_iso_datetime(ts_str)
    if not dt:
        return False
    # Weekends (Saturday = 5, Sunday = 6)
    if dt.weekday() in (5, 6):
        return True
    hour = dt.hour
    # Off-hours: from shutdown time until 07:00 AM
    if shutdown_hour <= hour or hour < 7:
        return True
    return False


class AutoStartVmAssessment(BaseAssessment):
    assessment_id = "auto_start_vm"
    code = "COST-17"
    category = "cost"
    name = "VM Auto-Shutdown Off-Hours Execution"
    description = "Detect virtual machines with auto-shutdown configured that are running or active during their scheduled shutdown windows, including manual start activity logs and weekend executions."
    purpose = "Eliminate off-hours compute waste when auto-shutdown policies are bypassed, overridden, or running outside business hours."
    required_permissions = [
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.DevTestLab/schedules/read",
        "Microsoft.Insights/eventtypes/values/read",
        "Microsoft.CostManagement/query/action",
        "Reader"
    ]
    required_data_sources = ["Azure DevTestLab Schedules API, Azure Activity Logs & Cost Management"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        now_str = now_dt.isoformat()
        thirty_days_ago_dt = now_dt - datetime.timedelta(days=30)
        thirty_days_ago_str = thirty_days_ago_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()

        for sub in context.subscriptions:
            # 1. Query Cost Management for real VM expenditure
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=cost_start,
                end_date=cost_end
            )

            # 2. Query VMs and DevTestLab Schedules
            try:
                vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id, expand_instance_view=True)
                schedules = await ComputeAdapter.get_devtest_schedules(context.client, sub.subscription_id)
            except Exception as ex:
                errors.append(f"Failed to query compute/schedules for {sub.subscription_id}: {ex}")
                continue

            # 3. Query Activity Logs to capture off-hours start/restart operations
            vm_activity_logs: Dict[str, List[Dict[str, Any]]] = {}
            try:
                activity_logs = await MonitorAdapter.get_activity_logs(
                    context.client,
                    sub.subscription_id,
                    start_time=thirty_days_ago_str
                )
                for evt in activity_logs:
                    res_id = (evt.get("resourceId") or "").strip().lower()
                    if res_id and "microsoft.compute/virtualmachines" in res_id:
                        if res_id not in vm_activity_logs:
                            vm_activity_logs[res_id] = []
                        vm_activity_logs[res_id].append(evt)
            except Exception as ex:
                errors.append(f"Failed to query activity logs for {sub.subscription_id}: {ex}")

            # 4. Build schedule maps
            start_schedules = {}
            shutdown_schedules = {}
            for sch in schedules:
                props = sch.get("properties", {})
                task_type = props.get("taskType", "")
                target_id = normalize_resource_id(props.get("targetResourceId", ""))
                if target_id:
                    if "Start" in task_type or "Startup" in task_type:
                        start_schedules[target_id] = sch
                    elif "Shutdown" in task_type or task_type == "ComputeVmShutdownTask":
                        shutdown_schedules[target_id] = sch

            for vm in vms:
                vm_name = vm.get("name", "")
                vm_id = vm.get("id", "")
                norm_id = normalize_resource_id(vm_id)
                tags = vm.get("tags") or {}
                if not matches_target_tags(tags, context.target_tags):
                    continue
                parsed = parse_azure_resource_id(vm_id)
                rg = parsed.get("resource_group") or vm.get("resourceGroup") or "Unknown"

                # Check if auto-shutdown is configured on this VM
                matched_shutdown = shutdown_schedules.get(norm_id)
                if not matched_shutdown:
                    continue

                s_props = matched_shutdown.get("properties", {})
                shutdown_status = s_props.get("status", "Disabled")
                if shutdown_status.lower() != "enabled":
                    # If auto-shutdown is not enabled, it is governed by COST-08
                    continue

                resources_evaluated += 1
                env_val = resolve_environment(
                    tags,
                    vm_name,
                    rg,
                    prod_tags=context.prod_tags,
                    test_tags=context.test_tags,
                    target_tags=context.target_tags
                )

                s_rec = s_props.get("dailyRecurrence", {})
                s_time_raw = s_rec.get("time", "1900")
                s_tz = s_props.get("timeZoneId", "UTC")

                # Parse shutdown time e.g. "1900" -> 19:00
                shutdown_hour = 19
                shutdown_minute = 0
                if s_time_raw and len(s_time_raw) == 4 and s_time_raw.isdigit():
                    shutdown_hour = int(s_time_raw[:2])
                    shutdown_minute = int(s_time_raw[2:])
                    shutdown_time_str = f"{s_time_raw[:2]}:{s_time_raw[2:]} ({s_tz})"
                else:
                    shutdown_time_str = f"{s_time_raw} ({s_tz})"

                # 5. Check VM PowerState
                props = vm.get("properties", {})
                inst_view = props.get("instanceView", {})
                statuses = inst_view.get("statuses", [])
                power_state = "Running"
                for st in statuses:
                    code = st.get("code", "")
                    if "PowerState/deallocated" in code:
                        power_state = "Deallocated"
                        break
                    elif "PowerState/stopped" in code:
                        power_state = "Stopped"
                        break
                    elif "PowerState/running" in code:
                        power_state = "Running"

                # 6. Check Activity Logs during shutdown/off-hours duration
                norm_lower = norm_id.lower()
                vm_logs = vm_activity_logs.get(norm_lower, [])
                off_hours_log_entries: List[str] = []

                for evt in vm_logs:
                    op_val = evt.get("operationName")
                    op_name = (op_val.get("value") if isinstance(op_val, dict) else str(op_val or "")).lower()
                    ts = evt.get("eventTimestamp") or ""
                    caller = evt.get("caller") or "Unknown"

                    # Look for start or restart operations
                    if any(action in op_name for action in ("start/action", "restart/action")):
                        if _is_event_in_off_hours(ts, shutdown_hour, shutdown_minute):
                            clean_ts = ts.replace("T", " ")[:16]
                            short_caller = caller.split("@")[0] if "@" in caller else caller
                            off_hours_log_entries.append(f"Started at {clean_ts} by {short_caller}")

                # 7. Check Auto-Start Schedule
                matched_start = start_schedules.get(norm_id)
                auto_start_status = "Not Configured"
                configured_start_time = "--"
                has_weekend_start = False
                if matched_start:
                    start_props = matched_start.get("properties", {})
                    start_st = start_props.get("status", "Disabled")
                    start_rec = start_props.get("dailyRecurrence", {})
                    start_time_val = start_rec.get("time")
                    start_tz = start_props.get("timeZoneId", "UTC")
                    auto_start_status = f"Configured ({start_st})"
                    if start_time_val:
                        configured_start_time = f"{start_time_val} ({start_tz})"
                    if start_st.lower() == "enabled":
                        has_weekend_start = True

                # 8. Evaluate Off-Hours Execution Conditions:
                # - Condition A: VM is currently in Running state despite having auto-shutdown enabled
                # - Condition B: Off-hours start/restart activity logs detected during shutdown window
                # - Condition C: Auto-start initiates runtime on weekends
                is_running_in_shutdown = (power_state == "Running")
                has_off_hours_activity = len(off_hours_log_entries) > 0

                if is_running_in_shutdown or has_off_hours_activity or has_weekend_start:
                    vm_size = props.get("hardwareProfile", {}).get("vmSize")
                    vm_region = vm.get("location", "")
                    os_type = props.get("storageProfile", {}).get("osDisk", {}).get("osType", "Linux")

                    cost_item = cost_map.get(norm_id, {})
                    actual_cost = cost_item.get("cost")
                    currency = cost_item.get("currency", context.currency)

                    cost_val: Optional[float] = None
                    hourly_rate: Optional[float] = None
                    if actual_cost is not None and actual_cost > 0:
                        cost_val = float(actual_cost)
                        hourly_rate = round(cost_val / 730.0, 4)
                    elif vm_size:
                        vm_rates = await PricingEngine.get_vm_rates(vm_size, vm_region, os_type=os_type, currency=currency)
                        if vm_rates:
                            cost_val = vm_rates.get("monthly")
                            hourly_rate = vm_rates.get("hourly")

                    # Formula (R18): Weekday shutdown 10 hours/day * 5 days/week -> 2600 annual shutdown hours / 8760 = 29.68%
                    assumption_ratio = 2600.0 / 8760.0
                    assumption_pct = round(assumption_ratio * 100.0, 2)  # 29.68%
                    monthly_impact: Optional[float] = round(cost_val * assumption_ratio, 2) if (cost_val is not None and cost_val > 0) else None
                    annual_impact: Optional[float] = round(monthly_impact * 12.0, 2) if monthly_impact is not None else None

                    # Determine descriptive status and activity summary
                    if is_running_in_shutdown and has_off_hours_activity:
                        status_label = "Running in Shutdown Window"
                        latest_log = off_hours_log_entries[0]
                        activity_summary = f"Running | {latest_log}"
                        rec_label = (
                            f"VM '{vm_name}' is running during its configured shutdown duration ({shutdown_time_str}). "
                            f"Activity Log: {latest_log}. Deallocate VM after off-hours work completes to prevent recurring idle spend."
                        )
                    elif is_running_in_shutdown:
                        status_label = "Running in Shutdown Window"
                        activity_summary = f"Running during scheduled shutdown ({shutdown_time_str})"
                        rec_label = (
                            f"VM '{vm_name}' is currently running during its configured auto-shutdown period ({shutdown_time_str}). "
                            "Ensure the VM is deallocated when off-hours tasks finish."
                        )
                    elif has_off_hours_activity:
                        status_label = "Off-Hours Activity Logged"
                        activity_summary = off_hours_log_entries[0]
                        rec_label = (
                            f"VM '{vm_name}' has off-hours start logs during its shutdown period ({off_hours_log_entries[0]}). "
                            "Align runtime schedules to prevent paying for unmanaged off-hours compute."
                        )
                    else:
                        status_label = "Weekend Auto-Start Scheduled"
                        activity_summary = f"Auto-Start: {configured_start_time} (Mon-Sun)"
                        rec_label = f"VM '{vm_name}' has an auto-start schedule that initiates runtime during weekends."

                    measured_val = (
                        f"Shutdown: {shutdown_time_str} | State: {power_state} | "
                        f"Activity: {activity_summary}"
                    )

                    findings.append(
                        FindingModel(
                            finding_id=f"cost17-{sub.subscription_id[:8]}-{vm_name[:20]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg,
                            resource_name=vm_name,
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_id=vm_id,
                            region=vm.get("location", "global"),
                            severity="High" if (annual_impact or 0) > 600.0 else "Medium",
                            status=status_label,
                            current_configuration=f"Size: {vm_size or 'Unknown'} | Shutdown: {shutdown_time_str} | State: {power_state}",
                            measured_value=measured_val,
                            recommended_configuration="Ensure VM shuts down during off-hours; deallocate when ad-hoc off-hours work completes",
                            recommendation=rec_label,
                            metric_period=f"Last Completed Month ({cost_month})",
                            data_source="Azure DevTestLab Schedules & Azure Activity Logs",
                            evidence={
                                "environment": env_val,
                                "vm_size": vm_size,
                                "scheduled_shutdown_time": shutdown_time_str,
                                "power_state": power_state,
                                "off_hours_status": activity_summary,
                                "off_hours_logs": off_hours_log_entries,
                                "auto_start_status": auto_start_status,
                                "configured_start_time": configured_start_time,
                                "hourly_rate": hourly_rate,
                                "savings_pct": assumption_pct,
                                "annual_cost_impact": annual_impact,
                                "actual_cost_mtd": round(cost_val, 2) if cost_val is not None else None,
                                "cost_month": cost_month
                            },
                            current_monthly_cost=round(cost_val, 2) if cost_val is not None else None,
                            estimated_monthly_savings=monthly_impact,
                            estimated_annual_savings=annual_impact,
                            currency=currency,
                            savings_type="Scenario Savings" if monthly_impact is not None else "Not Estimated",
                            confidence="Medium" if monthly_impact is not None else "Low",
                            calculation_method="Assumption % = 2600/8760 (29.68%); monthly savings = eligible VM compute cost * 29.68%; annual = monthly * 12",
                            validation_required="Apply only to eligible compute; verify schedule and actual shutdowns. Potentially duplicate with Auto Shutdown Status.",
                            collected_at=now_str
                        )
                    )

        # Sort findings by annual cost impact descending
        findings.sort(key=lambda f: (f.estimated_annual_savings or 0.0), reverse=True)

        total_impact = sum((f.estimated_annual_savings or 0.0) for f in findings if f.estimated_annual_savings)
        total_monthly = sum((f.estimated_monthly_savings or 0.0) for f in findings if f.estimated_monthly_savings)
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
            total_annual_savings=round(total_impact, 2),
            currency=context.currency,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
