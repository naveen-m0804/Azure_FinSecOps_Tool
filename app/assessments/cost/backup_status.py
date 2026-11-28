import datetime
import time
import logging
from typing import List, Dict, Any, Optional, Tuple
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.backup import BackupAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.environment import resolve_environment, matches_target_tags
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id

logger = logging.getLogger("azure_finsecops.assessments.backup_status")

# Severity order helper
SEVERITY_ORDER = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

def _pick_higher_severity(current: str, proposed: str) -> str:
    if SEVERITY_ORDER.get(proposed, 0) > SEVERITY_ORDER.get(current, 0):
        return proposed
    return current


def _parse_policy_retention(policy: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Parses backup policy properties across diverse Azure Backup workload types:
    - AzureIaasVM (Azure Virtual Machines)
    - AzureStorage (Azure Files / Blob Storage)
    - AzureWorkload (SQL Server, SAP HANA in Azure VMs via subProtectionPolicy)
    - MAB (Microsoft Azure Backup Server / Windows agent)
    """
    props = policy.get("properties", {}) or {}
    workload_type = props.get("backupManagementType") or props.get("workLoadType") or "AzureIaasVM"

    retention: Dict[str, Any] = {
        "daily_days": None,
        "weekly_weeks": None,
        "monthly_months": None,
        "yearly_years": None,
        "summary": "No explicit schedule"
    }

    ret_policy = props.get("retentionPolicy") or {}
    
    # Handle AzureWorkload (SQL / HANA) which uses subProtectionPolicy array
    if not ret_policy and "subProtectionPolicy" in props:
        sub_policies = props.get("subProtectionPolicy", [])
        for sub in sub_policies:
            # Prioritize Full backup retention schedule
            p_type = sub.get("policyType", "")
            if p_type.lower() in ("full", ""):
                ret_policy = sub.get("retentionPolicy") or {}
                if ret_policy:
                    break

    # 1. Daily Schedule
    daily = ret_policy.get("dailySchedule")
    if daily and isinstance(daily, dict):
        dur = daily.get("retentionDuration", {})
        cnt = dur.get("count")
        dtype = (dur.get("durationType") or "Days").lower()
        if cnt is not None:
            retention["daily_days"] = cnt * 7 if "week" in dtype else cnt

    # Simple retention format fallback
    if retention["daily_days"] is None and "retentionDuration" in ret_policy:
        simple_dur = ret_policy.get("retentionDuration", {})
        cnt = simple_dur.get("count")
        dtype = (simple_dur.get("durationType") or "Days").lower()
        if cnt is not None:
            if "day" in dtype:
                retention["daily_days"] = cnt
            elif "week" in dtype:
                retention["weekly_weeks"] = cnt

    # 2. Weekly Schedule
    weekly = ret_policy.get("weeklySchedule")
    if weekly and isinstance(weekly, dict):
        dur = weekly.get("retentionDuration", {})
        cnt = dur.get("count")
        dtype = (dur.get("durationType") or "Weeks").lower()
        if cnt is not None:
            retention["weekly_weeks"] = (cnt // 7) if "day" in dtype else cnt

    # 3. Monthly Schedule
    monthly = ret_policy.get("monthlySchedule")
    if monthly and isinstance(monthly, dict):
        dur = monthly.get("retentionDuration", {})
        cnt = dur.get("count")
        dtype = (dur.get("durationType") or "Months").lower()
        if cnt is not None:
            retention["monthly_months"] = cnt

    # 4. Yearly Schedule
    yearly = ret_policy.get("yearlySchedule")
    if yearly and isinstance(yearly, dict):
        dur = yearly.get("retentionDuration", {})
        cnt = dur.get("count")
        dtype = (dur.get("durationType") or "Years").lower()
        if cnt is not None:
            retention["yearly_years"] = cnt

    # Build human summary
    parts = []
    if retention["daily_days"] is not None:
        parts.append(f"Daily: {retention['daily_days']}d")
    if retention["weekly_weeks"] is not None:
        parts.append(f"Weekly: {retention['weekly_weeks']}w")
    if retention["monthly_months"] is not None:
        parts.append(f"Monthly: {retention['monthly_months']}m")
    if retention["yearly_years"] is not None:
        parts.append(f"Yearly: {retention['yearly_years']}y")

    retention["summary"] = " | ".join(parts) if parts else "Default Retention"
    return workload_type, retention


class BackupStatusAssessment(BaseAssessment):
    assessment_id = "backup_status"
    code = "COST-14"
    category = "cost"
    name = "Backup Status / Policy / Retention"
    description = "Audit Azure Recovery Services Vault backup policies to identify excessive retention schedules driving unnecessary backup storage costs."
    purpose = "Optimize cloud storage by right-sizing backup retention configurations across daily, weekly, monthly, and yearly schedules."
    required_permissions = [
        "Microsoft.RecoveryServices/vaults/read",
        "Microsoft.RecoveryServices/vaults/backupPolicies/read",
        "Reader"
    ]
    required_data_sources = ["Azure Recovery Services Vaults API & Backup Policies API"]

    # Official Optimization Thresholds
    DAILY_THRESHOLD_DAYS = 90
    WEEKLY_THRESHOLD_WEEKS = 52
    MONTHLY_THRESHOLD_MONTHS = 36
    YEARLY_THRESHOLD_YEARS = 7

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        permission_errors = 0
        resources_evaluated = 0

        # Retrieve last completed calendar month date range for real cost attribution
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()

        for sub in context.subscriptions:
            # Query last completed month cost for Recovery Services Vaults
            cost_map: Dict[str, Dict[str, Any]] = {}
            try:
                cost_map = await CostManagementAdapter.query_resource_costs(
                    context.client,
                    subscription_id=sub.subscription_id,
                    start_date=cost_start,
                    end_date=cost_end,
                    resource_type_filter="Microsoft.RecoveryServices/vaults"
                )
            except Exception as ex:
                logger.debug("Cost Management query for vaults in sub %s: %s", sub.subscription_id, ex)

            # Discover Recovery Services Vaults
            vaults: List[Dict[str, Any]] = []
            try:
                vaults = await BackupAdapter.get_recovery_vaults(context.client, sub.subscription_id)
            except PermissionError as pex:
                permission_errors += 1
                errors.append(f"Subscription {sub.display_name} ({sub.subscription_id}): {pex}")
                continue
            except Exception as ex:
                errors.append(f"Failed to scan recovery vaults for subscription {sub.subscription_id}: {ex}")
                continue

            for vault in vaults:
                vault_id = vault.get("id", "")
                vault_name = vault.get("name", "UnknownVault")
                vault_parsed = parse_azure_resource_id(vault_id)
                vault_rg = vault_parsed.get("resource_group", "")
                vault_loc = vault.get("location", "global")
                vault_tags = vault.get("tags") or {}
                if not matches_target_tags(vault_tags, context.target_tags):
                    continue

                env_val = resolve_environment(
                    vault_tags, vault_name, vault_rg,
                    prod_tags=context.prod_tags,
                    test_tags=context.test_tags,
                    target_tags=context.target_tags
                )

                # Query policies for this specific vault
                policies: List[Dict[str, Any]] = []
                try:
                    policies = await BackupAdapter.get_backup_policies(context.client, vault_id)
                except PermissionError as pex:
                    errors.append(f"Permission denied on vault '{vault_name}': {pex}")
                    continue
                except Exception as ex:
                    errors.append(f"Failed to fetch policies for vault '{vault_name}': {ex}")
                    continue

                # Query protected items in vault to map workloads to policies and estimate storage
                protected_items_by_policy: Dict[str, int] = {}
                total_protected_items = 0
                try:
                    items = await BackupAdapter.get_backup_protected_items(context.client, vault_id)
                    total_protected_items = len(items)
                    for it in items:
                        p_props = it.get("properties", {}) or {}
                        p_name = p_props.get("policyName") or ""
                        p_id = p_props.get("policyId") or ""
                        p_key = p_name or (p_id.split("/")[-1] if p_id else "")
                        if p_key:
                            protected_items_by_policy[p_key.lower()] = protected_items_by_policy.get(p_key.lower(), 0) + 1
                except Exception as ex:
                    logger.debug("Failed to retrieve protected items for %s: %s", vault_name, ex)

                # Each policy is an evaluated protection resource
                resources_evaluated += len(policies) if policies else 1

                # Check if vault cost is recorded
                norm_vault_id = normalize_resource_id(vault_id)
                vault_cost_data = cost_map.get(norm_vault_id, {})
                vault_cost = vault_cost_data.get("cost", 0.0)
                vault_currency = vault_cost_data.get("currency", context.currency)

                # Filter non-default policies to allocate costs fairly
                non_default_policies = [p for p in policies if "default" not in p.get("name", "").lower()]
                active_policy_count = len(non_default_policies) if non_default_policies else len(policies)

                for policy in policies:
                    policy_id = policy.get("id", "")
                    policy_name = policy.get("name", "DefaultPolicy")
                    workload_type, ret = _parse_policy_retention(policy)

                    items_for_policy = protected_items_by_policy.get(policy_name.lower(), 0)

                    # Fair-share cost allocation: based on protected workload count or active policies
                    if total_protected_items > 0 and items_for_policy > 0:
                        weight = items_for_policy / total_protected_items
                        policy_share_cost = round(vault_cost * weight, 2)
                    elif active_policy_count > 0:
                        policy_share_cost = round(vault_cost / active_policy_count, 2)
                    else:
                        policy_share_cost = round(vault_cost, 2)

                    # Estimate backup storage volume from allocated spend using Azure Retail Prices API
                    storage_rate = await PricingEngine.get_backup_storage_gb_price(vault_loc, vault_currency)
                    if policy_share_cost > 0 and storage_rate and storage_rate > 0:
                        est_storage_gb = round(policy_share_cost / storage_rate, 1)
                        est_storage_tb = round(est_storage_gb / 1024, 2)
                        if est_storage_tb >= 1.0:
                            backup_storage_disp = f"~{est_storage_tb:.2f} TB"
                        else:
                            backup_storage_disp = f"~{est_storage_gb:.0f} GB"
                    elif items_for_policy > 0:
                        backup_storage_disp = f"{items_for_policy} Item(s)"
                        est_storage_gb = None
                        est_storage_tb = None
                    else:
                        backup_storage_disp = "--"
                        est_storage_gb = None
                        est_storage_tb = None

                    daily_days = ret.get("daily_days")
                    weekly_weeks = ret.get("weekly_weeks")
                    monthly_months = ret.get("monthly_months")
                    yearly_years = ret.get("yearly_years")

                    exceeded_details: List[str] = []
                    severity = "Low"
                    max_excess_ratio = 0.0

                    # 1. Evaluate Daily Retention (> 90 days)
                    if daily_days is not None and daily_days > self.DAILY_THRESHOLD_DAYS:
                        ratio = (daily_days - self.DAILY_THRESHOLD_DAYS) / daily_days
                        max_excess_ratio = max(max_excess_ratio, ratio)
                        if daily_days <= 180:
                            s = "Medium"
                        elif daily_days <= 365:
                            s = "High"
                        else:
                            s = "Critical"
                        severity = _pick_higher_severity(severity, s)
                        exceeded_details.append(
                            f"Daily retention of {daily_days} days exceeds recommended {self.DAILY_THRESHOLD_DAYS} days threshold"
                        )

                    # 2. Evaluate Weekly Retention (> 52 weeks)
                    if weekly_weeks is not None and weekly_weeks > self.WEEKLY_THRESHOLD_WEEKS:
                        ratio = (weekly_weeks - self.WEEKLY_THRESHOLD_WEEKS) / weekly_weeks
                        max_excess_ratio = max(max_excess_ratio, ratio)
                        if weekly_weeks <= 104:
                            s = "Medium"
                        elif weekly_weeks <= 260:
                            s = "High"
                        else:
                            s = "Critical"
                        severity = _pick_higher_severity(severity, s)
                        exceeded_details.append(
                            f"Weekly retention of {weekly_weeks} weeks exceeds recommended {self.WEEKLY_THRESHOLD_WEEKS} weeks threshold"
                        )

                    # 3. Evaluate Monthly Retention (> 36 months)
                    if monthly_months is not None and monthly_months > self.MONTHLY_THRESHOLD_MONTHS:
                        ratio = (monthly_months - self.MONTHLY_THRESHOLD_MONTHS) / monthly_months
                        max_excess_ratio = max(max_excess_ratio, ratio)
                        if monthly_months <= 60:
                            s = "Medium"
                        elif monthly_months <= 120:
                            s = "High"
                        else:
                            s = "Critical"
                        severity = _pick_higher_severity(severity, s)
                        exceeded_details.append(
                            f"Monthly retention of {monthly_months} months exceeds recommended {self.MONTHLY_THRESHOLD_MONTHS} months threshold"
                        )

                    # 4. Evaluate Yearly Retention (> 7 years)
                    if yearly_years is not None and yearly_years > self.YEARLY_THRESHOLD_YEARS:
                        ratio = (yearly_years - self.YEARLY_THRESHOLD_YEARS) / yearly_years
                        max_excess_ratio = max(max_excess_ratio, ratio)
                        if yearly_years <= 10:
                            s = "Medium"
                        elif yearly_years <= 15:
                            s = "High"
                        else:
                            s = "Critical"
                        severity = _pick_higher_severity(severity, s)
                        exceeded_details.append(
                            f"Yearly retention of {yearly_years} years exceeds recommended {self.YEARLY_THRESHOLD_YEARS} years threshold"
                        )

                    # Only generate finding when excessive retention is identified
                    if exceeded_details:
                        # Cost optimization savings calculation:
                        # Formula: Excess Retention Ratio * Policy Allocated Share Cost
                        est_monthly_saving = None
                        est_annual_saving = None
                        savings_type = "Not Estimated"

                        if policy_share_cost > 0 and max_excess_ratio > 0:
                            est_monthly_saving = round(policy_share_cost * max_excess_ratio, 2)
                            est_annual_saving = round(est_monthly_saving * 12, 2)
                            savings_type = "Estimated Savings"

                        measured_str = "; ".join(exceeded_details)
                        rec_str = (
                            f"Policy '{policy_name}' in vault '{vault_name}' ({workload_type}) retains recovery points beyond recommended operational thresholds. "
                            "Review compliance requirements and shorten retention windows to reduce recurring backup storage fees."
                        )

                        primary_retention = ret["summary"]
                        primary_days = daily_days or (weekly_weeks * 7 if weekly_weeks else None)

                        findings.append(
                            FindingModel(
                                finding_id=f"cost14-{vault_name[:12]}-{policy_name[:16]}",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=vault_rg,
                                resource_name=f"{vault_name} / {policy_name}",
                                resource_type="Microsoft.RecoveryServices/vaults/backupPolicies",
                                resource_id=policy_id or vault_id,
                                region=vault_loc,
                                severity=severity,
                                status="Excessive Retention",
                                current_configuration=f"Workload: {workload_type} | {primary_retention}",
                                measured_value=measured_str,
                                recommended_configuration="Align retention: Daily <= 90 days, Weekly <= 52 weeks, Monthly <= 36 months, Yearly <= 7 years",
                                recommendation=rec_str,
                                metric_period=f"Last Completed Month ({cost_month})",
                                data_source=self.required_data_sources[0],
                                evidence={
                                    "vault_name": vault_name,
                                    "policy_name": policy_name,
                                    "backup_policy": policy_name,
                                    "backup_management_type": workload_type,
                                    "backup_status": "Excessive Retention",
                                    "retention_display": primary_retention,
                                    "retention_days": primary_days,
                                    "daily_retention_days": daily_days,
                                    "weekly_retention_weeks": weekly_weeks,
                                    "monthly_retention_months": monthly_months,
                                    "yearly_retention_years": yearly_years,
                                    "exceeded_rules": exceeded_details,
                                    "environment": env_val,
                                    "actual_cost_mtd": round(policy_share_cost, 2) if policy_share_cost > 0 else (round(vault_cost, 2) if vault_cost > 0 else None),
                                    "vault_total_cost": round(vault_cost, 2),
                                    "policy_share_cost": round(policy_share_cost, 2),
                                    "backup_storage_gb": est_storage_gb,
                                    "backup_storage_tb": est_storage_tb,
                                    "backup_storage_display": backup_storage_disp,
                                    "protected_items_count": items_for_policy,
                                    "savings_pct": round(max_excess_ratio * 100.0, 2) if est_monthly_saving else None,
                                    "cost_month": cost_month
                                },
                                current_monthly_cost=round(policy_share_cost, 2) if policy_share_cost > 0 else (round(vault_cost, 2) if vault_cost > 0 else None),
                                estimated_monthly_savings=est_monthly_saving,
                                estimated_annual_savings=est_annual_saving,
                                currency=vault_currency,
                                savings_type=savings_type,
                                confidence="High" if est_monthly_saving else "Low",
                                calculation_method=(
                                    "Monthly savings = current backup cost/policy - proposed backup cost/policy; % = savings/current cost; annual = monthly * 12"
                                    if est_monthly_saving else "Cost telemetry not available for vault storage sizing"
                                ),
                                validation_required="Confirm compliance, restore points, vault redundancy and backup storage; don't assume deletion.",
                                collected_at=now_str
                            )
                        )

        # Determine Assessment Status according to comprehensive health matrix
        total_subs = len(context.subscriptions)
        if findings:
            status = AssessmentStatus.COMPLETED
        elif errors:
            if permission_errors >= total_subs and total_subs > 0:
                status = AssessmentStatus.PERMISSION_DENIED
            elif len(errors) >= total_subs and total_subs > 0:
                status = AssessmentStatus.DATA_UNAVAILABLE
            else:
                status = AssessmentStatus.COMPLETED_WITH_WARNINGS
        else:
            status = AssessmentStatus.NO_FINDINGS

        total_monthly = sum((f.estimated_monthly_savings or 0.0) for f in findings if f.estimated_monthly_savings)
        total_annual = sum((f.estimated_annual_savings or 0.0) for f in findings if f.estimated_annual_savings)

        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(resources_evaluated, 1),
            findings_count=len(findings),
            findings=findings,
            total_monthly_savings=round(total_monthly, 2),
            total_annual_savings=round(total_annual, 2),
            currency=context.currency,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
