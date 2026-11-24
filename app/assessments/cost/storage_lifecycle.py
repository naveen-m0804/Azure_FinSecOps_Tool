import datetime
import time
from typing import List, Dict, Any, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.storage import StorageAdapter
from app.azure.cost_management import CostManagementAdapter
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment


class StorageLifecycleAssessment(BaseAssessment):
    assessment_id = "storage_lifecycle"
    code = "COST-12"
    category = "cost"
    name = "Storage Account Lifecycle Management (LCM) Status"
    description = "Audit storage accounts to verify whether Lifecycle Management (LCM) is applied/configured, or if applied, whether all rules are currently disabled."
    purpose = "Audit storage accounts to verify whether Lifecycle Management (LCM) is applied/configured, or if applied, whether all rules are currently disabled."
    required_permissions = [
        "Microsoft.CostManagement/query/action",
        "Microsoft.Storage/storageAccounts/managementPolicies/read",
        "Cost Management Reader",
        "Reader"
    ]
    required_data_sources = ["Azure Cost Management Query API & Microsoft.Storage ManagementPolicies API"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()

        for sub in context.subscriptions:
            # 1. Query real-time resource costs for the last completed month - strictly for storage accounts
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=cost_start,
                end_date=cost_end,
                resource_type_filter="Microsoft.Storage/storageAccounts"
            )

            # 2. Retrieve all storage accounts in subscription
            try:
                storage_accounts = await StorageAdapter.get_storage_accounts(context.client, sub.subscription_id)
            except Exception as ex:
                errors.append(f"Failed to list storage accounts for {sub.subscription_id}: {ex}")
                continue

            for sa in storage_accounts:
                sa_name = sa.get("name", "")
                sa_id = sa.get("id", "")
                sa_type = sa.get("type", "")

                # Strict check: Evaluate ONLY Microsoft.Storage/storageAccounts
                if sa_type and sa_type.lower() not in ("microsoft.storage/storageaccounts", "storageaccounts"):
                    continue
                if sa_id and "/providers/" in sa_id.lower() and "/microsoft.storage/storageaccounts/" not in sa_id.lower():
                    continue

                resources_evaluated += 1
                norm_id = normalize_resource_id(sa_id)
                cost_item = cost_map.get(norm_id, {})
                cost_val = float(cost_item.get("cost", 0.0))
                currency = cost_item.get("currency", context.currency)

                # Storage account SKU, tier, and redundancy attributes
                sku = sa.get("sku") or {}
                sku_tier = sku.get("tier") or "Standard"
                sku_name = sku.get("name") or "Standard_LRS"
                redundancy = sku_name.split("_")[-1] if "_" in sku_name else sku_name
                properties = sa.get("properties") or {}
                access_tier = properties.get("accessTier") or "Hot"

                # 3. Retrieve storage account lifecycle management policy
                policy_res = await StorageAdapter.get_lifecycle_policy(context.client, sa_id)
                total_rules = policy_res.get("total_rules", 0)
                enabled_rules_count = policy_res.get("enabled_rules_count", 0)
                disabled_rules_count = policy_res.get("disabled_rules_count", 0)
                policy_status = policy_res.get("status", "Not Configured")

                # 4. Strict Detection Criteria matching LCM_Status_Check_Top_Storageaccounts:
                # - Condition 1: Lifecycle Management (LCM) policy applied/configured (is_lcm_configured)
                # - Condition 2: Active (enabled) rules exist in policy (has_active_rules)
                #
                # Decision Matrix:
                # - If BOTH are True (LCM configured AND has active rules) -> Compliant, NO NEED TO SHOW.
                # - If ANYONE is False, or if BOTH are False -> Non-compliant gap, MUST SHOW:
                #     * Anyone is False (LCM configured, but all rules disabled) -> "Configured - All Rules Disabled"
                #     * Both are False (LCM not configured, 0 rules) -> "Not Configured"
                is_lcm_configured = (total_rules > 0) and (policy_status not in ("Not Configured", "Configured - No Rules"))
                has_active_rules = (enabled_rules_count > 0)

                # Both are true -> Compliant: active rules transition blobs to Cool/Archive; no need to show
                if is_lcm_configured and has_active_rules:
                    continue

                if is_lcm_configured and not has_active_rules:
                    # One is false: LCM policy configured, but ALL rules are disabled
                    status_label = "Configured - All Rules Disabled"
                    display_total_rules = total_rules
                    display_active_rules = 0  # Always 0 for flagged accounts
                    measured_val = f"{total_rules} rule(s) configured, all {disabled_rules_count} disabled"
                    rec_text = (
                        f"Storage account '{sa_name}' has a lifecycle policy with {total_rules} rule(s) configured, "
                        "but every rule is disabled. Enable active rules to automatically transition older blobs to Cool/Archive."
                    )
                else:
                    # Both are false: LCM policy not configured (or 0 rules)
                    status_label = "Not Configured"
                    display_total_rules = 0
                    display_active_rules = 0  # Always 0 for flagged accounts
                    measured_val = "Lifecycle management policy not configured (0 rules)"
                    rec_text = (
                        f"Storage account '{sa_name}' has no active lifecycle management (LCM) policy configured. "
                        "Implement automated tiering rules to move aged, infrequently accessed data to Cool/Archive."
                    )

                parsed = parse_azure_resource_id(sa_id)
                rg_name = parsed.get("resource_group") or "Unknown"

                env_val = resolve_environment(
                    tags=sa.get("tags"),
                    resource_name=sa_name,
                    resource_group=rg_name,
                    prod_tags=context.prod_tags,
                    test_tags=context.test_tags,
                    target_tags=context.target_tags
                )

                actual_cost = round(cost_val, 2)
                # Defensible FinOps savings: Transitioning aged blobs to Cool/Archive yields ~30% savings
                est_monthly_saving = round(actual_cost * 0.30, 2) if actual_cost > 0 else 0.0
                est_annual_saving = round(est_monthly_saving * 12, 2) if est_monthly_saving > 0 else 0.0

                findings.append(
                    FindingModel(
                        finding_id=f"cost12-{sub.subscription_id[:8]}-{sa_name[:20]}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=rg_name,
                        resource_name=sa_name,
                        resource_type="Microsoft.Storage/storageAccounts",
                        resource_id=sa_id,
                        region=sa.get("location", "global"),
                        severity="High" if actual_cost > 200.0 else ("Medium" if actual_cost > 50.0 else "Low"),
                        status=status_label,
                        current_configuration=f"LCM Status: {status_label} | Total Rules: {display_total_rules} | Active Rules: {display_active_rules}",
                        measured_value=measured_val,
                        recommended_configuration="Apply and enable Lifecycle Management (LCM) policy to automate blob tiering to Cool/Archive",
                        recommendation=rec_text,
                        metric_period=f"Last Completed Month ({cost_month})",
                        data_source="Azure Cost Management Query API & Microsoft.Storage ManagementPolicies API",
                        evidence={
                            "storage_account": sa_name,
                            "resource_type": "Storage Account",
                            "lcm_status": status_label,
                            "total_rules": display_total_rules,
                            "enabled_rules": display_active_rules,
                            "active_rules": display_active_rules,
                            "disabled_rules": disabled_rules_count,
                            "rules_display": f"{display_active_rules} / {display_total_rules} Active",
                            "environment": env_val,
                            "storage_tier": sku_tier,
                            "access_tier": access_tier,
                            "redundancy": redundancy,
                            "is_lcm_configured": is_lcm_configured,
                            "has_active_rules": has_active_rules,
                            "actual_cost_mtd": actual_cost,
                            "cost_month": cost_month,
                            "rule_names": policy_res.get("rule_names", ""),
                            "enabled_rule_names": policy_res.get("enabled_rule_names", "")
                        },
                        current_monthly_cost=actual_cost,
                        estimated_monthly_savings=est_monthly_saving,
                        estimated_annual_savings=est_annual_saving if est_annual_saving > 0 else None,
                        currency=currency,
                        savings_type="Scenario Savings",
                        confidence="High" if actual_cost > 0 else "Medium",
                        calculation_method="Estimated 30% storage savings from automated tiering of aged data from Hot to Cool/Archive",
                        validation_required="Review application data access patterns before configuring lifecycle transitions",
                        collected_at=now_str
                    )
                )

        # 5. Prioritize higher-cost storage accounts at top (matching LCM_Status_Check_Top_Storageaccounts)
        findings.sort(key=lambda f: (f.current_monthly_cost or 0.0), reverse=True)

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
