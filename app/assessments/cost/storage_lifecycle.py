import datetime
import time
from typing import List
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.storage import StorageAdapter
from app.azure.cost_management import CostManagementAdapter
from app.utils.dates import get_current_month_to_date
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment

class StorageLifecycleAssessment(BaseAssessment):
    assessment_id = "storage_lifecycle"
    code = "COST-12"
    category = "cost"
    name = "Storage Account Lifecycle Management"
    description = "Audit storage accounts to identify configured lifecycle management policies where every rule is currently disabled."
    purpose = "Detect configured but completely inactive lifecycle management policies that fail to transition or expire aged blobs."
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
        mtd_start, mtd_end = get_current_month_to_date()

        for sub in context.subscriptions:
            # Query actual MTD cost for storage accounts
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=mtd_start,
                end_date=mtd_end,
                resource_type_filter="microsoft.storage/storageaccounts"
            )

            storage_accounts = await StorageAdapter.get_storage_accounts(context.client, sub.subscription_id)

            for sa in storage_accounts:
                resources_evaluated += 1
                sa_name = sa.get("name", "")
                sa_id = sa.get("id", "")
                norm_id = normalize_resource_id(sa_id)
                cost_item = cost_map.get(norm_id, {})
                cost_val = cost_item.get("cost", 0.0)
                currency = cost_item.get("currency", context.currency)

                policy_res = await StorageAdapter.get_lifecycle_policy(context.client, sa_id)
                if not policy_res.get("success", False):
                    errors.append(f"Failed to query lifecycle policy for {sa_name}: {policy_res.get('error')}")
                    continue

                total_rules = policy_res.get("total_rules", 0)
                enabled_rules_count = policy_res.get("enabled_rules_count", 0)

                # STRICT DETECTION MATRIX (COST-12):
                # 1. Policy exists and every rule is disabled -> INCLUDE
                # 2. Policy exists and at least one rule is enabled -> EXCLUDE
                # 3. Policy does not exist -> EXCLUDE
                # 4. Policy exists but contains no rules -> EXCLUDE
                if total_rules > 0 and enabled_rules_count == 0:
                    sku = sa.get("sku", {})
                    props = sa.get("properties", {})
                    storage_tier = sku.get("tier", "Standard")
                    access_tier = props.get("accessTier", "Hot")
                    redundancy = sku.get("name", "Standard_GRS").split("_")[-1]
                    env_val = resolve_environment(sa.get("tags"), sa_name, prod_tags=context.prod_tags, test_tags=context.test_tags)

                    # Financially defensible savings estimate:
                    # Enabling dormant lifecycle rules to transition aged blobs to Cool/Archive
                    # saves ~30% of storage cost if cost data is verified.
                    est_monthly_saving = round(cost_val * 0.30, 2) if cost_val > 0 else 0.0
                    parsed = parse_azure_resource_id(sa_id)

                    findings.append(
                        FindingModel(
                            finding_id=f"cost12-{sa_name[:12]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=parsed.get("resource_group") or "Unknown",
                            resource_name=sa_name,
                            resource_type="Microsoft.Storage/storageAccounts",
                            resource_id=sa_id,
                            region=sa.get("location", "global"),
                            severity="Medium" if cost_val > 150.0 else "Low",
                            status="All Rules Disabled",
                            current_configuration=f"Tier: {storage_tier} | Access: {access_tier} | Redundancy: {redundancy} | Rules: {total_rules} (0 enabled)",
                            measured_value=f"{total_rules} lifecycle rules defined, 0 enabled",
                            recommended_configuration="Enable configured lifecycle management rules to activate automated tiering/expiration",
                            recommendation=f"Storage account '{sa_name}' has {total_rules} lifecycle rules defined, but every rule is disabled.",
                            metric_period=f"{mtd_start} to {mtd_end} (MTD)",
                            data_source="Azure Cost Management & Microsoft.Storage ManagementPolicies API",
                            evidence={
                                "environment": env_val,
                                "storage_tier": storage_tier,
                                "access_tier": access_tier,
                                "redundancy": redundancy,
                                "actual_cost_mtd": round(cost_val, 2),
                                "total_rules": total_rules,
                                "enabled_rules": enabled_rules_count,
                                "rule_names": policy_res.get("rule_names", "")
                            },
                            current_monthly_cost=round(cost_val, 2),
                            estimated_monthly_savings=est_monthly_saving,
                            estimated_annual_savings=round(est_monthly_saving * 12, 2) if est_monthly_saving > 0 else None,
                            currency=currency,
                            savings_type="Scenario Savings",
                            confidence="Medium",
                            calculation_method="Estimated 30% storage savings from enabling dormant lifecycle rules to auto-tier older blobs",
                            validation_required="Review application data access requirements before re-enabling lifecycle rules",
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
