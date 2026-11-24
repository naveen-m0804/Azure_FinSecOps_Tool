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

REDUNDANCY_SAVINGS_MAP = {
    "ZRS": 0.22,
    "GRS": 0.50,
    "RA-GRS": 0.55,
    "GZRS": 0.60,
    "RA-GZRS": 0.65,
}

class NonLrsStorageRedundancyAssessment(BaseAssessment):
    assessment_id = "non_lrs_storage_redundancy"
    code = "COST-18"
    category = "cost"
    name = "Non-LRS Storage Redundancy Optimization"
    description = "Identify storage accounts configured with expensive multi-zone or geo-redundant storage (ZRS, GRS, RA-GRS, GZRS, RA-GZRS) matching user-provided evaluation tags or non-production scopes instead of Locally Redundant Storage (LRS)."
    purpose = "Enforce LRS redundancy on targeted storage accounts to eliminate unnecessary replication overhead based on user-provided tags."
    required_permissions = [
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.CostManagement/query/action",
        "Reader"
    ]
    required_data_sources = ["Azure Storage Accounts API & Cost Management Query API"]

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
                resource_type_filter="Microsoft.Storage/storageAccounts"
            )

            try:
                storage_accounts = await StorageAdapter.get_storage_accounts(context.client, sub.subscription_id)
            except Exception as ex:
                errors.append(f"Failed to fetch storage accounts for subscription {sub.subscription_id}: {ex}")
                continue

            for sa in storage_accounts:
                resources_evaluated += 1

                tags = sa.get("tags") or {}
                sa_name = sa.get("name", "")
                sa_id = sa.get("id", "")
                parsed = parse_azure_resource_id(sa_id)
                sa_rg = parsed.get("resource_group") or ""

                # Evaluate based on user-provided tags if supplied; otherwise evaluate all non-LRS accounts
                matched_target = False
                tag_matched_label = ""

                user_tags = [t.strip() for t in (context.target_tags or []) if t.strip()]
                test_tags = [t.strip() for t in (context.test_tags or []) if t.strip()]
                active_filter_tags = user_tags or test_tags

                if active_filter_tags:
                    # User-provided tags take precedence - evaluate accounts matching tags
                    for ut in active_filter_tags:
                        ut_lower = ut.lower()
                        # Check tag keys and values
                        for k, v in tags.items():
                            k_str = str(k).strip()
                            v_str = str(v).strip()
                            if ut_lower == k_str.lower() or ut_lower == v_str.lower() or ut_lower in f"{k_str}={v_str}".lower():
                                matched_target = True
                                tag_matched_label = f"Tag: {k}={v}"
                                break
                        if not matched_target and (ut_lower in sa_rg.lower() or ut_lower in sa_name.lower()):
                            matched_target = True
                            tag_matched_label = f"Match: {ut}"
                            break
                        if matched_target:
                            break
                    if not matched_target:
                        continue
                else:
                    # Pure tag-based scoping: If NO tags configured, analyze ALL non-LRS storage accounts
                    matched_target = True
                    tag_matched_label = resolve_environment(tags, sa_name, sa_rg, prod_tags=context.prod_tags, test_tags=context.test_tags, target_tags=context.target_tags)

                env_val = tag_matched_label or "Target Scope"

                # Check Redundancy SKU
                sku = sa.get("sku")
                if not sku:
                    errors.append(f"Storage account '{sa_name}' SKU information unavailable.")
                    continue

                sku_name = sku.get("name", "")
                # Extract redundancy part from SKU name (e.g., 'Standard_GRS' -> 'GRS', 'Standard_RAGRS' -> 'RA-GRS')
                parts = sku_name.split("_")
                raw_red = parts[-1].upper() if len(parts) > 1 else sku_name.upper()

                if raw_red == "RAGRS":
                    current_redundancy = "RA-GRS"
                elif raw_red == "RAGZRS":
                    current_redundancy = "RA-GZRS"
                else:
                    current_redundancy = raw_red

                # CRITICAL RULE: If already LRS -> EXCLUDE!
                if current_redundancy == "LRS":
                    continue

                # Non-LRS redundancy in test environment detected!
                norm_id = normalize_resource_id(sa_id)
                cost_item = cost_map.get(norm_id, {})
                cost_val = cost_item.get("cost", 0.0)
                currency = cost_item.get("currency", context.currency)

                # Granular, defensible savings calculation based on exact SKU tier
                savings_pct = REDUNDANCY_SAVINGS_MAP.get(
                    current_redundancy,
                    0.50 if "GRS" in current_redundancy else 0.22
                )
                est_monthly_saving = round(cost_val * savings_pct, 2) if cost_val > 0 else 0.0
                est_annual_saving = round(est_monthly_saving * 12, 2) if est_monthly_saving > 0 else None
                parsed = parse_azure_resource_id(sa_id)

                findings.append(
                    FindingModel(
                        finding_id=f"cost19-{sa_name[:12]}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=parsed.get("resource_group") or "Unknown",
                        resource_name=sa_name,
                        resource_type="Microsoft.Storage/storageAccounts",
                        resource_id=sa_id,
                        region=sa.get("location", "global"),
                        severity="High" if "GRS" in current_redundancy else "Medium",
                        status=f"Non-LRS ({current_redundancy})",
                        current_configuration=f"Environment: {env_val} | Current Redundancy: {current_redundancy} | SKU: {sku_name}",
                        measured_value=f"Configured with {current_redundancy} in test environment",
                        recommended_configuration="Migrate storage account redundancy to LRS (Locally Redundant Storage)",
                        recommendation=f"Storage account '{sa_name}' is deployed in test environment '{env_val}' with {current_redundancy} redundancy. Convert to LRS to reduce recurring replication cost.",
                        metric_period=f"Last Completed Month ({cost_month})",
                        data_source="Azure Storage Accounts API & Cost Management Query API",
                        evidence={
                            "environment": env_val,
                            "current_redundancy": current_redundancy,
                            "required_redundancy": "LRS",
                            "sku_name": sku_name,
                            "actual_cost_mtd": round(cost_val, 2),
                            "savings_pct": f"{int(savings_pct * 100)}%",
                            "cost_month": cost_month
                        },
                        current_monthly_cost=round(cost_val, 2),
                        estimated_monthly_savings=est_monthly_saving,
                        estimated_annual_savings=est_annual_saving,
                        currency=currency,
                        savings_type="Scenario Savings",
                        confidence="High",
                        calculation_method=f"Switching from {current_redundancy} to LRS reduces storage cost by ~{int(savings_pct * 100)}% by eliminating cross-region replication",
                        validation_required="Confirm test workload data does not require multi-region disaster recovery replication",
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
