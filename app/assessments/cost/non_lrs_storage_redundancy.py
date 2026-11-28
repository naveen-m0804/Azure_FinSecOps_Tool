import datetime
import time
from typing import List, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.storage import StorageAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment, matches_target_tags

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

                # Strict tag-based scoping: If user entered target_tags, evaluate ONLY resources with matching tags.
                # If no target_tags entered, evaluate ALL non-LRS storage accounts (tagged or untagged).
                if not matches_target_tags(tags, context.target_tags):
                    continue
                env_val = resolve_environment(tags, sa_name, sa_rg, prod_tags=context.prod_tags, test_tags=context.test_tags, target_tags=context.target_tags)

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

                # Non-LRS redundancy detected!
                norm_id = normalize_resource_id(sa_id)
                cost_item = cost_map.get(norm_id, {})
                cost_val = float(cost_item.get("cost", 0.0))
                currency = cost_item.get("currency", context.currency)
                sa_region = sa.get("location", "")

                # Formula (R19): Monthly savings = current eligible redundancy cost - proposed LRS cost
                # Fetch real regional redundancy vs LRS unit prices from Azure Retail Prices API
                est_monthly_saving: Optional[float] = None
                est_annual_saving: Optional[float] = None
                savings_pct: Optional[float] = None
                proposed_lrs_cost: Optional[float] = None

                red_prices = await PricingEngine.get_storage_redundancy_unit_prices(current_redundancy, sa_region, currency)
                if cost_val > 0 and red_prices:
                    lrs_p = red_prices["lrs_unit_price"]
                    curr_p = red_prices["current_unit_price"]
                    if curr_p > lrs_p > 0:
                        proposed_lrs_cost = round(cost_val * (lrs_p / curr_p), 2)
                        est_monthly_saving = round(max(0.0, cost_val - proposed_lrs_cost), 2)
                        est_annual_saving = round(est_monthly_saving * 12, 2)
                        savings_pct = round((est_monthly_saving / cost_val) * 100.0, 2)

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
                        region=sa_region or "global",
                        severity="High" if "GRS" in current_redundancy else "Medium",
                        status=f"Non-LRS ({current_redundancy})",
                        current_configuration=f"Environment: {env_val} | Current Redundancy: {current_redundancy} | SKU: {sku_name}",
                        measured_value=f"Configured with {current_redundancy}",
                        recommended_configuration="Migrate storage account redundancy to LRS (Locally Redundant Storage)",
                        recommendation=f"Storage account '{sa_name}' in '{env_val}' uses {current_redundancy} redundancy. Convert to LRS if durability/DR requirements permit.",
                        metric_period=f"Last Completed Month ({cost_month})",
                        data_source="Azure Storage Accounts API, Cost Management & Azure Retail Prices API",
                        evidence={
                            "environment": env_val,
                            "current_redundancy": current_redundancy,
                            "required_redundancy": "LRS",
                            "sku_name": sku_name,
                            "actual_cost_mtd": round(cost_val, 2),
                            "proposed_lrs_cost": proposed_lrs_cost,
                            "savings_pct": f"{savings_pct:.1f}%" if savings_pct is not None else None,
                            "cost_month": cost_month
                        },
                        current_monthly_cost=round(cost_val, 2),
                        estimated_monthly_savings=est_monthly_saving,
                        estimated_annual_savings=est_annual_saving,
                        currency=currency,
                        savings_type="Scenario Savings" if est_monthly_saving is not None else "Not Estimated",
                        confidence="High" if est_monthly_saving is not None else "Low",
                        calculation_method="Monthly savings = current eligible redundancy cost - proposed LRS cost (via Azure Retail Prices API); savings % = savings/current eligible cost; annual = monthly * 12",
                        validation_required="Only if durability, availability, recovery and business requirements permit.",
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
