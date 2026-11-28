import datetime
import time
from typing import List, Dict, Any, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.resources import ResourcesAdapter
from app.azure.monitor import MonitorAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.dates import get_observation_window
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment, matches_target_tags


class FunctionAppsAssessment(BaseAssessment):
    assessment_id = "function_apps"
    code = "COST-16"
    category = "cost"
    name = "Function App Execution Time / Frequency"
    description = "Audit Function Apps hosted on dedicated App Service Plans that have low execution counts and can transition to serverless Consumption."
    purpose = "Eliminate dedicated compute plan charges for sporadic, event-driven functions."
    required_permissions = ["Microsoft.Web/sites/read", "Microsoft.Web/serverfarms/read", "Microsoft.Insights/metrics/read", "Reader"]
    required_data_sources = ["Azure Monitor Function App Executions", "Microsoft.Web APIs", "Azure Cost Management", "Azure Retail Prices API"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        obs_start, obs_end = get_observation_window(days=30)
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()

        for sub in context.subscriptions:
            try:
                sites = await ResourcesAdapter.get_app_services(context.client, sub.subscription_id)
                plans = await ResourcesAdapter.get_app_service_plans(context.client, sub.subscription_id)
            except Exception as ex:
                errors.append(f"Failed to scan App Services for subscription {sub.subscription_id}: {ex}")
                continue

            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=cost_start,
                end_date=cost_end,
            )

            plan_map: Dict[str, Dict[str, Any]] = {
                normalize_resource_id(p.get("id", "")): p for p in plans if p.get("id")
            }

            for site in sites:
                kind = (site.get("kind") or "").lower()
                if "functionapp" not in kind:
                    continue
                if not matches_target_tags(site.get("tags"), context.target_tags):
                    continue

                resources_evaluated += 1
                site_name = site.get("name", "")
                site_id = site.get("id", "")
                site_region = site.get("location", "")
                props = site.get("properties", {})
                sf_id = props.get("serverFarmId") or ""
                plan = plan_map.get(normalize_resource_id(sf_id), {})
                plan_sku = plan.get("sku", {})
                plan_tier = plan_sku.get("tier") or ""
                plan_name = plan_sku.get("name") or ""
                plan_cap = int(plan_sku.get("capacity") or 1)

                # Skip if already on Consumption (Dynamic / Y1 / FlexConsumption FC1) or Free/Shared
                if plan_tier.lower() in ("dynamic", "flexconsumption", "free", "shared") or plan_name.upper() in ("Y1", "FC1"):
                    continue

                # Fetch real execution metrics from Azure Monitor
                metric_res = await MonitorAdapter.get_metrics(
                    context.client,
                    resource_id=site_id,
                    metric_names="FunctionExecutionCount,FunctionExecutionUnits",
                    start_time=obs_start,
                    end_time=obs_end,
                    time_grain="P1D",
                    aggregation="Total",
                )

                exec_count: Optional[float] = None
                exec_units_mb_ms: Optional[float] = None
                if metric_res.get("success"):
                    metrics = metric_res.get("metrics", {})
                    if "FunctionExecutionCount" in metrics or "functionexecutioncount" in metrics:
                        exec_count = float(metrics.get("FunctionExecutionCount") or metrics.get("functionexecutioncount") or 0.0)
                    if "FunctionExecutionUnits" in metrics or "functionexecutionunits" in metrics:
                        exec_units_mb_ms = float(metrics.get("FunctionExecutionUnits") or metrics.get("functionexecutionunits") or 0.0)

                # Determine current hosting plan monthly cost from Cost Management or Azure Retail Prices API
                site_cost_info = cost_map.get(normalize_resource_id(site_id), {})
                plan_cost_info = cost_map.get(normalize_resource_id(sf_id), {})
                curr_cost: Optional[float] = None
                currency = site_cost_info.get("currency") or plan_cost_info.get("currency") or context.currency

                if site_cost_info.get("cost") and float(site_cost_info["cost"]) > 0:
                    curr_cost = float(site_cost_info["cost"])
                elif plan_cost_info.get("cost") and float(plan_cost_info["cost"]) > 0:
                    curr_cost = float(plan_cost_info["cost"])
                elif plan_name:
                    curr_cost = await PricingEngine.get_app_service_plan_monthly_price(
                        plan_name, plan_tier, plan_cap, site_region, currency
                    )

                # Calculate proposed Consumption plan cost from Azure Retail Prices API
                proposed_cost: Optional[float] = None
                cons_rates = await PricingEngine.get_function_consumption_rates(site_region, currency)
                if cons_rates and exec_count is not None:
                    # Azure Functions Consumption: 1M free executions, 400,000 GB-s free grant per month
                    billable_exec_millions = max(0.0, (exec_count - 1_000_000.0) / 1_000_000.0)
                    gb_s = (exec_units_mb_ms or 0.0) / (1024.0 * 1000.0)
                    billable_gbs = max(0.0, gb_s - 400_000.0)
                    proposed_cost = round(
                        billable_exec_millions * cons_rates.get("executions_per_million", 0.0)
                        + billable_gbs * cons_rates.get("execution_time_gbs", 0.0),
                        2,
                    )

                # Formula (R17): Monthly savings = current eligible cost / frequency - proposed plan cost / frequency
                monthly_saving: Optional[float] = None
                annual_saving: Optional[float] = None
                savings_pct: Optional[float] = None
                if curr_cost is not None and curr_cost > 0 and proposed_cost is not None and curr_cost > proposed_cost:
                    monthly_saving = round(curr_cost - proposed_cost, 2)
                    annual_saving = round(monthly_saving * 12.0, 2)
                    savings_pct = round((monthly_saving / curr_cost) * 100.0, 2)

                parsed = parse_azure_resource_id(site_id)
                rg_name = parsed.get("resource_group") or "Unknown"
                env_name = resolve_environment(
                    tags=site.get("tags") or {},
                    resource_name=site_name,
                    resource_group=rg_name,
                    prod_tags=context.prod_tags,
                    test_tags=context.test_tags,
                    target_tags=context.target_tags,
                )

                avg_dur_ms: Optional[float] = None
                if exec_count and exec_count > 0 and exec_units_mb_ms is not None:
                    # Approximate duration in ms assuming 128 MB / 512 MB average allocation if units available
                    avg_dur_ms = round((exec_units_mb_ms / exec_count) / 128.0, 1)

                hosting_label = f"{plan_tier} ({plan_name})".strip() if (plan_tier or plan_name) else "Dedicated App Service Plan"

                findings.append(
                    FindingModel(
                        finding_id=f"cost16-{sub.subscription_id[:8]}-{site_name[:16]}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=rg_name,
                        resource_name=site_name,
                        resource_type="Microsoft.Web/sites",
                        resource_id=site_id,
                        region=site_region or "global",
                        severity="Medium" if (monthly_saving or 0) > 0 else "Low",
                        status="Dedicated Plan Candidate",
                        current_configuration=f"Hosting Plan: {hosting_label} | Executions (30d): {int(exec_count) if exec_count is not None else 'Unavailable'}",
                        measured_value=f"{int(exec_count)} runs/30d" if exec_count is not None else "Execution Telemetry Unavailable",
                        recommended_configuration="Evaluate migration to Azure Functions Consumption (Y1) or Flex Consumption plan",
                        recommendation=(
                            f"Function App '{site_name}' runs on dedicated plan '{hosting_label}'."
                            + (f" Recorded {int(exec_count)} executions in 30 days." if exec_count is not None else " Execution telemetry unavailable.")
                            + " Validate execution volume, cold starts, and plan features before migrating."
                        ),
                        metric_period=f"Last 30 Days (Cost Month: {cost_month})",
                        data_source="Azure Monitor FunctionExecutionCount & Cost Management",
                        evidence={
                            "environment": env_name,
                            "hosting_plan": hosting_label,
                            "execution_count": int(exec_count) if exec_count is not None else None,
                            "avg_duration_ms": avg_dur_ms,
                            "proposed_consumption_cost": proposed_cost,
                            "savings_pct": savings_pct,
                            "actual_cost_mtd": round(curr_cost, 2) if curr_cost is not None else None,
                            "cost_month": cost_month,
                        },
                        current_monthly_cost=round(curr_cost, 2) if curr_cost is not None else None,
                        estimated_monthly_savings=monthly_saving,
                        estimated_annual_savings=annual_saving,
                        currency=currency,
                        savings_type="Estimated Savings" if monthly_saving is not None else "Not Estimated",
                        confidence="High" if (monthly_saving is not None and exec_count is not None) else "Low",
                        calculation_method="Monthly savings = current eligible cost / frequency - proposed plan cost / frequency; savings % = savings/current eligible cost; annual = monthly * 12",
                        validation_required="Validate execution volume, cold starts, plan features (VNet/always-on) and supporting storage.",
                        collected_at=now_str,
                    )
                )

        total_monthly = sum((f.estimated_monthly_savings or 0.0) for f in findings if f.estimated_monthly_savings)
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
            last_run_time=now_str,
        )
