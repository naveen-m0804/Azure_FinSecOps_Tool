import datetime
import time
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.cost_management import CostManagementAdapter
from app.azure.resources import ResourcesAdapter
from app.utils.dates import get_previous_calendar_month, get_current_month_to_date
from app.utils.resource_ids import parse_azure_resource_id
from app.utils.environment import resolve_environment

class CostComparisonAssessment(BaseAssessment):
    assessment_id = "cost_comparison"
    code = "COST-05"
    category = "cost"
    name = "Monthly Billing & Service Analysis"
    description = "Compare previous complete calendar month actual expenditure with current month-to-date and run rate across services and subscriptions."
    purpose = "Track month-over-month expenditure trends, identify cost acceleration, and flag spending velocity increases."
    required_permissions = ["Microsoft.CostManagement/query/action", "Cost Management Reader"]
    required_data_sources = ["Azure Cost Management Query API"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        prev_start, prev_end = get_previous_calendar_month()
        curr_start, curr_end = get_current_month_to_date()
        total_resources_evaluated = 0

        for sub in context.subscriptions:
            try:
                prev_costs = await CostManagementAdapter.query_resource_costs(
                    context.client, sub.subscription_id, prev_start, prev_end
                )
            except Exception as ex:
                errors.append(f"Failed to query previous month costs for sub {sub.subscription_id}: {ex}")
                prev_costs = {}

            try:
                curr_costs = await CostManagementAdapter.query_resource_costs(
                    context.client, sub.subscription_id, curr_start, curr_end
                )
            except Exception as ex:
                errors.append(f"Failed to query current MTD costs for sub {sub.subscription_id}: {ex}")
                curr_costs = {}

            total_prev = sum(item["cost"] for item in prev_costs.values())
            total_curr = sum(item["cost"] for item in curr_costs.values())
            sub_diff = round(total_curr - total_prev, 2)
            sub_pct = round(((total_curr - total_prev) / total_prev) * 100.0, 1) if total_prev > 0 else (100.0 if total_curr > 0 else 0.0)

            active_curr = next(
                (item["currency"] for item in curr_costs.values() if item.get("currency")),
                next((item["currency"] for item in prev_costs.values() if item.get("currency")), context.currency or "USD")
            )

            # Subscription-Level Aggregated Spend Finding
            findings.append(
                FindingModel(
                    finding_id=f"cost05-sub-{sub.subscription_id[:8]}",
                    assessment_id=self.assessment_id,
                    category=self.category,
                    subscription_id=sub.subscription_id,
                    subscription_name=sub.display_name,
                    resource_group="Subscription Scope",
                    resource_name=f"Spend Comparison - {sub.display_name}",
                    resource_type="Microsoft.CostManagement/query",
                    resource_id=f"/subscriptions/{sub.subscription_id}",
                    region="global",
                    severity="Informational" if sub_diff <= 0 else ("High" if sub_pct > 25 else "Medium"),
                    status="Completed",
                    current_configuration=f"Previous Month ({prev_start} to {prev_end}): {total_prev:,.2f} {active_curr} | Current MTD ({curr_start} to {curr_end}): {total_curr:,.2f} {active_curr}",
                    measured_value=f"{total_prev:,.2f} {active_curr} vs {total_curr:,.2f} {active_curr} MTD (Diff: {'+' if sub_diff >= 0 else ''}{sub_diff:,.2f} {active_curr})",
                    recommended_configuration="Analyze top spending resource groups and configure proactive budget alerts",
                    recommendation=f"Subscription spend: Previous Month was {total_prev:,.2f} {active_curr}, Current MTD is {total_curr:,.2f} {active_curr} ({'+' if sub_diff >= 0 else ''}{sub_diff:,.2f} {active_curr}, {'+' if sub_pct >= 0 else ''}{sub_pct:.1f}%).",
                    metric_period=f"{prev_start} to {curr_end}",
                    data_source="Azure Cost Management Query API",
                    evidence={
                        "previous_period_start": prev_start,
                        "previous_period_end": prev_end,
                        "previous_period_cost": round(total_prev, 2),
                        "prev_cost": round(total_prev, 2),
                        "previous_month_cost": round(total_prev, 2),
                        "current_period_start": curr_start,
                        "current_period_end": curr_end,
                        "current_period_cost": round(total_curr, 2),
                        "current_mtd_cost": round(total_curr, 2),
                        "actual_cost_mtd": round(total_curr, 2),
                        "cost_difference": sub_diff,
                        "cost_change_pct": sub_pct,
                        "environment": "All Environments"
                    },
                    current_monthly_cost=round(total_curr, 2),
                    currency=active_curr,
                    collected_at=now_str
                )
            )

            # Individual Resource / Service Comparison Findings
            all_res_ids = set(prev_costs.keys()) | set(curr_costs.keys())
            resource_findings: List[FindingModel] = []

            for r_id in all_res_ids:
                p_item = prev_costs.get(r_id, {})
                c_item = curr_costs.get(r_id, {})
                p_val = float(p_item.get("cost", 0.0))
                c_val = float(c_item.get("cost", 0.0))
                r_diff = round(c_val - p_val, 2)
                r_pct = round(((c_val - p_val) / p_val) * 100.0, 1) if p_val > 0 else (100.0 if c_val > 0 else 0.0)

                raw_id = c_item.get("resource_id") or p_item.get("resource_id") or r_id
                parsed = parse_azure_resource_id(raw_id)
                res_name = parsed.get("resource_name") or raw_id.split("/")[-1]
                res_rg = parsed.get("resource_group") or "Unknown"
                res_type = parsed.get("resource_type") or "Microsoft.Resources/resource"

                res_curr = c_item.get("currency") or p_item.get("currency") or active_curr
                env_val = "Production"

                resource_findings.append(
                    FindingModel(
                        finding_id=f"cost05-res-{hash(raw_id) & 0xffffffff:08x}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=res_rg,
                        resource_name=res_name,
                        resource_type=res_type,
                        resource_id=raw_id,
                        region="global",
                        severity="High" if r_diff > 100 or r_pct > 50 else ("Medium" if r_diff > 0 else "Informational"),
                        status="Completed",
                        current_configuration=f"Previous: {p_val:,.2f} {res_curr} | Current MTD: {c_val:,.2f} {res_curr}",
                        measured_value=f"Diff: {'+' if r_diff >= 0 else ''}{r_diff:,.2f} {res_curr} ({'+' if r_pct >= 0 else ''}{r_pct:.1f}%)",
                        recommended_configuration="Review resource utilization and adjust provisioning or purchase reservations",
                        recommendation=f"Resource '{res_name}' expenditure changed by {'+' if r_diff >= 0 else ''}{r_diff:,.2f} {res_curr} ({'+' if r_pct >= 0 else ''}{r_pct:.1f}%).",
                        metric_period=f"{prev_start} to {curr_end}",
                        data_source="Azure Cost Management Query API",
                        evidence={
                            "previous_period_start": prev_start,
                            "previous_period_end": prev_end,
                            "previous_period_cost": round(p_val, 2),
                            "prev_cost": round(p_val, 2),
                            "previous_month_cost": round(p_val, 2),
                            "current_period_start": curr_start,
                            "current_period_end": curr_end,
                            "current_period_cost": round(c_val, 2),
                            "current_mtd_cost": round(c_val, 2),
                            "actual_cost_mtd": round(c_val, 2),
                            "cost_difference": r_diff,
                            "cost_change_pct": r_pct,
                            "environment": env_val
                        },
                        current_monthly_cost=round(c_val, 2),
                        currency=res_curr,
                        collected_at=now_str
                    )
                )

            # If Cost Management had no historical rows, fall back to ARM discovered resources
            if not all_res_ids:
                try:
                    res_list = await ResourcesAdapter.get_subscription_resources(context.client, sub.subscription_id)
                    for r in res_list[:25]:
                        r_id = r.get("id", "")
                        r_name = r.get("name", "Unknown")
                        r_rg = r.get("resourceGroup", "Unknown")
                        r_type = r.get("type", "Microsoft.Resources/resource")
                        tags = r.get("tags") or {}
                        env_val = resolve_environment(tags, r_name, r_rg, prod_tags=context.prod_tags, test_tags=context.test_tags, target_tags=context.target_tags)

                        resource_findings.append(
                            FindingModel(
                                finding_id=f"cost05-arm-{hash(r_id) & 0xffffffff:08x}",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=r_rg,
                                resource_name=r_name,
                                resource_type=r_type,
                                resource_id=r_id,
                                region=r.get("location", "global"),
                                severity="Informational",
                                status="Completed",
                                current_configuration=f"Previous: 0.00 {active_curr} | Current MTD: 0.00 {active_curr}",
                                measured_value=f"Diff: 0.00 {active_curr} (0.0%)",
                                recommended_configuration="Monitor resource consumption as workload scales",
                                recommendation=f"Resource '{r_name}' spend is currently nominal.",
                                metric_period=f"{prev_start} to {curr_end}",
                                data_source="Azure Resource Manager & Cost Management API",
                                evidence={
                                    "previous_period_start": prev_start,
                                    "previous_period_end": prev_end,
                                    "previous_period_cost": 0.0,
                                    "prev_cost": 0.0,
                                    "previous_month_cost": 0.0,
                                    "current_period_start": curr_start,
                                    "current_period_end": curr_end,
                                    "current_period_cost": 0.0,
                                    "current_mtd_cost": 0.0,
                                    "actual_cost_mtd": 0.0,
                                    "cost_difference": 0.0,
                                    "cost_change_pct": 0.0,
                                    "environment": env_val
                                },
                                current_monthly_cost=0.0,
                                currency=active_curr,
                                collected_at=now_str
                            )
                        )
                except Exception as ex:
                    errors.append(f"Failed to discover resources for sub {sub.subscription_id}: {ex}")

            # Sort resource findings by current spend or change descending
            resource_findings.sort(key=lambda x: (x.evidence.get("current_period_cost", 0.0), abs(x.evidence.get("cost_difference", 0.0))), reverse=True)
            findings.extend(resource_findings)
            total_resources_evaluated += max(len(all_res_ids), len(resource_findings), 1)

        status = AssessmentStatus.COMPLETED if findings else AssessmentStatus.NO_FINDINGS
        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=total_resources_evaluated or len(context.subscriptions),
            findings_count=len(findings),
            findings=findings,
            currency=context.currency,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
