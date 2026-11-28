import datetime
import time
import re
from typing import List, Dict, Any, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.cost_management import CostManagementAdapter
from app.azure.resources import ResourcesAdapter
from app.utils.resource_ids import parse_azure_resource_id


def _extract_resource_group(resource_id: str, fallback: Optional[str] = None) -> str:
    """Extracts valid resource group name from resource ID, avoiding 'Unknown'."""
    if fallback and fallback not in ("Unknown", "--", "", "Subscription Scope"):
        return fallback
    if resource_id:
        m = re.search(r"/resourceGroups/([^/]+)", resource_id, re.IGNORECASE)
        if m:
            return m.group(1)
        parsed = parse_azure_resource_id(resource_id)
        rg = parsed.get("resource_group")
        if rg and rg not in ("Unknown", "--", ""):
            return rg
    return fallback or "--"


class Top20OpportunitiesAssessment(BaseAssessment):
    assessment_id = "top_20_opportunities"
    code = "COST-06"
    category = "cost"
    name = "Top 20 Optimization Opportunities"
    description = "Aggregate and rank the highest-impact cloud financial optimization opportunities across all cost assessment modules."
    purpose = "Provide cloud leadership with an executive priority ranking of actionable cost savings opportunities."
    required_permissions = [
        "Microsoft.CostManagement/query/action",
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/disks/read",
        "Microsoft.Storage/storageAccounts/read",
        "Reader"
    ]
    required_data_sources = ["Unified Cross-Assessment Evaluation & Azure Cost Management"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []

        seen_resource_ids = set()
        candidate_findings: List[FindingModel] = []

        # 1. If previous assessment results are stored on context, aggregate them
        if hasattr(context, "cached_cost_findings") and context.cached_cost_findings:
            for f in context.cached_cost_findings:
                if f.resource_id not in seen_resource_ids and (f.estimated_annual_savings or 0.0) > 0:
                    seen_resource_ids.add(f.resource_id)
                    # Ensure accurate resource group is populated on candidate findings
                    f.resource_group = _extract_resource_group(f.resource_id, f.resource_group)
                    candidate_findings.append(f)

        # 2. If standalone execution without prior cached findings, query Cost Management for top spending resources
        # Per Savings Formula Guide (R7): Shortlist only; do not fabricate savings or add separately.
        if not candidate_findings:
            cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()
            for sub in context.subscriptions:
                try:
                    sub_costs = await CostManagementAdapter.query_resource_costs(
                        context.client,
                        subscription_id=sub.subscription_id,
                        start_date=cost_start,
                        end_date=cost_end
                    )
                    sorted_items = sorted(sub_costs.values(), key=lambda x: x.get("cost", 0.0), reverse=True)[:25]
                    for idx, item in enumerate(sorted_items, 1):
                        res_id = item.get("resource_id", "")
                        cost_val = float(item.get("cost", 0.0))
                        if cost_val <= 0.001:
                            continue

                        curr = item.get("currency", context.currency)
                        parsed = parse_azure_resource_id(res_id)
                        res_name = parsed.get("resource_name") or f"Resource-{idx}"
                        res_type = parsed.get("resource_type") or "Microsoft.Resources/resource"
                        rg = _extract_resource_group(res_id, parsed.get("resource_group"))

                        candidate_findings.append(
                            FindingModel(
                                finding_id=f"cost06-top-{idx}",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=rg,
                                resource_name=res_name,
                                resource_type=res_type,
                                resource_id=res_id,
                                region="global",
                                severity="High" if cost_val > 500 else "Medium",
                                status="Top Cost Consumer",
                                current_configuration=f"Monthly Spend: {cost_val:,.2f} {curr}",
                                measured_value=f"High spending cloud resource ({cost_val:,.2f} {curr})",
                                recommended_configuration="Review underlying optimization assessments for exact savings",
                                recommendation=f"Resource '{res_name}' in resource group '{rg}' is among the top cost drivers. Link to underlying optimization category.",
                                metric_period=f"{cost_start} to {cost_end} ({cost_month})",
                                data_source="Azure Cost Management Query API",
                                evidence={
                                    "actual_cost_mtd": round(cost_val, 2),
                                    "resource_group": rg,
                                    "assessment_type": "High Cost Resource"
                                },
                                current_monthly_cost=round(cost_val, 2),
                                estimated_monthly_savings=None,
                                estimated_annual_savings=None,
                                currency=curr,
                                savings_type="Shortlist Reference (Do Not Add)",
                                confidence="Not Available",
                                calculation_method="Shortlist only; calculate savings using the underlying relevant optimization category (do not add separately)",
                                validation_required="Validate workload requirements with service owners and link to underlying optimization category",
                                collected_at=now_str
                            )
                        )
                except Exception as ex:
                    errors.append(f"Failed to query Cost Management for sub {sub.subscription_id}: {ex}")

        # Sort globally across the entire tenant descending by Annual Savings, then monthly cost
        candidate_findings.sort(
            key=lambda x: (
                float(x.estimated_annual_savings or 0.0),
                float(x.current_monthly_cost or (x.evidence.get("actual_cost_mtd") if x.evidence else 0.0) or 0.0)
            ),
            reverse=True
        )
        # Strictly top 20 opportunities across the entire tenant (unified tenant-level ranking)
        top_20 = candidate_findings[:20]

        # Ensure each finding has assessment_type, verified resource_group, and tenant rank in evidence
        for idx, f in enumerate(top_20, start=1):
            ass_type = f.evidence.get("assessment_type") or f.evidence.get("opportunity_source") or f.category.title()
            rg_verified = _extract_resource_group(f.resource_id, f.resource_group)

            cloned_finding = FindingModel(
                finding_id=f"cost06-tenant-{idx:02d}",
                assessment_id=self.assessment_id,
                category=self.category,
                subscription_id=f.subscription_id,
                subscription_name=f.subscription_name,
                resource_group=rg_verified,
                resource_name=f.resource_name,
                resource_type=f.resource_type,
                resource_id=f.resource_id,
                region=f.region,
                severity=f.severity,
                status=f.status or "Optimization Opportunity",
                current_configuration=f.current_configuration,
                measured_value=f.measured_value,
                recommended_configuration=f.recommended_configuration,
                recommendation=f.recommendation,
                metric_period=f.metric_period,
                data_source=f.data_source,
                evidence=dict(f.evidence or {}),
                current_monthly_cost=f.current_monthly_cost,
                estimated_monthly_savings=f.estimated_monthly_savings,
                estimated_annual_savings=f.estimated_annual_savings,
                currency=f.currency,
                savings_type=f.savings_type or "Estimated Savings",
                confidence=f.confidence or "High",
                calculation_method=f.calculation_method,
                validation_required=f.validation_required,
                collected_at=f.collected_at or now_str
            )
            cloned_finding.evidence["assessment_type"] = ass_type
            cloned_finding.evidence["tenant_rank"] = idx
            cloned_finding.evidence["ranking_scope"] = "Tenant Level"
            cloned_finding.evidence["resource_group"] = rg_verified
            findings.append(cloned_finding)

        # Per Savings Formula Guide (R7): Top 20 is a shortlist only; do not add separately.
        status = AssessmentStatus.COMPLETED if findings else AssessmentStatus.NO_FINDINGS

        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=len(candidate_findings),
            findings_count=len(findings),
            findings=findings,
            total_monthly_savings=0.0,
            total_annual_savings=0.0,
            currency=context.currency,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
