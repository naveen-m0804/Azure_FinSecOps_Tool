import datetime
import time
from typing import List
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.dates import get_previous_calendar_month, get_cutoff_date
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id

class OldSnapshotsAssessment(BaseAssessment):
    assessment_id = "old_snapshots"
    code = "COST-16"
    category = "cost"
    name = "Old Snapshot Expired"
    description = "Identify managed disk snapshots older than 365 days and cross-reference with last month's actual storage cost."
    purpose = "Detect obsolete point-in-time snapshots that have exceeded reasonable retention thresholds."
    required_permissions = [
        "Microsoft.Compute/snapshots/read",
        "Microsoft.CostManagement/query/action",
        "Cost Management Reader",
        "Reader"
    ]
    required_data_sources = ["Microsoft.Compute Snapshots & Azure Cost Management Query API"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        cutoff_dt = get_cutoff_date(days=365)
        prev_start, prev_end = get_previous_calendar_month()

        for sub in context.subscriptions:
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=prev_start,
                end_date=prev_end,
                resource_type_filter="Microsoft.Compute/snapshots"
            )

            snapshots = await ComputeAdapter.get_snapshots(context.client, sub.subscription_id)
            for snap in snapshots:
                resources_evaluated += 1
                snap_name = snap.get("name", "")
                snap_id = snap.get("id", "")
                props = snap.get("properties", {})
                time_created_str = props.get("timeCreated")

                if not time_created_str:
                    continue

                try:
                    time_created = datetime.datetime.fromisoformat(time_created_str.replace("Z", "+00:00"))
                except Exception:
                    continue

                age_days = (datetime.datetime.now(datetime.timezone.utc) - time_created).days

                # Flag snapshots older than 365 days as in old_snapshots_alert.txt
                if age_days > 365:
                    size_gb = props.get("diskSizeGB", 128)
                    incremental = props.get("incremental", False)
                    norm_id = normalize_resource_id(snap_id)
                    cost_info = cost_map.get(norm_id, {})
                    actual_cost = cost_info.get("cost")
                    currency = cost_info.get("currency", context.currency)

                    # If actual cost from API, use it; otherwise calculate based on standard snapshot storage rate ($0.05/GB/mo)
                    monthly_price = actual_cost if actual_cost is not None and actual_cost > 0 else round(size_gb * PricingEngine.SNAPSHOT_GB_MONTHLY, 2)
                    savings_type = "Actual Cost" if (actual_cost is not None and actual_cost > 0) else "Estimated Savings"
                    parsed = parse_azure_resource_id(snap_id)

                    findings.append(
                        FindingModel(
                            finding_id=f"cost16-{snap_name[:12]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=parsed.get("resource_group") or "Unknown",
                            resource_name=snap_name,
                            resource_type="Microsoft.Compute/snapshots",
                            resource_id=snap_id,
                            region=snap.get("location", "global"),
                            severity="Medium",
                            status="Expired Retention (>365d)",
                            current_configuration=f"Age: {age_days} days | Size: {size_gb} GB | Incremental: {incremental}",
                            measured_value=f"Snapshot age is {age_days} days (Created: {time_created.strftime('%Y-%m-%d')})",
                            recommended_configuration="Verify compliance requirement and delete expired snapshot",
                            recommendation=f"Snapshot '{snap_name}' was created {age_days} days ago and exceeds standard retention policy.",
                            metric_period=f"Previous calendar month ({prev_start} to {prev_end})",
                            data_source="Microsoft.Compute Snapshots & Cost Management API",
                            evidence={
                                "age_days": age_days,
                                "size_gb": size_gb,
                                "incremental": incremental,
                                "created_date": time_created.strftime("%Y-%m-%d"),
                                "previous_month_actual_cost": actual_cost,
                                "actual_cost_mtd": round(monthly_price, 2)
                            },
                            current_monthly_cost=round(monthly_price, 2),
                            estimated_monthly_savings=round(monthly_price, 2),
                            estimated_annual_savings=round(monthly_price * 12, 2),
                            currency=currency,
                            savings_type=savings_type,
                            confidence="High",
                            calculation_method="100% avoidable snapshot storage fee via resource deletion",
                            validation_required="Confirm snapshot is not required for disaster recovery or regulatory audit compliance",
                            collected_at=now_str
                        )
                    )

        total_monthly = sum((f.estimated_monthly_savings or 0.0) for f in findings)
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
            last_run_time=now_str
        )
