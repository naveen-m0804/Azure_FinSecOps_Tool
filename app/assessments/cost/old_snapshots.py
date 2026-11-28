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
from app.utils.environment import matches_target_tags

class OldSnapshotsAssessment(BaseAssessment):
    assessment_id = "old_snapshots"
    code = "COST-15"
    category = "cost"
    name = "Old Snapshot Expired"
    description = "Identify managed disk snapshots older than 365 days and cross-reference with last month's actual storage cost."
    purpose = "Detect obsolete point-in-time snapshots that have exceeded reasonable retention thresholds (>365 days)."
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
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()

        for sub in context.subscriptions:
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=cost_start,
                end_date=cost_end,
                resource_type_filter="Microsoft.Compute/snapshots"
            )

            snapshots = await ComputeAdapter.get_snapshots(context.client, sub.subscription_id)
            for snap in snapshots:
                if not matches_target_tags(snap.get("tags"), context.target_tags):
                    continue
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

                # Flag snapshots older than 365 days as per requirements (> 365 days)
                if age_days > 365:
                    size_gb = props.get("diskSizeGB")
                    if size_gb is None and props.get("diskSizeBytes"):
                        size_gb = round(props.get("diskSizeBytes") / (1024 ** 3), 1)
                    if not size_gb:
                        size_gb = 128

                    snap_region = snap.get("location", "")
                    incremental = props.get("incremental", False)
                    norm_id = normalize_resource_id(snap_id)
                    cost_info = cost_map.get(norm_id, {})
                    actual_cost = cost_info.get("cost")
                    currency = cost_info.get("currency", context.currency)

                    # Formula (R16): Monthly savings = snapshot monthly cost; annual = monthly * 12; % = 100% if entire charge stops
                    monthly_price: Optional[float] = None
                    savings_type = "Not Estimated"
                    if actual_cost is not None and actual_cost > 0:
                        monthly_price = float(actual_cost)
                        savings_type = "Actual Cost"
                    elif size_gb:
                        snap_rate = await PricingEngine.get_snapshot_gb_monthly_price(snap_region, currency)
                        if snap_rate is not None and snap_rate > 0:
                            monthly_price = round(float(size_gb) * snap_rate, 2)
                            savings_type = "Estimated Savings"
                    parsed = parse_azure_resource_id(snap_id)

                    # Extract source disk from creationData if available
                    creation_data = props.get("creationData", {})
                    source_res_id = (
                        creation_data.get("sourceResourceId")
                        or creation_data.get("sourceUri")
                        or props.get("sourceResourceId")
                        or ""
                    )
                    source_disk = "--"
                    if source_res_id:
                        source_disk = source_res_id.split("/")[-1]
                        if source_disk.lower().endswith(".vhd"):
                            source_disk = source_disk[:-4]
                    else:
                        tags = snap.get("tags") or {}
                        source_disk = (
                            tags.get("sourceDisk")
                            or tags.get("SourceDisk")
                            or tags.get("source")
                            or tags.get("Source")
                            or tags.get("DiskName")
                            or "Standalone Disk"
                        )

                    findings.append(
                        FindingModel(
                            finding_id=f"cost15-{snap_name[:12]}",
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
                            current_configuration=f"Source Disk: {source_disk} | Size: {size_gb} GiB | Created: {time_created.strftime('%Y-%m-%d')} ({age_days} days ago)",
                            measured_value=f"Snapshot age is {age_days} days (> 365 days threshold, Created: {time_created.strftime('%Y-%m-%d')})",
                            recommended_configuration="Verify compliance requirement and delete expired snapshot",
                            recommendation=f"Snapshot '{snap_name}' created from source disk '{source_disk}' is {age_days} days old and exceeds standard 365-day retention. Delete expired snapshot to eliminate ongoing storage costs.",
                            metric_period=f"Last Completed Month ({cost_month})",
                            data_source="Microsoft.Compute Snapshots & Cost Management API",
                            evidence={
                                "source_disk": source_disk,
                                "source_resource_id": source_res_id,
                                "age_days": age_days,
                                "size_gb": size_gb,
                                "disk_size_gb": size_gb,
                                "incremental": incremental,
                                "created_date": time_created.strftime("%Y-%m-%d"),
                                "previous_month_actual_cost": actual_cost,
                                "actual_cost_mtd": round(monthly_price, 2) if monthly_price is not None else None,
                                "savings_pct": 100.0 if (monthly_price is not None and monthly_price > 0) else None,
                                "cost_month": cost_month
                            },
                            current_monthly_cost=round(monthly_price, 2) if monthly_price is not None else None,
                            estimated_monthly_savings=round(monthly_price, 2) if monthly_price is not None else None,
                            estimated_annual_savings=round(monthly_price * 12, 2) if monthly_price is not None else None,
                            currency=currency,
                            savings_type=savings_type,
                            confidence="High" if monthly_price is not None else "Low",
                            calculation_method="Monthly savings = snapshot monthly cost; annual = monthly * 12; savings % = 100% if entire snapshot charge stops",
                            validation_required="Deletion approval required; check retention, restore/DR needs and ownership (overlaps New and Unused Resources).",
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
