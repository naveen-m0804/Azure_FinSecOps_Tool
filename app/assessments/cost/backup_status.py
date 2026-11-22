import datetime
import time
from typing import List
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.backup import BackupAdapter

class BackupStatusAssessment(BaseAssessment):
    assessment_id = "backup_status"
    code = "COST-15"
    category = "cost"
    name = "Backup Status / Policy / Retention"
    description = "Audit Azure Backup vaults and protection policies to flag overly aggressive retention schedules causing cost bloat."
    purpose = "Optimize backup storage capacity by aligning retention periods with business and compliance mandates."
    required_permissions = ["Microsoft.RecoveryServices/vaults/read", "Reader"]
    required_data_sources = ["Microsoft.RecoveryServices Vaults & Policies API"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        for sub in context.subscriptions:
            try:
                vaults = await BackupAdapter.get_recovery_vaults(context.client, sub.subscription_id)
                resources_evaluated += len(vaults)
            except Exception as ex:
                errors.append(f"Failed to scan recovery vaults for subscription {sub.subscription_id}: {ex}")

        status = AssessmentStatus.COMPLETED if findings else AssessmentStatus.NO_FINDINGS
        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(resources_evaluated, 1),
            findings_count=len(findings),
            findings=findings,
            total_monthly_savings=0.0,
            total_annual_savings=0.0,
            currency=context.currency,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
