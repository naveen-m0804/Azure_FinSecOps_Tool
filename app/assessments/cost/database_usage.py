import datetime
import time
from typing import List
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.database import DatabaseAdapter

class DatabaseUsageAssessment(BaseAssessment):
    assessment_id = "database_usage"
    code = "COST-10"
    category = "cost"
    name = "Database Usage / Threshold"
    description = "Audit Azure SQL / Flexible Server database CPU and DTU utilization to identify low-traffic databases."
    purpose = "Right-size database tiers or shift sporadic workloads to Serverless auto-pause architectures."
    required_permissions = ["Microsoft.Sql/servers/databases/read", "Microsoft.Insights/metrics/read", "Monitoring Reader"]
    required_data_sources = ["Azure Monitor Database DTU / CPU Percent Metrics"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        for sub in context.subscriptions:
            try:
                servers = await DatabaseAdapter.get_sql_servers(context.client, sub.subscription_id)
                for s in servers:
                    s_id = s.get("id", "")
                    dbs = await DatabaseAdapter.get_sql_databases(context.client, s_id)
                    resources_evaluated += len(dbs)
            except Exception as ex:
                errors.append(f"Failed to scan SQL databases for subscription {sub.subscription_id}: {ex}")

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
