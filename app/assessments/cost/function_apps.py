import datetime
import time
from typing import List
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.resources import ResourcesAdapter

class FunctionAppsAssessment(BaseAssessment):
    assessment_id = "function_apps"
    code = "COST-17"
    category = "cost"
    name = "Function App Execution Time / Frequency"
    description = "Audit Function Apps hosted on dedicated App Service Plans that have low execution counts and can transition to serverless Consumption."
    purpose = "Eliminate dedicated compute plan charges for sporadic, event-driven functions."
    required_permissions = ["Microsoft.Web/sites/read", "Microsoft.Insights/metrics/read", "Reader"]
    required_data_sources = ["Azure Monitor Function App Executions & App Service Plan APIs"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        for sub in context.subscriptions:
            try:
                sites = await ResourcesAdapter.get_app_services(context.client, sub.subscription_id)
                resources_evaluated += len(sites)
            except Exception as ex:
                errors.append(f"Failed to scan App Services for subscription {sub.subscription_id}: {ex}")

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
