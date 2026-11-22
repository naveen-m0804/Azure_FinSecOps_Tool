from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Tuple
import datetime
from app.schemas.assessment import AssessmentDefinition, AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.schemas.subscription import SubscriptionModel
from app.azure.client_base import AzureClientBase

class AssessmentContext:
    def __init__(
        self,
        connection_id: str,
        workspace_name: str,
        tenant_id: str,
        subscriptions: List[SubscriptionModel],
        client: Optional[AzureClientBase] = None,
        currency: str = "USD",
        target_tags: Optional[List[str]] = None,
        prod_tags: Optional[List[str]] = None,
        test_tags: Optional[List[str]] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None
    ):
        self.connection_id = connection_id
        self.workspace_name = workspace_name
        self.tenant_id = tenant_id
        self.subscriptions = subscriptions
        self.client = client
        self.currency = currency
        self.target_tags = target_tags or []
        self.prod_tags = prod_tags or []
        self.test_tags = test_tags or []
        self.client_id = client_id
        self.client_secret = client_secret
        self.cached_cost_findings: List[FindingModel] = []

class BaseAssessment(ABC):
    assessment_id: str
    code: str
    category: str
    name: str
    description: str
    purpose: str
    required_permissions: List[str] = []
    required_data_sources: List[str] = []

    def get_definition(self) -> AssessmentDefinition:
        return AssessmentDefinition(
            assessment_id=self.assessment_id,
            code=self.code,
            category=self.category,
            name=self.name,
            description=self.description,
            purpose=self.purpose,
            required_permissions=self.required_permissions,
            required_data_sources=self.required_data_sources,
        )

    @abstractmethod
    async def run(self, context: AssessmentContext) -> AssessmentResult:
        """Executes assessment across subscriptions in context."""
        pass

    def validate_prerequisites(self, context: AssessmentContext) -> Tuple[bool, Optional[str]]:
        if not context.subscriptions:
            return False, "No enabled subscriptions available for assessment."
        return True, None

    def create_empty_result(self, status: AssessmentStatus = AssessmentStatus.NO_FINDINGS) -> AssessmentResult:
        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=0,
            findings_count=0,
            findings=[],
            total_monthly_savings=0.0 if self.category == "cost" else None,
            total_annual_savings=0.0 if self.category == "cost" else None,
            currency="USD",
            last_run_time=datetime.datetime.now(datetime.timezone.utc).isoformat()
        )
