from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field
from .finding import FindingModel

class AssessmentCategory(str, Enum):
    SECURITY = "security"
    COST = "cost"

class AssessmentStatus(str, Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    COMPLETED = "Completed"
    COMPLETED_WITH_WARNINGS = "Completed with Warnings"
    NO_FINDINGS = "No Findings"
    FAILED = "Failed"
    METRICS_UNAVAILABLE = "Metrics Unavailable"
    DATA_UNAVAILABLE = "Data Unavailable"
    PERMISSION_MISSING = "Permission Missing"
    PERMISSION_DENIED = "Permission Denied"
    NOT_SUPPORTED = "Not Supported"

class AssessmentDefinition(BaseModel):
    assessment_id: str
    code: str
    category: str
    name: str
    description: str
    purpose: str
    required_permissions: List[str] = Field(default_factory=list)
    required_data_sources: List[str] = Field(default_factory=list)

class AssessmentResult(BaseModel):
    assessment_id: str
    category: str
    name: str
    status: AssessmentStatus
    resources_evaluated: int = 0
    findings_count: int = 0
    findings: List[FindingModel] = Field(default_factory=list)
    total_monthly_savings: Optional[float] = None
    total_annual_savings: Optional[float] = None
    currency: Optional[str] = "USD"
    security_score_improvement: Optional[float] = None
    execution_time_seconds: float = 0.0
    errors: List[str] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
    last_run_time: Optional[str] = None
