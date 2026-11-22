from typing import List, Optional, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field
from .assessment import AssessmentResult, AssessmentStatus

class JobStatus(str, Enum):
    PENDING = "Pending"
    RUNNING = "Running"
    COMPLETED = "Completed"
    COMPLETED_WITH_WARNINGS = "Completed with Warnings"
    FAILED = "Failed"
    CANCELLED = "Cancelled"
    EXPIRED = "Expired"

class LogEvent(BaseModel):
    timestamp: str
    level: str = "INFO" # INFO, WARNING, ERROR, SUCCESS
    message: str
    assessment_id: Optional[str] = None
    subscription_name: Optional[str] = None

class JobProgressModel(BaseModel):
    job_id: str
    status: JobStatus
    scope: str = "all" # all, security, cost, single
    total_assessments: int = 0
    completed_assessments: int = 0
    running_assessments: int = 0
    pending_assessments: int = 0
    failed_assessments: int = 0
    current_subscription: Optional[str] = None
    current_assessment: Optional[str] = None
    progress_percentage: float = 0.0
    start_time: str
    duration_seconds: float = 0.0
    assessment_statuses: Dict[str, AssessmentStatus] = Field(default_factory=dict)
    recent_logs: List[LogEvent] = Field(default_factory=list)

class JobResponse(BaseModel):
    job_id: str
    status: JobStatus
    progress: JobProgressModel
    summary: Dict[str, Any] = Field(default_factory=dict)
    results: Dict[str, AssessmentResult] = Field(default_factory=dict)
