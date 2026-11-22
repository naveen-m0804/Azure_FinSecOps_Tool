from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field

class EvidenceModel(BaseModel):
    data: Dict[str, Any] = Field(default_factory=dict)

class FindingModel(BaseModel):
    finding_id: str
    assessment_id: str
    category: str = Field(..., description="security or cost")
    subscription_id: str
    subscription_name: str
    resource_group: Optional[str] = None
    resource_name: str
    resource_type: str
    resource_id: str
    region: Optional[str] = None
    severity: str = "Medium" # Critical, High, Medium, Low, Informational
    status: str = "Active" # Optimization Candidate, Compliant, Non-Compliant, etc.
    current_configuration: Optional[str] = None
    measured_value: Optional[str] = None
    recommended_configuration: Optional[str] = None
    recommendation: str
    metric_period: Optional[str] = None
    data_source: str = "Azure Monitor"
    evidence: Dict[str, Any] = Field(default_factory=dict)
    
    # Financial fields
    current_monthly_cost: Optional[float] = None
    estimated_monthly_savings: Optional[float] = None
    estimated_annual_savings: Optional[float] = None
    currency: Optional[str] = "USD"
    savings_type: str = "Not Estimated" # Actual Cost, Estimated Savings, Scenario Savings, Not Estimated
    confidence: str = "Not Available" # High, Medium, Low, Not Available
    calculation_method: Optional[str] = None
    pricing_source: Optional[str] = None
    pricing_timestamp: Optional[str] = None
    validation_required: Optional[str] = None
    
    # Security fields
    security_score_impact: Optional[float] = None
    security_score_basis: Optional[str] = None
    
    # Execution & Status
    assessment_status: str = "Completed"
    limitations: List[str] = Field(default_factory=list)
    collected_at: str
