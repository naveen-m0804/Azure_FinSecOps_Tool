from typing import List, Optional
from pydantic import BaseModel, Field

class SubscriptionModel(BaseModel):
    id: str
    subscription_id: str
    display_name: str
    state: str = "Enabled"
    tenant_id: str
    authorization_source: Optional[str] = "RoleAssignment"
    cost_permission: bool = True
    security_permission: bool = True
    monitor_permission: bool = True

class SubscriptionListResponse(BaseModel):
    total_count: int
    subscriptions: List[SubscriptionModel]

class ValidateSubscriptionRequest(BaseModel):
    tenant_id: str = Field(..., description="Azure Tenant ID (GUID)")
    client_id: str = Field(..., description="Service Principal Client ID (GUID)")
    client_secret: str = Field(..., description="Service Principal Client Secret")
    subscription_id: str = Field(..., description="Azure Subscription ID to validate")

class ValidateSubscriptionResponse(BaseModel):
    valid: bool
    subscription_id: str
    display_name: Optional[str] = None
    state: Optional[str] = None
    message: Optional[str] = None
    error: Optional[str] = None
