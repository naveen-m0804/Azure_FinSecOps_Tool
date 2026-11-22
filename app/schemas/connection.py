from typing import Optional, List
from pydantic import BaseModel, Field

class TestConnectionRequest(BaseModel):
    tenant_id: str = Field(..., description="Azure Tenant ID (GUID)")
    client_id: str = Field(..., description="Service Principal Application/Client ID")
    client_secret: str = Field(..., description="Service Principal Client Secret")

class ConnectRequest(BaseModel):
    workspace_name: str = Field(..., min_length=2, max_length=100, description="Customer or Workspace Name")
    tenant_id: str = Field(..., description="Azure Tenant ID (GUID)")
    client_id: str = Field(..., description="Service Principal Client ID")
    client_secret: str = Field(..., description="Service Principal Client Secret")
    target_tags: Optional[str] = Field(default="prod, test, dev, staging", description="Comma-separated environment evaluation tags")
    target_subscription_ids: Optional[List[str]] = Field(default=None, description="Optional list of specific subscription IDs to evaluate")

class ConnectResponse(BaseModel):
    connection_id: str
    workspace_name: str
    tenant_id: str
    client_id: str
    accessible_subscriptions_count: int
    connected_at: str
    status: str
    currency: Optional[str] = None
    target_tags: Optional[str] = None

class ConnectionStatusResponse(BaseModel):
    connection_id: str
    workspace_name: str
    tenant_id: str
    is_connected: bool
    subscription_count: int
    connected_at: str
    currency: Optional[str] = None
    target_tags: Optional[str] = None
