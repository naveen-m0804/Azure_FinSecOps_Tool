from fastapi import APIRouter, HTTPException
from app.schemas.subscription import (
    SubscriptionListResponse, ValidateSubscriptionRequest, ValidateSubscriptionResponse
)
from app.core.session_store import session_store
from app.core.subscription_discovery import SubscriptionDiscoveryService

router = APIRouter(prefix="/api/subscriptions", tags=["Subscriptions"])

@router.post("/validate", response_model=ValidateSubscriptionResponse)
async def validate_subscription(req: ValidateSubscriptionRequest):
    """Validate a single Azure subscription in live action before or during connection."""
    result = await SubscriptionDiscoveryService.validate_single_subscription(
        tenant_id=req.tenant_id,
        client_id=req.client_id,
        client_secret=req.client_secret,
        subscription_id=req.subscription_id
    )
    return ValidateSubscriptionResponse(
        valid=result.get("valid", False),
        subscription_id=result.get("subscription_id", req.subscription_id),
        display_name=result.get("display_name"),
        state=result.get("state"),
        message=result.get("message"),
        error=result.get("error")
    )

@router.get("/{connection_id}", response_model=SubscriptionListResponse)
async def list_accessible_subscriptions(connection_id: str):
    conn = await session_store.get_connection(connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Active connection session not found.")

    subs = conn.get("subscriptions", [])
    return SubscriptionListResponse(
        total_count=len(subs),
        subscriptions=subs
    )
