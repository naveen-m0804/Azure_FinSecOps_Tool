import datetime
import re
from fastapi import APIRouter, HTTPException
from app.schemas.connection import (
    ConnectRequest, ConnectResponse, TestConnectionRequest, ConnectionStatusResponse
)
from app.core.authentication import AzureAuthService
from app.core.subscription_discovery import SubscriptionDiscoveryService
from app.core.session_store import session_store
from app.utils.validators import is_valid_guid

router = APIRouter(prefix="/api/connection", tags=["Connection"])

def parse_environment_tags(tag_str: str):
    tags = [t.strip() for t in tag_str.split(",") if t.strip()] if tag_str else []
    prod_tags = [t for t in tags if re.search(r"(?i)(prod|production|live|prd)", t)]
    test_tags = [t for t in tags if re.search(r"(?i)(test|testing|qa|uat|staging|stage|sandbox|dev|development|nonprod)", t)]
    return tags, prod_tags, test_tags

@router.post("/test")
async def test_azure_connection(req: TestConnectionRequest):
    if not is_valid_guid(req.tenant_id):
        raise HTTPException(status_code=400, detail="Tenant ID must be a valid GUID.")
    if not is_valid_guid(req.client_id):
        raise HTTPException(status_code=400, detail="Client ID must be a valid GUID.")
    if not req.client_secret or len(req.client_secret.strip()) < 3:
        raise HTTPException(status_code=400, detail="Client Secret cannot be blank.")

    success, message, sub_count = await AzureAuthService.test_credentials(
        req.tenant_id, req.client_id, req.client_secret
    )
    if not success:
        raise HTTPException(status_code=401, detail=message)

    return {
        "success": True,
        "message": message,
        "accessible_subscriptions_count": sub_count
    }

@router.post("/connect", response_model=ConnectResponse)
async def connect_azure(req: ConnectRequest):
    if not is_valid_guid(req.tenant_id):
        raise HTTPException(status_code=400, detail="Tenant ID must be a valid GUID.")
    if not is_valid_guid(req.client_id):
        raise HTTPException(status_code=400, detail="Client ID must be a valid GUID.")
    if not req.client_secret:
        raise HTTPException(status_code=400, detail="Client Secret is required.")
    
    tag_str = (req.target_tags or "").strip()
    all_tags, prod_tags, test_tags = parse_environment_tags(tag_str)

    try:
        subs = await SubscriptionDiscoveryService.discover_subscriptions(
            tenant_id=req.tenant_id,
            client_id=req.client_id,
            client_secret=req.client_secret,
            target_subscription_ids=req.target_subscription_ids
        )
    except Exception as ex:
        raise HTTPException(status_code=401, detail=f"Authentication or subscription discovery failed: {str(ex)}")

    if req.target_subscription_ids and not subs:
        raise HTTPException(status_code=400, detail="None of the specified subscription IDs could be accessed with this Service Principal. Please check permissions.")

    if not subs or len(subs) == 0:
        raise HTTPException(
            status_code=400,
            detail="No accessible subscriptions found in this Azure tenant for the provided Service Principal. Ensure 'Reader' role is assigned on at least one subscription."
        )

    detected_currency = None
    if subs and len(subs) > 0:
        try:
            from app.core.azure_client_factory import azure_client_factory
            from app.azure.cost_management import CostManagementAdapter
            client = await azure_client_factory.get_client_for_session(
                tenant_id=req.tenant_id,
                client_id=req.client_id,
                client_secret=req.client_secret
            )
            first_sub_id = subs[0].subscription_id if hasattr(subs[0], "subscription_id") else subs[0].get("subscription_id")
            queried_curr = await CostManagementAdapter.get_subscription_currency(client, first_sub_id)
            if queried_curr:
                detected_currency = queried_curr.upper()
        except Exception:
            pass

    conn_id = await session_store.create_connection(
        workspace_name=req.workspace_name,
        tenant_id=req.tenant_id,
        client_id=req.client_id,
        client_secret=req.client_secret,
        subscriptions=subs,
        currency=detected_currency,
        target_tags=all_tags,
        prod_tags=prod_tags,
        test_tags=test_tags
    )

    return ConnectResponse(
        connection_id=conn_id,
        workspace_name=req.workspace_name,
        tenant_id=req.tenant_id,
        client_id=req.client_id,
        accessible_subscriptions_count=len(subs),
        connected_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        status="Connected",
        currency=detected_currency,
        target_tags=tag_str
    )

@router.get("/status/{connection_id}", response_model=ConnectionStatusResponse)
async def get_connection_status(connection_id: str):
    conn = await session_store.get_connection(connection_id)
    if not conn:
        raise HTTPException(status_code=404, detail="Active connection session not found.")

    return ConnectionStatusResponse(
        connection_id=conn["connection_id"],
        workspace_name=conn["workspace_name"],
        tenant_id=conn["tenant_id"],
        is_connected=True,
        subscription_count=len(conn.get("subscriptions", [])),
        connected_at=conn["connected_at"],
        currency=conn.get("currency", "USD"),
        target_tags=",".join(conn.get("target_tags", []))
    )

@router.delete("/{connection_id}")
async def disconnect(connection_id: str):
    removed = await session_store.remove_connection(connection_id)
    if not removed:
        raise HTTPException(status_code=404, detail="Connection ID not found.")
    return {"success": True, "message": "Disconnected and cleared all in-memory session data."}
