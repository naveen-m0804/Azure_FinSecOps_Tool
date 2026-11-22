from typing import Dict, Any, List, Optional, Set
import httpx
from app.azure.client_base import AzureClientBase
from app.core.authentication import AzureAuthService

# Known Microsoft 1st-party service principals and common system identities
WELL_KNOWN_PRINCIPALS = {
    "00000002-0000-0000-c000-000000000000": "Windows Azure Active Directory",
    "00000003-0000-0000-c000-000000000000": "Microsoft Graph",
    "f2ff4f21-789a-41d3-a620-80252538b8c5": "Microsoft Defender for Cloud",
    "c5c8e474-0f2b-4d4f-9e6b-a25e01140082": "Azure Security Center",
    "60c3b88b-0599-4d8e-be89-32321557008a": "Azure Monitor Autoscale",
    "fa980993-a4a3-441f-8646-fa2a88a09ee3": "Azure Backup Service",
    "a073f1d4-8d4e-4f76-8e58-6a581458e08d": "Azure Site Recovery",
    "b8813a27-a066-4a0b-8d00-47b2ff688e14": "Azure Container Registry",
}

class AuthorizationAdapter:
    @staticmethod
    async def get_role_assignments(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves all role assignments in the subscription with pagination.
        Enriches assignments with principal details using ARM $expand=principal with $filter=atScope().
        """
        all_assignments: List[Dict[str, Any]] = []
        principal_info_map: Dict[str, Dict[str, str]] = {}

        # 1. Query role assignments at subscription scope with $expand=principal (ARM natively supports $expand with atScope)
        at_scope_url: Optional[str] = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$filter=atScope()&$expand=principal"
        )
        try:
            resp = await client.execute_request("GET", at_scope_url)
            if resp.status_code == 200:
                scope_data = resp.json().get("value", [])
                for item in scope_data:
                    props = item.get("properties", {})
                    p_id = (props.get("principalId") or "").strip().lower()
                    if p_id:
                        exp = props.get("expandedProperties") or {}
                        dname = exp.get("displayName") or props.get("displayName") or ""
                        upn = exp.get("email") or exp.get("principalName") or props.get("principalName") or props.get("userPrincipalName") or ""
                        ptype = exp.get("principalType") or props.get("principalType") or ""
                        principal_info_map[p_id] = {
                            "display_name": dname,
                            "user_principal_name": upn,
                            "type": ptype
                        }
        except Exception:
            pass

        # 2. Query all role assignments across subscription and child scopes
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    page_items = data.get("value", [])
                    all_assignments.extend(page_items)
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        # 3. Enrich all assignments with cached expanded principal information
        for item in all_assignments:
            props = item.get("properties", {})
            p_id = (props.get("principalId") or "").strip().lower()
            if p_id and p_id in principal_info_map:
                cached = principal_info_map[p_id]
                if not props.get("expandedProperties"):
                    props["expandedProperties"] = {}
                if cached.get("display_name") and not props["expandedProperties"].get("displayName"):
                    props["expandedProperties"]["displayName"] = cached["display_name"]
                if cached.get("user_principal_name") and not props["expandedProperties"].get("email"):
                    props["expandedProperties"]["email"] = cached["user_principal_name"]
                if cached.get("user_principal_name") and not props.get("principalName"):
                    props["principalName"] = cached["user_principal_name"]

        return all_assignments

    @staticmethod
    async def resolve_principals(
        client: AzureClientBase,
        subscription_id: str,
        principal_ids: Set[str],
        tenant_id: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None
    ) -> Dict[str, Dict[str, str]]:
        """
        Resolves object IDs to actual User Display Names, UserPrincipalNames, or Service Principal Names.
        Strategy:
        1. Match against well-known Azure identities & current client_id.
        2. Query Microsoft Graph getByIds (if tenant_id, client_id, and client_secret are provided).
        3. Query Microsoft Graph individual user/sp endpoints for remaining IDs.
        4. Query ARM getDirectoryObjectsByKeys on management.azure.com.
        """
        resolved: Dict[str, Dict[str, str]] = {}
        unresolved: Set[str] = set()

        for pid in principal_ids:
            if not pid:
                continue
            pid_clean = pid.strip().lower()
            if pid_clean in WELL_KNOWN_PRINCIPALS:
                resolved[pid_clean] = {
                    "display_name": WELL_KNOWN_PRINCIPALS[pid_clean],
                    "user_principal_name": "",
                    "type": "ServicePrincipal"
                }
            elif client_id and pid_clean == client_id.strip().lower():
                resolved[pid_clean] = {
                    "display_name": f"Current Scanner App ({client_id[:8]}...)",
                    "user_principal_name": "",
                    "type": "ServicePrincipal"
                }
            else:
                unresolved.add(pid)

        if not unresolved:
            return resolved

        # 1. Attempt Microsoft Graph API Directory Object Lookup
        graph_token = None
        if tenant_id and client_id and client_secret:
            try:
                graph_token, _ = await AzureAuthService.acquire_graph_token(tenant_id, client_id, client_secret)
                if graph_token:
                    async with httpx.AsyncClient(timeout=15.0) as http_c:
                        chunks = [list(unresolved)[i:i + 1000] for i in range(0, len(unresolved), 1000)]
                        for chunk in chunks:
                            resp = await http_c.post(
                                "https://graph.microsoft.com/v1.0/directoryObjects/getByIds",
                                headers={"Authorization": f"Bearer {graph_token}", "Content-Type": "application/json"},
                                json={"ids": chunk, "types": ["user", "group", "servicePrincipal"]}
                            )
                            if resp.status_code == 200:
                                g_data = resp.json().get("value", [])
                                for obj in g_data:
                                    oid = (obj.get("id") or "").lower()
                                    dname = obj.get("displayName") or ""
                                    upn = obj.get("userPrincipalName") or obj.get("mail") or ""
                                    otype = obj.get("@odata.type", "").replace("#microsoft.graph.", "").capitalize()
                                    if oid:
                                        resolved[oid] = {
                                            "display_name": dname,
                                            "user_principal_name": upn,
                                            "type": otype or "User"
                                        }
                                        unresolved.discard(oid)
            except Exception:
                pass

        # 2. If getByIds failed or some IDs remain, try individual user lookup via Graph
        if unresolved and graph_token:
            try:
                async with httpx.AsyncClient(timeout=10.0) as http_c:
                    for uid in list(unresolved)[:25]:
                        try:
                            # Try user endpoint
                            u_resp = await http_c.get(
                                f"https://graph.microsoft.com/v1.0/users/{uid}?$select=displayName,userPrincipalName,mail",
                                headers={"Authorization": f"Bearer {graph_token}"}
                            )
                            if u_resp.status_code == 200:
                                u_data = u_resp.json()
                                dname = u_data.get("displayName") or ""
                                upn = u_data.get("userPrincipalName") or u_data.get("mail") or ""
                                if dname or upn:
                                    resolved[uid.lower()] = {
                                        "display_name": dname,
                                        "user_principal_name": upn,
                                        "type": "User"
                                    }
                                    unresolved.discard(uid)
                                    continue

                            # Try servicePrincipal endpoint
                            sp_resp = await http_c.get(
                                f"https://graph.microsoft.com/v1.0/servicePrincipals/{uid}?$select=displayName,appDisplayName",
                                headers={"Authorization": f"Bearer {graph_token}"}
                            )
                            if sp_resp.status_code == 200:
                                sp_data = sp_resp.json()
                                dname = sp_data.get("displayName") or sp_data.get("appDisplayName") or ""
                                if dname:
                                    resolved[uid.lower()] = {
                                        "display_name": dname,
                                        "user_principal_name": "",
                                        "type": "ServicePrincipal"
                                    }
                                    unresolved.discard(uid)
                        except Exception:
                            continue
            except Exception:
                pass

        # 3. Attempt Azure ARM getDirectoryObjectsByKeys
        if unresolved:
            try:
                arm_chunks = [list(unresolved)[i:i + 1000] for i in range(0, len(unresolved), 1000)]
                for chunk in arm_chunks:
                    arm_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Authorization/getDirectoryObjectsByKeys?api-version=2018-07-01-preview"
                    resp = await client.execute_request("POST", arm_url, json_data={"keys": chunk, "types": ["User", "Group", "ServicePrincipal"]})
                    if resp.status_code == 200:
                        arm_objs = resp.json().get("value", [])
                        for obj in arm_objs:
                            oid = (obj.get("objectId") or obj.get("id") or "").lower()
                            dname = obj.get("displayName") or ""
                            upn = obj.get("userPrincipalName") or obj.get("mail") or obj.get("signInNames", [{}])[0].get("value", "")
                            otype = obj.get("objectType") or "User"
                            if oid:
                                resolved[oid] = {
                                    "display_name": dname,
                                    "user_principal_name": upn,
                                    "type": otype
                                }
                                unresolved.discard(oid)
            except Exception:
                pass

        return resolved

    @staticmethod
    async def get_role_definitions(client: AzureClientBase, subscription_id: str) -> List[Dict[str, Any]]:
        """
        Retrieves role definitions with pagination.
        URI: /subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01
        """
        url: Optional[str] = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01"
        all_definitions: List[Dict[str, Any]] = []

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    all_definitions.extend(data.get("value", []))
                    url = data.get("nextLink")
                else:
                    break
            except Exception:
                break

        return all_definitions
