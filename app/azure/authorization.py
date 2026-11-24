from typing import Dict, Any, List, Optional, Set
import httpx
import logging
from app.azure.client_base import AzureClientBase
from app.core.authentication import AzureAuthService

logger = logging.getLogger("azure_finsecops.azure.authorization")

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
        Enriches assignments with principal details using ARM $expand=principal.
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
                        upn = (
                            exp.get("email")
                            or exp.get("principalName")
                            or exp.get("userPrincipalName")
                            or props.get("principalName")
                            or props.get("userPrincipalName")
                            or ""
                        )
                        ptype = exp.get("principalType") or props.get("principalType") or ""
                        principal_info_map[p_id] = {
                            "display_name": dname,
                            "user_principal_name": upn,
                            "type": ptype
                        }
        except Exception as ex:
            logger.debug("atScope $expand=principal failed: %s", ex)

        # 2. Query all role assignments across subscription and child scopes with $expand=principal
        url: Optional[str] = (
            f"https://management.azure.com/subscriptions/{subscription_id}"
            f"/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01&$expand=principal"
        )

        while url:
            try:
                resp = await client.execute_request("GET", url)
                if resp.status_code == 200:
                    data = resp.json()
                    page_items = data.get("value", [])
                    all_assignments.extend(page_items)
                    url = data.get("nextLink")
                else:
                    # Fallback without $expand=principal if rejected or errored
                    fallback_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
                    resp_fb = await client.execute_request("GET", fallback_url)
                    if resp_fb.status_code == 200:
                        all_assignments.extend(resp_fb.json().get("value", []))
                    break
            except Exception:
                break

        # Fallback to Azure Resource Graph if no assignments were retrieved via ARM
        if not all_assignments:
            try:
                arg_url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
                arg_payload = {
                    "subscriptions": [subscription_id],
                    "query": (
                        f"authorizationresources "
                        f"| where subscriptionId =~ '{subscription_id}' "
                        f"| where type =~ 'microsoft.authorization/roleassignments' "
                        f"| project id, name, type, properties"
                    ),
                    "options": {"resultFormat": "objectArray"}
                }
                arg_resp = await client.execute_request("POST", arg_url, json_data=arg_payload)
                if arg_resp.status_code == 200:
                    arg_data = arg_resp.json().get("data", [])
                    if isinstance(arg_data, list):
                        all_assignments.extend(arg_data)
            except Exception as ex:
                logger.debug("ARG authorizationresources query failed: %s", ex)

        # 3. Enrich all assignments with cached expanded principal information
        for item in all_assignments:
            props = item.get("properties", {})
            p_id = (props.get("principalId") or "").strip().lower()
            exp = props.get("expandedProperties") or {}

            # Cache any names discovered directly in page items
            dname = exp.get("displayName") or props.get("displayName") or ""
            upn = (
                exp.get("email")
                or exp.get("principalName")
                or exp.get("userPrincipalName")
                or props.get("principalName")
                or props.get("userPrincipalName")
                or ""
            )
            if p_id and (dname or upn):
                if p_id not in principal_info_map or not principal_info_map[p_id].get("display_name"):
                    principal_info_map[p_id] = {
                        "display_name": dname,
                        "user_principal_name": upn,
                        "type": exp.get("principalType") or props.get("principalType") or "User"
                    }

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
        2. Query ARM native getDirectoryObjectsByKeys on management.azure.com (requires NO Graph permissions).
        3. Query Microsoft Graph getByIds (if tenant_id, client_id, and client_secret are provided).
        4. Query Microsoft Graph individual user/sp endpoints for remaining IDs.
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

        # 1. Attempt ARM native getDirectoryObjectsByKeys (runs under standard Azure Subscription Reader permissions)
        try:
            arm_dir_url = f"https://management.azure.com/subscriptions/{subscription_id}/providers/Microsoft.Authorization/getDirectoryObjectsByKeys?api-version=2022-04-01"
            unresolved_list = list(unresolved)
            chunks = [unresolved_list[i:i + 100] for i in range(0, len(unresolved_list), 100)]
            for chunk in chunks:
                arm_resp = await client.execute_request("POST", arm_dir_url, json_data={"ids": chunk})
                if arm_resp.status_code == 200:
                    objs = arm_resp.json().get("value", [])
                    for obj in objs:
                        oid = (obj.get("objectId") or obj.get("id") or "").lower()
                        dname = obj.get("displayName") or ""
                        upn = obj.get("userPrincipalName") or obj.get("principalName") or obj.get("signInName") or obj.get("email") or ""
                        otype = obj.get("objectType") or obj.get("principalType") or "User"
                        if oid and (dname or upn):
                            resolved[oid] = {
                                "display_name": dname,
                                "user_principal_name": upn,
                                "type": otype
                            }
                            unresolved.discard(oid)
        except Exception as ex:
            logger.debug("ARM getDirectoryObjectsByKeys failed: %s", ex)

        if not unresolved:
            return resolved

        # 2. Attempt Microsoft Graph API Directory Object Lookup
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

        # 3. If getByIds failed or some IDs remain, try individual user lookup via Graph
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

        return resolved
