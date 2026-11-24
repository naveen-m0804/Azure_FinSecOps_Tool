import datetime
import time
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.authorization import AuthorizationAdapter
from app.utils.resource_ids import parse_azure_resource_id

# Known privileged role definition GUIDs
CONTRIBUTOR_ROLE_ID = "b24988ac-6180-42a0-ab88-20f7382dd24c"
OWNER_ROLE_ID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

class ContributorRbacAssessment(BaseAssessment):
    assessment_id = "contributor_rbac"
    code = "SEC-14"
    category = "security"
    name = "Contributor RBAC Review"
    description = "Review broad Contributor role assignments across subscription and resource group scopes."
    purpose = "Enforce least privilege access principles and eliminate direct user-assigned Contributor privileges."
    required_permissions = [
        "Microsoft.Authorization/roleAssignments/read",
        "Microsoft.Authorization/roleDefinitions/read",
        "Reader"
    ]
    required_data_sources = ["Microsoft.Authorization RoleAssignments API (2022-04-01)"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        for sub in context.subscriptions:
            assignments = await AuthorizationAdapter.get_role_assignments(context.client, sub.subscription_id)
            if not assignments:
                continue

            # Collect unique principal IDs for real-name directory resolution
            pids_to_resolve = set()
            for a in assignments:
                p_id = a.get("properties", {}).get("principalId")
                if p_id:
                    pids_to_resolve.add(p_id)

            resolved_map = await AuthorizationAdapter.resolve_principals(
                client=context.client,
                subscription_id=sub.subscription_id,
                principal_ids=pids_to_resolve,
                tenant_id=context.tenant_id,
                client_id=context.client_id,
                client_secret=context.client_secret
            )

            for a in assignments:
                resources_evaluated += 1
                props = a.get("properties", {})
                role_def_id = str(props.get("roleDefinitionId") or "").lower()
                scope = props.get("scope") or f"/subscriptions/{sub.subscription_id}"
                raw_principal_type = props.get("principalType") or "User"
                principal_id = props.get("principalId") or a.get("name", "Unknown Principal")
                pid_clean = str(principal_id).strip().lower()

                # Scope Filter: Strictly filter to Subscription scope ("This resource") matching Azure Portal Subscription IAM
                sub_clean = sub.subscription_id.lower().strip()
                sub_scope_clean = f"/subscriptions/{sub_clean}"
                scope_clean = str(scope).lower().strip().rstrip("/")
                is_sub_scope = (
                    scope_clean in (sub_scope_clean, f"subscriptions/{sub_clean}", sub_clean)
                    or "/resourcegroups/" not in scope_clean
                )
                if not is_sub_scope:
                    continue

                # Check if this assignment is the built-in Contributor role (exclude Owner and non-Contributor roles)
                exp_props = props.get("expandedProperties") or {}
                role_def_name = str(exp_props.get("roleDefinitionName") or props.get("roleDefinitionName") or "").strip().lower()
                is_contributor = (
                    CONTRIBUTOR_ROLE_ID in role_def_id
                    or role_def_id.endswith(CONTRIBUTOR_ROLE_ID)
                    or role_def_name == "contributor"
                )
                is_owner = OWNER_ROLE_ID in role_def_id or "owner" in role_def_id or "owner" in role_def_name

                if not is_contributor or is_owner:
                    continue

                role_name = "Contributor"

                # Determine accurate real display name and username
                resolved_info = resolved_map.get(pid_clean, {})
                resolved_dname = resolved_info.get("display_name")
                resolved_upn = resolved_info.get("user_principal_name")
                resolved_type = resolved_info.get("type") or raw_principal_type

                prop_dname = exp_props.get("displayName") or props.get("displayName")
                prop_upn = (
                    exp_props.get("email")
                    or exp_props.get("principalName")
                    or props.get("principalName")
                    or props.get("userPrincipalName")
                    or props.get("email")
                )

                final_dname = resolved_dname or prop_dname
                final_upn = resolved_upn or prop_upn

                # Clean display name matching Azure Portal IAM blade
                if final_dname:
                    real_principal_name = final_dname
                elif final_upn:
                    real_principal_name = final_upn
                else:
                    real_principal_name = f"Identity {principal_id[:8]}..."

                # Normalize principal type matching Azure Portal (Group, Service principal, User, Managed identity)
                ptype_raw = (resolved_type or raw_principal_type or "").strip().lower()
                if "group" in ptype_raw:
                    norm_principal_type = "Group"
                elif "serviceprincipal" in ptype_raw or "application" in ptype_raw or "spn" in ptype_raw:
                    norm_principal_type = "Service principal"
                elif "user" in ptype_raw or "guest" in ptype_raw:
                    norm_principal_type = "User"
                elif "identity" in ptype_raw:
                    norm_principal_type = "Managed identity"
                else:
                    norm_principal_type = resolved_type or "Identity"

                # Security Review Criteria for broad Subscription Contributor permissions
                if norm_principal_type == "Group":
                    remediation = "Subscription-wide Contributor privileges granted to group. Review group membership regularly and enforce Azure AD PIM just-in-time role elevation."
                elif norm_principal_type == "Service principal":
                    remediation = "Service principal possesses broad Subscription Contributor permissions. Restrict permissions to least-privilege custom roles or scope down to target resource groups."
                else:
                    remediation = "Replace direct user assignment at subscription scope with Azure AD Security Group membership or Azure AD PIM just-in-time role activation."

                findings.append(
                    FindingModel(
                        finding_id=f"sec14-{sub.subscription_id[:8]}-{a.get('name', '')[:10]}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group="Subscription Scope",
                        resource_name=sub.display_name,
                        resource_type="Microsoft.Authorization/roleAssignments",
                        resource_id=a.get("id", f"{scope}/providers/Microsoft.Authorization/roleAssignments/{a.get('name')}"),
                        region="global",
                        severity="High",
                        status="Review Required",
                        current_configuration=f"Contributor role granted to {norm_principal_type} '{real_principal_name}' at Subscription scope",
                        measured_value=f"{norm_principal_type} Contributor (This resource)",
                        recommended_configuration="Replace broad Subscription Contributor role with scoped role assignment or PIM eligible elevation",
                        recommendation=f"Broad 'Contributor' role is assigned to {norm_principal_type} '{real_principal_name}' at the Subscription scope ({sub.display_name}). {remediation}",
                        metric_period="Current RBAC state",
                        data_source="Microsoft.Authorization RoleAssignments API (2022-04-01)",
                        evidence={
                            "principal_name": real_principal_name,
                            "principal_id": principal_id,
                            "user_name": final_upn or final_dname or real_principal_name,
                            "principal_type": norm_principal_type,
                            "role_name": role_name,
                            "scope": "This resource",
                            "assignment_type": "Active Permanent",
                            "security_control": "Review Contributor permissions",
                            "potential_score_increase": "+3.5%",
                            "remediation": remediation
                        },
                        security_score_impact=3.5,
                        collected_at=now_str
                    )
                )

        status = AssessmentStatus.COMPLETED if findings else AssessmentStatus.NO_FINDINGS
        total_score_impact = round(sum(f.security_score_impact for f in findings if f.security_score_impact), 1) if findings else None

        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(resources_evaluated, len(context.subscriptions)),
            findings_count=len(findings),
            findings=findings,
            errors=errors,
            security_score_improvement=total_score_impact,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
