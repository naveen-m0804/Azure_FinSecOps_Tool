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
                role_def_id = (props.get("roleDefinitionId") or "").lower()
                scope = props.get("scope") or f"/subscriptions/{sub.subscription_id}"
                raw_principal_type = props.get("principalType") or "User"
                principal_id = props.get("principalId") or a.get("name", "Unknown Principal")
                pid_clean = str(principal_id).strip().lower()

                # Determine accurate real display name and username
                resolved_info = resolved_map.get(pid_clean, {})
                resolved_dname = resolved_info.get("display_name")
                resolved_upn = resolved_info.get("user_principal_name")
                resolved_type = resolved_info.get("type") or raw_principal_type

                exp_props = props.get("expandedProperties") or {}
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

                if final_dname and final_upn and final_dname.lower() != final_upn.lower():
                    real_principal_name = f"{final_dname} ({final_upn})"
                elif final_dname:
                    real_principal_name = final_dname
                elif final_upn:
                    real_principal_name = final_upn
                else:
                    real_principal_name = f"Direct Identity ({resolved_type})"

                principal_type = resolved_type

                # Check if this assignment is Contributor or Owner
                is_contributor = CONTRIBUTOR_ROLE_ID in role_def_id or "contributor" in role_def_id
                is_owner = OWNER_ROLE_ID in role_def_id or "owner" in role_def_id

                if not (is_contributor or is_owner):
                    continue

                role_name = "Owner" if is_owner else "Contributor"

                # Classify assignment scope: Subscription vs Resource Group vs Resource
                scope_lower = scope.lower().strip("/")
                rg_name = "Subscription Scope"
                res_name = "All Subscription Resources"
                assignment_scope_type = "Subscription"

                if "/resourcegroups/" in scope_lower:
                    parts = scope_lower.split("/resourcegroups/")
                    rg_part = parts[1].split("/")[0]
                    rg_name = rg_part
                    if "/providers/" in parts[1]:
                        assignment_scope_type = "Resource"
                        res_name = parts[1].split("/")[-1]
                    else:
                        assignment_scope_type = "Resource Group"
                        res_name = f"All Resources in {rg_part}"
                else:
                    assignment_scope_type = "Subscription"
                    rg_name = "Subscription Scope"
                    res_name = f"All Resources in {sub.display_name}"

                # Security Review Criteria:
                # Flag broad subscription-level Contributor/Owner assignments, especially to individual users or direct assignments
                is_gap = False
                if assignment_scope_type == "Subscription":
                    # Subscription-wide Contributor/Owner assignment
                    if principal_type.lower() in ("user", "guest") or is_owner:
                        is_gap = True
                elif assignment_scope_type == "Resource Group" and principal_type.lower() == "user":
                    # Direct individual user assignment at resource group level (should use group RBAC)
                    is_gap = True

                if is_gap:
                    remediation = (
                        "Replace direct user assignment with Azure AD Security Group membership or migrate "
                        "to Privileged Identity Management (PIM) for just-in-time elevation."
                    )

                    findings.append(
                        FindingModel(
                            finding_id=f"sec14-{sub.subscription_id[:8]}-{a.get('name', '')[:10]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg_name,
                            resource_name=res_name,
                            resource_type="Microsoft.Authorization/roleAssignments",
                            resource_id=a.get("id", f"{scope}/providers/Microsoft.Authorization/roleAssignments/{a.get('name')}"),
                            region="global",
                            severity="High" if assignment_scope_type == "Subscription" and is_owner else "Medium",
                            status="Review Required",
                            current_configuration=f"{role_name} granted to {real_principal_name} at {assignment_scope_type} scope",
                            measured_value=f"Direct {principal_type} {role_name} Assignment",
                            recommended_configuration="Enforce RBAC group assignments or Azure AD PIM just-in-time role activation",
                            recommendation=f"Direct {principal_type} role assignment '{role_name}' granted to '{real_principal_name}' at {assignment_scope_type} scope requires review. {remediation}",
                            metric_period="Current RBAC state",
                            data_source="Microsoft.Authorization RoleAssignments API (2022-04-01)",
                            evidence={
                                "principal_name": real_principal_name,
                                "user_name": final_upn or final_dname or real_principal_name,
                                "principal_type": f"{principal_type} (Direct)",
                                "role_name": role_name,
                                "scope": "Subscription Scope" if assignment_scope_type == "Subscription" else (f"Resource Group ({rg_name})" if assignment_scope_type == "Resource Group" else f"Resource ({res_name})"),
                                "assignment_type": "Direct Assignment",
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
