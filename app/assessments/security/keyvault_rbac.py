import datetime
import time
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.keyvault import KeyVaultAdapter
from app.utils.resource_ids import parse_azure_resource_id

class KeyVaultRbacAssessment(BaseAssessment):
    assessment_id = "keyvault_rbac"
    code = "SEC-13"
    category = "security"
    name = "Key Vault RBAC Migration"
    description = "Audit Azure Key Vault authorization models to identify vaults using legacy access policies instead of Azure RBAC."
    purpose = "Promote centralized, role-based identity management across secret, key, and certificate stores."
    required_permissions = ["Microsoft.KeyVault/vaults/read", "Reader"]
    required_data_sources = ["Microsoft.KeyVault Vaults API (2023-07-01)"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        for sub in context.subscriptions:
            vaults = await KeyVaultAdapter.get_key_vaults(context.client, sub.subscription_id)
            for v in vaults:
                resources_evaluated += 1
                v_name = v.get("name", "Unknown Vault")
                v_id = v.get("id", "")
                parsed = parse_azure_resource_id(v_id)
                rg_name = parsed.get("resource_group") or "Unknown"
                region = v.get("location", "global")
                props = v.get("properties", {})
                
                # Check Azure RBAC authorization model
                is_rbac = bool(props.get("enableRbacAuthorization", False))
                access_policies = props.get("accessPolicies", [])
                policy_count = len(access_policies)

                # Collect permission summary from access policies
                key_perms = set()
                secret_perms = set()
                cert_perms = set()
                for p in access_policies:
                    perms = p.get("permissions", {})
                    key_perms.update(perms.get("keys", []))
                    secret_perms.update(perms.get("secrets", []))
                    cert_perms.update(perms.get("certificates", []))

                perm_parts = []
                if key_perms:
                    perm_parts.append(f"Keys: {', '.join(sorted(key_perms)[:3])}")
                if secret_perms:
                    perm_parts.append(f"Secrets: {', '.join(sorted(secret_perms)[:3])}")
                if cert_perms:
                    perm_parts.append(f"Certs: {', '.join(sorted(cert_perms)[:3])}")
                perm_summary = "; ".join(perm_parts) if perm_parts else "Legacy Access Policies configured"

                # Only report security gaps: Vaults NOT using Azure RBAC
                if not is_rbac:
                    remediation = "Migrate authorization model to Azure role-based access control (Azure RBAC) and assign granular Key Vault built-in roles."

                    findings.append(
                        FindingModel(
                            finding_id=f"sec13-{sub.subscription_id[:8]}-{v_name[:12]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg_name,
                            resource_name=v_name,
                            resource_type="Microsoft.KeyVault/vaults",
                            resource_id=v_id,
                            region=region,
                            severity="Medium",
                            status="Access Policies Active",
                            current_configuration=f"Authorization Model: Vault Access Policies ({policy_count} policies active)",
                            measured_value=f"{policy_count} access policies configured; RBAC disabled",
                            recommended_configuration="Enable Azure RBAC authorization model (enableRbacAuthorization: true)",
                            recommendation=f"Key Vault '{v_name}' uses legacy vault access policies instead of Azure RBAC. {remediation}",
                            metric_period="Current configuration",
                            data_source="Microsoft.KeyVault Vaults API (2023-07-01)",
                            evidence={
                                "enableRbacAuthorization": False,
                                "policy_count": policy_count,
                                "role_assignment_count": 0,
                                "permissions": perm_summary,
                                "assigned_roles": "None (Using Access Policies)",
                                "security_control": "Migrate Key Vault to Azure RBAC",
                                "potential_score_increase": "+4.0%",
                            },
                            security_score_impact=4.0,
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
