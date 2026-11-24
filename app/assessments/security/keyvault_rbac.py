import datetime
import time
import logging
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.keyvault import KeyVaultAdapter
from app.azure.defender import DefenderAdapter
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id

logger = logging.getLogger("azure_finsecops.assessments.keyvault_rbac")

class KeyVaultRbacAssessment(BaseAssessment):
    assessment_id = "keyvault_rbac"
    code = "SEC-13"
    category = "security"
    name = "Key Vault RBAC Migration"
    description = "Audit Azure Key Vault authorization models to identify vaults using legacy access policies instead of Azure role-based access control (Azure RBAC)."
    purpose = "Promote centralized, role-based identity governance across secrets, keys, and certificates, eliminating unmanaged direct access policies."
    required_permissions = [
        "Microsoft.KeyVault/vaults/read",
        "Microsoft.Security/assessments/read",
        "Reader"
    ]
    required_data_sources = ["Microsoft.KeyVault Vaults API & Microsoft Defender for Cloud Recommendations"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        seen_vault_ids = set()

        for sub in context.subscriptions:
            # 1. Discover Key Vaults via KeyVaultAdapter (with automatic detail enrichment)
            vaults = await KeyVaultAdapter.get_key_vaults(context.client, sub.subscription_id)

            # 2. Query Defender recommendations for Key Vault RBAC to ensure 100% portal alignment
            defender_kv_recommendations: Dict[str, Dict[str, Any]] = {}
            try:
                def_resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id, max_items=300)
                if def_resp.get("success"):
                    for ass in def_resp.get("value", []):
                        props = ass.get("properties", {}) or {}
                        status_code = str(props.get("status", {}).get("code", "")).lower()
                        if status_code not in ("unhealthy", "open"):
                            continue

                        meta = props.get("metadata", {}) or {}
                        disp = (meta.get("displayName") or props.get("displayName") or "").lower()

                        if "key vault" in disp and ("rbac" in disp or "role-based access control" in disp or "access policy" in disp):
                            target_id = props.get("resourceDetails", {}).get("Id") or props.get("resourceDetails", {}).get("id") or ""
                            if target_id:
                                defender_kv_recommendations[normalize_resource_id(target_id)] = {
                                    "title": meta.get("displayName") or props.get("displayName"),
                                    "remediation": meta.get("remediationDescription") or meta.get("description")
                                }
            except Exception as ex:
                logger.debug("Defender Key Vault RBAC scan in sub %s: %s", sub.subscription_id, ex)

            # Evaluate each vault
            for v in vaults:
                resources_evaluated += 1
                v_name = v.get("name", "Unknown Vault")
                v_id = v.get("id", "")
                norm_v_id = normalize_resource_id(v_id)
                parsed = parse_azure_resource_id(v_id)
                rg_name = parsed.get("resource_group") or "Unknown"
                region = v.get("location", "global")
                props = v.get("properties", {}) or {}

                # Check Azure RBAC authorization model
                is_rbac = bool(props.get("enableRbacAuthorization", False))
                access_policies = props.get("accessPolicies", []) or []
                policy_count = len(access_policies)

                # Collect permission summary from access policies
                key_perms = set()
                secret_perms = set()
                cert_perms = set()
                for p in access_policies:
                    perms = p.get("permissions", {}) or {}
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
                perm_summary = "; ".join(perm_parts) if perm_parts else f"{policy_count} Legacy Access Policies configured"

                # Query live IAM role assignments directly on this Key Vault scope
                role_assignment_count = 0
                assigned_roles_str = "None (Using Access Policies)"
                try:
                    iam_url = f"https://management.azure.com{v_id}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"
                    iam_resp = await context.client.execute_request("GET", iam_url)
                    if iam_resp.status_code == 200:
                        iam_items = iam_resp.json().get("value", [])
                        role_assignment_count = len(iam_items)
                        roles_seen = []
                        for ra in iam_items:
                            r_props = ra.get("properties", {}) or {}
                            exp_props = r_props.get("expandedProperties") or {}
                            role_name = exp_props.get("roleDefinitionName") or r_props.get("roleDefinitionName")
                            if not role_name:
                                rdef_id = r_props.get("roleDefinitionId", "")
                                role_name = rdef_id.split("/")[-1][:8] if rdef_id else "Assigned Role"
                            if role_name not in roles_seen:
                                roles_seen.append(role_name)
                        if roles_seen:
                            assigned_roles_str = ", ".join(roles_seen[:3])
                except Exception as ex:
                    logger.debug("IAM role assignments check failed for Key Vault %s: %s", v_name, ex)

                # Flag vaults where Azure RBAC is disabled, legacy access policies exist, or Defender flags them
                has_defender_flag = norm_v_id in defender_kv_recommendations
                is_access_policy = (not is_rbac) or (policy_count > 0) or has_defender_flag
                if is_access_policy:
                    seen_vault_ids.add(norm_v_id)
                    remediation = (
                        "Migrate Key Vault authorization model to Azure role-based access control (Azure RBAC) "
                        "and assign built-in roles such as 'Key Vault Secrets Officer' or 'Key Vault Reader'."
                    )

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
                            current_configuration=f"Authorization Model: Vault Access Policies ({policy_count} policies configured)",
                            measured_value=f"{policy_count} access policies configured; RBAC disabled",
                            recommended_configuration="Enable Azure RBAC authorization model (enableRbacAuthorization: true)",
                            recommendation=f"Key Vault '{v_name}' uses legacy vault access policies instead of Azure RBAC. {remediation}",
                            metric_period="Current configuration",
                            data_source="Microsoft.KeyVault Vaults API & Microsoft Defender for Cloud",
                            evidence={
                                "enableRbacAuthorization": is_rbac,
                                "policy_count": policy_count,
                                "role_assignment_count": role_assignment_count,
                                "permissions": perm_summary,
                                "assigned_roles": assigned_roles_str,
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
