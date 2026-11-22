import datetime
import time
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.defender import DefenderAdapter
from app.utils.resource_ids import parse_azure_resource_id

class AttackPathsAssessment(BaseAssessment):
    assessment_id = "attack_paths"
    code = "SEC-07"
    category = "security"
    name = "Attack Paths"
    description = "Identify exposed lateral movement attack paths and target high-value assets from Defender CSPM."
    purpose = "Discover multi-hop exploitation vectors that attackers can traverse to compromise critical resources."
    required_permissions = ["Microsoft.Security/attackPaths/read", "Security Reader"]
    required_data_sources = ["Defender CSPM Attack Paths API (2023-05-01)"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        cspm_unavailable = False

        for sub in context.subscriptions:
            resp = await DefenderAdapter.get_attack_paths(context.client, sub.subscription_id)
            paths = resp.get("value", []) if resp.get("success") else []

            # If attack paths endpoint is empty or unavailable, inspect Defender assessments for lateral movement & attack path recommendations
            if not paths:
                assessments_resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id)
                if assessments_resp.get("success"):
                    for ass in assessments_resp.get("value", []):
                        props = ass.get("properties", {})
                        meta = props.get("metadata", {})
                        title = meta.get("displayName") or props.get("displayName", "")
                        cats = meta.get("categories", [])
                        cat_str = " ".join(cats).lower() if isinstance(cats, list) else str(cats).lower()
                        status_code = props.get("status", {}).get("code", "")

                        if status_code.lower() in ("unhealthy", "open") and (
                            "attack path" in title.lower() or "lateral" in title.lower() or "attackpath" in cat_str or "lateralmovement" in cat_str
                        ):
                            target_id = props.get("resourceDetails", {}).get("Id") or ass.get("id", "")
                            parsed_target = parse_azure_resource_id(target_id)
                            rg_name = parsed_target.get("resource_group") or "DefenderCSPM"
                            target_name = parsed_target.get("resource_name") or target_id.split("/")[-1] or "High-Value Asset"
                            res_type = parsed_target.get("resource_type") or "Microsoft.Security/assessments"
                            remediation_desc = meta.get("remediationDescription") or meta.get("description") or "Remediate lateral movement risk."

                            findings.append(
                                FindingModel(
                                    finding_id=f"sec07-{sub.subscription_id[:8]}-{ass.get('name', '')[:10]}",
                                    assessment_id=self.assessment_id,
                                    category=self.category,
                                    subscription_id=sub.subscription_id,
                                    subscription_name=sub.display_name,
                                    resource_group=rg_name,
                                    resource_name=title,
                                    resource_type=res_type,
                                    resource_id=ass.get("id", target_id),
                                    region="global",
                                    severity=meta.get("severity", "High").capitalize(),
                                    status="Active Attack Path Risk",
                                    current_configuration=f"Lateral movement vector detected: '{title}'",
                                    measured_value=f"Risk Level: {meta.get('severity', 'High')}",
                                    recommended_configuration="Break attack path chain by remediating entry-point vulnerabilities",
                                    recommendation=remediation_desc,
                                    metric_period="Active CSPM analysis",
                                    data_source="Microsoft Defender for Cloud",
                                    evidence={
                                        "attack_path_name": title,
                                        "source_resource": "Public Endpoint / Perimeter",
                                        "target_resource": target_name,
                                        "affected_resource": target_name,
                                        "risk_level": meta.get("severity", "High"),
                                        "attack_techniques": "Lateral Tool Transfer, Exploitation of Remote Services",
                                        "recommendation": remediation_desc
                                    },
                                    collected_at=now_str
                                )
                            )

            for path in paths:
                resources_evaluated += 1
                props = path.get("properties", {})
                display_name = props.get("displayName") or path.get("name", "Attack Path")
                target_id = props.get("targetResourceId") or ""
                parsed_target = parse_azure_resource_id(target_id) if target_id else {}
                rg_name = parsed_target.get("resource_group") or "DefenderCSPM"
                target_name = parsed_target.get("resource_name") or target_id.split("/")[-1] or "High-Value Asset"
                res_type = parsed_target.get("resource_type") or "Microsoft.Security/attackPaths"
                
                # Source, target, techniques, risk
                entry_point = props.get("entryPoint") or "Internet / Public Endpoint"
                risk_level = props.get("riskLevel") or props.get("severity") or "Critical"
                techniques = props.get("techniques")
                tech_str = ", ".join(techniques) if isinstance(techniques, list) and techniques else (str(techniques) if techniques else "Exploit Public-Facing Application (T1190), Lateral Tool Transfer (T1570)")
                recs = props.get("recommendations")
                rec_str = recs[0] if (isinstance(recs, list) and recs) else "Break attack path chain by remediating entry-point vulnerabilities"

                findings.append(
                    FindingModel(
                        finding_id=f"sec07-{sub.subscription_id[:8]}-{path.get('name', '')[:10]}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=rg_name,
                        resource_name=display_name,
                        resource_type=res_type,
                        resource_id=path.get("id") or target_id,
                        region=path.get("location", "global"),
                        severity=risk_level.capitalize() if risk_level else "Critical",
                        status="Active Attack Path",
                        current_configuration=f"Exposed attack path to target '{target_name}'",
                        measured_value=f"Risk Level: {risk_level}",
                        recommended_configuration=rec_str,
                        recommendation=f"Remediate attack path '{display_name}' targeting asset '{target_name}'. {rec_str}",
                        metric_period="Active CSPM analysis",
                        data_source="Defender CSPM Attack Paths API (2023-05-01)",
                        evidence={
                            "attack_path_name": display_name,
                            "source_resource": entry_point,
                            "target_resource": target_name,
                            "affected_resource": target_name,
                            "risk_level": risk_level,
                            "attack_techniques": tech_str,
                            "recommendation": rec_str
                        },
                        collected_at=now_str
                    )
                )

        if findings:
            status = AssessmentStatus.COMPLETED
        elif errors and any("Permission" in e for e in errors):
            status = AssessmentStatus.PERMISSION_MISSING
        elif errors and not findings:
            status = AssessmentStatus.FAILED
        else:
            status = AssessmentStatus.NO_FINDINGS

        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(resources_evaluated, len(context.subscriptions)),
            findings_count=len(findings),
            findings=findings,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
