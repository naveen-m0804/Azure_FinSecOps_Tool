import datetime
import time
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.defender import DefenderAdapter
from app.utils.resource_ids import parse_azure_resource_id

class NewSecurityRecommendationsAssessment(BaseAssessment):
    assessment_id = "new_recommendations"
    code = "SEC-02"
    category = "security"
    name = "New Security Recommendations"
    description = "Identify newly available or active recommendations from Microsoft Defender for Cloud."
    purpose = "Detect recent security gaps and newly generated Defender security recommendations."
    required_permissions = ["Microsoft.Security/assessments/read", "Security Reader"]
    required_data_sources = ["Defender for Cloud Assessments API (2021-06-01)"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        for sub in context.subscriptions:
            resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id)
            if not resp.get("success"):
                status_code = resp.get("status_code", 500)
                if status_code in (401, 403):
                    errors.append(f"Subscription '{sub.display_name}': Permission Missing (Microsoft.Security/assessments/read)")
                else:
                    errors.append(f"Subscription '{sub.display_name}': {resp.get('error', 'Error fetching assessments')}")
                continue

            items = resp.get("value", [])
            for item in items:
                resources_evaluated += 1
                props = item.get("properties", {})
                status_obj = props.get("status", {})
                status_code = status_obj.get("code", "")

                # Only report security gaps: Unhealthy recommendations
                if status_code.lower() == "unhealthy":
                    metadata = props.get("metadata", {})
                    display_name = props.get("displayName") or metadata.get("displayName") or item.get("name", "Unknown Recommendation")
                    res_details = props.get("resourceDetails", {})
                    raw_res_id = (
                        res_details.get("Id")
                        or res_details.get("id")
                        or item.get("id", "")
                    )
                    parsed = parse_azure_resource_id(raw_res_id)
                    severity = metadata.get("severity", "Medium")
                    first_eval = status_obj.get("firstEvaluationDate")
                    first_detected = first_eval[:10] if first_eval else "--"
                    description = metadata.get("description") or status_obj.get("description") or "Security configuration gap identified by Defender for Cloud."
                    
                    # Official Azure remediation guidance directly from Defender metadata
                    remediation_raw = (
                        metadata.get("remediationDescription")
                        or props.get("remediationDescription")
                        or metadata.get("remediationSteps")
                        or props.get("remediationSteps")
                        or ""
                    )
                    if isinstance(remediation_raw, list):
                        remediation = "\n".join(str(s) for s in remediation_raw if s)
                    else:
                        remediation = str(remediation_raw).strip()
                    if not remediation or remediation == "--":
                        remediation = f"Remediate Defender recommendation '{display_name}' according to official Microsoft Azure guidance."
                    
                    # Security control and potential score impact
                    sec_ctrl = metadata.get("securityControl") or (metadata.get("categories", ["General"])[0] if metadata.get("categories") else "General")
                    
                    # Determine Potential Score Increase
                    raw_impact = (
                        metadata.get("securityScoreImpact")
                        or metadata.get("scoreImpact")
                        or metadata.get("weight")
                        or props.get("weight")
                        or metadata.get("maxScore")
                    )
                    score_impact = None
                    if raw_impact is not None:
                        try:
                            score_impact = float(raw_impact)
                        except (ValueError, TypeError):
                            score_impact = None
                    if score_impact is None or score_impact <= 0:
                        sev_l = severity.lower()
                        if sev_l in ("critical", "critical risk"):
                            score_impact = 4.0
                        elif sev_l == "high":
                            score_impact = 3.0
                        elif sev_l == "medium":
                            score_impact = 2.0
                        else:
                            score_impact = 1.0
                    
                    pot_score_str = f"+{score_impact:.1f}%"

                    # Determine clean, user-friendly resource name and group
                    sub_id_clean = sub.subscription_id.lower().strip()
                    parsed_res_name = parsed.get("resource_name") or ""
                    parsed_rg = parsed.get("resource_group")
                    
                    is_sub_scope = False
                    if not raw_res_id or raw_res_id.strip("/").lower() in (f"subscriptions/{sub_id_clean}", sub_id_clean):
                        is_sub_scope = True
                    elif parsed_res_name.lower() in (sub_id_clean, item.get("name", "").lower()):
                        if not parsed_rg or parsed_rg.lower() in ("unknown", "subscription scope"):
                            is_sub_scope = True
                    elif not parsed_rg or parsed_rg == "Unknown":
                        is_sub_scope = True

                    if is_sub_scope:
                        resolved_rg = "Subscription Scope"
                        resolved_res_name = sub.display_name
                        resolved_res_type = "Microsoft.Resources/subscriptions"
                        resolved_res_id = f"/subscriptions/{sub.subscription_id}"
                    else:
                        resolved_rg = res_details.get("ResourceGroupName") or parsed_rg or "Subscription Scope"
                        resolved_res_name = res_details.get("ResourceName") or parsed_res_name or sub.display_name
                        resolved_res_type = res_details.get("ResourceType") or parsed.get("resource_type") or "Microsoft.Security/assessments"
                        resolved_res_id = raw_res_id

                    findings.append(
                        FindingModel(
                            finding_id=f"sec02-{sub.subscription_id[:8]}-{item.get('name', '')[:10]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=resolved_rg,
                            resource_name=resolved_res_name,
                            resource_type=resolved_res_type,
                            resource_id=resolved_res_id,
                            region="global",
                            severity=severity,
                            status="Unhealthy",
                            current_configuration=description[:150],
                            measured_value="Unhealthy",
                            recommended_configuration=remediation[:150] if remediation != "--" else "Apply remediation guidance from Defender for Cloud",
                            recommendation=remediation if remediation != "--" else f"Remediate Defender finding: {display_name}",
                            metric_period="Active assessment",
                            data_source="Defender for Cloud Assessments API",
                            evidence={
                                "recommendation_name": display_name,
                                "first_detected_date": first_detected,
                                "description": description,
                                "remediation": remediation,
                                "security_control": sec_ctrl,
                                "potential_score_increase": pot_score_str,
                                "status_code": status_code,
                            },
                            security_score_impact=float(score_impact),
                            collected_at=now_str
                        )
                    )

        if errors and not findings:
            if any("Permission" in e for e in errors):
                status = AssessmentStatus.PERMISSION_MISSING
            else:
                status = AssessmentStatus.FAILED
        elif errors and findings:
            status = AssessmentStatus.COMPLETED_WITH_WARNINGS
        elif findings:
            status = AssessmentStatus.COMPLETED
        else:
            status = AssessmentStatus.NO_FINDINGS

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
