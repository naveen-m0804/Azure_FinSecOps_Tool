import datetime
import time
import re
from typing import List, Dict, Any, Optional, Tuple
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.defender import DefenderAdapter
from app.utils.resource_ids import parse_azure_resource_id


def extract_first_detected_date(item: Dict[str, Any]) -> Tuple[Optional[str], Optional[float]]:
    """
    Extracts the official first detection/evaluation date from Defender assessment telemetry.
    Returns (date_str_YYYY_MM_DD, days_old).
    If no valid date is recorded, returns (None, None).
    """
    props = item.get("properties", {}) or {}
    status_obj = props.get("status", {}) or {}
    metadata = props.get("metadata", {}) or {}
    add_data = props.get("additionalData", {}) or {}
    sys_data = item.get("systemData", {}) or {}

    candidates = [
        status_obj.get("firstEvaluationDate"),
        props.get("firstEvaluationDate"),
        status_obj.get("timeCreated"),
        props.get("timeCreated"),
        sys_data.get("createdAt"),
        add_data.get("FirstEvaluationDate"),
        add_data.get("firstEvaluationDate"),
        metadata.get("firstEvaluationDate"),
    ]

    for cand in candidates:
        if not cand:
            continue
        cand_str = str(cand).strip()
        m = re.search(r'(\d{4}-\d{2}-\d{2})', cand_str)
        if m:
            date_str = m.group(1)
            try:
                dt = datetime.datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
                now_dt = datetime.datetime.now(datetime.timezone.utc)
                days_old = (now_dt - dt).total_seconds() / 86400.0
                return date_str, days_old
            except Exception:
                continue
    return None, None


def resolve_target_resource(item: Dict[str, Any], sub_id: str, sub_name: str) -> Dict[str, str]:
    """
    Resolves the true target resource, true resource group, and actual resource name
    by stripping trailing /providers/Microsoft.Security/assessments(/.*)? sub-paths.
    """
    props = item.get("properties", {}) or {}
    res_details = props.get("resourceDetails", {}) or {}

    raw_res_id = (
        res_details.get("Id")
        or res_details.get("id")
        or item.get("id", "")
    ).strip()

    target_id = re.sub(r"/providers/Microsoft\.Security/assessments(/.*)?$", "", raw_res_id, flags=re.IGNORECASE).rstrip("/")
    if not target_id or target_id.lower().endswith(f"/subscriptions/{sub_id.lower()}"):
        target_id = f"/subscriptions/{sub_id}"

    item_rg = item.get("resourceGroup") or res_details.get("ResourceGroupName")

    parsed = parse_azure_resource_id(target_id)
    parsed_rg = item_rg or parsed.get("resource_group")
    parsed_name = res_details.get("ResourceName") or parsed.get("resource_name")
    parsed_type = res_details.get("ResourceType") or parsed.get("resource_type")

    sub_id_clean = sub_id.lower().strip()
    target_clean = target_id.strip("/").lower()

    if target_clean in (f"subscriptions/{sub_id_clean}", sub_id_clean):
        resolved_rg = "Subscription Scope"
        resolved_name = sub_name
        resolved_type = "Microsoft.Resources/subscriptions"
        resolved_id = f"/subscriptions/{sub_id}"
    else:
        resolved_rg = parsed_rg or "Subscription Scope"
        resolved_name = parsed_name or target_id.split("/")[-1] or sub_name
        resolved_type = parsed_type or "Microsoft.Resources/resources"
        resolved_id = target_id

    return {
        "resource_group": resolved_rg,
        "resource_name": resolved_name,
        "resource_type": resolved_type,
        "resource_id": resolved_id,
    }


class NewSecurityRecommendationsAssessment(BaseAssessment):
    assessment_id = "new_recommendations"
    code = "SEC-02"
    category = "security"
    name = "New Security Recommendations"
    description = "Identify newly available or active recommendations from Microsoft Defender for Cloud detected within the last 30 days."
    purpose = "Detect recent security gaps and newly generated Defender security recommendations from current date to last 30 days."
    required_permissions = ["Microsoft.Security/assessments/read", "Security Reader"]
    required_data_sources = ["Defender for Cloud Assessments API (2021-06-01)"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        # Load Defender assessment metadata definitions for dynamic enrichment
        metadata_cache = await DefenderAdapter.get_assessment_metadata(context.client)

        for sub in context.subscriptions:
            resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id, max_items=1000)
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
                props = item.get("properties", {}) or {}
                status_obj = props.get("status", {}) or {}
                status_code = status_obj.get("code", "")

                # Only report unresolved security gaps: Unhealthy / Open recommendations
                if status_code.lower() not in ("unhealthy", "open", "actionrequired", "active"):
                    continue

                # STRICT LAST 30 DAYS FIRST DETECTED FILTER:
                # Only show recommendations from current date to last 30 days.
                # If date is missing, older than 30 days (> 30.0), or in the future (< -1.0), exclude.
                date_str, days_old = extract_first_detected_date(item)
                if date_str is None or days_old is None:
                    continue
                if days_old > 30.0 or days_old < -1.0:
                    continue

                item_key = (item.get("name") or "").lower()
                cached_meta = metadata_cache.get(item_key, {})
                metadata = props.get("metadata", {}) or cached_meta

                display_name = (
                    props.get("displayName")
                    or metadata.get("displayName")
                    or cached_meta.get("displayName")
                    or item.get("name", "Unknown Recommendation")
                )

                severity = (
                    metadata.get("severity")
                    or cached_meta.get("severity")
                    or props.get("severity")
                    or "Medium"
                )

                description = (
                    metadata.get("description")
                    or cached_meta.get("description")
                    or status_obj.get("description")
                    or "Security configuration gap identified by Defender for Cloud."
                )

                # Official Azure remediation guidance directly from Defender metadata
                remediation_raw = (
                    metadata.get("remediationDescription")
                    or cached_meta.get("remediationDescription")
                    or props.get("remediationDescription")
                    or metadata.get("remediationSteps")
                    or cached_meta.get("remediationSteps")
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
                sec_ctrl = (
                    metadata.get("securityControl")
                    or cached_meta.get("securityControl")
                    or (metadata.get("categories", ["General"])[0] if metadata.get("categories") else None)
                    or (cached_meta.get("categories", ["General"])[0] if cached_meta.get("categories") else "General")
                )

                raw_impact = (
                    metadata.get("securityScoreImpact")
                    or cached_meta.get("securityScoreImpact")
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

                # Accurate target resource resolution (strips assessment tails)
                res_info = resolve_target_resource(item, sub.subscription_id, sub.display_name)

                findings.append(
                    FindingModel(
                        finding_id=f"sec02-{sub.subscription_id[:8]}-{item.get('name', '')[:10]}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=res_info["resource_group"],
                        resource_name=res_info["resource_name"],
                        resource_type=res_info["resource_type"],
                        resource_id=res_info["resource_id"],
                        region="global",
                        severity=severity,
                        status="Unhealthy",
                        current_configuration=description[:150],
                        measured_value="Unhealthy",
                        recommended_configuration=remediation[:150] if remediation != "--" else "Apply remediation guidance from Defender for Cloud",
                        recommendation=remediation if remediation != "--" else f"Remediate Defender finding: {display_name}",
                        metric_period="Detected within last 30 days",
                        data_source="Defender for Cloud Assessments API",
                        evidence={
                            "recommendation_name": display_name,
                            "first_detected_date": date_str,
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

