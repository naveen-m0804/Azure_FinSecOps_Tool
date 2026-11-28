import datetime
import json
import time
import re
from typing import List, Dict, Any, Optional, Tuple
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.defender import DefenderAdapter, clean_html_text
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
        or res_details.get("ResourceId")
        or res_details.get("id")
        or res_details.get("resourceId")
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


def _parse_additional_software_fields(add_data: Dict[str, Any], display_name: str) -> Dict[str, str]:
    """Extracts software/patch metadata from Defender additionalData when present."""
    software_name = str(add_data.get("SoftwareName") or add_data.get("softwareName") or "").strip()
    if not software_name and display_name.lower().startswith("update "):
        software_name = display_name[7:].strip()

    publisher = str(add_data.get("SoftwareVendor") or add_data.get("vendor") or "--").strip() or "--"

    installed_ver = "--"
    raw_detected = add_data.get("DetectedSoftwareVersions") or add_data.get("version")
    if isinstance(raw_detected, str) and raw_detected.strip().startswith("["):
        try:
            parsed_vers = json.loads(raw_detected)
            if isinstance(parsed_vers, list) and parsed_vers:
                installed_ver = ", ".join(str(v) for v in parsed_vers if v)
        except Exception:
            installed_ver = raw_detected
    elif isinstance(raw_detected, list) and raw_detected:
        installed_ver = ", ".join(str(v) for v in raw_detected if v)
    elif raw_detected:
        installed_ver = str(raw_detected).strip()

    fixed_ver = str(add_data.get("FixedVersion") or add_data.get("fixedVersion") or "").strip()
    if not fixed_ver and add_data.get("Kbid"):
        fixed_ver = f"KB{add_data.get('Kbid')}"

    cve_str = "--"
    raw_cves = add_data.get("CvesDetails")
    if isinstance(raw_cves, str) and raw_cves.strip().startswith("["):
        try:
            cve_items = json.loads(raw_cves)
            seen_cves = []
            for c in cve_items:
                cid = c.get("CveId")
                if cid and cid not in seen_cves:
                    seen_cves.append(cid)
                if not fixed_ver and c.get("FixedVersion"):
                    fixed_ver = str(c.get("FixedVersion")).strip()
            if seen_cves:
                cve_str = ", ".join(seen_cves[:5]) + (f" (+{len(seen_cves) - 5} more)" if len(seen_cves) > 5 else "")
        except Exception:
            pass

    return {
        "software_name": software_name or "--",
        "publisher": publisher,
        "installed_version": installed_ver or "--",
        "recommended_version": fixed_ver or "--",
        "cve": cve_str,
    }


class NewSecurityRecommendationsAssessment(BaseAssessment):
    assessment_id = "new_recommendations"
    code = "SEC-02"
    category = "security"
    name = "New Security Recommendations"
    description = "Identify newly available or active recommendations from Microsoft Defender for Cloud detected within the last 30 days."
    purpose = "Detect recent security gaps and newly generated Defender security recommendations from current date to last 30 days."
    required_permissions = ["Microsoft.Security/assessments/read", "Security Reader"]
    required_data_sources = ["Defender for Cloud Assessments API (2021-06-01) & Azure Resource Graph"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        metadata_cache = await DefenderAdapter.get_assessment_metadata(context.client)
        control_map = await DefenderAdapter.get_security_control_map(context.client)

        for sub in context.subscriptions:
            items: List[Dict[str, Any]] = []
            try:
                items = await DefenderAdapter.get_security_assessments_via_arg(
                    context.client, sub.subscription_id, unhealthy_only=True
                )
            except Exception:
                items = []

            if not items:
                resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id, max_items=1000)
                if not resp.get("success"):
                    status_code = resp.get("status_code", 500)
                    if status_code in (401, 403):
                        errors.append(f"Subscription '{sub.display_name}': Permission Missing (Microsoft.Security/assessments/read)")
                    else:
                        errors.append(f"Subscription '{sub.display_name}': {resp.get('error', 'Error fetching assessments')}")
                    continue
                items = resp.get("value", [])

            seen_keys = set()
            for item in items:
                resources_evaluated += 1
                props = item.get("properties", {}) or {}
                status_obj = props.get("status", {}) or {}
                status_code = str(status_obj.get("code") or "").strip()

                # Only report unresolved security gaps: Unhealthy / Open recommendations
                if status_code.lower() not in ("unhealthy", "open", "actionrequired", "active"):
                    continue

                # STRICT LAST 30 DAYS FIRST DETECTED FILTER:
                date_str, days_old = extract_first_detected_date(item)
                if date_str is None or days_old is None:
                    continue
                if days_old > 30.0 or days_old < -1.0:
                    continue

                item_key = (item.get("name") or "").strip().lower()
                raw_meta_id = (
                    props.get("assessmentMetaDataId")
                    or props.get("assessmentMetadataId")
                    or props.get("metadataId")
                    or (props.get("metadata", {}) or {}).get("assessmentMetadataId")
                    or item_key
                )
                meta_id = str(raw_meta_id).split("/")[-1].strip().lower()

                cached_meta = metadata_cache.get(meta_id) or metadata_cache.get(item_key) or {}
                metadata = props.get("metadata", {}) or cached_meta

                display_name = (
                    props.get("displayName")
                    or metadata.get("displayName")
                    or cached_meta.get("displayName")
                    or item.get("name", "Unknown Recommendation")
                ).strip()

                severity = str(
                    metadata.get("severity")
                    or cached_meta.get("severity")
                    or status_obj.get("severity")
                    or props.get("severity")
                    or "Medium"
                ).strip().capitalize()

                raw_desc = (
                    metadata.get("description")
                    or cached_meta.get("description")
                    or status_obj.get("description")
                    or "Security configuration gap identified by Defender for Cloud."
                )
                description = clean_html_text(raw_desc) or "Security configuration gap identified by Defender for Cloud."

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
                    remediation = clean_html_text("\n".join(str(s) for s in remediation_raw if s))
                else:
                    remediation = clean_html_text(remediation_raw)
                if not remediation or remediation == "--":
                    remediation = f"Remediate Defender recommendation '{display_name}' according to official Microsoft Azure guidance."

                # Official Security Control from Defender secureScoreControlDefinitions
                rec_cat = metadata.get("recommendationCategory") or cached_meta.get("recommendationCategory")
                sec_ctrl = (
                    control_map.get(meta_id)
                    or control_map.get(item_key)
                    or metadata.get("securityControl")
                    or cached_meta.get("securityControl")
                    or (re.sub(r"(?<!^)([A-Z])", r" \1", str(rec_cat)) if rec_cat else None)
                    or (metadata.get("categories", [None])[0] if metadata.get("categories") else None)
                    or (cached_meta.get("categories", [None])[0] if cached_meta.get("categories") else None)
                    or "--"
                )

                res_info = resolve_target_resource(item, sub.subscription_id, sub.display_name)
                dedup_key = (res_info["resource_id"].lower(), item_key, display_name.lower())
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                add_data = props.get("additionalData", {}) or {}
                sw_info = _parse_additional_software_fields(add_data, display_name)

                findings.append(
                    FindingModel(
                        finding_id=f"sec02-{sub.subscription_id[:8]}-{item.get('name', '')[:10]}-{len(findings)}",
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
                        recommended_configuration=remediation[:150],
                        recommendation=remediation,
                        metric_period="Detected within last 30 days",
                        data_source="Defender for Cloud Assessments API",
                        evidence={
                            "recommendation_name": display_name,
                            "first_detected_date": date_str,
                            "description": description,
                            "remediation": remediation,
                            "security_control": sec_ctrl,
                            "status_code": status_code,
                            **sw_info,
                        },
                        security_score_impact=None,
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

        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(resources_evaluated, len(context.subscriptions)),
            findings_count=len(findings),
            findings=findings,
            errors=errors,
            security_score_improvement=None,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
