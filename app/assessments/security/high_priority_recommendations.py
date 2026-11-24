import datetime
import time
import re
import logging
from typing import List, Dict, Any, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.defender import DefenderAdapter
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id

logger = logging.getLogger("azure_finsecops.assessments.high_priority_recommendations")

def resolve_target_resource(item: Dict[str, Any], sub_id: str, sub_name: str) -> Dict[str, str]:
    """
    Extracts the accurate target Azure resource details (Resource Group, Resource Name, Resource Type, Resource ID)
    from a Defender security assessment object, avoiding assessment tails and erroneous subscription scope fallbacks.
    """
    props = item.get("properties", {}) or {}
    res_details = props.get("resourceDetails", {}) or {}

    raw_res_id = (
        res_details.get("Id")
        or res_details.get("ResourceId")
        or res_details.get("id")
        or res_details.get("resourceId")
        or props.get("additionalData", {}).get("ResourceId")
        or item.get("id", "")
    )

    # Strip any trailing Microsoft.Security/assessments sub-resource path
    # e.g.: /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}/providers/Microsoft.Security/assessments/{guid}
    target_id = re.sub(r"/providers/Microsoft\.Security/assessments(/.*)?$", "", raw_res_id, flags=re.IGNORECASE).rstrip("/")
    if not target_id or target_id.lower().endswith(f"/subscriptions/{sub_id.lower()}"):
        target_id = f"/subscriptions/{sub_id}"

    # Top-level resource group from ARG or item
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

class HighPriorityRecommendationsAssessment(BaseAssessment):
    assessment_id = "high_priority_recommendations"
    code = "SEC-04"
    category = "security"
    name = "High Priority Recommendations"
    description = "Filter and report Microsoft Defender for Cloud recommendations with High severity matching the Azure Portal."
    purpose = "Direct remediation attention to High severity security vulnerabilities identified in Microsoft Defender for Cloud."
    required_permissions = ["Microsoft.Security/assessments/read", "Security Reader"]
    required_data_sources = ["Defender for Cloud Assessments API (2021-06-01) & Azure Resource Graph"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        # Fetch metadata cache for deep enrichment if properties.metadata is empty
        meta_cache: Dict[str, Dict[str, Any]] = {}
        try:
            meta_cache = await DefenderAdapter.get_assessment_metadata(context.client)
        except Exception:
            pass

        for sub in context.subscriptions:
            all_items: List[Dict[str, Any]] = []

            # 1. Primary: Direct query via Azure Resource Graph (matches Azure Portal Defender Recommendations blade)
            try:
                arg_items = await DefenderAdapter.get_high_priority_assessments_via_arg(context.client, sub.subscription_id)
                if arg_items:
                    all_items.extend(arg_items)
            except Exception as ex:
                logger.debug("ARG query for high priority recommendations in sub %s: %s", sub.subscription_id, ex)

            # 2. Secondary: Fallback to Defender for Cloud Assessments API
            if not all_items:
                resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id)
                if not resp.get("success"):
                    status_code = resp.get("status_code", 500)
                    if status_code in (401, 403):
                        errors.append(f"Subscription '{sub.display_name}': Permission Missing (Microsoft.Security/assessments/read)")
                    else:
                        errors.append(f"Subscription '{sub.display_name}': {resp.get('error', 'Error fetching assessments')}")
                else:
                    all_items.extend(resp.get("value", []))

            grouped_recommendations: Dict[str, Dict[str, Any]] = {}

            for item in all_items:
                props = item.get("properties", {}) or {}
                item_name = str(item.get("name") or "").strip()
                status_obj = props.get("status", {}) or {}
                status_code = str(status_obj.get("code") or props.get("status", {}).get("code") or "").strip().lower()

                # Filter out resolved, healthy, or non-applicable assessments (must be active gap)
                if status_code not in ("unhealthy", "open", "actionrequired", "active"):
                    continue

                # Extract metadata identifier (GUID)
                raw_meta_id = (
                    props.get("assessmentMetaDataId")
                    or props.get("assessmentMetadataId")
                    or props.get("metadataId")
                    or props.get("metadata", {}).get("assessmentMetadataId")
                    or ""
                )
                meta_id = str(raw_meta_id).split("/")[-1].strip().lower() if raw_meta_id else ""

                metadata = props.get("metadata", {}) or {}
                # If metadata is empty or missing severity, look up from official Defender metadata definitions
                if not metadata or not metadata.get("severity"):
                    cached_meta = (
                        meta_cache.get(meta_id)
                        or meta_cache.get(item_name.lower())
                        or meta_cache.get((props.get("displayName") or "").strip().lower())
                        or {}
                    )
                    if cached_meta:
                        metadata = {**cached_meta, **metadata}

                # Evaluate severity (check metadata, status, and properties)
                raw_severity = (
                    metadata.get("severity")
                    or status_obj.get("severity")
                    or props.get("severity")
                    or props.get("additionalData", {}).get("severity")
                    or ""
                )
                severity_str = str(raw_severity).strip().capitalize()

                # Strictly only report security gaps with High severity matching Defender for Cloud High category
                if severity_str != "High":
                    continue

                # Recommendation Name
                display_name = (
                    props.get("displayName")
                    or metadata.get("displayName")
                    or props.get("metadata", {}).get("displayName")
                    or item_name
                    or "High Priority Security Finding"
                ).strip()

                # Deep target resource resolution (strips assessment tails)
                target_res = resolve_target_resource(item, sub.subscription_id, sub.display_name)
                res_id = target_res["resource_id"]

                # Group by recommendation key (metadata GUID or distinct recommendation name)
                rec_key = meta_id or display_name.lower()

                if rec_key not in grouped_recommendations:
                    # Description
                    description = (
                        metadata.get("description")
                        or status_obj.get("description")
                        or props.get("description")
                        or f"High-priority security configuration gap identified by Defender for Cloud: {display_name}"
                    ).strip()

                    # Official Azure Remediation guidance
                    remediation_raw = (
                        metadata.get("remediationDescription")
                        or props.get("remediationDescription")
                        or metadata.get("remediationSteps")
                        or props.get("remediationSteps")
                        or ""
                    )
                    if isinstance(remediation_raw, list):
                        remediation = "\n".join(str(s) for s in remediation_raw if s).strip()
                    else:
                        remediation = str(remediation_raw).strip()
                    if not remediation:
                        remediation = f"Remediate Defender recommendation '{display_name}' according to official Microsoft Azure guidance."

                    # Related Security Control
                    sec_ctrl = (
                        metadata.get("securityControl")
                        or (metadata.get("categories")[0] if metadata.get("categories") else None)
                        or props.get("category")
                        or "Remediate security configurations"
                    ).strip()

                    # Potential Secure Score Increase
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
                        score_impact = 3.0

                    grouped_recommendations[rec_key] = {
                        "metadata_id": meta_id or item_name,
                        "display_name": display_name,
                        "description": description,
                        "remediation": remediation,
                        "security_control": sec_ctrl,
                        "score_impact": score_impact,
                        "affected_resources": [],
                        "seen_resource_ids": set(),
                    }

                rec_entry = grouped_recommendations[rec_key]
                if res_id not in rec_entry["seen_resource_ids"]:
                    rec_entry["seen_resource_ids"].add(res_id)
                    rec_entry["affected_resources"].append(target_res)

            # Build high-priority findings grouped by recommendation (matching Defender for Cloud High category)
            for rec_key, rec in grouped_recommendations.items():
                affected = rec["affected_resources"]
                unhealthy_count = len(affected)
                if unhealthy_count == 0:
                    continue

                resources_evaluated += unhealthy_count

                # Formulate Resource Name display
                if unhealthy_count == 1:
                    res_name = affected[0]["resource_name"]
                elif unhealthy_count == 2:
                    res_name = f"{affected[0]['resource_name']}, {affected[1]['resource_name']}"
                else:
                    res_name = f"{unhealthy_count} Resources ({affected[0]['resource_name']}, +{unhealthy_count - 1} more)"

                # Formulate Resource Group display
                unique_rgs = list(dict.fromkeys(r["resource_group"] for r in affected if r.get("resource_group")))
                if not unique_rgs or unique_rgs == ["Subscription Scope"]:
                    res_group = "Subscription Scope"
                elif len(unique_rgs) == 1:
                    res_group = unique_rgs[0]
                elif len(unique_rgs) == 2:
                    res_group = f"{unique_rgs[0]}, {unique_rgs[1]}"
                else:
                    res_group = f"{len(unique_rgs)} Resource Groups"

                # Formulate Resource Type display
                unique_types = list(dict.fromkeys(r["resource_type"] for r in affected if r.get("resource_type")))
                if not unique_types:
                    res_type = "Microsoft.Security/assessments"
                elif len(unique_types) == 1:
                    res_type = unique_types[0]
                else:
                    res_type = "Multiple Services"

                # Formulate Resource ID
                res_id = (
                    affected[0]["resource_id"]
                    if unhealthy_count == 1
                    else f"/subscriptions/{sub.subscription_id}/providers/Microsoft.Security/assessments/{rec['metadata_id']}"
                )

                pot_score_str = f"+{rec['score_impact']:.1f}%"
                clean_f_id = f"sec04-{sub.subscription_id[:8]}-{rec['metadata_id'][:12].replace('/', '-')}"

                findings.append(
                    FindingModel(
                        finding_id=clean_f_id,
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=res_group,
                        resource_name=res_name,
                        resource_type=res_type,
                        resource_id=res_id,
                        region="global",
                        severity="High",
                        status="Unhealthy",
                        current_configuration=rec["description"][:150],
                        measured_value=f"High Severity Finding ({unhealthy_count} Unhealthy Resource{'s' if unhealthy_count > 1 else ''})",
                        recommended_configuration=rec["remediation"][:150],
                        recommendation=rec["remediation"],
                        metric_period="Active assessment",
                        data_source="Defender for Cloud Assessments API",
                        evidence={
                            "recommendation_name": rec["display_name"],
                            "description": rec["description"],
                            "remediation": rec["remediation"],
                            "security_control": rec["security_control"],
                            "potential_score_increase": pot_score_str,
                            "unhealthy_resource_count": unhealthy_count,
                            "affected_resources": [r["resource_name"] for r in affected],
                            "affected_resource_ids": [r["resource_id"] for r in affected],
                        },
                        security_score_impact=float(rec["score_impact"]),
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
