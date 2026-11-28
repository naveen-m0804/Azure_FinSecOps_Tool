import datetime
import time
import logging
import re
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.defender import DefenderAdapter, clean_html_text
from app.azure.compute import ComputeAdapter
from app.assessments.security.new_recommendations import (
    extract_first_detected_date,
    resolve_target_resource,
    _parse_additional_software_fields,
)
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id

logger = logging.getLogger("azure_finsecops.assessments.software_upgrades")


class SoftwareUpgradesAssessment(BaseAssessment):
    assessment_id = "software_upgrades"
    code = "SEC-10"
    category = "security"
    name = "Software Version Upgrades"
    description = "Identify outdated installed software, libraries, and applications from Defender recommendations starting with 'Update' and VM vulnerability findings."
    purpose = "Mitigate known CVEs and exploitable vulnerabilities in installed third-party software packages and system libraries."
    required_permissions = [
        "Microsoft.Security/assessments/read",
        "Microsoft.Security/assessments/subAssessments/read",
        "Security Reader"
    ]
    required_data_sources = ["Defender for Cloud Assessments API & Azure Resource Graph"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        metadata_cache = await DefenderAdapter.get_assessment_metadata(context.client)
        control_map = await DefenderAdapter.get_security_control_map(context.client)

        for sub in context.subscriptions:
            # Build VM region lookup so resources show their real Azure region
            vm_regions: Dict[str, str] = {}
            try:
                vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id, expand_instance_view=False)
                for vm in vms:
                    vm_id = vm.get("id")
                    if vm_id:
                        vm_regions[normalize_resource_id(vm_id)] = vm.get("location", "global")
            except Exception:
                pass

            seen_keys = set()

            # 1. Primary: Defender recommendations starting with 'Update' from last 30 days (matching New Security Recommendations)
            items: List[Dict[str, Any]] = []
            try:
                items = await DefenderAdapter.get_security_assessments_via_arg(
                    context.client, sub.subscription_id, unhealthy_only=True
                )
            except Exception as ex:
                logger.debug("ARG assessments query in sub %s: %s", sub.subscription_id, ex)

            if not items:
                try:
                    ass_resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id, max_items=1000)
                    if ass_resp.get("success"):
                        items = ass_resp.get("value", [])
                except Exception as ex:
                    logger.debug("Defender assessments query in sub %s: %s", sub.subscription_id, ex)

            for item in items:
                resources_evaluated += 1
                props = item.get("properties", {}) or {}
                status_obj = props.get("status", {}) or {}
                status_code = str(status_obj.get("code") or "").strip()
                if status_code.lower() not in ("unhealthy", "open", "actionrequired", "active"):
                    continue

                date_str, days_old = extract_first_detected_date(item)
                if date_str is None or days_old is None or days_old > 30.0 or days_old < -1.0:
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
                    or item.get("name", "")
                ).strip()

                # Strictly include recommendations whose Recommendation Name starts with 'update'
                if not display_name.lower().startswith("update"):
                    continue

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
                    or f"Software update required: {display_name}"
                )
                description = clean_html_text(raw_desc) or f"Software update required: {display_name}"

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
                if not remediation:
                    remediation = f"Remediate Defender recommendation '{display_name}' according to official Microsoft Azure guidance."

                rec_cat = metadata.get("recommendationCategory") or cached_meta.get("recommendationCategory")
                sec_ctrl = (
                    control_map.get(meta_id)
                    or control_map.get(item_key)
                    or metadata.get("securityControl")
                    or cached_meta.get("securityControl")
                    or (re.sub(r"(?<!^)([A-Z])", r" \1", str(rec_cat)) if rec_cat else None)
                    or (metadata.get("categories", [None])[0] if metadata.get("categories") else None)
                    or "--"
                )

                res_info = resolve_target_resource(item, sub.subscription_id, sub.display_name)
                dedup_key = (res_info["resource_id"].lower(), display_name.lower())
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)

                add_data = props.get("additionalData", {}) or {}
                sw_info = _parse_additional_software_fields(add_data, display_name)
                region = vm_regions.get(normalize_resource_id(res_info["resource_id"]), "global")

                findings.append(
                    FindingModel(
                        finding_id=f"sec10-{sub.subscription_id[:8]}-{item.get('name', '')[:10]}-{len(findings)}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=res_info["resource_group"],
                        resource_name=res_info["resource_name"],
                        resource_type=res_info["resource_type"],
                        resource_id=res_info["resource_id"],
                        region=region,
                        severity=severity,
                        status="Update Required",
                        current_configuration=f"{sw_info['software_name']} {sw_info['installed_version']}",
                        measured_value=f"Installed: {sw_info['installed_version']} | Update: {sw_info['recommended_version']}",
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
                            "software": sw_info["software_name"],
                            "software_name": sw_info["software_name"],
                            "publisher": sw_info["publisher"],
                            "installed_version": sw_info["installed_version"],
                            "recommended_version": sw_info["recommended_version"],
                            "latest_version": sw_info["recommended_version"],
                            "support_status": "Update Required",
                            "update_keyword_detected": "Yes",
                            "end_of_support_date": "--",
                            "cve": sw_info["cve"],
                        },
                        security_score_impact=None,
                        collected_at=now_str
                    )
                )

            # 2. Secondary: Sub-assessments via ARG (or REST fallback if ARG/assessments returned nothing)
            sub_items: List[Dict[str, Any]] = []
            try:
                sub_items = await DefenderAdapter.get_sub_assessments_via_arg(context.client, sub.subscription_id)
            except Exception:
                pass
            if not sub_items and not findings:
                try:
                    resp = await DefenderAdapter.get_sub_assessments(context.client, sub.subscription_id, "11982ea1-e508-49fb-b03a-3ee0a8276f57")
                    if resp.get("success") and resp.get("value"):
                        sub_items = resp.get("value", [])
                except Exception:
                    pass

            for s_item in sub_items:
                props = s_item.get("properties", {}) or {}
                status_obj = props.get("status", {}) or {}
                code = str(status_obj.get("code") or "").lower()
                if code and code not in ("unhealthy", "open", "active"):
                    continue

                display_name = (props.get("displayName") or s_item.get("name") or "").strip()
                if not display_name.lower().startswith("update"):
                    continue

                res_details = props.get("resourceDetails", {}) or {}
                vm_id = res_details.get("id") or res_details.get("Id") or s_item.get("id") or ""
                dedup_key = (vm_id.lower(), display_name.lower())
                if dedup_key in seen_keys:
                    continue
                seen_keys.add(dedup_key)
                resources_evaluated += 1

                parsed = parse_azure_resource_id(vm_id)
                rg_name = parsed.get("resource_group") or "Subscription Scope"
                vm_name = parsed.get("resource_name") or "Virtual Machine"
                severity = str(status_obj.get("severity") or props.get("severity") or "Medium").capitalize()

                add_data = props.get("additionalData", {}) or {}
                software_name = str(add_data.get("softwareName") or add_data.get("SoftwareName") or display_name[7:].strip() or display_name)
                publisher = str(add_data.get("vendor") or add_data.get("SoftwareVendor") or "--")
                installed_ver = str(add_data.get("version") or "--")
                fixed_ver = str(add_data.get("fixedVersion") or "--")
                remediation = clean_html_text(props.get("remediation") or f"Apply update for {software_name} to version {fixed_ver}")
                description = clean_html_text(props.get("description") or display_name)
                cve_list = props.get("cve", [])
                cve_str = ", ".join([c.get("title", "") for c in cve_list if c.get("title")]) if isinstance(cve_list, list) and cve_list else "--"

                findings.append(
                    FindingModel(
                        finding_id=f"sec10-{sub.subscription_id[:8]}-{s_item.get('name', '')[:10]}-{len(findings)}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=rg_name,
                        resource_name=vm_name,
                        resource_type="Microsoft.Compute/virtualMachines",
                        resource_id=vm_id or s_item.get("id", ""),
                        region=vm_regions.get(normalize_resource_id(vm_id), "global"),
                        severity=severity,
                        status="Update Required",
                        current_configuration=f"{software_name} {installed_ver}",
                        measured_value=f"Installed: {installed_ver} | Update: {fixed_ver}",
                        recommended_configuration=remediation[:150],
                        recommendation=remediation,
                        metric_period="Defender Vulnerability Assessment",
                        data_source="Defender Vulnerability Management SubAssessments API",
                        evidence={
                            "recommendation_name": display_name,
                            "first_detected_date": "--",
                            "description": description,
                            "remediation": remediation,
                            "security_control": "Remediate vulnerabilities",
                            "software": software_name,
                            "software_name": software_name,
                            "publisher": publisher,
                            "installed_version": installed_ver,
                            "recommended_version": fixed_ver,
                            "latest_version": fixed_ver,
                            "support_status": "Update Required",
                            "update_keyword_detected": "Yes",
                            "end_of_support_date": "--",
                            "cve": cve_str,
                        },
                        security_score_impact=None,
                        collected_at=now_str
                    )
                )

        if findings:
            status = AssessmentStatus.COMPLETED
        elif errors and any("Permission" in e for e in errors):
            status = AssessmentStatus.PERMISSION_MISSING
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
