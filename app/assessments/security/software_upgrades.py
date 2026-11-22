import datetime
import time
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.defender import DefenderAdapter
from app.utils.resource_ids import parse_azure_resource_id

# Known Defender Vulnerability Assessment Definition GUIDs for Virtual Machines
VULNERABILITY_ASSESSMENT_IDS = [
    "11982ea1-e508-49fb-b03a-3ee0a8276f57", # Machines should have vulnerability findings resolved
    "c609cf0f-714f-40e9-a099-80944d373564", # Vulnerabilities on virtual machines should be remediated
    "477461f4-e123-4a4b-a6fb-2d350f452e87"  # Container and machine software vulnerability scan
]

class SoftwareUpgradesAssessment(BaseAssessment):
    assessment_id = "software_upgrades"
    code = "SEC-10"
    category = "security"
    name = "Software Version Upgrades"
    description = "Identify outdated installed software, libraries, and applications on virtual machines via software inventory."
    purpose = "Mitigate known CVEs and exploitable vulnerabilities in installed third-party software packages."
    required_permissions = ["Microsoft.Security/assessments/subAssessments/read", "Security Reader"]
    required_data_sources = ["Defender Vulnerability Management SubAssessments API (2019-01-01-preview)"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        telemetry_missing = False

        for sub in context.subscriptions:
            all_sub_items: List[Dict[str, Any]] = []

            # 1. Query subscription-level sub-assessments
            top_sub = await DefenderAdapter.get_all_sub_assessments(context.client, sub.subscription_id)
            if top_sub.get("success") and top_sub.get("value"):
                all_sub_items.extend(top_sub.get("value", []))

            # 2. Query known Defender Vulnerability Assessment definitions
            for ass_guid in VULNERABILITY_ASSESSMENT_IDS:
                resp = await DefenderAdapter.get_sub_assessments(context.client, sub.subscription_id, ass_guid)
                if resp.get("success") and resp.get("value"):
                    all_sub_items.extend(resp.get("value", []))

            # 3. Discover dynamic vulnerability assessments from Defender recommendations
            if not all_sub_items:
                ass_list_resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id)
                if ass_list_resp.get("success"):
                    for a_item in ass_list_resp.get("value", []):
                        a_name = a_item.get("name", "")
                        props = a_item.get("properties", {})
                        meta = props.get("metadata", {})
                        disp = (meta.get("displayName") or props.get("displayName") or "").lower()
                        if any(w in disp for w in ["update", "upgrade", "vulnerabilit", "cve", "qualys", "tvm", "software"]):
                            sub_resp = await DefenderAdapter.get_sub_assessments(context.client, sub.subscription_id, a_name)
                            if sub_resp.get("success") and sub_resp.get("value"):
                                all_sub_items.extend(sub_resp.get("value", []))

            seen_item_ids = set()
            for item in all_sub_items:
                item_id = item.get("id") or item.get("name")
                if item_id in seen_item_ids:
                    continue
                seen_item_ids.add(item_id)
                resources_evaluated += 1

                props = item.get("properties", {})
                status_obj = props.get("status", {})
                code = status_obj.get("code", "")

                # Only report security gaps: Unhealthy software vulnerabilities
                if code.lower() in ("unhealthy", "open", "active"):
                    display_name = props.get("displayName") or item.get("name", "Vulnerable Software")
                    severity = status_obj.get("severity") or props.get("severity", "Medium")
                    res_details = props.get("resourceDetails", {})
                    vm_id = res_details.get("id") or res_details.get("Id") or ""
                    parsed = parse_azure_resource_id(vm_id)
                    rg_name = parsed.get("resource_group") or "Unknown"
                    vm_name = parsed.get("resource_name") or "Virtual Machine"

                    # Extract software details and check for update keyword
                    add_data = props.get("additionalData", {})
                    software_name = add_data.get("softwareName") or display_name.split(" ")[0]
                    publisher = add_data.get("vendor") or "--"
                    installed_ver = add_data.get("version") or "--"
                    fixed_ver = add_data.get("fixedVersion") or "--"
                    remediation = props.get("remediation") or f"Apply update for {software_name} to version {fixed_ver}"
                    cve_list = props.get("cve", [])
                    cve_str = ", ".join([c.get("title", "") for c in cve_list]) if isinstance(cve_list, list) and cve_list else "--"
                    is_update = any("update" in str(x).lower() for x in [display_name, software_name, remediation, props.get("description", "")])

                    findings.append(
                        FindingModel(
                            finding_id=f"sec10-{sub.subscription_id[:8]}-{item.get('name', '')[:10]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg_name,
                            resource_name=vm_name,
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_id=vm_id,
                            region="global",
                            severity=severity.capitalize(),
                            status="Update Required" if is_update else "Outdated",
                            current_configuration=f"{software_name} {installed_ver} (CVE: {cve_str})",
                            measured_value=f"Installed: {installed_ver} | Update: {fixed_ver}",
                            recommended_configuration=f"Apply vendor security update to version {fixed_ver}" if fixed_ver != "--" else "Apply latest vendor security update",
                            recommendation=remediation,
                            metric_period="Defender Vulnerability Assessment",
                            data_source="Defender for Cloud SubAssessments API (2019-01-01-preview)",
                            evidence={
                                "software": software_name,
                                "software_name": software_name,
                                "publisher": publisher,
                                "installed_version": installed_ver,
                                "recommended_version": fixed_ver,
                                "latest_version": fixed_ver,
                                "support_status": "Update Required" if is_update else "Outdated / Vulnerable",
                                "update_keyword_detected": "Yes" if is_update else "No",
                                "end_of_support_date": "--",
                                "cve": cve_str,
                                "security_control": "Remediate vulnerability findings",
                                "potential_score_increase": "+2.0%",
                            },
                            security_score_impact=2.0,
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
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
