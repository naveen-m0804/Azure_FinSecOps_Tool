import datetime
import time
import logging
import re
from typing import List, Dict, Any, Optional, Set
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.defender import DefenderAdapter
from app.azure.resources import ResourcesAdapter
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id

logger = logging.getLogger("azure_finsecops.assessments.vm_os_version")

# Dynamic date extraction patterns from live Azure API responses
DATE_REGEX_PATTERNS = [
    re.compile(r'\b\d{4}-\d{2}-\d{2}\b'),
    re.compile(r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b', re.IGNORECASE),
    re.compile(r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b', re.IGNORECASE),
]

def resolve_os_build(instance_view: Dict[str, Any], image_ref: Dict[str, Any], guest_os_name: str, sku: str) -> str:
    """
    Dynamically extracts or maps the real OS build number for Windows and Linux VMs.
    Handles instanceView osVersion (e.g., '10.0.20348.2655' -> '20348'),
    imageReference exactVersion ('20348.2655.240905' -> '20348'), and known OS SKUs.
    """
    # 1. Check instanceView.osVersion
    os_version = str(instance_view.get("osVersion") or "").strip()
    if os_version and os_version.lower() not in ("--", "latest", "unknown"):
        m = re.search(r'\b(2[0-9]{4}|1[0-9]{4}|9600|9200|760[0-1])(?:\.\d+)?\b', os_version)
        if m:
            return m.group(0)
        if re.search(r'\d+\.\d+', os_version):
            return os_version

    # 2. Check exactVersion in imageReference
    exact_ver = str(image_ref.get("exactVersion") or image_ref.get("version") or "").strip()
    if exact_ver and exact_ver.lower() not in ("--", "latest", "unknown"):
        m = re.search(r'\b(2[0-9]{4}|1[0-9]{4}|9600|9200|760[0-1])(?:\.\d+)?\b', exact_ver)
        if m:
            return m.group(0)
        if re.search(r'\d+\.\d+', exact_ver):
            return exact_ver

    # 3. Derive standard OS build from known SKU / OS Name
    combined = f"{guest_os_name} {sku}".lower()
    if "2025" in combined:
        return "26100"
    if "2022" in combined:
        return "20348"
    if "2019" in combined:
        return "17763"
    if "2016" in combined:
        return "14393"
    if "2012-r2" in combined or "2012r2" in combined:
        return "9600"
    if "2012" in combined:
        return "9200"
    if "2008-r2" in combined or "2008r2" in combined:
        return "7601"
    if "2008" in combined:
        return "6002"

    m_linux = re.search(r'\b(\d{2}\.\d{2}(?:\.\d+)?)\b', combined)
    if m_linux:
        return m_linux.group(1)

    m_rhel = re.search(r'\b(?:rhel|centos|redhat)[-_\s]*(\d+(?:\.\d+)?)\b', combined)
    if m_rhel:
        return f"Release {m_rhel.group(1)}"

    return "--"

class VmOsVersionAssessment(BaseAssessment):
    assessment_id = "vm_os_version"
    code = "SEC-08"
    category = "security"
    name = "OS Version per VM"
    description = "Audit operating system images and versions across virtual machines to flag unsupported or end-of-life platforms."
    purpose = "Ensure compliance with operating system support lifecycle and mitigate risks from unpatchable legacy OS installations."
    required_permissions = [
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/virtualMachines/instanceView/read",
        "Microsoft.Security/assessments/read",
        "Microsoft.Advisor/recommendations/read",
        "Reader"
    ]
    required_data_sources = [
        "Microsoft.Compute VirtualMachines API (2023-09-01)",
        "Microsoft Defender for Cloud Assessments API (2021-06-01)",
        "Microsoft Advisor Recommendations API (2020-01-01)"
    ]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        for sub in context.subscriptions:
            # Step 1: Query Microsoft Defender for Cloud for OS lifecycle and vulnerability assessments
            defender_os_alerts: Dict[str, Dict[str, Any]] = {}
            try:
                def_resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id, max_items=250)
                if def_resp.get("success"):
                    for ass in def_resp.get("value", []):
                        props = ass.get("properties", {}) or {}
                        status_code = str(props.get("status", {}).get("code", "")).lower()
                        if status_code not in ("unhealthy", "open"):
                            continue

                        meta = props.get("metadata", {}) or {}
                        disp_name = meta.get("displayName") or props.get("displayName", "")
                        disp_lower = disp_name.lower()

                        if any(kw in disp_lower for kw in [
                            "operating system", "supported os", "end of support", "end of life",
                            "unsupported os", "upgrade your operating system", "os version", "system updates"
                        ]):
                            res_details = props.get("resourceDetails", {}) or {}
                            target_id = res_details.get("Id") or res_details.get("id") or ""
                            if target_id:
                                norm_id = normalize_resource_id(target_id)
                                first_eval = str(props.get("status", {}).get("firstEvaluationDate") or "")[:10]
                                dyn_date = extract_date_from_text(disp_name) or extract_date_from_text(meta.get("description", "")) or (first_eval if first_eval else None)

                                defender_os_alerts[norm_id] = {
                                    "title": disp_name,
                                    "severity": meta.get("severity", "High"),
                                    "remediation": meta.get("remediationDescription") or meta.get("description") or "Upgrade operating system to a supported release.",
                                    "date": dyn_date
                                }
            except Exception as ex:
                logger.debug("Failed querying Defender for Cloud OS assessments in sub %s: %s", sub.subscription_id, ex)

            # Step 2: Query Azure Advisor for OS lifecycle advisories
            advisor_os_alerts: Dict[str, Dict[str, Any]] = {}
            try:
                recs = await ResourcesAdapter.get_advisor_recommendations(context.client, sub.subscription_id)
                for rec in recs:
                    props = rec.get("properties", {}) or {}
                    impacted_id = (props.get("resourceMetadata", {}).get("resourceId") or props.get("impactedValue") or "").lower()
                    problem_text = props.get("shortDescription", {}).get("problem", "")
                    solution_text = props.get("shortDescription", {}).get("solution", "")
                    combined_text = f"{problem_text} {solution_text}".lower()

                    if any(kw in combined_text for kw in ["operating system", "os upgrade", "end of support", "unsupported os", "linux", "windows server"]):
                        dyn_date = extract_date_from_text(problem_text) or extract_date_from_text(solution_text)
                        advisor_os_alerts[normalize_resource_id(impacted_id)] = {
                            "problem": problem_text,
                            "solution": solution_text,
                            "date": dyn_date,
                            "impact": props.get("impact", "High")
                        }
            except Exception as ex:
                logger.debug("Failed querying Azure Advisor OS recommendations in sub %s: %s", sub.subscription_id, ex)

            # Step 3: Scan all Virtual Machines with live instance view telemetry
            vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id, expand_instance_view=True)
            for vm in vms:
                resources_evaluated += 1
                vm_name = vm.get("name", "Unknown VM")
                vm_id = vm.get("id", "")
                norm_vm_id = normalize_resource_id(vm_id)

                props = vm.get("properties", {}) or {}
                storage_profile = props.get("storageProfile", {}) or {}
                image_ref = storage_profile.get("imageReference", {}) or {}
                os_disk = storage_profile.get("osDisk", {}) or {}
                os_type = os_disk.get("osType") or ("Windows" if "win" in str(image_ref).lower() else "Linux")

                publisher = image_ref.get("publisher", "Custom / Marketplace")
                offer = image_ref.get("offer", "")
                sku = image_ref.get("sku", "")
                image_ver = image_ref.get("version") or image_ref.get("exactVersion") or "Marketplace Image"

                instance_view = props.get("instanceView", {}) or {}
                guest_os_name = instance_view.get("osName") or f"{publisher} {offer} {sku}".strip()
                guest_os_version = instance_view.get("osVersion") or sku or image_ver

                os_build = resolve_os_build(instance_view, image_ref, guest_os_name, sku)

                combined_check = f"{guest_os_name} {sku} {offer} {image_ver}".lower()
                is_outdated = False
                matched_os = guest_os_name
                matched_status = "Unsupported OS"
                dyn_date = "--"
                rec_text = ""
                rec_config = ""

                # Correlate live Azure Defender for Cloud findings
                if norm_vm_id in defender_os_alerts:
                    def_info = defender_os_alerts[norm_vm_id]
                    is_outdated = True
                    matched_status = "Vendor End of Life / Unsupported"
                    rec_text = f"Microsoft Defender flagged '{vm_name}' for OS lifecycle risk: {def_info['title']}. {def_info['remediation']}"
                    rec_config = def_info['remediation']
                    if def_info.get("date"):
                        dyn_date = def_info["date"]

                # Correlate live Azure Advisor recommendations
                elif norm_vm_id in advisor_os_alerts:
                    adv_info = advisor_os_alerts[norm_vm_id]
                    is_outdated = True
                    matched_status = "Vendor End of Life / Unsupported"
                    rec_text = f"Azure Advisor flagged '{vm_name}': {adv_info['problem']} {adv_info['solution']}"
                    rec_config = adv_info['solution']
                    if adv_info.get("date"):
                        dyn_date = adv_info["date"]

                # Dynamic operating system release lifecycle analysis (< 2025 baseline)
                BASELINE_OS_YEAR = 2025

                if not is_outdated:
                    # Windows Server dynamic generation check
                    if "windows" in combined_check:
                        win_year_match = re.search(r'\b(19\d{2}|20\d{2})\b', combined_check)
                        if win_year_match:
                            win_year = int(win_year_match.group(1))
                            is_r2 = "r2" in combined_check or "-r2" in combined_check
                            display_win = f"Windows Server {win_year}{' R2' if is_r2 else ''}"
                            matched_os = display_win
                            if win_year < BASELINE_OS_YEAR:
                                is_outdated = True
                                matched_status = f"Outdated OS (< {BASELINE_OS_YEAR})"
                                rec_text = f"Virtual machine '{vm_name}' runs {display_win} (version {win_year} < {BASELINE_OS_YEAR}). Upgrade VM guest operating system to Windows Server 2025 or newer."
                                rec_config = "Upgrade operating system to version 2025 or newer"
                            else:
                                matched_status = "Actively Supported"

                    # Ubuntu Linux dynamic LTS release check (< 2025 baseline)
                    elif "ubuntu" in combined_check:
                        ub_ver_match = re.search(r'\b(\d{2}\.04)\b', combined_check)
                        if ub_ver_match:
                            ub_ver = ub_ver_match.group(1)
                            ub_year = 2000 + int(ub_ver.split(".")[0])
                            matched_os = f"Ubuntu Linux {ub_ver} LTS"
                            if ub_year < BASELINE_OS_YEAR:
                                is_outdated = True
                                matched_status = f"Outdated OS (< {BASELINE_OS_YEAR})"
                                rec_text = f"Virtual machine '{vm_name}' runs Ubuntu Linux {ub_ver} LTS (release year {ub_year} < {BASELINE_OS_YEAR}). Upgrade to an actively supported distribution (version 2025 or newer)."
                                rec_config = "Upgrade operating system to version 2025 or newer"
                            else:
                                matched_status = "Actively Supported"

                    # CentOS Linux dynamic lifecycle check
                    elif "centos" in combined_check:
                        is_outdated = True
                        matched_status = f"Outdated OS (< {BASELINE_OS_YEAR})"
                        if any(k in combined_check for k in ["centos-7", "centos 7", "centos_7"]):
                            matched_os = "CentOS Linux 7"
                            rec_text = f"Virtual machine '{vm_name}' runs CentOS Linux 7 (< {BASELINE_OS_YEAR}), which has reached vendor end-of-life. Migrate to Azure Linux, RHEL, or AlmaLinux."
                        elif any(k in combined_check for k in ["centos-8", "centos 8", "centos_8"]):
                            matched_os = "CentOS Linux 8"
                            rec_text = f"Virtual machine '{vm_name}' runs CentOS Linux 8 (< {BASELINE_OS_YEAR}), which has reached vendor end-of-life. Migrate to CentOS Stream or modern Linux distribution."
                        else:
                            matched_os = "CentOS Linux"
                            rec_text = f"Virtual machine '{vm_name}' runs legacy CentOS Linux (< {BASELINE_OS_YEAR})."
                        rec_config = "Migrate to an actively supported modern Linux distribution"

                    # Debian Linux dynamic lifecycle check
                    elif "debian" in combined_check:
                        deb_ver_match = re.search(r'\bdebian-(\d+)\b|\bdebian\s+(\d+)\b', combined_check)
                        deb_ver = int(deb_ver_match.group(1) or deb_ver_match.group(2)) if deb_ver_match else 0
                        if deb_ver > 0 and deb_ver <= 12:
                            is_outdated = True
                            matched_os = f"Debian Linux {deb_ver}"
                            matched_status = f"Outdated OS (< {BASELINE_OS_YEAR})"
                            rec_text = f"Virtual machine '{vm_name}' runs Debian {deb_ver} (< {BASELINE_OS_YEAR}). Upgrade to latest supported Debian release."
                            rec_config = "Upgrade to supported Debian distribution"

                    # Red Hat Enterprise Linux dynamic lifecycle check
                    elif any(k in combined_check for k in ["rhel", "redhat"]):
                        rhel_match = re.search(r'\brhel[- ]?(\d+)\b|\bredhat[- ]?(\d+)\b', combined_check)
                        rhel_ver = int(rhel_match.group(1) or rhel_match.group(2)) if rhel_match else 0
                        if rhel_ver > 0 and rhel_ver <= 9:
                            is_outdated = True
                            matched_os = f"Red Hat Enterprise Linux {rhel_ver}"
                            matched_status = f"Outdated OS (< {BASELINE_OS_YEAR})"
                            rec_text = f"Virtual machine '{vm_name}' runs RHEL {rhel_ver} (< {BASELINE_OS_YEAR}). Upgrade to modern RHEL distribution."
                            rec_config = "Upgrade to supported enterprise Linux release"

                # Filter strictly to outdated operating systems (< 2025)
                if not is_outdated:
                    continue

                parsed = parse_azure_resource_id(vm.get("id", ""))
                rg = parsed.get("resource_group") or "Unknown"

                sev = "High"
                stat = matched_status
                meas = matched_status
                if not rec_text:
                    rec_text = f"Virtual machine '{vm_name}' runs {matched_os} (< {BASELINE_OS_YEAR}). Upgrade VM guest operating system to restore vendor security patching."
                if not rec_config:
                    rec_config = "Upgrade operating system to version 2025 or newer"

                findings.append(
                    FindingModel(
                        finding_id=f"sec08-{sub.subscription_id[:8]}-{vm_name[:12]}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=rg,
                        resource_name=vm_name,
                        resource_type="Microsoft.Compute/virtualMachines",
                        resource_id=vm.get("id", ""),
                        region=vm.get("location", "global"),
                        severity=sev,
                        status=stat,
                        current_configuration=f"Installed/Image OS: {matched_os} (Status: {matched_status})",
                        measured_value=meas,
                        recommended_configuration=rec_config,
                        recommendation=rec_text,
                        metric_period="Vendor Official Operating System Lifecycle",
                        data_source="Microsoft.Compute VirtualMachines API (2023-09-01)",
                        evidence={
                            "os_type": os_type,
                            "os_version": guest_os_version,
                            "os_build": os_build,
                            "publisher": publisher,
                            "image_version": image_ver,
                            "support_status": matched_status,
                            "end_of_support_date": dyn_date,
                            "security_control": "Maintain supported operating system release",
                            "potential_score_increase": "+2.0%" if is_outdated else "--",
                        },
                        security_score_impact=2.0 if is_outdated else 0.0,
                        collected_at=now_str
                    )
                )

        status = AssessmentStatus.COMPLETED if findings else AssessmentStatus.NO_FINDINGS
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
