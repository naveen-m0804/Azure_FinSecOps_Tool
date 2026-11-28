import datetime
import time
import logging
import re
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.defender import DefenderAdapter
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id

logger = logging.getLogger("azure_finsecops.assessments.vm_patching")


def _resolve_vm_os_display(props: Dict[str, Any], instance_view: Dict[str, Any]) -> tuple[str, str]:
    """Derives clean OS type and OS version string from VM instanceView and imageReference."""
    storage_profile = props.get("storageProfile", {}) or {}
    image_ref = storage_profile.get("imageReference", {}) or {}
    os_disk = storage_profile.get("osDisk", {}) or {}
    os_profile = props.get("osProfile", {}) or {}

    os_type = os_disk.get("osType")
    if not os_type:
        if os_profile.get("windowsConfiguration") or "win" in str(image_ref).lower() or "ws20" in str(image_ref).lower():
            os_type = "Windows"
        elif os_profile.get("linuxConfiguration"):
            os_type = "Linux"
        else:
            os_type = "Windows / Linux"

    iv_name = str(instance_view.get("osName") or "").strip()
    iv_ver = str(instance_view.get("osVersion") or "").strip()
    if iv_name and iv_ver:
        return os_type, f"{iv_name} ({iv_ver})"
    if iv_ver:
        return os_type, iv_ver

    offer = str(image_ref.get("offer") or "").strip()
    sku = str(image_ref.get("sku") or "").strip()
    exact_ver = str(image_ref.get("exactVersion") or "").strip()
    ver = str(image_ref.get("version") or "").strip()

    sql_ws_match = re.search(r'sql(\d{4})[-_]ws(\d{4})', offer.lower())
    if sql_ws_match:
        sql_yr, ws_yr = sql_ws_match.group(1), sql_ws_match.group(2)
        base = f"Windows Server {ws_yr} (SQL {sql_yr})"
        return os_type, f"{base} ({exact_ver})" if exact_ver else base

    if offer or sku:
        parts = [p for p in (offer, sku) if p and p.lower() != "latest"]
        label = " ".join(parts)
        if exact_ver and exact_ver.lower() != "latest":
            return os_type, f"{label} ({exact_ver})"
        if ver and ver.lower() != "latest":
            return os_type, f"{label} ({ver})"
        return os_type, label

    return os_type, "Custom / Unmanaged Image"


class VmPatchingAssessment(BaseAssessment):
    assessment_id = "vm_patching"
    code = "SEC-09"
    category = "security"
    name = "VM Patching / Missing Patches"
    description = "Audit Azure Update Manager and Microsoft Defender for Cloud to detect pending critical and security operating system patches across virtual machines."
    purpose = "Maintain vulnerability patch compliance, eliminate exploitable OS vulnerabilities, and enforce reboot governance on active server workloads."
    required_permissions = [
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/virtualMachines/patchAssessmentResults/read",
        "Microsoft.Security/assessments/read",
        "Reader"
    ]
    required_data_sources = ["Azure Update Manager, VM Instance View & Microsoft Defender for Cloud System Updates"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        missing_telemetry_count = 0

        for sub in context.subscriptions:
            vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id, expand_instance_view=True)

            # 1. Fetch ARG patch assessment summaries & individual software patches for the subscription
            arg_patch_map: Dict[str, Dict[str, Any]] = {}
            try:
                arg_patches = await ComputeAdapter.get_all_patch_assessments_via_arg(context.client, sub.subscription_id)
                for ap in arg_patches:
                    target_id = ap.get("id") or ap.get("properties", {}).get("targetResourceId") or ""
                    if target_id:
                        vm_prefix = target_id.lower().split("/patchassessmentresults")[0]
                        arg_patch_map[normalize_resource_id(vm_prefix)] = ap.get("properties", {})
            except Exception as ex:
                logger.debug("ARG patch assessment query for sub %s: %s", sub.subscription_id, ex)

            arg_software_patches_map: Dict[str, List[Dict[str, Any]]] = {}
            try:
                sp_list = await ComputeAdapter.get_software_patches_via_arg(context.client, sub.subscription_id)
                for sp in sp_list:
                    sp_id = sp.get("id") or ""
                    if "/patchassessmentresults" in sp_id.lower():
                        vm_prefix = sp_id.lower().split("/patchassessmentresults")[0]
                        arg_software_patches_map.setdefault(normalize_resource_id(vm_prefix), []).append(sp.get("properties", {}) or {})
            except Exception as ex:
                logger.debug("ARG software patches query for sub %s: %s", sub.subscription_id, ex)

            # 2. Query Defender recommendations for system updates dynamically
            defender_patch_vms: Dict[str, Dict[str, Any]] = {}
            try:
                def_items = await DefenderAdapter.get_security_assessments_via_arg(context.client, sub.subscription_id, unhealthy_only=True)
                for ass in def_items:
                    props = ass.get("properties", {}) or {}
                    meta = props.get("metadata", {}) or {}
                    title = (meta.get("displayName") or props.get("displayName") or "").lower()
                    if any(kw in title for kw in ["system updates", "missing updates", "missing patches", "periodic assessment", "cumulative update"]):
                        res_id = props.get("resourceDetails", {}).get("Id") or props.get("resourceDetails", {}).get("id") or ""
                        if res_id:
                            norm_id = normalize_resource_id(res_id)
                            defender_patch_vms[norm_id] = {
                                "title": meta.get("displayName") or props.get("displayName"),
                                "severity": meta.get("severity", "High"),
                                "remediation": meta.get("remediationDescription") or meta.get("description")
                            }
            except Exception as ex:
                logger.debug("Defender system updates scan for sub %s: %s", sub.subscription_id, ex)

            # Evaluate each virtual machine
            for vm in vms:
                resources_evaluated += 1
                vm_name = vm.get("name", "Unknown VM")
                vm_id = vm.get("id", "")
                norm_vm_id = normalize_resource_id(vm_id)
                parsed = parse_azure_resource_id(vm_id)
                rg_name = parsed.get("resource_group") or "Unknown"
                vm_location = vm.get("location", "global")

                props = vm.get("properties", {}) or {}
                instance_view = props.get("instanceView", {}) or {}
                os_type, os_version = _resolve_vm_os_display(props, instance_view)

                crit_count = 0
                sec_count = 0
                other_count = 0
                bundled_count = 0
                reboot_pending = False
                last_assess_date = now_str[:10]
                has_valid_assessment = False
                assessment_status = "Succeeded"
                patch_details: List[str] = []

                # A. Check ARG patch assessment data (authoritative Azure Update Manager)
                if norm_vm_id in arg_patch_map:
                    has_valid_assessment = True
                    ap_props = arg_patch_map[norm_vm_id]
                    reboot_pending = bool(ap_props.get("rebootPending", False))
                    last_mod = ap_props.get("lastModifiedDateTime")
                    if last_mod:
                        last_assess_date = str(last_mod)[:10]
                    if ap_props.get("status"):
                        assessment_status = str(ap_props.get("status"))

                    # Modern ARG schema: availablePatchCountByClassification
                    by_cls = ap_props.get("availablePatchCountByClassification")
                    if isinstance(by_cls, dict):
                        crit_count = int(by_cls.get("critical", 0))
                        sec_count = int(by_cls.get("security", 0))
                        other_count = sum(
                            int(by_cls.get(k, 0))
                            for k in ("definition", "updateRollup", "servicePack", "featurePack", "updates", "tools")
                        )
                    else:
                        bundled_count = int(ap_props.get("criticalAndSecurityPatchCount", 0))
                        other_count = int(ap_props.get("otherPatchCount", 0))

                    # Parse individual software patches from ARG if available
                    vm_sp = arg_software_patches_map.get(norm_vm_id, [])
                    if vm_sp:
                        c_sp, s_sp, o_sp = 0, 0, 0
                        for sp in vm_sp:
                            cls_list = [str(c).lower() for c in sp.get("classifications", [])]
                            p_name = str(sp.get("patchName") or "")
                            if p_name:
                                patch_details.append(p_name)
                            if "critical" in cls_list:
                                c_sp += 1
                            elif "security" in cls_list:
                                s_sp += 1
                            else:
                                o_sp += 1
                        if crit_count == 0 and sec_count == 0 and other_count == 0:
                            crit_count, sec_count, other_count = c_sp, s_sp, o_sp

                    for p in ap_props.get("availablePatches", []):
                        classifications = [str(c).lower() for c in p.get("classifications", [])]
                        title_lower = str(p.get("title", "")).lower()
                        if any("critical" in c for c in classifications) or "critical update" in title_lower:
                            crit_count += 1
                        elif any("security" in c for c in classifications) or "security update" in title_lower:
                            sec_count += 1
                        else:
                            other_count += 1

                # B. Fallback to direct REST patchAssessmentResults/latest only when ARG had no record
                if not has_valid_assessment:
                    patch_res = await ComputeAdapter.get_vm_patch_assessment_latest(context.client, sub.subscription_id, rg_name, vm_name)
                    if patch_res.get("success"):
                        has_valid_assessment = True
                        data = patch_res.get("data", {})
                        p_props = data.get("properties", {}) or {}
                        last_mod = p_props.get("lastModifiedDateTime")
                        if last_mod:
                            last_assess_date = str(last_mod)[:10]
                        reboot_pending = reboot_pending or bool(p_props.get("rebootPending", False))
                        if p_props.get("status"):
                            assessment_status = str(p_props.get("status"))

                        available = p_props.get("availablePatches", [])
                        for p in available:
                            classifications = [str(c).lower() for c in p.get("classifications", [])]
                            title_lower = str(p.get("title", "")).lower()
                            if any("critical" in c for c in classifications) or "critical update" in title_lower:
                                crit_count += 1
                            elif any("security" in c for c in classifications) or "security update" in title_lower:
                                sec_count += 1
                            else:
                                other_count += 1

                        if crit_count == 0 and sec_count == 0:
                            summary_info = p_props.get("availablePatchSummary", {}) or {}
                            bundled_count = max(bundled_count, int(summary_info.get("criticalAndSecurityPatchCount", 0)))
                            if summary_info.get("status"):
                                assessment_status = str(summary_info.get("status"))

                # C. Check VM Instance View patchStatus if still unresolved
                if not has_valid_assessment:
                    iv = await ComputeAdapter.get_vm_instance_view(context.client, vm_id)
                    if iv.get("success"):
                        ps = iv.get("patch_status", {}) or {}
                        summary = ps.get("availablePatchSummary", {}) or {}
                        if summary:
                            has_valid_assessment = True
                            bundled_count = max(bundled_count, int(summary.get("criticalAndSecurityPatchCount", 0)))
                            other_count = max(other_count, int(summary.get("allOtherPatchCount", 0)))
                            reboot_pending = reboot_pending or bool(summary.get("rebootPending", False))
                            last_mod = summary.get("lastModifiedTime")
                            if last_mod:
                                last_assess_date = str(last_mod)[:10]
                            if summary.get("status"):
                                assessment_status = str(summary.get("status"))

                # D. Cross-reference Defender for Cloud system update recommendations (only if Update Manager had no record)
                if not has_valid_assessment and norm_vm_id in defender_patch_vms:
                    has_valid_assessment = True
                    sec_count = 1

                if crit_count == 0 and sec_count == 0 and bundled_count > 0:
                    sec_count = bundled_count

                total_pending_patches = crit_count + sec_count + other_count

                # Report finding only for VMs that actually need to update patches
                if total_pending_patches > 0:
                    reboot_str = "Yes" if reboot_pending else "No"
                    if reboot_pending and total_pending_patches > 0:
                        patch_status = f"{total_pending_patches} Updates Pending (Reboot Required)"
                    elif reboot_pending:
                        patch_status = "Reboot Required"
                    else:
                        patch_status = f"{total_pending_patches} Updates Pending"

                    severity = "High" if (crit_count > 0 or sec_count > 0 or total_pending_patches >= 5) else "Medium"
                    rec_guidance = (
                        f"Virtual machine '{vm_name}' has {total_pending_patches} pending updates "
                        f"({crit_count} Critical, {sec_count} Security, {other_count} Other/Definition, Reboot Pending: {reboot_str}). "
                        f"Apply updates via Azure Update Manager during the scheduled maintenance window."
                    )

                    findings.append(
                        FindingModel(
                            finding_id=f"sec09-{sub.subscription_id[:8]}-{vm_name[:12]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg_name,
                            resource_name=vm_name,
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_id=vm_id,
                            region=vm_location,
                            severity=severity,
                            status="Non-Compliant",
                            current_configuration=f"Critical: {crit_count} | Security: {sec_count} | Other: {other_count} | Reboot Required: {reboot_str}",
                            measured_value=f"{total_pending_patches} Pending ({crit_count} Critical, {sec_count} Security, {other_count} Other)",
                            recommended_configuration="Install pending updates via Azure Update Manager",
                            recommendation=rec_guidance,
                            metric_period="Azure Update Manager & Defender for Cloud",
                            data_source="Azure Update Manager & Defender for Cloud",
                            evidence={
                                "os_type": os_type,
                                "os_version": os_version,
                                "last_assessment_date": last_assess_date,
                                "assessment_status": assessment_status,
                                "security_updates": sec_count,
                                "critical_updates": crit_count,
                                "other_updates": other_count,
                                "total_pending_patches": total_pending_patches,
                                "missing_higher_patches": crit_count,
                                "missing_medium_patches": sec_count,
                                "patch_breakdown": f"Critical: {crit_count}, Security: {sec_count}, Other: {other_count}",
                                "pending_patch_names": patch_details[:5],
                                "reboot_required": reboot_pending,
                                "patch_status": patch_status,
                                "security_control": "Apply system updates",
                            },
                            security_score_impact=None,
                            collected_at=now_str
                        )
                    )
                elif not has_valid_assessment:
                    missing_telemetry_count += 1

        if findings:
            status = AssessmentStatus.COMPLETED
        elif errors and not findings and any("Permission" in e for e in errors):
            status = AssessmentStatus.PERMISSION_MISSING
        elif missing_telemetry_count > 0 and resources_evaluated > 0 and missing_telemetry_count == resources_evaluated and not findings:
            status = AssessmentStatus.METRICS_UNAVAILABLE
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
