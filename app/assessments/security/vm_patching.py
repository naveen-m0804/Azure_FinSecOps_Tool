import datetime
import time
import logging
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.defender import DefenderAdapter
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id

logger = logging.getLogger("azure_finsecops.assessments.vm_patching")

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

            # 1. Fetch ARG patch assessment summaries for the subscription
            arg_patch_map: Dict[str, Dict[str, Any]] = {}
            try:
                arg_patches = await ComputeAdapter.get_all_patch_assessments_via_arg(context.client, sub.subscription_id)
                for ap in arg_patches:
                    target_id = ap.get("id") or ap.get("properties", {}).get("targetResourceId") or ""
                    if target_id:
                        # Extract VM ID from patch result ID
                        # Format: .../virtualMachines/{vmName}/patchAssessmentResults/...
                        vm_prefix = target_id.lower().split("/patchassessmentresults")[0]
                        arg_patch_map[normalize_resource_id(vm_prefix)] = ap.get("properties", {})
            except Exception as ex:
                logger.debug("ARG patch assessment query for sub %s: %s", sub.subscription_id, ex)

            # 2. Query Defender recommendations for system updates dynamically
            defender_patch_vms: Dict[str, Dict[str, Any]] = {}
            try:
                def_resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id, max_items=300)
                if def_resp.get("success"):
                    for ass in def_resp.get("value", []):
                        props = ass.get("properties", {}) or {}
                        meta = props.get("metadata", {}) or {}
                        title = (meta.get("displayName") or props.get("displayName") or "").lower()
                        status_code = str(props.get("status", {}).get("code", "")).lower()

                        if status_code in ("unhealthy", "open") and any(
                            kw in title for kw in ["system updates", "missing updates", "missing patches", "periodic assessment", "check for missing"]
                        ):
                            res_id = props.get("resourceDetails", {}).get("Id") or props.get("resourceDetails", {}).get("id") or ""
                            if res_id:
                                norm_id = normalize_resource_id(res_id)
                                defender_patch_vms[norm_id] = {
                                    "title": meta.get("displayName") or props.get("displayName"),
                                    "severity": meta.get("severity", "High"),
                                    "remediation": meta.get("remediationDescription") or meta.get("description")
                                }

                                # Also fetch sub-assessments for this specific update assessment
                                ass_name = ass.get("name")
                                if ass_name:
                                    sub_resp = await DefenderAdapter.get_sub_assessments(context.client, sub.subscription_id, ass_name)
                                    if sub_resp.get("success") and sub_resp.get("value"):
                                        for s_item in sub_resp.get("value", []):
                                            s_props = s_item.get("properties", {})
                                            s_target = s_props.get("resourceDetails", {}).get("id") or s_props.get("resourceDetails", {}).get("Id") or ""
                                            if s_target:
                                                s_norm = normalize_resource_id(s_target)
                                                if s_norm not in defender_patch_vms:
                                                    defender_patch_vms[s_norm] = {
                                                        "title": s_props.get("displayName", "Missing System Update"),
                                                        "severity": s_props.get("status", {}).get("severity", "High"),
                                                        "remediation": s_props.get("remediation", "Apply missing updates via Azure Update Manager.")
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
                storage_profile = props.get("storageProfile", {}) or {}
                image_ref = storage_profile.get("imageReference", {}) or {}
                os_disk = storage_profile.get("osDisk", {}) or {}
                os_type = os_disk.get("osType") or "Windows / Linux"
                os_version = image_ref.get("sku") or image_ref.get("offer") or "Unknown OS Version"

                crit_count = 0
                sec_count = 0
                other_count = 0
                bundled_count = 0
                reboot_pending = False
                last_assess_date = now_str[:10]
                has_valid_assessment = False
                assessment_status = "Succeeded"

                # A. Check ARG patch assessment data
                if norm_vm_id in arg_patch_map:
                    has_valid_assessment = True
                    ap_props = arg_patch_map[norm_vm_id]
                    bundled_count = int(ap_props.get("criticalAndSecurityPatchCount", 0))
                    other_count = int(ap_props.get("otherPatchCount", 0))
                    reboot_pending = bool(ap_props.get("rebootPending", False))
                    last_mod = ap_props.get("lastModifiedDateTime")
                    if last_mod:
                        last_assess_date = str(last_mod)[:10]
                    if ap_props.get("status"):
                        assessment_status = str(ap_props.get("status"))

                    # Parse availablePatches directly if ARG returned the array
                    for p in ap_props.get("availablePatches", []):
                        classifications = [str(c).lower() for c in p.get("classifications", [])]
                        title_lower = str(p.get("title", "")).lower()
                        if any("critical" in c for c in classifications) or "critical update" in title_lower:
                            crit_count += 1
                        elif any("security" in c for c in classifications) or "security update" in title_lower:
                            sec_count += 1
                        else:
                            other_count += 1

                # B. Query direct Azure Update Manager patch assessment endpoint if counts need itemization
                if not has_valid_assessment or (crit_count == 0 and sec_count == 0):
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
                if not has_valid_assessment or (crit_count == 0 and sec_count == 0 and bundled_count == 0 and not reboot_pending):
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

                # D. Cross-reference Defender for Cloud system update recommendations
                if norm_vm_id in defender_patch_vms:
                    has_valid_assessment = True
                    def_info = defender_patch_vms[norm_vm_id]
                    if crit_count == 0 and sec_count == 0 and bundled_count == 0 and not reboot_pending:
                        sec_count = 1

                # If only bundled criticalAndSecurityPatchCount was returned without itemized array:
                # Accurately assign bundled patches to security updates (predominant in Azure updates)
                if crit_count == 0 and sec_count == 0 and bundled_count > 0:
                    sec_count = bundled_count

                total_pending_patches = crit_count + sec_count + other_count

                # Report finding if patches are missing or reboot is pending
                if total_pending_patches > 0 or reboot_pending:
                    reboot_str = "Yes" if reboot_pending else "No"
                    if reboot_pending and total_pending_patches > 0:
                        patch_status = f"{total_pending_patches} Updates Pending (Reboot Required)"
                    elif reboot_pending:
                        patch_status = "Reboot Required"
                    else:
                        patch_status = f"{total_pending_patches} Updates Pending"

                    severity = "High" if (crit_count > 0 or total_pending_patches >= 5) else "Medium"
                    rec_guidance = (
                        f"Virtual machine '{vm_name}' has {total_pending_patches} pending updates "
                        f"({crit_count} Critical, {sec_count} Security, Reboot Pending: {reboot_str}). "
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
                            current_configuration=f"Critical: {crit_count} | Security: {sec_count} | Total Pending: {total_pending_patches} | Reboot Required: {reboot_str}",
                            measured_value=f"{total_pending_patches} Pending ({crit_count} Critical, {sec_count} Security)",
                            recommended_configuration="Install pending Critical/Security updates and reboot VM",
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
                                "patch_breakdown": f"Critical: {crit_count}, Security: {sec_count}",
                                "reboot_required": reboot_pending,
                                "patch_status": patch_status,
                                "security_control": "Apply system updates",
                                "potential_score_increase": f"+{3.0 if crit_count > 0 else 1.5:.1f}%",
                            },
                            security_score_impact=3.0 if crit_count > 0 else 1.5,
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
