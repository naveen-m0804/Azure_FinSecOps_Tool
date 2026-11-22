import datetime
import time
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.utils.resource_ids import parse_azure_resource_id

class VmPatchingAssessment(BaseAssessment):
    assessment_id = "vm_patching"
    code = "SEC-09"
    category = "security"
    name = "VM Patching / Missing Patches"
    description = "Audit Azure Update Manager status to detect pending critical and security operating system patches."
    purpose = "Maintain vulnerability patch compliance on active server workloads."
    required_permissions = ["Microsoft.Compute/virtualMachines/read", "Microsoft.Compute/virtualMachines/patchAssessmentResults/read", "Reader"]
    required_data_sources = ["Azure Update Manager / Patch Assessment API (2023-09-01)"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        missing_telemetry_count = 0

        for sub in context.subscriptions:
            vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id, expand_instance_view=True)
            for vm in vms:
                resources_evaluated += 1
                vm_name = vm.get("name", "Unknown VM")
                vm_id = vm.get("id", "")
                parsed = parse_azure_resource_id(vm_id)
                rg_name = parsed.get("resource_group") or "Unknown"
                vm_location = vm.get("location", "global")

                props = vm.get("properties", {})
                storage_profile = props.get("storageProfile", {})
                image_ref = storage_profile.get("imageReference", {})
                os_disk = storage_profile.get("osDisk", {})
                os_type = os_disk.get("osType") or "Windows / Linux"
                os_version = image_ref.get("sku") or image_ref.get("offer") or "Unknown OS Version"

                # Query Azure Update Manager patch assessment
                patch_res = await ComputeAdapter.get_vm_patch_assessment_latest(context.client, sub.subscription_id, rg_name, vm_name)
                
                crit_count = 0
                sec_count = 0
                reboot_pending = False
                last_assess_date = now_str[:10]
                has_valid_assessment = False

                if patch_res.get("success"):
                    has_valid_assessment = True
                    data = patch_res.get("data", {})
                    patch_props = data.get("properties", {})
                    last_modified = patch_props.get("lastModifiedDateTime")
                    if last_modified:
                        last_assess_date = last_modified[:10]
                    reboot_pending = bool(patch_props.get("rebootPending", False))

                    available_patches = patch_props.get("availablePatches", [])
                    for p in available_patches:
                        classifications = p.get("classifications", [])
                        if any("critical" in str(c).lower() for c in classifications):
                            crit_count += 1
                        elif any("security" in str(c).lower() for c in classifications):
                            sec_count += 1

                    if crit_count == 0 and sec_count == 0:
                        crit_count = int(patch_props.get("criticalAndSecurityPatchCount", 0))

                # Secondary inspection: VM Instance View patchStatus
                if not has_valid_assessment or (crit_count == 0 and not reboot_pending):
                    iv = await ComputeAdapter.get_vm_instance_view(context.client, vm_id)
                    if iv.get("success"):
                        ps = iv.get("patch_status", {})
                        summary = ps.get("availablePatchSummary", {})
                        if summary:
                            has_valid_assessment = True
                            crit_count = max(crit_count, int(summary.get("criticalAndSecurityPatchCount", 0)))
                            sec_count = max(sec_count, int(summary.get("allOtherPatchCount", 0)))
                            reboot_pending = reboot_pending or bool(summary.get("rebootPending", False))
                            last_mod = summary.get("lastModifiedTime")
                            if last_mod:
                                last_assess_date = str(last_mod)[:10]

                # Tertiary inspection: Defender for Cloud system update assessments
                if not has_valid_assessment or (crit_count == 0 and not reboot_pending):
                    for def_guid in ["4ab6e338-7657-4185-920f-0d927a7c64cf", "bc11a0bb-2b08-410a-ba6a-5494cb3fa6e4"]:
                        def_resp = await DefenderAdapter.get_sub_assessments(context.client, sub.subscription_id, def_guid)
                        if def_resp.get("success") and def_resp.get("value"):
                            has_valid_assessment = True
                            for item in def_resp.get("value", []):
                                props = item.get("properties", {})
                                r_id = props.get("resourceDetails", {}).get("id") or props.get("resourceDetails", {}).get("Id") or ""
                                if vm_id.lower() in r_id.lower() or vm_name.lower() in r_id.lower():
                                    sev = str(props.get("status", {}).get("severity", "")).lower()
                                    if "high" in sev or "critical" in sev:
                                        crit_count += 1
                                    else:
                                        sec_count += 1

                if crit_count > 0 or sec_count > 0 or reboot_pending:
                    patch_status = "Action Required" if (crit_count > 0 or reboot_pending) else "Updates Pending"
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
                            severity="High" if crit_count > 0 else "Medium",
                            status="Non-Compliant",
                            current_configuration=f"Higher (Critical): {crit_count} patches | Medium (Security): {sec_count} patches | Reboot: {'Yes' if reboot_pending else 'No'}",
                            measured_value=f"Higher: {crit_count} | Medium: {sec_count}",
                            recommended_configuration="Apply pending Higher (Critical) and Medium (Security) patches and reboot host during maintenance window",
                            recommendation=f"Virtual machine '{vm_name}' is missing {crit_count} Higher (Critical) and {sec_count} Medium (Security) updates. Schedule immediate patching via Azure Update Manager.",
                            metric_period="Azure Update Manager Latest Assessment",
                            data_source="Azure Update Manager & Defender for Cloud",
                            evidence={
                                "os_type": os_type,
                                "os_version": os_version,
                                "last_assessment_date": last_assess_date,
                                "security_updates": sec_count,
                                "critical_updates": crit_count,
                                "missing_higher_patches": crit_count,
                                "missing_medium_patches": sec_count,
                                "patch_breakdown": f"Higher: {crit_count}, Medium: {sec_count}",
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
