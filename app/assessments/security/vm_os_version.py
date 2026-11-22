import datetime
import time
from typing import List, Dict, Any, Tuple, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.utils.resource_ids import parse_azure_resource_id

# Official Operating System Lifecycle Guidance
OUTDATED_OS_PATTERNS: List[Tuple[str, str, str, str]] = [
    # (pattern_in_sku_or_os_name, operating_system, support_status, end_of_support_date)
    ("2008-r2", "Windows Server 2008 R2", "Retired / End of Life", "2020-01-14"),
    ("2008", "Windows Server 2008", "Retired / End of Life", "2020-01-14"),
    ("2012-r2", "Windows Server 2012 R2", "Retired / End of Life", "2023-10-10"),
    ("2012", "Windows Server 2012", "Retired / End of Life", "2023-10-10"),
    ("14.04", "Ubuntu Linux 14.04 LTS", "End of Standard Support", "2019-04-30"),
    ("16.04", "Ubuntu Linux 16.04 LTS", "End of Standard Support", "2021-04-30"),
    ("18.04", "Ubuntu Linux 18.04 LTS", "End of Standard Support", "2023-05-31"),
    ("centos-7", "CentOS Linux 7", "Retired / End of Life", "2024-06-30"),
    ("centos-8", "CentOS Linux 8", "Retired / End of Life", "2021-12-31"),
    ("debian-9", "Debian Linux 9", "Retired / End of Life", "2022-06-30"),
    ("debian-10", "Debian Linux 10", "End of Standard Support", "2024-06-30"),
    ("rhel-7", "Red Hat Enterprise Linux 7", "End of Maintenance Support", "2024-06-30"),
]

class VmOsVersionAssessment(BaseAssessment):
    assessment_id = "vm_os_version"
    code = "SEC-08"
    category = "security"
    name = "OS Version per VM"
    description = "Audit operating system images and versions across virtual machines to flag unsupported or end-of-life platforms."
    purpose = "Ensure compliance with operating system support lifecycle and mitigate risks from unpatchable legacy OS installations."
    required_permissions = ["Microsoft.Compute/virtualMachines/read", "Microsoft.Compute/virtualMachines/instanceView/read", "Reader"]
    required_data_sources = ["Microsoft.Compute VirtualMachines API (2023-09-01)"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        for sub in context.subscriptions:
            vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id, expand_instance_view=True)
            for vm in vms:
                resources_evaluated += 1
                vm_name = vm.get("name", "Unknown VM")
                props = vm.get("properties", {})
                storage_profile = props.get("storageProfile", {})
                image_ref = storage_profile.get("imageReference", {})
                os_disk = storage_profile.get("osDisk", {})
                os_type = os_disk.get("osType") or ("Windows" if "win" in str(image_ref).lower() else "Linux")

                publisher = image_ref.get("publisher", "Custom / Marketplace")
                offer = image_ref.get("offer", "")
                sku = image_ref.get("sku", "")
                image_ver = image_ref.get("version") or image_ref.get("exactVersion") or "Marketplace Image"

                # Check guest OS details from instanceView if available
                instance_view = props.get("instanceView", {})
                guest_os_name = instance_view.get("osName") or f"{publisher} {offer} {sku}".strip()
                guest_os_version = instance_view.get("osVersion") or sku or image_ver
                
                # Check for OS build
                os_build = "--"
                if "." in guest_os_version and len(guest_os_version.split(".")) >= 3:
                    os_build = guest_os_version

                # Match against verified lifecycle guidance
                combined_check = f"{guest_os_name} {sku} {offer} {image_ver}".lower()
                is_outdated = False
                matched_os = guest_os_name
                matched_status = "Unsupported OS"
                matched_eos = "--"

                for pattern, os_display, sup_status, eos_date in OUTDATED_OS_PATTERNS:
                    if pattern in combined_check:
                        is_outdated = True
                        matched_os = os_display
                        matched_status = sup_status
                        matched_eos = eos_date
                        break

                parsed = parse_azure_resource_id(vm.get("id", ""))
                rg = parsed.get("resource_group") or "Unknown"

                if is_outdated:
                    sev = "High"
                    stat = matched_status
                    meas = f"{matched_status} (EOL: {matched_eos})"
                    rec = f"Virtual machine '{vm_name}' runs {matched_os}, which reached official End-of-Support on {matched_eos}. Upgrade VM guest operating system to restore security update support."
                    rec_config = "Upgrade operating system to an actively supported LTS distribution or Windows Server release"
                else:
                    sev = "Informational"
                    stat = "Supported"
                    matched_status = "Actively Supported"
                    matched_eos = "Active Support"
                    meas = f"Supported ({guest_os_name})"
                    rec = f"Virtual machine '{vm_name}' is running an actively supported OS platform ({matched_os}). Maintain regular security patching."
                    rec_config = "Maintain active vendor patch level and security baseline compliance"

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
                        recommendation=rec,
                        metric_period="Microsoft Official OS Lifecycle",
                        data_source="Microsoft.Compute VirtualMachines API (2023-09-01)",
                        evidence={
                            "os_type": os_type,
                            "os_version": guest_os_version,
                            "os_build": os_build,
                            "publisher": publisher,
                            "image_version": image_ver,
                            "support_status": matched_status,
                            "end_of_support_date": matched_eos,
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
