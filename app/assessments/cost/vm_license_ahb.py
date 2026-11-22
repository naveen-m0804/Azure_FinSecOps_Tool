import datetime
import time
from typing import List
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.dates import get_current_month_to_date
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id

class VmLicenseAhbAssessment(BaseAssessment):
    assessment_id = "vm_license_ahb"
    code = "COST-07"
    category = "cost"
    name = "License Cost on VM – Separate"
    description = "Audit and separate all virtual machine operating system and application license types across the fleet (Windows Server PAYG vs AHB, RHEL PAYG vs BYOS, SLES PAYG vs BYOS, SQL Server, and Open-Source Linux)."
    purpose = "Identify license expenditures, verify Azure Hybrid Benefit (AHB) adoption, and uncover BYOS optimization opportunities across all VM license models."
    required_permissions = ["Microsoft.Compute/virtualMachines/read", "Reader"]
    required_data_sources = ["Microsoft.Compute VirtualMachines API"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        mtd_start, mtd_end = get_current_month_to_date()

        for sub in context.subscriptions:
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=mtd_start,
                end_date=mtd_end,
                resource_type_filter="Microsoft.Compute/virtualMachines"
            )

            vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id)
            for vm in vms:
                resources_evaluated += 1
                vm_name = vm.get("name", "")
                vm_id = vm.get("id", "")
                props = vm.get("properties", {})
                license_type = props.get("licenseType")
                storage_profile = props.get("storageProfile", {})
                os_disk = storage_profile.get("osDisk", {})
                os_type = (os_disk.get("osType") or "").lower()
                image_ref = storage_profile.get("imageReference", {})
                offer = (image_ref.get("offer") or "").lower()
                publisher = (image_ref.get("publisher") or "").lower()
                sku_str = (image_ref.get("sku") or "").lower()
                plan = vm.get("plan", {})
                plan_name = (plan.get("name") or "").lower() if plan else ""

                hardware_profile = props.get("hardwareProfile", {})
                vm_size = hardware_profile.get("vmSize", "Standard_D2s_v5")
                rates = PricingEngine.get_vm_rates(vm_size)

                norm_id = normalize_resource_id(vm_id)
                cost_info = cost_map.get(norm_id, {})
                actual_cost = cost_info.get("cost")
                currency = cost_info.get("currency", context.currency)
                curr_cost = actual_cost if actual_cost is not None and actual_cost > 0 else rates.get("monthly", 87.60)
                parsed = parse_azure_resource_id(vm_id)

                # Classify all VM license types
                is_windows = os_type == "windows" or "windowsserver" in offer or "microsoftwindowsserver" in publisher or "windows" in offer
                is_sql = "sql" in offer or "microsoftsqlserver" in publisher or "sql" in sku_str or "sql" in plan_name
                is_rhel = "rhel" in offer or "redhat" in publisher or "redhat" in offer
                is_sles = "sles" in offer or "suse" in publisher or "suse" in offer

                monthly_saving = 0.0
                confidence = "High"

                if is_sql:
                    if license_type in ("Base", "AHB"):
                        license_status = "SQL Server (AHB Active)"
                        license_category = "SQL Server on Azure VM"
                        status_label = "Optimized (SQL AHB Active)"
                        severity = "Informational"
                        recommendation = f"VM '{vm_name}' has Azure Hybrid Benefit enabled for SQL Server."
                    else:
                        license_status = "SQL Server (PAYG License)"
                        license_category = "SQL Server on Azure VM"
                        status_label = "Eligible for SQL AHB"
                        severity = "Medium"
                        monthly_saving = round(curr_cost * 0.35, 2)
                        recommendation = f"VM '{vm_name}' runs on-demand SQL Server licensing. Enable Azure Hybrid Benefit for SQL Server if licensed under Software Assurance."

                elif is_windows:
                    if license_type == "Windows_Server":
                        license_status = "Windows Server (AHB Active)"
                        license_category = "Windows Server"
                        status_label = "Optimized (AHB Active)"
                        severity = "Informational"
                        recommendation = f"VM '{vm_name}' is actively utilizing Azure Hybrid Benefit for Windows Server."
                    elif license_type == "Windows_Client":
                        license_status = "Windows Client (Multitenant VDI)"
                        license_category = "Windows Client"
                        status_label = "Optimized (Hosting Rights)"
                        severity = "Informational"
                        recommendation = f"VM '{vm_name}' is licensed under Windows 10/11 Enterprise Multitenant Hosting rights."
                    else:
                        license_status = "Windows Server (PAYG - Eligible for AHB)"
                        license_category = "Windows Server"
                        status_label = "Eligible for AHB"
                        severity = "Medium"
                        monthly_saving = round(curr_cost * 0.40, 2)
                        recommendation = f"VM '{vm_name}' is billed for on-demand Windows Server licensing. Enable Azure Hybrid Benefit (licenseType: Windows_Server) to save up to 40% compute rate."

                elif is_rhel:
                    if license_type == "RHEL_BYOS":
                        license_status = "RHEL (BYOS Active)"
                        license_category = "Red Hat Enterprise Linux"
                        status_label = "Optimized (BYOS Active)"
                        severity = "Informational"
                        recommendation = f"VM '{vm_name}' uses Red Hat Cloud Access (RHEL_BYOS) licensing."
                    else:
                        license_status = "RHEL (PAYG License Billed)"
                        license_category = "Red Hat Enterprise Linux"
                        status_label = "Eligible for Red Hat BYOS"
                        severity = "Medium"
                        monthly_saving = 43.80  # Approximate monthly RHEL license surcharge
                        recommendation = f"VM '{vm_name}' is billed for on-demand RHEL licensing (~$43.80/mo). Transition to Red Hat Cloud Access (RHEL_BYOS) if enterprise licenses exist."

                elif is_sles:
                    if license_type == "SLES_BYOS":
                        license_status = "SLES (BYOS Active)"
                        license_category = "SUSE Linux Enterprise"
                        status_label = "Optimized (BYOS Active)"
                        severity = "Informational"
                        recommendation = f"VM '{vm_name}' uses SUSE BYOS licensing."
                    else:
                        license_status = "SLES (PAYG License Billed)"
                        license_category = "SUSE Linux Enterprise"
                        status_label = "Eligible for SUSE BYOS"
                        severity = "Medium"
                        monthly_saving = 43.80  # Approximate monthly SLES license surcharge
                        recommendation = f"VM '{vm_name}' is billed for on-demand SUSE Linux licensing. Transition to SUSE BYOS if subscription exists."

                else:
                    # Standard Open Source Linux
                    distro = offer.replace("-", " ").title() if offer else "Linux"
                    license_status = f"Linux ({distro}) - Free Open-Source"
                    license_category = "Open-Source Linux"
                    status_label = "Free Open-Source ($0 License)"
                    severity = "Informational"
                    recommendation = f"VM '{vm_name}' runs open-source {distro}. No Azure OS licensing premiums apply."

                findings.append(
                    FindingModel(
                        finding_id=f"cost07-{vm_name[:12]}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=parsed.get("resource_group") or "Unknown",
                        resource_name=vm_name,
                        resource_type="Microsoft.Compute/virtualMachines",
                        resource_id=vm_id,
                        region=vm.get("location", "global"),
                        severity=severity,
                        status=status_label,
                        current_configuration=f"License: {license_status} | Size: {vm_size}",
                        measured_value=license_status,
                        recommended_configuration=f"Verify license optimization for {license_category}",
                        recommendation=recommendation,
                        metric_period="Current configuration",
                        data_source="Microsoft.Compute VirtualMachines API",
                        evidence={
                            "os_type": os_type,
                            "license_type": license_type or "None (PAYG)",
                            "license_status": license_status,
                            "license_category": license_category,
                            "vm_size": vm_size,
                            "environment": "Production" if not any(x in (parsed.get("resource_group") or "").lower() for x in ["test", "dev", "qa"]) else "Non-Production",
                            "actual_cost_mtd": round(curr_cost, 2)
                        },
                        current_monthly_cost=round(curr_cost, 2),
                        estimated_monthly_savings=monthly_saving if monthly_saving > 0 else None,
                        estimated_annual_savings=round(monthly_saving * 12, 2) if monthly_saving > 0 else None,
                        currency=currency,
                        savings_type="Scenario Savings" if monthly_saving > 0 else "Not Estimated",
                        confidence=confidence,
                        calculation_method="Deduplicated compute license savings based on eligible AHB or BYOS models",
                        validation_required="Customer must verify eligible licenses with active Software Assurance / Cloud Access",
                        collected_at=now_str
                    )
                )

        total_monthly = sum((f.estimated_monthly_savings or 0.0) for f in findings if f.estimated_monthly_savings)
        status = AssessmentStatus.COMPLETED if findings else AssessmentStatus.NO_FINDINGS
        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(resources_evaluated, 1),
            findings_count=len(findings),
            findings=findings,
            total_monthly_savings=round(total_monthly, 2),
            total_annual_savings=round(total_monthly * 12, 2),
            currency=context.currency,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
