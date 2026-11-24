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
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()

        for sub in context.subscriptions:
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=cost_start,
                end_date=cost_end,
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
                rg_name = parsed.get("resource_group") or "Unknown"
                env_name = "Production" if not any(x in rg_name.lower() for x in ["test", "dev", "qa"]) else "Non-Production"

                # Classify all VM license dimensions
                is_windows = os_type == "windows" or "windowsserver" in offer or "microsoftwindowsserver" in publisher or "windows" in offer
                is_sql = "sql" in offer or "microsoftsqlserver" in publisher or "sql" in sku_str or "sql" in plan_name
                is_rhel = "rhel" in offer or "redhat" in publisher or "redhat" in offer
                is_sles = "sles" in offer or "suse" in publisher or "suse" in offer

                vm_license_rows = []

                # 1. Windows Server / Windows Client License Row
                if is_windows:
                    if license_type == "Windows_Server":
                        win_status = "Windows Server (AHB Active)"
                        win_label = "Optimized (AHB Active)"
                        win_sev = "Informational"
                        win_sav = 0.0
                        win_rec = f"VM '{vm_name}' is actively utilizing Azure Hybrid Benefit for Windows Server."
                    elif license_type == "Windows_Client":
                        win_status = "Windows Client (Multitenant VDI)"
                        win_label = "Optimized (Hosting Rights)"
                        win_sev = "Informational"
                        win_sav = 0.0
                        win_rec = f"VM '{vm_name}' is licensed under Windows 10/11 Enterprise Multitenant Hosting rights."
                    else:
                        win_status = "Windows Server (PAYG - Eligible for AHB)"
                        win_label = "Eligible for AHB"
                        win_sev = "Medium"
                        win_sav = round(curr_cost * 0.40, 2)
                        win_rec = f"VM '{vm_name}' is billed for on-demand Windows Server licensing. Enable Azure Hybrid Benefit (licenseType: Windows_Server) to save up to 40% compute rate."

                    vm_license_rows.append({
                        "id_suffix": "win",
                        "display_name": f"{vm_name} (Windows)" if is_sql else vm_name,
                        "license_status": win_status,
                        "license_category": "Windows Server",
                        "status_label": win_label,
                        "severity": win_sev,
                        "monthly_saving": win_sav,
                        "recommendation": win_rec
                    })

                # 2. SQL Server License Row (shown in distinct row if present)
                if is_sql:
                    if license_type in ("Base", "AHB"):
                        sql_status = "SQL Server (AHB Active)"
                        sql_label = "Optimized (SQL AHB Active)"
                        sql_sev = "Informational"
                        sql_sav = 0.0
                        sql_rec = f"VM '{vm_name}' has Azure Hybrid Benefit enabled for SQL Server."
                    else:
                        sql_status = "SQL Server (PAYG License)"
                        sql_label = "Eligible for SQL AHB"
                        sql_sev = "Medium"
                        sql_sav = round(curr_cost * 0.35, 2)
                        sql_rec = f"VM '{vm_name}' runs on-demand SQL Server licensing. Enable Azure Hybrid Benefit for SQL Server if licensed under Software Assurance."

                    vm_license_rows.append({
                        "id_suffix": "sql",
                        "display_name": f"{vm_name} (SQL Server)" if is_windows else vm_name,
                        "license_status": sql_status,
                        "license_category": "SQL Server on Azure VM",
                        "status_label": sql_label,
                        "severity": sql_sev,
                        "monthly_saving": sql_sav,
                        "recommendation": sql_rec
                    })

                # 3. RHEL / SLES / Linux
                if not is_windows and not is_sql:
                    if is_rhel:
                        if license_type == "RHEL_BYOS":
                            rhel_status = "RHEL (BYOS Active)"
                            rhel_label = "Optimized (BYOS Active)"
                            rhel_sev = "Informational"
                            rhel_sav = 0.0
                            rhel_rec = f"VM '{vm_name}' uses Red Hat Cloud Access (RHEL_BYOS) licensing."
                        else:
                            rhel_status = "RHEL (PAYG License Billed)"
                            rhel_label = "Eligible for Red Hat BYOS"
                            rhel_sev = "Medium"
                            rhel_sav = 43.80
                            rhel_rec = f"VM '{vm_name}' is billed for on-demand RHEL licensing (~$43.80/mo). Transition to Red Hat Cloud Access (RHEL_BYOS) if enterprise licenses exist."

                        vm_license_rows.append({
                            "id_suffix": "rhel",
                            "display_name": vm_name,
                            "license_status": rhel_status,
                            "license_category": "Red Hat Enterprise Linux",
                            "status_label": rhel_label,
                            "severity": rhel_sev,
                            "monthly_saving": rhel_sav,
                            "recommendation": rhel_rec
                        })
                    elif is_sles:
                        if license_type == "SLES_BYOS":
                            sles_status = "SLES (BYOS Active)"
                            sles_label = "Optimized (BYOS Active)"
                            sles_sev = "Informational"
                            sles_sav = 0.0
                            sles_rec = f"VM '{vm_name}' uses SUSE BYOS licensing."
                        else:
                            sles_status = "SLES (PAYG License Billed)"
                            sles_label = "Eligible for SUSE BYOS"
                            sles_sev = "Medium"
                            sles_sav = 43.80
                            sles_rec = f"VM '{vm_name}' is billed for on-demand SUSE Linux licensing. Transition to SUSE BYOS if subscription exists."

                        vm_license_rows.append({
                            "id_suffix": "sles",
                            "display_name": vm_name,
                            "license_status": sles_status,
                            "license_category": "SUSE Linux Enterprise",
                            "status_label": sles_label,
                            "severity": sles_sev,
                            "monthly_saving": sles_sav,
                            "recommendation": sles_rec
                        })
                    else:
                        distro = offer.replace("-", " ").title() if offer else "Linux"
                        vm_license_rows.append({
                            "id_suffix": "linux",
                            "display_name": vm_name,
                            "license_status": f"Linux ({distro}) - Free Open-Source",
                            "license_category": "Open-Source Linux",
                            "status_label": "Free Open-Source ($0 License)",
                            "severity": "Informational",
                            "monthly_saving": 0.0,
                            "recommendation": f"VM '{vm_name}' runs open-source {distro}. No Azure OS licensing premiums apply."
                        })

                # Create findings for each detected license dimension
                for row in vm_license_rows:
                    findings.append(
                        FindingModel(
                            finding_id=f"cost07-{vm_name[:10]}-{row['id_suffix']}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg_name,
                            resource_name=row["display_name"],
                            resource_type="Microsoft.Compute/virtualMachines",
                            resource_id=vm_id,
                            region=vm.get("location", "global"),
                            severity=row["severity"],
                            status=row["status_label"],
                            current_configuration=f"License: {row['license_status']} | Size: {vm_size}",
                            measured_value=row["license_status"],
                            recommended_configuration=f"Verify license optimization for {row['license_category']}",
                            recommendation=row["recommendation"],
                            metric_period=f"Last Completed Month ({cost_month})",
                            data_source="Microsoft.Compute VirtualMachines API",
                            evidence={
                                "os_type": os_type,
                                "license_type": license_type or "None (PAYG)",
                                "license_status": row["license_status"],
                                "license_category": row["license_category"],
                                "vm_size": vm_size,
                                "environment": env_name,
                                "actual_cost_mtd": round(curr_cost, 2),
                                "cost_month": cost_month
                            },
                            current_monthly_cost=round(curr_cost, 2),
                            estimated_monthly_savings=row["monthly_saving"] if row["monthly_saving"] > 0 else None,
                            estimated_annual_savings=round(row["monthly_saving"] * 12, 2) if row["monthly_saving"] > 0 else None,
                            currency=currency,
                            savings_type="Scenario Savings" if row["monthly_saving"] > 0 else "Not Estimated",
                            confidence="High",
                            calculation_method="Azure Hybrid Benefit / BYOS licensing discount",
                            validation_required="Confirm Software Assurance / Cloud Access entitlements before applying AHB",
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
