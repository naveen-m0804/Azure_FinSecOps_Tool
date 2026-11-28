import datetime
import time
from typing import List, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment, matches_target_tags


class VmLicenseAhbAssessment(BaseAssessment):
    assessment_id = "vm_license_ahb"
    code = "COST-07"
    category = "cost"
    name = "License Cost on VM – Separate"
    description = "Audit and separate all virtual machine operating system and application license types across the fleet (Windows Server PAYG vs AHB, RHEL PAYG vs BYOS, SLES PAYG vs BYOS, SQL Server, and Open-Source Linux)."
    purpose = "Identify license expenditures, verify Azure Hybrid Benefit (AHB) adoption, and uncover BYOS optimization opportunities across all VM license models."
    required_permissions = ["Microsoft.Compute/virtualMachines/read", "Reader"]
    required_data_sources = ["Microsoft.Compute VirtualMachines API", "Azure Cost Management", "Azure Retail Prices API"]

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
                if not matches_target_tags(vm.get("tags"), context.target_tags):
                    continue
                resources_evaluated += 1
                vm_name = vm.get("name", "")
                vm_id = vm.get("id", "")
                region = vm.get("location", "")
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
                vm_size = hardware_profile.get("vmSize")
                if not vm_size:
                    continue

                norm_id = normalize_resource_id(vm_id)
                cost_info = cost_map.get(norm_id, {})
                actual_cost = cost_info.get("cost")
                currency = cost_info.get("currency", context.currency)

                curr_cost: Optional[float] = float(actual_cost) if (actual_cost is not None and actual_cost > 0) else None
                if curr_cost is None:
                    vm_rates = await PricingEngine.get_vm_rates(vm_size, region, os_type=os_type or "Linux", currency=currency)
                    if vm_rates and vm_rates.get("monthly") is not None:
                        curr_cost = vm_rates["monthly"]

                parsed = parse_azure_resource_id(vm_id)
                rg_name = parsed.get("resource_group") or "Unknown"
                env_name = resolve_environment(
                    tags=vm.get("tags") or {},
                    resource_name=vm_name,
                    resource_group=rg_name,
                    prod_tags=context.prod_tags,
                    test_tags=context.test_tags,
                    target_tags=context.target_tags,
                )

                is_windows = os_type == "windows" or "windowsserver" in offer or "microsoftwindowsserver" in publisher or "windows" in offer
                is_sql = "sql" in offer or "microsoftsqlserver" in publisher or "sql" in sku_str or "sql" in plan_name
                is_rhel = "rhel" in offer or "redhat" in publisher or "redhat" in offer
                is_sles = "sles" in offer or "suse" in publisher or "suse" in offer

                vm_license_rows = []

                # 1. Windows Server / Windows Client License Row
                if is_windows:
                    if license_type == "Windows_Server":
                        vm_license_rows.append({
                            "id_suffix": "win",
                            "display_name": f"{vm_name} (Windows)" if is_sql else vm_name,
                            "license_status": "Windows Server (AHB Active)",
                            "license_category": "Windows Server",
                            "status_label": "Optimized (AHB Active)",
                            "severity": "Informational",
                            "monthly_saving": None,
                            "savings_pct": None,
                            "recommendation": f"VM '{vm_name}' is actively utilizing Azure Hybrid Benefit for Windows Server.",
                        })
                    elif license_type == "Windows_Client":
                        vm_license_rows.append({
                            "id_suffix": "win",
                            "display_name": f"{vm_name} (Windows)" if is_sql else vm_name,
                            "license_status": "Windows Client (Multitenant VDI)",
                            "license_category": "Windows Client",
                            "status_label": "Optimized (Hosting Rights)",
                            "severity": "Informational",
                            "monthly_saving": None,
                            "savings_pct": None,
                            "recommendation": f"VM '{vm_name}' is licensed under Windows 10/11 Enterprise Multitenant Hosting rights.",
                        })
                    else:
                        # Formula (R8): Monthly savings = eligible PAYG license charge - eligible AHB charge
                        rate_diff = await PricingEngine.get_vm_license_rate_diff(vm_size, region, "windows", currency=currency)
                        win_sav = rate_diff["license_charge_monthly"] if rate_diff else None
                        payg_lic = rate_diff["license_charge_monthly"] if rate_diff else None
                        win_pct = round((win_sav / payg_lic) * 100.0, 2) if (win_sav is not None and payg_lic and payg_lic > 0) else None
                        vm_license_rows.append({
                            "id_suffix": "win",
                            "display_name": f"{vm_name} (Windows)" if is_sql else vm_name,
                            "license_status": "Windows Server (PAYG - Eligible for AHB)",
                            "license_category": "Windows Server",
                            "status_label": "Eligible for AHB",
                            "severity": "Medium",
                            "monthly_saving": win_sav,
                            "savings_pct": win_pct,
                            "recommendation": (
                                f"VM '{vm_name}' is billed for on-demand Windows Server licensing. "
                                f"Enable Azure Hybrid Benefit (licenseType: Windows_Server)"
                                + (f" to save {currency} {win_sav:,.2f}/mo." if win_sav is not None else " (license pricing comparison required).")
                            ),
                        })

                # 2. SQL Server License Row
                if is_sql:
                    if license_type in ("Base", "AHB"):
                        vm_license_rows.append({
                            "id_suffix": "sql",
                            "display_name": f"{vm_name} (SQL Server)" if is_windows else vm_name,
                            "license_status": "SQL Server (AHB Active)",
                            "license_category": "SQL Server on Azure VM",
                            "status_label": "Optimized (SQL AHB Active)",
                            "severity": "Informational",
                            "monthly_saving": None,
                            "savings_pct": None,
                            "recommendation": f"VM '{vm_name}' has Azure Hybrid Benefit enabled for SQL Server.",
                        })
                    else:
                        rate_diff = await PricingEngine.get_vm_license_rate_diff(vm_size, region, "sql", currency=currency)
                        sql_sav = rate_diff["license_charge_monthly"] if rate_diff else None
                        sql_pct = 100.0 if (sql_sav is not None and sql_sav > 0) else None
                        vm_license_rows.append({
                            "id_suffix": "sql",
                            "display_name": f"{vm_name} (SQL Server)" if is_windows else vm_name,
                            "license_status": "SQL Server (PAYG License)",
                            "license_category": "SQL Server on Azure VM",
                            "status_label": "Eligible for SQL AHB",
                            "severity": "Medium",
                            "monthly_saving": sql_sav,
                            "savings_pct": sql_pct,
                            "recommendation": f"VM '{vm_name}' runs on-demand SQL Server licensing. Enable Azure Hybrid Benefit for SQL Server if licensed under Software Assurance.",
                        })

                # 3. RHEL / SLES / Linux
                if not is_windows and not is_sql:
                    if is_rhel:
                        if license_type == "RHEL_BYOS":
                            rhel_sav = None
                            rhel_pct = None
                            rhel_status, rhel_label, rhel_sev = "RHEL (BYOS Active)", "Optimized (BYOS Active)", "Informational"
                            rhel_rec = f"VM '{vm_name}' uses Red Hat Cloud Access (RHEL_BYOS) licensing."
                        else:
                            rate_diff = await PricingEngine.get_vm_license_rate_diff(vm_size, region, "rhel", currency=currency)
                            rhel_sav = rate_diff["license_charge_monthly"] if rate_diff else None
                            rhel_pct = 100.0 if (rhel_sav is not None and rhel_sav > 0) else None
                            rhel_status, rhel_label, rhel_sev = "RHEL (PAYG License Billed)", "Eligible for Red Hat BYOS", "Medium"
                            rhel_rec = f"VM '{vm_name}' is billed for on-demand RHEL licensing. Transition to Red Hat Cloud Access (RHEL_BYOS) if enterprise licenses exist."
                        vm_license_rows.append({
                            "id_suffix": "rhel",
                            "display_name": vm_name,
                            "license_status": rhel_status,
                            "license_category": "Red Hat Enterprise Linux",
                            "status_label": rhel_label,
                            "severity": rhel_sev,
                            "monthly_saving": rhel_sav,
                            "savings_pct": rhel_pct,
                            "recommendation": rhel_rec,
                        })
                    elif is_sles:
                        if license_type == "SLES_BYOS":
                            sles_sav = None
                            sles_pct = None
                            sles_status, sles_label, sles_sev = "SLES (BYOS Active)", "Optimized (BYOS Active)", "Informational"
                            sles_rec = f"VM '{vm_name}' uses SUSE BYOS licensing."
                        else:
                            rate_diff = await PricingEngine.get_vm_license_rate_diff(vm_size, region, "sles", currency=currency)
                            sles_sav = rate_diff["license_charge_monthly"] if rate_diff else None
                            sles_pct = 100.0 if (sles_sav is not None and sles_sav > 0) else None
                            sles_status, sles_label, sles_sev = "SLES (PAYG License Billed)", "Eligible for SUSE BYOS", "Medium"
                            sles_rec = f"VM '{vm_name}' is billed for on-demand SUSE Linux licensing. Transition to SUSE BYOS if subscription exists."
                        vm_license_rows.append({
                            "id_suffix": "sles",
                            "display_name": vm_name,
                            "license_status": sles_status,
                            "license_category": "SUSE Linux Enterprise",
                            "status_label": sles_label,
                            "severity": sles_sev,
                            "monthly_saving": sles_sav,
                            "savings_pct": sles_pct,
                            "recommendation": sles_rec,
                        })
                    else:
                        distro = offer.replace("-", " ").title() if offer else "Linux"
                        vm_license_rows.append({
                            "id_suffix": "linux",
                            "display_name": vm_name,
                            "license_status": f"Linux ({distro}) - Free Open-Source",
                            "license_category": "Open-Source Linux",
                            "status_label": "Free Open-Source (No License Fee)",
                            "severity": "Informational",
                            "monthly_saving": None,
                            "savings_pct": None,
                            "recommendation": f"VM '{vm_name}' runs open-source {distro}. No Azure OS licensing premiums apply.",
                        })

                for row in vm_license_rows:
                    m_sav = row["monthly_saving"]
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
                            region=region or "global",
                            severity=row["severity"],
                            status=row["status_label"],
                            current_configuration=f"License: {row['license_status']} | Size: {vm_size}",
                            measured_value=row["license_status"],
                            recommended_configuration=f"Verify license optimization for {row['license_category']}",
                            recommendation=row["recommendation"],
                            metric_period=f"Last Completed Month ({cost_month})",
                            data_source="Microsoft.Compute VirtualMachines API & Azure Retail Prices API",
                            evidence={
                                "os_type": os_type,
                                "license_type": license_type or "None (PAYG)",
                                "license_status": row["license_status"],
                                "license_category": row["license_category"],
                                "recommended_license": (
                                    "Windows_Server (AHB)" if row["id_suffix"] == "win" and row["severity"] != "Informational"
                                    else ("SQL AHB" if row["id_suffix"] == "sql" and row["severity"] != "Informational"
                                          else ("RHEL_BYOS" if row["id_suffix"] == "rhel" and row["severity"] != "Informational"
                                                else ("SLES_BYOS" if row["id_suffix"] == "sles" and row["severity"] != "Informational"
                                                      else "No Change (Optimized)")))
                                ),
                                "vm_size": vm_size,
                                "environment": env_name,
                                "savings_pct": row["savings_pct"],
                                "actual_cost_mtd": round(curr_cost, 2) if curr_cost is not None else None,
                                "cost_month": cost_month
                            },
                            current_monthly_cost=round(curr_cost, 2) if curr_cost is not None else None,
                            estimated_monthly_savings=m_sav if (m_sav is not None and m_sav > 0) else None,
                            estimated_annual_savings=round(m_sav * 12, 2) if (m_sav is not None and m_sav > 0) else None,
                            currency=currency,
                            savings_type="Scenario Savings" if (m_sav is not None and m_sav > 0) else "Not Estimated",
                            confidence="High" if (m_sav is not None and m_sav > 0) else "Not Available",
                            calculation_method="Monthly savings = eligible PAYG license charge - eligible AHB charge; savings % = savings/eligible PAYG license charge; annual = monthly * 12",
                            validation_required="Confirm Software Assurance / Cloud Access entitlements and coverage; avoid overlap with VM resizing.",
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
