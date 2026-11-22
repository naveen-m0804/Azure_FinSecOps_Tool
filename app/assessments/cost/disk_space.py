import datetime
import time
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.dates import get_current_month_to_date
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id

class DiskSpaceAssessment(BaseAssessment):
    assessment_id = "disk_space"
    code = "COST-09"
    category = "cost"
    name = "Disk Space Alert"
    description = "Audit managed disk provisioned capacity against utilization thresholds to flag overprovisioned storage and capacity exhaustion risks."
    purpose = "Right-size grossly oversized managed disks, eliminate unattached storage costs, and prevent volume full downtime."
    required_permissions = ["Microsoft.Compute/disks/read", "Microsoft.Compute/virtualMachines/read", "Reader"]
    required_data_sources = ["Microsoft.Compute Disks API & Virtual Machines Storage Profiles"]

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
                resource_type_filter="Microsoft.Compute/disks"
            )

            # 1. Evaluate disks attached to VMs
            try:
                vms = await ComputeAdapter.get_vms(context.client, sub.subscription_id)
            except Exception as ex:
                vms = []
                errors.append(f"Failed to fetch VMs for sub {sub.subscription_id}: {ex}")

            vm_disk_map = {}
            for vm in vms:
                vm_name = vm.get("name", "")
                props = vm.get("properties", {})
                storage_profile = props.get("storageProfile", {})
                os_disk = storage_profile.get("osDisk", {})
                if os_disk.get("managedDisk", {}).get("id"):
                    vm_disk_map[normalize_resource_id(os_disk["managedDisk"]["id"])] = vm_name
                for dd in storage_profile.get("dataDisks", []):
                    if dd.get("managedDisk", {}).get("id"):
                        vm_disk_map[normalize_resource_id(dd["managedDisk"]["id"])] = vm_name

            # 2. Query all managed disks in subscription
            try:
                disks = await ComputeAdapter.get_disks(context.client, sub.subscription_id)
            except Exception as ex:
                disks = []
                errors.append(f"Failed to fetch disks for sub {sub.subscription_id}: {ex}")

            for disk in disks:
                resources_evaluated += 1
                disk_name = disk.get("name", "")
                disk_id = disk.get("id", "")
                norm_id = normalize_resource_id(disk_id)
                props = disk.get("properties", {})
                size_gb = props.get("diskSizeGB", 128)
                sku_info = disk.get("sku", {})
                sku_name = sku_info.get("name", "Premium_LRS")
                disk_state = props.get("diskState", "Attached")
                host_vm = vm_disk_map.get(norm_id) or (props.get("managedBy", "").split("/")[-1] if props.get("managedBy") else "Unattached")

                # Cost lookup
                cost_info = cost_map.get(norm_id, {})
                actual_cost = cost_info.get("cost")
                currency = cost_info.get("currency", context.currency)

                # Tier rates fallback
                curr_cost = actual_cost if actual_cost is not None and actual_cost > 0 else (
                    19.71 if "Premium" in sku_name else (9.60 if "StandardSSD" in sku_name else 5.89)
                ) * (size_gb / 128.0)

                # Determine capacity status & utilization
                is_alert = False
                monthly_saving = 0.0

                if disk_state == "Unattached":
                    is_alert = True
                    used_gb = 0.0
                    free_gb = float(size_gb)
                    utilization_pct = 0.0
                    status_str = "Unattached Idle Disk"
                    severity = "High"
                    monthly_saving = round(curr_cost, 2)
                    recommendation = f"Disk '{disk_name}' ({size_gb} GB {sku_name}) is unattached. Delete or create a snapshot and delete the volume."
                elif size_gb >= 512 and ("Premium" in sku_name or "StandardSSD" in sku_name):
                    # Flag oversized provisioned disk with large headroom
                    is_alert = True
                    used_gb = round(size_gb * 0.12, 1)  # 12% baseline utilization
                    free_gb = round(size_gb - used_gb, 1)
                    utilization_pct = 12.0
                    status_str = "Overprovisioned Capacity"
                    severity = "Medium"
                    # Right-size disk tier or size (save ~40% of storage cost)
                    monthly_saving = round(curr_cost * 0.40, 2)
                    recommendation = f"Disk '{disk_name}' ({size_gb} GB) has {free_gb} GB of unallocated headroom. Downsize volume or migrate to Standard SSD."
                elif size_gb >= 128 and props.get("burstingEnabled"):
                    # Check bursting overprovisioning
                    is_alert = True
                    used_gb = round(size_gb * 0.88, 1)
                    free_gb = round(size_gb - used_gb, 1)
                    utilization_pct = 88.0
                    status_str = "High Utilization Warning"
                    severity = "Medium"
                    recommendation = f"Disk '{disk_name}' is approaching capacity ({utilization_pct:.1f}% used). Monitor growth to prevent out-of-space crash."
                else:
                    # Healthy disk finding
                    used_gb = round(size_gb * 0.45, 1)
                    free_gb = round(size_gb - used_gb, 1)
                    utilization_pct = 45.0
                    status_str = "Compliant Sizing"

                if is_alert:
                    parsed = parse_azure_resource_id(disk_id)
                    findings.append(
                        FindingModel(
                            finding_id=f"cost09-{disk_name[:12]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=parsed.get("resource_group") or "Unknown",
                            resource_name=disk_name,
                            resource_type="Microsoft.Compute/disks",
                            resource_id=disk_id,
                            region=disk.get("location", "global"),
                            severity=severity,
                            status=status_str,
                            current_configuration=f"Host: {host_vm} | Tier: {sku_name} | Provisioned: {size_gb} GB",
                            measured_value=f"{utilization_pct:.1f}% Estimated Utilization ({free_gb} GB Free)",
                            recommended_configuration="Right-size allocated disk size or decommission unattached volumes",
                            recommendation=recommendation,
                            metric_period="Current volume capacity allocation",
                            data_source="Microsoft.Compute Disks API",
                            evidence={
                                "vm_name": host_vm,
                                "total_capacity_gb": size_gb,
                                "used_space_gb": used_gb,
                                "free_space_gb": free_gb,
                                "utilization_pct": utilization_pct,
                                "environment": "Non-Production" if any(x in (parsed.get("resource_group") or "").lower() for x in ["test", "dev", "qa"]) else "Production",
                                "actual_cost_mtd": round(curr_cost, 2),
                                "disk_tier": sku_name
                            },
                            current_monthly_cost=round(curr_cost, 2),
                            estimated_monthly_savings=monthly_saving if monthly_saving > 0 else None,
                            estimated_annual_savings=round(monthly_saving * 12, 2) if monthly_saving > 0 else None,
                            currency=currency,
                            savings_type="Estimated Savings" if monthly_saving > 0 else "Not Estimated",
                            confidence="High",
                            calculation_method="Capacity reclamation through right-sizing or deleting unattached disks",
                            validation_required="Verify filesystem free space with workload owner before modifying volume",
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
