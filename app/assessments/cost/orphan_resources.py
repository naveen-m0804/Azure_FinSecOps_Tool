import asyncio
import datetime
import time
from typing import List
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.compute import ComputeAdapter
from app.azure.network import NetworkAdapter
from app.azure.resources import ResourcesAdapter
from app.azure.pricing import PricingEngine
from app.utils.resource_ids import parse_azure_resource_id
from app.utils.environment import resolve_environment

class OrphanResourcesAssessment(BaseAssessment):
    assessment_id = "orphan_resources"
    code = "COST-02"
    category = "cost"
    name = "Orphan Resources"
    description = "Identify unattached managed disks, unassociated public IPs, unattached NICs, and empty App Service Plans."
    purpose = "Eliminate unnecessary Azure spend on obsolete resources detached from active workloads."
    required_permissions = [
        "Microsoft.Compute/disks/read",
        "Microsoft.Network/publicIPAddresses/read",
        "Microsoft.Network/networkInterfaces/read",
        "Microsoft.Web/serverfarms/read",
        "Microsoft.Web/sites/read",
        "Reader"
    ]
    required_data_sources = ["Microsoft.Compute, Microsoft.Network, Microsoft.Web APIs"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        total_resources_evaluated = 0
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()

        # Concurrent subscription evaluation to handle large enterprise tenants (25+ subs) in seconds
        sub_sem = asyncio.Semaphore(5)

        async def evaluate_sub(sub):
            nonlocal total_resources_evaluated
            async with sub_sem:
                sub_findings = []
                sub_errors = []
                sub_eval_count = 0

                try:
                    cost_map = await CostManagementAdapter.query_resource_costs(
                        context.client,
                        subscription_id=sub.subscription_id,
                        start_date=cost_start,
                        end_date=cost_end
                    )
                except Exception:
                    cost_map = {}

                # 1. Unattached Managed Disks (managedBy is None)
                try:
                    disks = await ComputeAdapter.get_disks(context.client, sub.subscription_id)
                    for d in disks:
                        sub_eval_count += 1
                        managed_by = d.get("managedBy")
                        if not managed_by:
                            d_name = d.get("name", "")
                            d_id = d.get("id", "")
                            sku = d.get("sku", {}).get("name", "Standard_LRS")
                            size_gb = d.get("properties", {}).get("diskSizeGB", 128)
                            pricing_price = PricingEngine.get_disk_monthly_price(sku, size_gb)
                            norm_id = normalize_resource_id(d_id)
                            cost_val = cost_map.get(norm_id, {}).get("cost")
                            monthly_price = cost_val if cost_val is not None and cost_val > 0 else pricing_price
                            parsed = parse_azure_resource_id(d_id)
                            rg_name = parsed.get("resource_group") or "Unknown"
                            tags = d.get("tags") or {}
                            env_val = resolve_environment(tags, d_name, rg_name, prod_tags=context.prod_tags, test_tags=context.test_tags, target_tags=context.target_tags)

                            sub_findings.append(
                                FindingModel(
                                    finding_id=f"cost02-disk-{sub.subscription_id[:8]}-{d_name[:12]}",
                                    assessment_id=self.assessment_id,
                                    category=self.category,
                                    subscription_id=sub.subscription_id,
                                    subscription_name=sub.display_name,
                                    resource_group=rg_name,
                                    resource_name=d_name,
                                    resource_type="Microsoft.Compute/disks",
                                    resource_id=d_id,
                                    region=d.get("location", "global"),
                                    severity="Medium",
                                    status="Unattached Managed Disk",
                                    current_configuration=f"SKU: {sku} | Size: {size_gb} GB",
                                    measured_value="ManagedBy property is null",
                                    recommended_configuration="Verify backup requirement and delete unattached disk",
                                    recommendation=f"Managed disk '{d_name}' is unattached to any VM and continues to incur storage charges.",
                                    metric_period=f"Last Completed Month ({cost_month})",
                                    data_source="Microsoft.Compute Disks API",
                                    evidence={
                                        "managed_by": None,
                                        "sku": sku,
                                        "size_gb": size_gb,
                                        "actual_cost_mtd": round(monthly_price, 2),
                                        "cost_month": cost_month,
                                        "environment": env_val,
                                        "orphan_reason": "Disk is not attached to any virtual machine"
                                    },
                                    current_monthly_cost=round(monthly_price, 2),
                                    estimated_monthly_savings=round(monthly_price, 2),
                                    estimated_annual_savings=round(monthly_price * 12, 2),
                                    currency=context.currency,
                                    savings_type="Actual Cost",
                                    confidence="High",
                                    calculation_method="100% avoidable monthly disk storage fee",
                                    validation_required="Confirm data retention compliance before deleting",
                                    collected_at=now_str
                                )
                            )
                except Exception as ex:
                    sub_errors.append(f"Failed to evaluate managed disks for sub {sub.display_name}: {ex}")

                # 2. Unattached Public IPs (ipConfiguration is None)
                try:
                    public_ips = await NetworkAdapter.get_public_ips(context.client, sub.subscription_id)
                    for pip in public_ips:
                        sub_eval_count += 1
                        props = pip.get("properties", {})
                        ip_config = props.get("ipConfiguration")
                        if not ip_config:
                            pip_name = pip.get("name", "")
                            pip_id = pip.get("id", "")
                            sku_name = pip.get("sku", {}).get("name", "Standard")
                            monthly_price = PricingEngine.get_public_ip_monthly_price(sku_name)
                            parsed = parse_azure_resource_id(pip_id)
                            rg_name = parsed.get("resource_group") or "Unknown"
                            tags = pip.get("tags") or {}
                            env_val = resolve_environment(tags, pip_name, rg_name, prod_tags=context.prod_tags, test_tags=context.test_tags, target_tags=context.target_tags)

                            sub_findings.append(
                                FindingModel(
                                    finding_id=f"cost02-pip-{sub.subscription_id[:8]}-{pip_name[:12]}",
                                    assessment_id=self.assessment_id,
                                    category=self.category,
                                    subscription_id=sub.subscription_id,
                                    subscription_name=sub.display_name,
                                    resource_group=rg_name,
                                    resource_name=pip_name,
                                    resource_type="Microsoft.Network/publicIPAddresses",
                                    resource_id=pip_id,
                                    region=pip.get("location", "global"),
                                    severity="Low",
                                    status="Unassociated Public IP",
                                    current_configuration=f"SKU: {sku_name} | Allocation: {props.get('publicIPAllocationMethod', 'Static')}",
                                    measured_value="ipConfiguration property is null",
                                    recommended_configuration="Disassociate or release unattached public IP address",
                                    recommendation=f"Public IP '{pip_name}' is not associated with any NIC or resource and incurs hourly reservation charges.",
                                    metric_period="Current configuration",
                                    data_source="Microsoft.Network PublicIPAddresses API",
                                    evidence={
                                        "ip_configuration": None,
                                        "sku": sku_name,
                                        "ip_address": props.get("ipAddress", "Pending"),
                                        "actual_cost_mtd": round(monthly_price, 2),
                                        "environment": env_val,
                                        "orphan_reason": "Public IP is not associated with any network interface"
                                    },
                                    current_monthly_cost=round(monthly_price, 2),
                                    estimated_monthly_savings=round(monthly_price, 2),
                                    estimated_annual_savings=round(monthly_price * 12, 2),
                                    currency=context.currency,
                                    savings_type="Actual Cost",
                                    confidence="High",
                                    calculation_method="100% avoidable public IP reservation fee",
                                    validation_required="Confirm no inbound DNS routing dependencies before deleting",
                                    collected_at=now_str
                                )
                            )
                except Exception as ex:
                    sub_errors.append(f"Failed to evaluate public IPs for sub {sub.display_name}: {ex}")

                # 3. Unattached Network Interfaces (virtualMachine is None and not attached to private endpoints)
                try:
                    nics = await NetworkAdapter.get_network_interfaces(context.client, sub.subscription_id)
                    for nic in nics:
                        sub_eval_count += 1
                        props = nic.get("properties", {})
                        vm_ref = props.get("virtualMachine")
                        priv_end = props.get("privateEndpoint")
                        hosted_workloads = props.get("hostedWorkloads")
                        if not vm_ref and not priv_end and not hosted_workloads:
                            nic_name = nic.get("name", "")
                            nic_id = nic.get("id", "")
                            monthly_price = PricingEngine.NIC_MONTHLY
                            parsed = parse_azure_resource_id(nic_id)
                            rg_name = parsed.get("resource_group") or "Unknown"
                            tags = nic.get("tags") or {}
                            env_val = resolve_environment(tags, nic_name, rg_name, prod_tags=context.prod_tags, test_tags=context.test_tags, target_tags=context.target_tags)

                            sub_findings.append(
                                FindingModel(
                                    finding_id=f"cost02-nic-{sub.subscription_id[:8]}-{nic_name[:12]}",
                                    assessment_id=self.assessment_id,
                                    category=self.category,
                                    subscription_id=sub.subscription_id,
                                    subscription_name=sub.display_name,
                                    resource_group=rg_name,
                                    resource_name=nic_name,
                                    resource_type="Microsoft.Network/networkInterfaces",
                                    resource_id=nic_id,
                                    region=nic.get("location", "global"),
                                    severity="Low",
                                    status="Unattached NIC",
                                    current_configuration="Detached from Virtual Machine & Private Endpoint",
                                    measured_value="virtualMachine reference is null",
                                    recommended_configuration="Verify IP allocation and remove detached NIC to clean network clutter",
                                    recommendation=f"Network interface '{nic_name}' is not attached to any VM or service.",
                                    metric_period="Current configuration",
                                    data_source="Microsoft.Network NetworkInterfaces API",
                                    evidence={
                                        "virtual_machine": None,
                                        "private_endpoint": None,
                                        "actual_cost_mtd": 0.0,
                                        "environment": env_val,
                                        "orphan_reason": "NIC is detached from any compute resource"
                                    },
                                    current_monthly_cost=0.0,
                                    estimated_monthly_savings=0.0,
                                    estimated_annual_savings=0.0,
                                    currency=context.currency,
                                    savings_type="Housekeeping",
                                    confidence="High",
                                    calculation_method="Zero monthly fee; hygiene optimization",
                                    validation_required="Confirm no static IP reservation requirements before deletion",
                                    collected_at=now_str
                                )
                            )
                except Exception as ex:
                    sub_errors.append(f"Failed to evaluate NICs for sub {sub.display_name}: {ex}")

                # 4. Empty App Service Plans (numberOfSites == 0 & unreferenced by web/function apps)
                try:
                    plans = await ResourcesAdapter.get_app_service_plans(context.client, sub.subscription_id)
                    web_apps = await ResourcesAdapter.get_web_apps(context.client, sub.subscription_id)
                    active_plan_ids = {
                        (app.get("properties", {}).get("serverFarmId") or "").lower()
                        for app in web_apps if app.get("properties", {}).get("serverFarmId")
                    }

                    for plan in plans:
                        sub_eval_count += 1
                        plan_id = plan.get("id", "")
                        plan_props = plan.get("properties", {})
                        num_sites = plan_props.get("numberOfSites", 0)

                        if num_sites == 0 and plan_id.lower() not in active_plan_ids:
                            plan_name = plan.get("name", "")
                            sku_info = plan.get("sku", {})
                            sku_tier = sku_info.get("tier", "Standard")
                            sku_size = sku_info.get("name", sku_info.get("size", "S1"))
                            capacity = int(sku_info.get("capacity") or plan_props.get("targetWorkerCount") or 1)
                            monthly_price = PricingEngine.get_app_service_plan_monthly_price(sku_tier, sku_size, capacity)

                            parsed = parse_azure_resource_id(plan_id)
                            rg_name = parsed.get("resource_group") or "Unknown"
                            tags = plan.get("tags") or {}
                            env_val = resolve_environment(
                                tags, plan_name, rg_name,
                                prod_tags=context.prod_tags,
                                test_tags=context.test_tags,
                                target_tags=context.target_tags
                            )

                            sub_findings.append(
                                FindingModel(
                                    finding_id=f"cost02-plan-{sub.subscription_id[:8]}-{plan_name[:12]}",
                                    assessment_id=self.assessment_id,
                                    category=self.category,
                                    subscription_id=sub.subscription_id,
                                    subscription_name=sub.display_name,
                                    resource_group=rg_name,
                                    resource_name=plan_name,
                                    resource_type="Microsoft.Web/serverfarms",
                                    resource_id=plan_id,
                                    region=plan.get("location", "global"),
                                    severity="High" if monthly_price > 100 else ("Medium" if monthly_price > 0 else "Low"),
                                    status="Orphan App Service Plan (No Apps)",
                                    current_configuration=f"SKU: {sku_tier} {sku_size} | Capacity: {capacity} | Active Sites: 0",
                                    measured_value="numberOfSites is 0 with no active Web or Function Apps attached",
                                    recommended_configuration="Verify with application teams and delete obsolete App Service Plan",
                                    recommendation=f"App Service Plan '{plan_name}' has 0 active apps or function apps attached and continues to incur plan compute charges.",
                                    metric_period="Current configuration",
                                    data_source="Microsoft.Web ServerFarms API",
                                    evidence={
                                        "number_of_sites": 0,
                                        "sku_name": sku_size,
                                        "sku_tier": sku_tier,
                                        "capacity": capacity,
                                        "environment": env_val,
                                        "actual_cost_mtd": round(monthly_price, 2),
                                        "orphan_reason": "App Service Plan has 0 attached web or function apps"
                                    },
                                    current_monthly_cost=round(monthly_price, 2),
                                    estimated_monthly_savings=round(monthly_price, 2),
                                    estimated_annual_savings=round(monthly_price * 12, 2),
                                    currency=context.currency,
                                    savings_type="Actual Cost",
                                    confidence="High",
                                    calculation_method="100% avoidable monthly App Service Plan compute rate",
                                    validation_required="Confirm with application teams before deleting App Service Plan",
                                    collected_at=now_str
                                )
                            )
                except Exception as ex:
                    sub_errors.append(f"Failed to evaluate App Service Plans for sub {sub.display_name}: {ex}")

                return sub_findings, sub_errors, sub_eval_count

        tasks = [evaluate_sub(sub) for sub in context.subscriptions]
        sub_results = await asyncio.gather(*tasks)

        for s_findings, s_errors, s_count in sub_results:
            findings.extend(s_findings)
            errors.extend(s_errors)
            total_resources_evaluated += s_count

        total_monthly = sum((f.estimated_monthly_savings or 0.0) for f in findings)
        status = AssessmentStatus.COMPLETED if findings else AssessmentStatus.NO_FINDINGS
        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(total_resources_evaluated, len(context.subscriptions)),
            findings_count=len(findings),
            findings=findings,
            total_monthly_savings=round(total_monthly, 2),
            total_annual_savings=round(total_monthly * 12, 2),
            currency=context.currency,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
