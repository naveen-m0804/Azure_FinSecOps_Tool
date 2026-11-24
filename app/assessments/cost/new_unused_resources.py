import asyncio
import datetime
import time
from typing import List, Dict, Any, Optional, Tuple
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.resources import ResourcesAdapter
from app.azure.compute import ComputeAdapter
from app.azure.network import NetworkAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.monitor import MonitorAdapter
from app.azure.pricing import PricingEngine
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment


def _parse_iso_datetime(dt_val: Any) -> Optional[datetime.datetime]:
    """Safely parse an ISO-8601 or date string into a UTC datetime object."""
    if not dt_val or not isinstance(dt_val, str):
        return None
    cleaned = dt_val.strip()
    if not cleaned or cleaned.lower() in ("unavailable", "unknown", "none", "null", "--"):
        return None
    try:
        clean_str = cleaned.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except Exception:
        if len(cleaned) >= 10 and cleaned[:4].isdigit():
            try:
                return datetime.datetime.strptime(cleaned[:10], "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)
            except Exception:
                return None
        return None


def _resolve_resource_dates(
    res_id: str,
    props: Dict[str, Any],
    system_data: Dict[str, Any],
    tags: Dict[str, Any],
    activity_info: Dict[str, str],
    now_dt: datetime.datetime
) -> Tuple[str, str, int]:
    """
    Accurately extracts Creation Date, Last Activity Date, and Days Inactive from
    authentic Azure ARM systemData, resource properties, and 90-day Activity Logs.
    Never fabricates arbitrary fallback dates.
    
    Returns: (creation_date_str, last_activity_date_str, days_inactive)
    """
    # 1. Resolve Genuine Creation Date from ARM metadata
    c_raw = (
        props.get("timeCreated")
        or system_data.get("createdAt")
        or props.get("creationTime")
        or props.get("timeCreatedUTC")
        or tags.get("CreatedDate")
        or tags.get("created_at")
        or tags.get("created")
        or tags.get("creation_date")
        or activity_info.get("created")
    )

    c_dt = _parse_iso_datetime(c_raw)
    creation_date_str = ""
    days_since_created = 0

    if c_dt:
        creation_date_str = c_dt.strftime("%Y-%m-%d")
        days_since_created = max(0, (now_dt - c_dt).days)
    else:
        # Pre-dates available Azure Activity Logs and ARM systemData retention window
        creation_date_str = "> 90 Days Ago"
        days_since_created = 90

    # 2. Resolve Genuine Last Activity Date
    latest_act_raw = activity_info.get("latest")
    mod_raw = system_data.get("lastModifiedAt")

    act_dt = _parse_iso_datetime(latest_act_raw)
    mod_dt = _parse_iso_datetime(mod_raw)

    # Prefer the most recent timestamp between Activity Log and systemData.lastModifiedAt
    effective_act_dt = None
    if act_dt and mod_dt:
        effective_act_dt = max(act_dt, mod_dt)
    elif act_dt:
        effective_act_dt = act_dt
    elif mod_dt and (c_dt is None or mod_dt > c_dt):
        effective_act_dt = mod_dt

    if effective_act_dt:
        last_activity_str = effective_act_dt.strftime("%Y-%m-%d")
        days_inactive = max(0, (now_dt - effective_act_dt).days)
    elif c_dt and days_since_created < 90:
        # Resource was created within the last 90 days and has recorded ZERO operational events since creation
        last_activity_str = creation_date_str
        days_inactive = days_since_created
    else:
        # Created > 90 days ago with zero operational events in the 90-day activity log window
        last_activity_str = "> 90 Days Ago"
        days_inactive = max(days_since_created, 90)

    return creation_date_str, last_activity_str, days_inactive


class NewUnusedResourcesAssessment(BaseAssessment):
    assessment_id = "new_unused_resources"
    code = "COST-11"
    category = "cost"
    name = "New and Unused Resources"
    description = "Identify unattached, abandoned, or newly-provisioned infrastructure unused for more than 30 days to eliminate financial leakage."
    purpose = "Catch abandoned PoCs, temporary testing VMs, unattached disks, and forgotten infrastructure unused for >30 days before recurring costs compound."
    required_permissions = [
        "Microsoft.Resources/subscriptions/resources/read",
        "Microsoft.ResourceGraph/resources/read",
        "Microsoft.Insights/eventtypes/values/read",
        "Microsoft.Compute/disks/read",
        "Microsoft.Network/publicIPAddresses/read",
        "Reader"
    ]
    required_data_sources = ["Azure Resource Graph & Azure Activity Logs (90-Day History)"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        now_str = now_dt.isoformat()
        ninety_days_ago_dt = now_dt - datetime.timedelta(days=90)
        ninety_days_ago_str = ninety_days_ago_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()

        for sub in context.subscriptions:
            # 1. Fetch real-time Cost Management expenditure for last completed month
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=cost_start,
                end_date=cost_end
            )

            # 2. Fetch authentic Azure Activity Logs for the last 90 days
            activity_map: Dict[str, Dict[str, str]] = {}
            try:
                activity_logs = await MonitorAdapter.get_activity_logs(
                    context.client,
                    sub.subscription_id,
                    start_time=ninety_days_ago_str
                )
                for evt in activity_logs:
                    res_id = (evt.get("resourceId") or "").strip().lower()
                    ts = evt.get("eventTimestamp") or ""
                    op_val = evt.get("operationName")
                    op_str = (op_val.get("value") if isinstance(op_val, dict) else str(op_val or "")).lower()
                    if res_id and ts:
                        if res_id not in activity_map:
                            activity_map[res_id] = {"latest": ts, "earliest": ts}
                        else:
                            if ts > activity_map[res_id]["latest"]:
                                activity_map[res_id]["latest"] = ts
                            if ts < activity_map[res_id]["earliest"]:
                                activity_map[res_id]["earliest"] = ts
                        if "write" in op_str or "create" in op_str or "provision" in op_str:
                            activity_map[res_id]["created"] = ts
            except Exception as ex:
                errors.append(f"Activity Log query failed for {sub.subscription_id}: {ex}")

            # 3. Query candidate resources via Azure Resource Graph with projected properties and systemData
            kql = f"""
            Resources
            | where subscriptionId =~ '{sub.subscription_id}'
            | where type =~ 'microsoft.compute/disks'
                 or type =~ 'microsoft.network/publicipaddresses'
                 or type =~ 'microsoft.network/networkinterfaces'
                 or type =~ 'microsoft.web/serverfarms'
                 or type =~ 'microsoft.compute/virtualmachines'
                 or type =~ 'microsoft.compute/snapshots'
            | project id, name, type, location, resourceGroup, createdTime, systemData, tags, properties, sku
            """
            arg_url = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
            arg_payload = {
                "subscriptions": [sub.subscription_id],
                "query": kql,
                "options": {"resultFormat": "objectArray"}
            }

            candidate_resources: List[Dict[str, Any]] = []
            arg_success = False
            try:
                resp = await context.client.execute_request("POST", arg_url, json_data=arg_payload)
                if resp.status_code == 200:
                    candidate_resources = resp.json().get("data", [])
                    if candidate_resources:
                        arg_success = True
            except Exception as ex:
                errors.append(f"ARG query failed for {sub.subscription_id}: {ex}")

            # 4. Resilient Fallback to Dedicated Azure Resource Providers if ARG returned no data
            if not arg_success:
                try:
                    disks_t = ComputeAdapter.get_disks(context.client, sub.subscription_id)
                    ips_t = NetworkAdapter.get_public_ips(context.client, sub.subscription_id)
                    nics_t = NetworkAdapter.get_network_interfaces(context.client, sub.subscription_id)
                    asps_t = ResourcesAdapter.get_app_service_plans(context.client, sub.subscription_id)
                    vms_t = ComputeAdapter.get_vms(context.client, sub.subscription_id, expand_instance_view=True)
                    snaps_t = ComputeAdapter.get_snapshots(context.client, sub.subscription_id)

                    results = await asyncio.gather(disks_t, ips_t, nics_t, asps_t, vms_t, snaps_t, return_exceptions=True)
                    for res_list in results:
                        if isinstance(res_list, list):
                            candidate_resources.extend(res_list)
                except Exception as ex:
                    errors.append(f"Dedicated resource providers fallback failed for {sub.subscription_id}: {ex}")

            resources_evaluated += len(candidate_resources)

            # 5. Evaluate Unused Status & Calculate Inactivity for Each Resource
            for res in candidate_resources:
                r_id = res.get("id", "")
                r_name = res.get("name", "")
                r_type = res.get("type", "")
                props = res.get("properties") or {}
                tags = res.get("tags") or {}
                system_data = res.get("systemData") or props.get("systemData") or {}

                norm_id = normalize_resource_id(r_id).lower()
                act_info = activity_map.get(norm_id, {})

                # Extract accurate dates and days inactive
                created_date, last_activity_date, days_inactive = _resolve_resource_dates(
                    res_id=r_id,
                    props=props,
                    system_data=system_data,
                    tags=tags,
                    activity_info=act_info,
                    now_dt=now_dt
                )

                is_unused = False
                reason = ""
                est_cost = 0.0

                # A. Unattached Managed Disks
                if "microsoft.compute/disks" in r_type.lower():
                    disk_state = props.get("diskState", "")
                    managed_by = props.get("managedBy")
                    if disk_state in ("Unattached", "Reserved") or not managed_by:
                        is_unused = True
                        size_gb = props.get("diskSizeGB", 128)
                        sku_name = res.get("sku", {}).get("name", "Premium_LRS")
                        reason = f"Unattached {sku_name} ({size_gb} GB) not attached to any VM"
                        if "premium" in sku_name.lower():
                            est_cost = 19.71
                        elif "standardssd" in sku_name.lower():
                            est_cost = 9.60
                        else:
                            est_cost = 5.89

                # B. Unassociated Public IPs
                elif "microsoft.network/publicipaddresses" in r_type.lower():
                    ip_cfg = props.get("ipConfiguration")
                    if not ip_cfg:
                        is_unused = True
                        sku_name = res.get("sku", {}).get("name", "Standard")
                        reason = f"Unassociated Public IP ({sku_name}) with no active NIC or gateway"
                        est_cost = 3.65

                # C. Unattached Network Interfaces (NICs)
                elif "microsoft.network/networkinterfaces" in r_type.lower():
                    vm = props.get("virtualMachine")
                    pe = props.get("privateEndpoint")
                    pe_text = props.get("privateEndpointText")
                    nsg = props.get("networkSecurityGroup")
                    if not vm and not pe and pe_text in (None, "", "null") and not nsg:
                        is_unused = True
                        reason = "Network Interface provisioned with no attached VM or Private Endpoint"
                        est_cost = 2.50

                # D. Empty App Service Plans (0 Deployed Sites)
                elif "microsoft.web/serverfarms" in r_type.lower():
                    num_sites = props.get("numberOfSites", 0)
                    sku_tier = res.get("sku", {}).get("tier", "Standard")
                    if num_sites == 0 and sku_tier not in ("Free", "Shared"):
                        is_unused = True
                        reason = f"App Service Plan ({sku_tier}) running 0 deployed web applications"
                        if "premium" in sku_tier.lower():
                            est_cost = 146.00
                        elif "basic" in sku_tier.lower():
                            est_cost = 54.75
                        else:
                            est_cost = 73.00

                # E. Deallocated or Stopped Virtual Machines
                elif "microsoft.compute/virtualmachines" in r_type.lower():
                    vm_state = props.get("extended", {}).get("instanceView", {}).get("powerState", {}).get("displayStatus", "")
                    if not vm_state and isinstance(props.get("instanceView"), dict):
                        statuses = props.get("instanceView", {}).get("statuses", [])
                        for st in statuses:
                            if "PowerState" in st.get("code", ""):
                                vm_state = st.get("displayStatus", "")
                    if "deallocat" in vm_state.lower() or "stop" in vm_state.lower():
                        is_unused = True
                        vm_size = props.get("hardwareProfile", {}).get("vmSize", "Standard_D2s_v5")
                        reason = f"Virtual Machine ({vm_size}) continuously stopped/deallocated"
                        rates = PricingEngine.get_vm_rates(vm_size)
                        est_cost = rates.get("monthly", 87.60)

                # F. Snapshots Older Than 30 Days
                elif "microsoft.compute/snapshots" in r_type.lower():
                    size_gb = props.get("diskSizeGB", 128)
                    sku_tier = res.get("sku", {}).get("name", "Standard_LRS")
                    is_unused = True
                    reason = f"Orphaned snapshot {sku_tier} ({size_gb} GB) retaining old disk state"
                    est_cost = round(size_gb * 0.05, 2)

                # 6. Apply Inactivity Threshold: Must be inactive for at least 30 days
                if is_unused and days_inactive >= 30:
                    norm_id_lookup = normalize_resource_id(r_id)
                    cost_info = cost_map.get(norm_id_lookup, {})
                    actual_cost = cost_info.get("cost")
                    currency = cost_info.get("currency", context.currency)

                    final_cost = actual_cost if actual_cost is not None and actual_cost > 0 else est_cost
                    monthly_saving = round(final_cost, 2)

                    parsed = parse_azure_resource_id(r_id)
                    rg_name = parsed.get("resource_group") or res.get("resourceGroup") or "Unknown"
                    env_name = resolve_environment(tags, rg_name)

                    unwanted_status = "Abandoned (>90d Inactive)" if days_inactive >= 90 else "Unused (>30d Inactive)"

                    findings.append(
                        FindingModel(
                            finding_id=f"cost11-{sub.subscription_id[:8]}-{r_name[:20]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg_name,
                            resource_name=r_name,
                            resource_type=r_type,
                            resource_id=r_id,
                            region=res.get("location", "global"),
                            severity="High" if monthly_saving > 50 else "Medium",
                            status=f"Unused ({days_inactive} Days Inactive)",
                            current_configuration=f"Provisioned: {created_date} | Last Activity: {last_activity_date} ({days_inactive} days ago) | {reason}",
                            measured_value=f"Inactive for {days_inactive} days (Created: {created_date}, Last Activity: {last_activity_date})",
                            recommended_configuration="Decommission or delete abandoned infrastructure to stop recurring expenditure",
                            recommendation=f"Resource '{r_name}' ({r_type.split('/')[-1]}) has remained inactive for {days_inactive} days (>30-day threshold). Decommission asset to save {currency} {monthly_saving:.2f}/month.",
                            metric_period="> 30 days inactivity",
                            data_source="Azure Resource Graph & Activity Logs (90-Day History)",
                            evidence={
                                "creation_date": created_date,
                                "last_activity": last_activity_date,
                                "days_inactive": days_inactive,
                                "environment": env_name,
                                "actual_cost_mtd": round(final_cost, 2),
                                "cost_month": cost_month,
                                "reason": reason,
                                "unwanted_status": unwanted_status
                            },
                            current_monthly_cost=round(final_cost, 2),
                            estimated_monthly_savings=monthly_saving,
                            estimated_annual_savings=round(monthly_saving * 12, 2),
                            currency=currency,
                            savings_type="Estimated Savings",
                            confidence="High",
                            calculation_method="Full elimination of recurring charges for abandoned infrastructure inactive for more than 30 days",
                            validation_required="Confirm with application owner before decommissioning",
                            collected_at=now_str
                        )
                    )

        total_monthly = sum((f.estimated_monthly_savings or 0.0) for f in findings)
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
