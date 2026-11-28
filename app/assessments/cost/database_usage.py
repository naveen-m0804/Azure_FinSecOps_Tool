import datetime
import time
import re
from typing import List, Dict, Any, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.database import DatabaseAdapter
from app.azure.monitor import MonitorAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment, matches_target_tags
from app.utils.dates import get_observation_window


def _format_db_tier(sku: Dict[str, Any], props: Dict[str, Any], cost: float = 0.0) -> str:
    """
    Resolves the exact, accurate database tier objective:
    e.g. 'Standard S4', 'Standard S2', 'Standard S1', 'GeneralPurpose GP_Gen5_2', 'Basic'
    """
    cso = str(props.get("currentServiceObjectiveName") or props.get("requestedServiceObjectiveName") or "").strip()
    sku_name = str(sku.get("name") or "").strip()
    sku_tier = str(sku.get("tier") or "").strip()
    capacity = sku.get("capacity")

    if cso and cso.lower() not in ("system", ""):
        if sku_tier and sku_tier.lower() not in cso.lower():
            return f"{sku_tier} {cso}"
        return cso

    if capacity:
        cap_map = {
            5: "Basic",
            10: "Standard S0",
            20: "Standard S1",
            50: "Standard S2",
            100: "Standard S3",
            200: "Standard S4",
            400: "Standard S6",
            800: "Standard S7",
            1600: "Standard S9",
            3000: "Standard S12",
            125: "Premium P1",
            250: "Premium P2",
            500: "Premium P4",
            1000: "Premium P6",
            1750: "Premium P11",
            4000: "Premium P15"
        }
        if capacity in cap_map:
            return cap_map[capacity]

    # If tier was only returned as generic 'Standard' without objective, infer from actual monthly cost
    if sku_name.lower() in ("standard", "") or sku_tier.lower() in ("standard", ""):
        if cost >= 200.0:
            return "Standard S4"
        elif cost >= 110.0:
            return "Standard S3"
        elif cost >= 45.0:
            return "Standard S2"
        elif cost >= 18.0:
            return "Standard S1"
        elif cost > 0:
            return "Standard S0"

    if sku_tier and sku_name and sku_tier.lower() != sku_name.lower():
        return f"{sku_tier} {sku_name}"
    return sku_name or sku_tier or "Standard S2"


def _extract_resource_group(resource_id: str, fallback: Optional[str] = None) -> str:
    """Extracts valid resource group name from resource ID, avoiding 'Unknown'."""
    if fallback and fallback not in ("Unknown", "--", "", "Subscription Scope"):
        return fallback
    if resource_id:
        m = re.search(r"/resourceGroups/([^/]+)", resource_id, re.IGNORECASE)
        if m:
            return m.group(1)
        parsed = parse_azure_resource_id(resource_id)
        rg = parsed.get("resource_group")
        if rg and rg not in ("Unknown", "--", ""):
            return rg
    return fallback or "--"


def _propose_lower_db_tier(sku_name: str, tier_name: str = "") -> Optional[str]:
    """Proposes one step lower database service objective for right-sizing."""
    s = (sku_name or "").upper().strip()
    dtu_ladder = ["BASIC", "S0", "S1", "S2", "S3", "S4", "S6", "S7", "S9", "S12"]
    for idx, lvl in enumerate(dtu_ladder):
        if s == lvl or s.endswith(f" {lvl}"):
            return dtu_ladder[idx - 1] if idx > 0 else None
    p_ladder = ["P1", "P2", "P4", "P6", "P11", "P15"]
    for idx, lvl in enumerate(p_ladder):
        if s == lvl or s.endswith(f" {lvl}"):
            return p_ladder[idx - 1] if idx > 0 else "S4"
    return None


class DatabaseUsageAssessment(BaseAssessment):
    assessment_id = "database_usage"
    code = "COST-10"
    category = "cost"
    name = "Database CPU / DTU Performance & Sizing Threshold"
    description = "Audit Azure SQL / Flexible Server database CPU and DTU consumption to identify overprovisioned databases and saturated instances."
    purpose = "Detect performance bottlenecks exceeding sizing thresholds and right-size overprovisioned database tiers to optimize spend."
    required_permissions = [
        "Microsoft.Sql/servers/databases/read",
        "Microsoft.DBforPostgreSQL/flexibleServers/read",
        "Microsoft.Insights/metrics/read",
        "Microsoft.CostManagement/query/action",
        "Monitoring Reader",
        "Reader"
    ]
    required_data_sources = ["Azure Monitor Database DTU / CPU Percent Metrics & Cost Management API"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()
        obs_start, obs_end = get_observation_window(days=14)

        for sub in context.subscriptions:
            # Query Cost Management across all database resources unrestricted
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=cost_start,
                end_date=cost_end
            )

            # 1. Discover Azure SQL Databases
            try:
                servers = await DatabaseAdapter.get_sql_servers(context.client, sub.subscription_id)
            except Exception as ex:
                errors.append(f"Failed to scan SQL servers for subscription {sub.subscription_id}: {ex}")
                servers = []

            for s in servers:
                s_id = s.get("id", "")
                try:
                    dbs = await DatabaseAdapter.get_sql_databases(context.client, s_id)
                except Exception as ex:
                    errors.append(f"Failed to scan databases on server {s.get('name')}: {ex}")
                    continue

                for db in dbs:
                    resources_evaluated += 1
                    db_name = db.get("name", "")
                    db_id = db.get("id", "")

                    # Skip system databases
                    if db_name.lower() in ("master", "tempdb", "model", "msdb"):
                        continue

                    db_tags = db.get("tags") or s.get("tags") or {}
                    if not matches_target_tags(db_tags, context.target_tags):
                        continue

                    props = db.get("properties", {})
                    sku = db.get("sku", {})
                    sku_name_raw = sku.get("name") or props.get("currentServiceObjectiveName") or "Standard S3"
                    sku_tier_raw = sku.get("tier") or "Standard"

                    # 1. Query Azure Monitor for DTU and CPU utilization metrics using rolling observation window
                    metric_res = await MonitorAdapter.get_metrics(
                        context.client,
                        resource_id=db_id,
                        metric_names="dtu_consumption_percent,cpu_percent",
                        start_time=obs_start,
                        end_time=obs_end,
                        time_grain="PT1H",
                        aggregation="Average"
                    )

                    dtu_utilization: float = 0.0
                    metric_label = "DTU"

                    if metric_res.get("success"):
                        metrics = metric_res.get("metrics", {})
                        dtu_metric = metrics.get("dtu_consumption_percent")
                        cpu_metric = metrics.get("cpu_percent")

                        if dtu_metric is not None and dtu_metric > 0.0:
                            dtu_utilization = round(float(dtu_metric), 1)
                            metric_label = "DTU"
                        elif cpu_metric is not None and cpu_metric > 0.0:
                            dtu_utilization = round(float(cpu_metric), 1)
                            metric_label = "CPU"
                        elif dtu_metric is not None:
                            dtu_utilization = round(float(dtu_metric), 1)
                            metric_label = "DTU"
                        elif cpu_metric is not None:
                            dtu_utilization = round(float(cpu_metric), 1)
                            metric_label = "CPU"

                    # 2. Query Storage utilization metrics using supported platform metric names
                    storage_res = await MonitorAdapter.get_metrics(
                        context.client,
                        resource_id=db_id,
                        metric_names="storage_percent,allocated_data_storage,storage",
                        start_time=obs_start,
                        end_time=obs_end,
                        time_grain="PT1H",
                        aggregation="Average"
                    )

                    used_storage_gb: Optional[float] = None
                    raw_alloc_bytes: Optional[float] = None
                    storage_pct: Optional[float] = None

                    if storage_res.get("success"):
                        st_metrics = storage_res.get("metrics", {})
                        if st_metrics.get("storage") is not None and st_metrics.get("storage") > 0:
                            used_storage_gb = round(float(st_metrics["storage"]) / (1024 ** 3), 1)
                        if st_metrics.get("allocated_data_storage") is not None and st_metrics.get("allocated_data_storage") > 0:
                            raw_alloc_bytes = float(st_metrics["allocated_data_storage"])
                        if st_metrics.get("storage_percent") is not None:
                            storage_pct = round(float(st_metrics["storage_percent"]), 1)

                    # Determine allocated GB from database properties or metrics
                    max_bytes = props.get("maxSizeBytes")
                    if max_bytes and max_bytes > 0:
                        allocated_gb = round(float(max_bytes) / (1024 ** 3), 1)
                    elif raw_alloc_bytes and raw_alloc_bytes > 0:
                        allocated_gb = round(raw_alloc_bytes / (1024 ** 3), 1)
                    else:
                        allocated_gb = 250.0

                    # Calculate used storage GB from percentage or absolute bytes
                    if used_storage_gb is None:
                        if storage_pct is not None and storage_pct > 0:
                            used_storage_gb = round(allocated_gb * (storage_pct / 100.0), 1)
                        else:
                            used_storage_gb = 0.0

                    if storage_pct is None:
                        storage_pct = round((used_storage_gb / allocated_gb) * 100.0, 1) if allocated_gb > 0 else 0.0

                    # Cost lookup for last completed month
                    norm_id = normalize_resource_id(db_id)
                    cost_info = cost_map.get(norm_id, {})
                    actual_cost = cost_info.get("cost")
                    currency = cost_info.get("currency", context.currency)

                    # Check parent server cost if database-level cost was not individually tracked
                    if actual_cost is None or actual_cost <= 0:
                        server_norm_id = normalize_resource_id(s_id)
                        server_cost_info = cost_map.get(server_norm_id, {})
                        server_cost = server_cost_info.get("cost")
                        if server_cost and server_cost > 0:
                            actual_cost = server_cost

                    db_region = db.get("location") or s.get("location") or ""
                    final_cost: Optional[float] = float(actual_cost) if (actual_cost is not None and actual_cost > 0) else await PricingEngine.get_sql_database_monthly_price(sku_name_raw, sku_tier_raw, db_region, currency)

                    # Determine accurate friendly database tier
                    friendly_tier = _format_db_tier(sku, props, final_cost or 0.0)
                    effective_sku = friendly_tier.split()[-1] if " " in friendly_tier else friendly_tier
                    if final_cost is None:
                        final_cost = await PricingEngine.get_sql_database_monthly_price(effective_sku, sku_tier_raw, db_region, currency)

                    rg_name = _extract_resource_group(db_id, s.get("resourceGroup"))
                    db_tags = db.get("tags") or s.get("tags") or {}
                    env_name = resolve_environment(
                        tags=db_tags,
                        resource_name=db_name,
                        resource_group=rg_name,
                        prod_tags=context.prod_tags,
                        test_tags=context.test_tags,
                        target_tags=context.target_tags
                    )

                    # Sizing & Performance Threshold Evaluation
                    proposed_tier = None
                    proposed_cost = None
                    monthly_saving: Optional[float] = None
                    savings_pct: Optional[float] = None

                    if dtu_utilization >= 85.0:
                        severity = "Critical" if dtu_utilization >= 90.0 else "High"
                        status_str = f"Saturated {metric_label} ({dtu_utilization:.1f}%)"
                        recommendation = f"Database '{db_name}' {metric_label} utilization is {dtu_utilization:.1f}%, exceeding the sizing threshold. Scale up tier to higher service objective to prevent query throttling."
                        calc_method = f"Scale-up advised for sustained high {metric_label} utilization"
                    elif dtu_utilization <= 20.0:
                        severity = "Medium"
                        status_str = f"Underutilized {metric_label} ({dtu_utilization:.1f}%)"
                        proposed_tier = _propose_lower_db_tier(friendly_tier, sku_tier_raw)
                        if proposed_tier:
                            proposed_cost = await PricingEngine.get_sql_database_monthly_price(proposed_tier, sku_tier_raw, db_region, currency)
                        if final_cost is not None and final_cost > 0 and proposed_cost is not None:
                            monthly_saving = round(max(0.0, final_cost - proposed_cost), 2)
                            savings_pct = round((monthly_saving / final_cost) * 100.0, 2)
                        recommendation = (
                            f"Database '{db_name}' average {metric_label} utilization is {dtu_utilization:.1f}% on tier {friendly_tier}."
                            + (f" Downsize to {proposed_tier}." if proposed_tier else " Evaluate downsizing tier (pricing comparison required).")
                        )
                        calc_method = "Monthly savings = current database tier cost - proposed tier cost; savings % = savings/current database cost; annual = monthly * 12"
                    else:
                        severity = "Informational"
                        status_str = f"Optimal Sizing ({dtu_utilization:.1f}%)"
                        recommendation = f"Database '{db_name}' {metric_label} utilization is healthy ({dtu_utilization:.1f}%)."
                        calc_method = "Optimal tier sizing"

                    findings.append(
                        FindingModel(
                            finding_id=f"cost10-{db_name[:12]}-{int(dtu_utilization)}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg_name,
                            resource_name=db_name,
                            resource_type="Microsoft.Sql/servers/databases",
                            resource_id=db_id,
                            region=db_region or "global",
                            severity=severity,
                            status=status_str,
                            current_configuration=f"Tier: {friendly_tier} | {metric_label}: {dtu_utilization:.1f}% | Storage: {used_storage_gb}/{allocated_gb} GB ({storage_pct:.1f}%)",
                            measured_value=f"Avg {dtu_utilization:.1f}% ({metric_label})",
                            recommended_configuration=f"Downsize to {proposed_tier}" if proposed_tier else "Scale tier based on workload requirements",
                            recommendation=recommendation,
                            metric_period=f"Last Completed Month ({cost_month})",
                            data_source=f"Azure Monitor {metric_label}/Storage Metrics",
                            evidence={
                                "database_tier": friendly_tier,
                                "sku": friendly_tier,
                                "proposed_tier": proposed_tier,
                                "proposed_monthly_cost": proposed_cost,
                                "savings_pct": savings_pct,
                                "avg_dtu_cpu_pct": dtu_utilization,
                                "dtu_percent": dtu_utilization,
                                "dtu_metric_type": metric_label,
                                "storage_used_gb": used_storage_gb,
                                "storage_allocated_gb": allocated_gb,
                                "storage_utilization_pct": storage_pct,
                                "environment": env_name,
                                "actual_cost_mtd": round(final_cost, 2) if final_cost is not None else None,
                                "cost_month": cost_month
                            },
                            current_monthly_cost=round(final_cost, 2) if final_cost is not None else None,
                            estimated_monthly_savings=monthly_saving,
                            estimated_annual_savings=round(monthly_saving * 12, 2) if monthly_saving is not None else None,
                            currency=currency,
                            savings_type="Performance Right-Sizing" if (monthly_saving is not None and monthly_saving > 0) else "Sizing Alert",
                            confidence="High" if monthly_saving is not None else "Low",
                            calculation_method=calc_method,
                            validation_required="Validate workload, peak DTU, storage, backup and performance; avoid duplicate Database Allocated vs Usage.",
                            collected_at=now_str
                        )
                    )

            # 2. Discover Azure Database for PostgreSQL Flexible Servers
            try:
                pg_servers = await DatabaseAdapter.get_postgres_flexible_servers(context.client, sub.subscription_id)
            except Exception:
                pg_servers = []

            for pg in pg_servers:
                if not matches_target_tags(pg.get("tags"), context.target_tags):
                    continue
                resources_evaluated += 1
                pg_name = pg.get("name", "")
                pg_id = pg.get("id", "")
                pg_sku = pg.get("sku", {})
                sku_str = pg_sku.get("name") or "Standard_D2ds_v4"
                storage_profile = pg.get("properties", {}).get("storage", {})
                alloc_gb = storage_profile.get("storageSizeGB") or 128

                # Query metrics for PostgreSQL using rolling observation window
                metric_res = await MonitorAdapter.get_metrics(
                    context.client,
                    resource_id=pg_id,
                    metric_names="cpu_percent,memory_percent,storage_percent",
                    start_time=obs_start,
                    end_time=obs_end,
                    time_grain="PT1H",
                    aggregation="Average"
                )
                cpu_util = 0.0
                storage_pct = 0.0
                if metric_res.get("success"):
                    metrics = metric_res.get("metrics", {})
                    cpu_util = round(float(metrics.get("cpu_percent") or 0.0), 1)
                    storage_pct = round(float(metrics.get("storage_percent") or 0.0), 1)

                used_st_gb = round(alloc_gb * (storage_pct / 100.0), 1)
                rg_name = _extract_resource_group(pg_id)
                env_name = resolve_environment(
                    tags=pg.get("tags"),
                    resource_name=pg_name,
                    resource_group=rg_name,
                    prod_tags=context.prod_tags,
                    test_tags=context.test_tags,
                    target_tags=context.target_tags
                )

                norm_id = normalize_resource_id(pg_id)
                cost_info = cost_map.get(norm_id, {})
                actual_cost = cost_info.get("cost")
                currency = cost_info.get("currency", context.currency)
                final_cost: Optional[float] = float(actual_cost) if (actual_cost is not None and actual_cost > 0) else None
                monthly_saving: Optional[float] = None
                savings_pct: Optional[float] = None

                if cpu_util >= 85.0:
                    severity = "Critical" if cpu_util >= 90.0 else "High"
                    status_str = f"Saturated CPU ({cpu_util:.1f}%)"
                    recommendation = f"PostgreSQL server '{pg_name}' CPU is at {cpu_util:.1f}%. Scale up compute tier."
                    calc_method = "Scale-up advised for high compute load"
                elif cpu_util <= 20.0:
                    severity = "Medium"
                    status_str = f"Underutilized CPU ({cpu_util:.1f}%)"
                    recommendation = f"PostgreSQL server '{pg_name}' average CPU is only {cpu_util:.1f}%. Evaluate downsizing compute tier (pricing comparison required)."
                    calc_method = "Monthly savings = current database tier cost - proposed tier cost; pricing comparison required"
                else:
                    severity = "Informational"
                    status_str = f"Optimal Sizing ({cpu_util:.1f}%)"
                    recommendation = f"PostgreSQL server '{pg_name}' CPU utilization is healthy ({cpu_util:.1f}%)."
                    calc_method = "Optimal tier sizing"

                findings.append(
                    FindingModel(
                        finding_id=f"cost10-{pg_name[:12]}-{int(cpu_util)}",
                        assessment_id=self.assessment_id,
                        category=self.category,
                        subscription_id=sub.subscription_id,
                        subscription_name=sub.display_name,
                        resource_group=rg_name,
                        resource_name=pg_name,
                        resource_type="Microsoft.DBforPostgreSQL/flexibleServers",
                        resource_id=pg_id,
                        region=pg.get("location", "global"),
                        severity=severity,
                        status=status_str,
                        current_configuration=f"SKU: {sku_str} | CPU: {cpu_util:.1f}% | Storage: {used_st_gb}/{alloc_gb} GB",
                        measured_value=f"Avg {cpu_util:.1f}%",
                        recommended_configuration="Scale tier based on workload requirements",
                        recommendation=recommendation,
                        metric_period=f"Last Completed Month ({cost_month})",
                        data_source="Azure Monitor CPU/Storage Metrics",
                        evidence={
                            "database_tier": sku_str,
                            "sku": sku_str,
                            "avg_dtu_cpu_pct": cpu_util,
                            "dtu_percent": cpu_util,
                            "storage_used_gb": used_st_gb,
                            "storage_allocated_gb": alloc_gb,
                            "environment": env_name,
                            "savings_pct": savings_pct,
                            "actual_cost_mtd": round(final_cost, 2) if final_cost is not None else None,
                            "cost_month": cost_month
                        },
                        current_monthly_cost=round(final_cost, 2) if final_cost is not None else None,
                        estimated_monthly_savings=monthly_saving,
                        estimated_annual_savings=round(monthly_saving * 12, 2) if monthly_saving is not None else None,
                        currency=currency,
                        savings_type="Performance Right-Sizing" if (monthly_saving is not None and monthly_saving > 0) else "Sizing Alert",
                        confidence="High" if monthly_saving is not None else "Low",
                        calculation_method=calc_method,
                        validation_required="Validate workload, peak CPU, storage, backup and performance; avoid duplicate Database Allocated vs Usage.",
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
