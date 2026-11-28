import datetime
import time
from typing import List, Dict, Any, Optional
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.database import DatabaseAdapter
from app.azure.resources import ResourcesAdapter
from app.azure.monitor import MonitorAdapter
from app.azure.cost_management import CostManagementAdapter
from app.azure.pricing import PricingEngine
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id
from app.utils.environment import resolve_environment, matches_target_tags


class DatabaseAllocatedUsageAssessment(BaseAssessment):
    assessment_id = "database_allocated_usage"
    code = "COST-13"
    category = "cost"
    name = "Database Allocated vs Usage"
    description = "Compare provisioned/allocated database storage space against actual data consumption to flag unused allocated space."
    purpose = "Reclaim provisioned database storage headroom and optimize file storage costs."
    required_permissions = [
        "Microsoft.Sql/servers/databases/read",
        "Microsoft.DBforPostgreSQL/flexibleServers/read",
        "Microsoft.DBforMySQL/flexibleServers/read",
        "Microsoft.Insights/metrics/read",
        "Cost Management Reader",
        "Reader"
    ]
    required_data_sources = ["Azure SQL Storage Allocation Metrics & Azure Cost Management"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        cost_start, cost_end, cost_month = CostManagementAdapter.get_last_completed_month_date_range()
        start_iso, end_iso = f"{cost_start}T00:00:00Z", f"{cost_end}T23:59:59Z"

        for sub in context.subscriptions:
            # 1. Fetch real-time Cost Management expenditure (unrestricted across all resources)
            cost_map = await CostManagementAdapter.query_resource_costs(
                context.client,
                subscription_id=sub.subscription_id,
                start_date=cost_start,
                end_date=cost_end
            )

            # -------------------------------------------------------------
            # Part A: Azure SQL Databases
            # -------------------------------------------------------------
            try:
                servers = await DatabaseAdapter.get_sql_servers(context.client, sub.subscription_id)
            except Exception as ex:
                servers = []
                errors.append(f"Failed to scan SQL servers for sub {sub.subscription_id}: {ex}")

            for s in servers:
                s_id = s.get("id", "")
                s_name = s.get("name", "")
                try:
                    dbs = await DatabaseAdapter.get_sql_databases(context.client, s_id)
                except Exception as ex:
                    errors.append(f"Failed to scan databases on server {s_name}: {ex}")
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
                    sku_name = sku.get("name") or props.get("currentServiceObjectiveName") or "Standard S3"
                    sku_tier = sku.get("tier") or "Standard"

                    # 1. Determine Allocated Storage (GB) from database maxSizeBytes
                    max_bytes = props.get("maxSizeBytes")
                    if max_bytes and max_bytes > 0:
                        allocated_gb = round(max_bytes / (1024 ** 3), 1)
                    else:
                        allocated_gb = 250.0  # Default standard Azure SQL size

                    # 2. Query Azure Monitor for storage metrics using reliable P1D interval
                    metric_res = await MonitorAdapter.get_metrics(
                        context.client,
                        resource_id=db_id,
                        metric_names="storage,allocated_data_storage,storage_percent",
                        start_time=start_iso,
                        end_time=end_iso,
                        time_grain="P1D",
                        aggregation="Average"
                    )

                    used_gb: Optional[float] = None
                    utilization_pct: Optional[float] = None

                    if metric_res.get("success"):
                        metrics = metric_res.get("metrics", {})
                        raw_used_bytes = metrics.get("storage")
                        raw_alloc_bytes = metrics.get("allocated_data_storage")
                        raw_pct = metrics.get("storage_percent")

                        # If raw_alloc_bytes is available and maxSizeBytes wasn't provided, refine allocated_gb
                        if (not max_bytes or max_bytes <= 0) and raw_alloc_bytes and raw_alloc_bytes > 0:
                            allocated_gb = round(float(raw_alloc_bytes) / (1024 ** 3), 1)

                        if raw_used_bytes is not None and raw_used_bytes > 0:
                            used_gb = round(float(raw_used_bytes) / (1024 ** 3), 2)
                            if allocated_gb > 0:
                                utilization_pct = round((used_gb / allocated_gb) * 100.0, 2)
                        elif raw_pct is not None and raw_pct >= 0:
                            utilization_pct = round(float(raw_pct), 2)
                            used_gb = round(allocated_gb * (utilization_pct / 100.0), 2)
                        elif raw_used_bytes == 0.0 or raw_pct == 0.0:
                            used_gb = 0.0
                            utilization_pct = 0.0

                    # If metrics query failed or was unavailable, do NOT fabricate fake utilization
                    if used_gb is None or utilization_pct is None:
                        continue

                    # 3. Determine Cost for last completed month
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
                    if actual_cost is not None and actual_cost > 0:
                        final_cost: Optional[float] = float(actual_cost)
                    else:
                        final_cost = await PricingEngine.get_sql_database_monthly_price(sku_name, sku_tier, db_region, currency)

                    # 4. Strict Underutilization Condition: Storage usage < 5% of allocated capacity
                    if utilization_pct < 5.0 and allocated_gb >= 5.0:
                        target_allocated_gb = max(10.0, round(used_gb * 2.0, 1))
                        reclaimable_gb = max(0.0, round(allocated_gb - target_allocated_gb, 1))

                        # Dynamic storage rate from Azure Retail Prices API
                        rate = await PricingEngine.get_database_storage_gb_price("sql", db_region, currency)
                        monthly_saving: Optional[float] = None
                        annual_saving: Optional[float] = None
                        savings_pct: Optional[float] = None
                        if rate is not None and rate > 0:
                            monthly_saving = round(reclaimable_gb * rate, 2)
                            if final_cost is not None and final_cost > 0:
                                if monthly_saving > final_cost:
                                    monthly_saving = round(final_cost, 2)
                                savings_pct = round((monthly_saving / final_cost) * 100.0, 2)
                            annual_saving = round(monthly_saving * 12.0, 2)

                        parsed = parse_azure_resource_id(db_id)
                        rg_name = parsed.get("resource_group") or s.get("resourceGroup") or "Unknown"
                        db_tags = db.get("tags") or s.get("tags") or {}
                        env_name = resolve_environment(
                            tags=db_tags,
                            resource_name=db_name,
                            resource_group=rg_name,
                            prod_tags=context.prod_tags,
                            test_tags=context.test_tags
                        )

                        findings.append(
                            FindingModel(
                                finding_id=f"cost13-{sub.subscription_id[:8]}-{db_name[:20]}",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=rg_name,
                                resource_name=db_name,
                                resource_type="Microsoft.Sql/servers/databases",
                                resource_id=db_id,
                                region=db.get("location", s.get("location", "global")),
                                severity="High" if utilization_pct < 2.0 else "Medium",
                                status=f"Underutilized Storage ({utilization_pct:.1f}%)",
                                current_configuration=f"Allocated: {allocated_gb:.1f} GB | Consumed: {used_gb:.2f} GB ({utilization_pct:.1f}%) | SKU: {sku_name}",
                                measured_value=f"{utilization_pct:.1f}% Storage Utilization ({reclaimable_gb:.1f} GB Reclaimable)",
                                recommended_configuration=f"Downsize provisioned storage limit to {target_allocated_gb:.1f} GB or shrink database files",
                                recommendation=(
                                    f"Database '{db_name}' storage consumption is only {utilization_pct:.1f}% of allocated {allocated_gb:.1f} GB "
                                    f"({used_gb:.2f} GB used). Reclaim up to {reclaimable_gb:.1f} GB of unused provisioned headroom to reduce monthly storage charges."
                                ),
                                metric_period=f"Last Completed Month ({cost_month})",
                                data_source="Azure SQL Storage Allocation Metrics & Cost Management",
                                evidence={
                                    "allocated_storage_gb": allocated_gb,
                                    "used_storage_gb": used_gb,
                                    "utilization_pct": utilization_pct,
                                    "reclaimable_headroom_gb": reclaimable_gb,
                                    "target_allocated_gb": target_allocated_gb,
                                    "environment": env_name,
                                    "actual_cost_mtd": round(final_cost, 2) if final_cost is not None else None,
                                    "savings_pct": savings_pct,
                                    "cost_month": cost_month,
                                    "sku": sku_name
                                },
                                current_monthly_cost=round(final_cost, 2) if final_cost is not None else None,
                                estimated_monthly_savings=monthly_saving,
                                estimated_annual_savings=annual_saving,
                                currency=currency,
                                savings_type="Estimated Savings" if monthly_saving is not None else "Not Estimated",
                                confidence="High" if (actual_cost and actual_cost > 0 and monthly_saving is not None) else "Low",
                                calculation_method="Monthly savings = current DB storage/compute eligible cost - proposed cost/storage; annual = monthly * 12",
                                validation_required="Avoid overlap with Database CPU - DTU Performance; verify data growth projections before reducing max database size.",
                                collected_at=now_str
                            )
                        )

            # -------------------------------------------------------------
            # Part B: PostgreSQL Flexible Servers
            # -------------------------------------------------------------
            try:
                pg_servers = await ResourcesAdapter.get_postgresql_flexible_servers(context.client, sub.subscription_id)
            except Exception as ex:
                pg_servers = []
                errors.append(f"Failed to scan PostgreSQL flexible servers for sub {sub.subscription_id}: {ex}")

            for pg in pg_servers:
                if not matches_target_tags(pg.get("tags"), context.target_tags):
                    continue
                resources_evaluated += 1
                pg_name = pg.get("name", "")
                pg_id = pg.get("id", "")
                pg_props = pg.get("properties", {})
                pg_sku = pg.get("sku", {})
                pg_sku_name = pg_sku.get("name") or "Standard_D2ds_v4"
                pg_sku_tier = pg_sku.get("tier") or "GeneralPurpose"

                allocated_gb = float(pg_props.get("storage", {}).get("storageSizeGB") or 128)

                # Query Azure Monitor storage_percent
                pg_metric_res = await MonitorAdapter.get_metrics(
                    context.client,
                    resource_id=pg_id,
                    metric_names="storage_percent",
                    start_time=start_iso,
                    end_time=end_iso,
                    time_grain="P1D",
                    aggregation="Average"
                )

                used_gb = None
                utilization_pct = None

                if pg_metric_res.get("success"):
                    metrics = pg_metric_res.get("metrics", {})
                    raw_pct = metrics.get("storage_percent")
                    if raw_pct is not None and raw_pct >= 0:
                        utilization_pct = round(float(raw_pct), 2)
                        used_gb = round(allocated_gb * (utilization_pct / 100.0), 2)

                if used_gb is None or utilization_pct is None:
                    continue

                if utilization_pct < 5.0 and allocated_gb >= 32.0:
                    target_allocated_gb = max(32.0, round(used_gb * 2.0, 1))
                    reclaimable_gb = max(0.0, round(allocated_gb - target_allocated_gb, 1))

                    norm_id = normalize_resource_id(pg_id)
                    cost_info = cost_map.get(norm_id, {})
                    actual_cost = cost_info.get("cost")
                    currency = cost_info.get("currency", context.currency)

                    pg_region = pg.get("location", "")
                    final_cost: Optional[float] = float(actual_cost) if (actual_cost and actual_cost > 0) else None
                    rate = await PricingEngine.get_database_storage_gb_price("postgresql", pg_region, currency)
                    monthly_saving = round(reclaimable_gb * rate, 2) if (rate is not None and rate > 0) else None
                    annual_saving = round(monthly_saving * 12.0, 2) if monthly_saving is not None else None
                    savings_pct = round((monthly_saving / final_cost) * 100.0, 2) if (monthly_saving is not None and final_cost and final_cost > 0) else None

                    parsed = parse_azure_resource_id(pg_id)
                    rg_name = parsed.get("resource_group") or "Unknown"
                    env_name = resolve_environment(
                        tags=pg.get("tags") or {},
                        resource_name=pg_name,
                        resource_group=rg_name,
                        prod_tags=context.prod_tags,
                        test_tags=context.test_tags
                    )

                    findings.append(
                        FindingModel(
                            finding_id=f"cost13-{sub.subscription_id[:8]}-{pg_name[:20]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg_name,
                            resource_name=pg_name,
                            resource_type="Microsoft.DBforPostgreSQL/flexibleServers",
                            resource_id=pg_id,
                            region=pg.get("location", "global"),
                            severity="High" if utilization_pct < 2.0 else "Medium",
                            status=f"Underutilized Storage ({utilization_pct:.1f}%)",
                            current_configuration=f"Allocated: {allocated_gb:.1f} GB | Consumed: {used_gb:.2f} GB ({utilization_pct:.1f}%) | SKU: {pg_sku_name}",
                            measured_value=f"{utilization_pct:.1f}% Storage Utilization ({reclaimable_gb:.1f} GB Reclaimable)",
                            recommended_configuration=f"Downsize provisioned storage to {target_allocated_gb:.1f} GB",
                            recommendation=(
                                f"PostgreSQL Server '{pg_name}' storage consumption is only {utilization_pct:.1f}% of allocated {allocated_gb:.1f} GB "
                                f"({used_gb:.2f} GB used). Reclaim up to {reclaimable_gb:.1f} GB of unused provisioned headroom."
                            ),
                            metric_period=f"Last Completed Month ({cost_month})",
                            data_source="Azure PostgreSQL Storage Metrics & Cost Management",
                            evidence={
                                "allocated_storage_gb": allocated_gb,
                                "used_storage_gb": used_gb,
                                "utilization_pct": utilization_pct,
                                "reclaimable_headroom_gb": reclaimable_gb,
                                "target_allocated_gb": target_allocated_gb,
                                "environment": env_name,
                                "actual_cost_mtd": round(final_cost, 2) if final_cost is not None else None,
                                "savings_pct": savings_pct,
                                "cost_month": cost_month,
                                "sku": pg_sku_name
                            },
                            current_monthly_cost=round(final_cost, 2) if final_cost is not None else None,
                            estimated_monthly_savings=monthly_saving,
                            estimated_annual_savings=annual_saving,
                            currency=currency,
                            savings_type="Estimated Savings" if monthly_saving is not None else "Not Estimated",
                            confidence="High" if (actual_cost and actual_cost > 0 and monthly_saving is not None) else "Low",
                            calculation_method="Monthly savings = current DB storage/compute eligible cost - proposed cost/storage; annual = monthly * 12",
                            validation_required="Avoid overlap with Database CPU - DTU Performance; verify data growth projections before reducing storage size.",
                            collected_at=now_str
                        )
                    )

            # -------------------------------------------------------------
            # Part C: MySQL Flexible Servers
            # -------------------------------------------------------------
            try:
                mysql_servers = await ResourcesAdapter.get_mysql_flexible_servers(context.client, sub.subscription_id)
            except Exception as ex:
                mysql_servers = []
                errors.append(f"Failed to scan MySQL flexible servers for sub {sub.subscription_id}: {ex}")

            for my in mysql_servers:
                if not matches_target_tags(my.get("tags"), context.target_tags):
                    continue
                resources_evaluated += 1
                my_name = my.get("name", "")
                my_id = my.get("id", "")
                my_props = my.get("properties", {})
                my_sku = my.get("sku", {})
                my_sku_name = my_sku.get("name") or "Standard_B1ms"
                my_sku_tier = my_sku.get("tier") or "Burstable"

                allocated_gb = float(my_props.get("storage", {}).get("storageSizeGB") or 64)

                my_metric_res = await MonitorAdapter.get_metrics(
                    context.client,
                    resource_id=my_id,
                    metric_names="storage_percent",
                    start_time=start_iso,
                    end_time=end_iso,
                    time_grain="P1D",
                    aggregation="Average"
                )

                used_gb = None
                utilization_pct = None

                if my_metric_res.get("success"):
                    metrics = my_metric_res.get("metrics", {})
                    raw_pct = metrics.get("storage_percent")
                    if raw_pct is not None and raw_pct >= 0:
                        utilization_pct = round(float(raw_pct), 2)
                        used_gb = round(allocated_gb * (utilization_pct / 100.0), 2)

                if used_gb is None or utilization_pct is None:
                    continue

                if utilization_pct < 5.0 and allocated_gb >= 20.0:
                    target_allocated_gb = max(20.0, round(used_gb * 2.0, 1))
                    reclaimable_gb = max(0.0, round(allocated_gb - target_allocated_gb, 1))

                    norm_id = normalize_resource_id(my_id)
                    cost_info = cost_map.get(norm_id, {})
                    actual_cost = cost_info.get("cost")
                    currency = cost_info.get("currency", context.currency)

                    my_region = my.get("location", "")
                    final_cost: Optional[float] = float(actual_cost) if (actual_cost and actual_cost > 0) else None
                    rate = await PricingEngine.get_database_storage_gb_price("mysql", my_region, currency)
                    monthly_saving = round(reclaimable_gb * rate, 2) if (rate is not None and rate > 0) else None
                    annual_saving = round(monthly_saving * 12.0, 2) if monthly_saving is not None else None
                    savings_pct = round((monthly_saving / final_cost) * 100.0, 2) if (monthly_saving is not None and final_cost and final_cost > 0) else None

                    parsed = parse_azure_resource_id(my_id)
                    rg_name = parsed.get("resource_group") or "Unknown"
                    env_name = resolve_environment(
                        tags=my.get("tags") or {},
                        resource_name=my_name,
                        resource_group=rg_name,
                        prod_tags=context.prod_tags,
                        test_tags=context.test_tags
                    )

                    findings.append(
                        FindingModel(
                            finding_id=f"cost13-{sub.subscription_id[:8]}-{my_name[:20]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg_name,
                            resource_name=my_name,
                            resource_type="Microsoft.DBforMySQL/flexibleServers",
                            resource_id=my_id,
                            region=my.get("location", "global"),
                            severity="High" if utilization_pct < 2.0 else "Medium",
                            status=f"Underutilized Storage ({utilization_pct:.1f}%)",
                            current_configuration=f"Allocated: {allocated_gb:.1f} GB | Consumed: {used_gb:.2f} GB ({utilization_pct:.1f}%) | SKU: {my_sku_name}",
                            measured_value=f"{utilization_pct:.1f}% Storage Utilization ({reclaimable_gb:.1f} GB Reclaimable)",
                            recommended_configuration=f"Downsize provisioned storage to {target_allocated_gb:.1f} GB",
                            recommendation=(
                                f"MySQL Server '{my_name}' storage consumption is only {utilization_pct:.1f}% of allocated {allocated_gb:.1f} GB "
                                f"({used_gb:.2f} GB used). Reclaim up to {reclaimable_gb:.1f} GB of unused provisioned headroom."
                            ),
                            metric_period=f"Last Completed Month ({cost_month})",
                            data_source="Azure MySQL Storage Metrics & Cost Management",
                            evidence={
                                "allocated_storage_gb": allocated_gb,
                                "used_storage_gb": used_gb,
                                "utilization_pct": utilization_pct,
                                "reclaimable_headroom_gb": reclaimable_gb,
                                "target_allocated_gb": target_allocated_gb,
                                "environment": env_name,
                                "actual_cost_mtd": round(final_cost, 2) if final_cost is not None else None,
                                "savings_pct": savings_pct,
                                "cost_month": cost_month,
                                "sku": my_sku_name
                            },
                            current_monthly_cost=round(final_cost, 2) if final_cost is not None else None,
                            estimated_monthly_savings=monthly_saving,
                            estimated_annual_savings=annual_saving,
                            currency=currency,
                            savings_type="Estimated Savings" if monthly_saving is not None else "Not Estimated",
                            confidence="High" if (actual_cost and actual_cost > 0 and monthly_saving is not None) else "Low",
                            calculation_method="Monthly savings = current DB storage/compute eligible cost - proposed cost/storage; annual = monthly * 12",
                            validation_required="Avoid overlap with Database CPU - DTU Performance; verify data growth projections before reducing storage size.",
                            collected_at=now_str
                        )
                    )

        # Sort findings by estimated monthly savings descending
        findings.sort(key=lambda f: (f.estimated_monthly_savings or 0.0), reverse=True)

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
