import datetime
import time
import logging
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.storage import StorageAdapter
from app.azure.resources import ResourcesAdapter
from app.azure.defender import DefenderAdapter
from app.utils.resource_ids import parse_azure_resource_id, normalize_resource_id

logger = logging.getLogger("azure_finsecops.assessments.tls_version")

class TlsVersionAssessment(BaseAssessment):
    assessment_id = "tls_version"
    code = "SEC-12"
    category = "security"
    name = "TLS Version"
    description = "Audit minimum TLS protocols configured across Azure services (Storage Accounts, App Services, Function Apps, SQL Servers, Cosmos DB, PostgreSQL, Redis)."
    purpose = "Enforce strong in-transit cipher standards (TLS 1.2+) and eliminate weak cryptographic legacy protocols (TLS 1.0 / 1.1)."
    required_permissions = [
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Web/sites/read",
        "Microsoft.Sql/servers/read",
        "Microsoft.DocumentDB/databaseAccounts/read",
        "Microsoft.Cache/Redis/read",
        "Reader"
    ]
    required_data_sources = ["Azure Storage, Web, SQL, Cosmos DB & Redis REST APIs"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        seen_res_ids = set()

        for sub in context.subscriptions:
            # 1. Storage Accounts
            try:
                storage_accounts = await StorageAdapter.get_storage_accounts(context.client, sub.subscription_id)
                for sa in storage_accounts:
                    resources_evaluated += 1
                    sa_id = sa.get("id", "")
                    sa_name = sa.get("name", "Unknown Storage")
                    props = sa.get("properties", {}) or {}
                    # If minimumTlsVersion is not explicitly set, legacy storage accounts default to TLS 1.0/1.1
                    min_tls = props.get("minimumTlsVersion")

                    if not min_tls or min_tls.upper() in ("TLS1_0", "TLS1_1"):
                        seen_res_ids.add(sa_id)
                        parsed = parse_azure_resource_id(sa_id)
                        rg_name = parsed.get("resource_group") or "Unknown"
                        region = sa.get("location", "global")
                        display_tls = min_tls if min_tls else "TLS 1.0 (Not Enforced)"

                        findings.append(
                            FindingModel(
                                finding_id=f"sec12-{sub.subscription_id[:8]}-{sa_name[:12]}",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=rg_name,
                                resource_name=sa_name,
                                resource_type="Microsoft.Storage/storageAccounts",
                                resource_id=sa_id,
                                region=region,
                                severity="Medium",
                                status="Insecure TLS Configured",
                                current_configuration=f"Configured minimumTlsVersion: {display_tls}",
                                measured_value=display_tls,
                                recommended_configuration="Enforce TLS 1.2 minimum version for all in-transit REST/Blob/File API traffic",
                                recommendation=f"Storage account '{sa_name}' allows deprecated TLS version ({display_tls}). Update minimumTlsVersion to TLS1_2.",
                                metric_period="Current configuration",
                                data_source="Microsoft.Storage storageAccounts API",
                                evidence={
                                    "service_name": "Azure Storage Account",
                                    "minimumTlsVersion": display_tls,
                                    "configured_tls_version": display_tls,
                                    "required": "TLS 1.2",
                                    "tls_status": "Insecure TLS Configured",
                                    "security_control": "Enforce secure TLS version",
                                    "potential_score_increase": "+2.0%",
                                },
                                security_score_impact=2.0,
                                collected_at=now_str
                            )
                        )
            except Exception as ex:
                logger.debug("Failed scanning storage accounts for TLS in sub %s: %s", sub.subscription_id, ex)

            # 2. App Services (Web Apps and Function Apps)
            try:
                app_services = await ResourcesAdapter.get_app_services(context.client, sub.subscription_id)
                for app in app_services:
                    resources_evaluated += 1
                    app_id = app.get("id", "")
                    app_name = app.get("name", "Unknown App")
                    props = app.get("properties", {}) or {}
                    site_cfg = props.get("siteConfig", {}) or {}
                    kind = app.get("kind", "")
                    is_func = "functionapp" in kind.lower()
                    service_display = "Azure Function App" if is_func else "Azure App Service"

                    # If minTlsVersion is not set or set to 1.0 or 1.1
                    min_tls_app = site_cfg.get("minTlsVersion")
                    if not min_tls_app or str(min_tls_app) in ("1.0", "1.1"):
                        seen_res_ids.add(app_id)
                        parsed = parse_azure_resource_id(app_id)
                        rg_name = parsed.get("resource_group") or "Unknown"
                        region = app.get("location", "global")
                        display_tls = f"TLS {min_tls_app}" if min_tls_app else "TLS 1.0 (Not Enforced)"

                        findings.append(
                            FindingModel(
                                finding_id=f"sec12-{sub.subscription_id[:8]}-{app_name[:12]}",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=rg_name,
                                resource_name=app_name,
                                resource_type="Microsoft.Web/sites",
                                resource_id=app_id,
                                region=region,
                                severity="Medium",
                                status="Insecure TLS Configured",
                                current_configuration=f"minTlsVersion: {display_tls}",
                                measured_value=display_tls,
                                recommended_configuration="Enforce TLS 1.2 minimum version for all incoming HTTPS traffic",
                                recommendation=f"{service_display} '{app_name}' accepts connections using legacy {display_tls}. Configure siteConfig.minTlsVersion to '1.2'.",
                                metric_period="Current configuration",
                                data_source="Microsoft.Web/sites API",
                                evidence={
                                    "service_name": service_display,
                                    "minimumTlsVersion": display_tls,
                                    "configured_tls_version": display_tls,
                                    "required": "TLS 1.2",
                                    "tls_status": "Insecure TLS Configured",
                                    "security_control": "Enforce secure TLS version",
                                    "potential_score_increase": "+2.0%",
                                },
                                security_score_impact=2.0,
                                collected_at=now_str
                            )
                        )
            except Exception as ex:
                logger.debug("Failed scanning app services for TLS in sub %s: %s", sub.subscription_id, ex)

            # 3. Azure SQL Servers
            try:
                sql_servers = await ResourcesAdapter.get_sql_servers(context.client, sub.subscription_id)
                for s in sql_servers:
                    resources_evaluated += 1
                    s_id = s.get("id", "")
                    s_name = s.get("name", "Unknown SQL Server")
                    props = s.get("properties", {}) or {}
                    min_tls_sql = props.get("minimalTlsVersion")

                    if not min_tls_sql or str(min_tls_sql) in ("1.0", "1.1"):
                        seen_res_ids.add(s_id)
                        parsed = parse_azure_resource_id(s_id)
                        rg_name = parsed.get("resource_group") or "Unknown"
                        region = s.get("location", "global")
                        display_tls = f"TLS {min_tls_sql}" if min_tls_sql else "TLS 1.0 (Not Enforced)"

                        findings.append(
                            FindingModel(
                                finding_id=f"sec12-{sub.subscription_id[:8]}-{s_name[:12]}",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=rg_name,
                                resource_name=s_name,
                                resource_type="Microsoft.Sql/servers",
                                resource_id=s_id,
                                region=region,
                                severity="High",
                                status="Insecure TLS Configured",
                                current_configuration=f"minimalTlsVersion: {display_tls}",
                                measured_value=display_tls,
                                recommended_configuration="Set minimalTlsVersion to 1.2 on Azure SQL Server",
                                recommendation=f"Azure SQL Server '{s_name}' allows client connections over deprecated {display_tls}. Upgrade minimalTlsVersion to 1.2.",
                                metric_period="Current configuration",
                                data_source="Microsoft.Sql/servers API",
                                evidence={
                                    "service_name": "Azure SQL Server",
                                    "minimumTlsVersion": display_tls,
                                    "configured_tls_version": display_tls,
                                    "required": "TLS 1.2",
                                    "tls_status": "Insecure TLS Configured",
                                    "security_control": "Enforce secure TLS version",
                                    "potential_score_increase": "+3.0%",
                                },
                                security_score_impact=3.0,
                                collected_at=now_str
                            )
                        )
            except Exception as ex:
                logger.debug("Failed scanning SQL servers for TLS in sub %s: %s", sub.subscription_id, ex)

            # 4. Azure Cache for Redis
            try:
                redis_caches = await ResourcesAdapter.get_redis_caches(context.client, sub.subscription_id)
                for r in redis_caches:
                    resources_evaluated += 1
                    r_id = r.get("id", "")
                    r_name = r.get("name", "Unknown Redis Cache")
                    props = r.get("properties", {}) or {}
                    min_tls_redis = props.get("minimumTlsVersion")

                    if not min_tls_redis or str(min_tls_redis) in ("1.0", "1.1"):
                        seen_res_ids.add(r_id)
                        parsed = parse_azure_resource_id(r_id)
                        rg_name = parsed.get("resource_group") or "Unknown"
                        region = r.get("location", "global")
                        display_tls = f"TLS {min_tls_redis}" if min_tls_redis else "TLS 1.0 (Not Enforced)"

                        findings.append(
                            FindingModel(
                                finding_id=f"sec12-{sub.subscription_id[:8]}-{r_name[:12]}-redis",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=rg_name,
                                resource_name=r_name,
                                resource_type="Microsoft.Cache/Redis",
                                resource_id=r_id,
                                region=region,
                                severity="Medium",
                                status="Insecure TLS Configured",
                                current_configuration=f"minimumTlsVersion: {display_tls}",
                                measured_value=display_tls,
                                recommended_configuration="Set minimumTlsVersion to 1.2 on Azure Cache for Redis",
                                recommendation=f"Redis cache '{r_name}' accepts connections using legacy {display_tls}. Configure minimumTlsVersion to '1.2'.",
                                metric_period="Current configuration",
                                data_source="Microsoft.Cache/Redis API",
                                evidence={
                                    "service_name": "Azure Cache for Redis",
                                    "minimumTlsVersion": display_tls,
                                    "configured_tls_version": display_tls,
                                    "required": "TLS 1.2",
                                    "tls_status": "Insecure TLS Configured",
                                    "security_control": "Enforce secure TLS version",
                                    "potential_score_increase": "+2.0%",
                                },
                                security_score_impact=2.0,
                                collected_at=now_str
                            )
                        )
            except Exception as ex:
                logger.debug("Failed scanning Redis for TLS in sub %s: %s", sub.subscription_id, ex)

            # 5. Azure Cosmos DB Accounts
            try:
                cosmos_accounts = await ResourcesAdapter.get_cosmos_db_accounts(context.client, sub.subscription_id)
                for c in cosmos_accounts:
                    resources_evaluated += 1
                    c_id = c.get("id", "")
                    c_name = c.get("name", "Unknown Cosmos DB")
                    props = c.get("properties", {}) or {}
                    min_tls_cosmos = props.get("minimalTlsVersion")

                    if not min_tls_cosmos or str(min_tls_cosmos) in ("1.0", "1.1", "Tls10", "Tls11"):
                        seen_res_ids.add(c_id)
                        parsed = parse_azure_resource_id(c_id)
                        rg_name = parsed.get("resource_group") or "Unknown"
                        region = c.get("location", "global")
                        display_tls = str(min_tls_cosmos) if min_tls_cosmos else "TLS 1.0 (Not Enforced)"

                        findings.append(
                            FindingModel(
                                finding_id=f"sec12-{sub.subscription_id[:8]}-{c_name[:12]}-cosmos",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=rg_name,
                                resource_name=c_name,
                                resource_type="Microsoft.DocumentDB/databaseAccounts",
                                resource_id=c_id,
                                region=region,
                                severity="Medium",
                                status="Insecure TLS Configured",
                                current_configuration=f"minimalTlsVersion: {display_tls}",
                                measured_value=display_tls,
                                recommended_configuration="Set minimalTlsVersion to 'Tls12' on Cosmos DB account",
                                recommendation=f"Cosmos DB account '{c_name}' allows client connections over deprecated {display_tls}. Upgrade minimalTlsVersion to Tls12.",
                                metric_period="Current configuration",
                                data_source="Microsoft.DocumentDB/databaseAccounts API",
                                evidence={
                                    "service_name": "Azure Cosmos DB",
                                    "minimumTlsVersion": display_tls,
                                    "configured_tls_version": display_tls,
                                    "required": "TLS 1.2",
                                    "tls_status": "Insecure TLS Configured",
                                    "security_control": "Enforce secure TLS version",
                                    "potential_score_increase": "+2.0%",
                                },
                                security_score_impact=2.0,
                                collected_at=now_str
                            )
                        )
            except Exception as ex:
                logger.debug("Failed scanning Cosmos DB for TLS in sub %s: %s", sub.subscription_id, ex)

            # 6. Cross-reference Defender for Cloud recommendations for TLS enforcement
            try:
                def_resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id, max_items=300)
                if def_resp.get("success"):
                    for ass in def_resp.get("value", []):
                        props = ass.get("properties", {}) or {}
                        status_code = str(props.get("status", {}).get("code", "")).lower()
                        if status_code not in ("unhealthy", "open"):
                            continue

                        meta = props.get("metadata", {}) or {}
                        disp = (meta.get("displayName") or props.get("displayName") or "").lower()

                        if "tls" in disp and any(w in disp for w in ["latest", "1.2", "version", "insecure", "deprecated"]):
                            target_id = props.get("resourceDetails", {}).get("Id") or props.get("resourceDetails", {}).get("id") or ""
                            if target_id and target_id not in seen_res_ids:
                                seen_res_ids.add(target_id)
                                parsed_t = parse_azure_resource_id(target_id)
                                t_name = parsed_t.get("resource_name") or target_id.split("/")[-1] or "Azure Resource"
                                rg_t = parsed_t.get("resource_group") or "Unknown"
                                r_type = parsed_t.get("resource_type") or "Microsoft.Security/assessments"
                                remed = meta.get("remediationDescription") or meta.get("description") or "Enforce TLS 1.2 minimum version."

                                findings.append(
                                    FindingModel(
                                        finding_id=f"sec12-{sub.subscription_id[:8]}-{ass.get('name', '')[:10]}",
                                        assessment_id=self.assessment_id,
                                        category=self.category,
                                        subscription_id=sub.subscription_id,
                                        subscription_name=sub.display_name,
                                        resource_group=rg_t,
                                        resource_name=t_name,
                                        resource_type=r_type,
                                        resource_id=target_id,
                                        region="global",
                                        severity=meta.get("severity", "Medium").capitalize(),
                                        status="Insecure TLS Configured",
                                        current_configuration=f"Defender TLS Alert: {meta.get('displayName')}",
                                        measured_value="Legacy TLS Permitted",
                                        recommended_configuration=remed,
                                        recommendation=f"Microsoft Defender identified insecure TLS on '{t_name}': {remed}",
                                        metric_period="Current configuration",
                                        data_source="Microsoft Defender for Cloud Assessments API",
                                        evidence={
                                            "service_name": t_name,
                                            "minimumTlsVersion": "Legacy TLS (Allows TLS 1.0/1.1)",
                                            "configured_tls_version": "Legacy TLS",
                                            "required": "TLS 1.2",
                                            "tls_status": "Insecure TLS Configured",
                                            "security_control": "Enforce secure TLS version",
                                            "potential_score_increase": "+2.0%",
                                        },
                                        security_score_impact=2.0,
                                        collected_at=now_str
                                    )
                                )
            except Exception as ex:
                logger.debug("Defender TLS recommendations scan in sub %s: %s", sub.subscription_id, ex)

        status = AssessmentStatus.COMPLETED if findings else AssessmentStatus.NO_FINDINGS
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
