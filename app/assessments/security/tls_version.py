import datetime
import time
from typing import List, Dict, Any
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.storage import StorageAdapter
from app.azure.resources import ResourcesAdapter
from app.utils.resource_ids import parse_azure_resource_id

class TlsVersionAssessment(BaseAssessment):
    assessment_id = "tls_version"
    code = "SEC-12"
    category = "security"
    name = "TLS Version"
    description = "Audit minimum TLS protocols configured across Azure services (Storage Accounts, App Services, SQL Servers, Redis)."
    purpose = "Enforce strong in-transit cipher standards (TLS 1.2+) and eliminate weak cryptographic legacy protocols."
    required_permissions = [
        "Microsoft.Storage/storageAccounts/read",
        "Microsoft.Web/sites/read",
        "Microsoft.Sql/servers/read",
        "Reader"
    ]
    required_data_sources = ["Microsoft.Storage, Microsoft.Web, Microsoft.Sql REST APIs"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        for sub in context.subscriptions:
            # 1. Storage Accounts
            storage_accounts = await StorageAdapter.get_storage_accounts(context.client, sub.subscription_id)
            for sa in storage_accounts:
                resources_evaluated += 1
                sa_name = sa.get("name", "Unknown Storage")
                props = sa.get("properties", {})
                min_tls = props.get("minimumTlsVersion", "TLS1_2")
                
                # Check for legacy TLS
                if min_tls.upper() in ("TLS1_0", "TLS1_1"):
                    parsed = parse_azure_resource_id(sa.get("id", ""))
                    rg_name = parsed.get("resource_group") or "Unknown"
                    region = sa.get("location", "global")
                    remed = "Update Storage Account 'minimumTlsVersion' to TLS1_2"

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
                            resource_id=sa.get("id", ""),
                            region=region,
                            severity="Medium",
                            status="Insecure TLS Configured",
                            current_configuration=f"Configured minimumTlsVersion: {min_tls}",
                            measured_value=min_tls,
                            recommended_configuration="Enforce TLS 1.2 minimum version for all in-transit REST/Blob/File API traffic",
                            recommendation=f"Storage account '{sa_name}' allows deprecated TLS version ({min_tls}). {remed}",
                            metric_period="Current configuration",
                            data_source="Microsoft.Storage storageAccounts API (2023-01-01)",
                            evidence={
                                "service_name": "Azure Storage Account",
                                "minimumTlsVersion": min_tls,
                                "configured_tls_version": min_tls,
                                "required": "TLS 1.2",
                                "tls_status": "Insecure TLS Configured",
                                "security_control": "Enforce secure TLS version",
                                "potential_score_increase": "+2.0%",
                            },
                            security_score_impact=2.0,
                            collected_at=now_str
                        )
                    )

            # 2. App Services (Web Apps)
            app_services = await ResourcesAdapter.get_app_services(context.client, sub.subscription_id)
            for app in app_services:
                resources_evaluated += 1
                app_name = app.get("name", "Unknown App")
                props = app.get("properties", {})
                site_cfg = props.get("siteConfig", {})
                min_tls_app = site_cfg.get("minTlsVersion", "1.2")

                if str(min_tls_app) in ("1.0", "1.1"):
                    parsed = parse_azure_resource_id(app.get("id", ""))
                    rg_name = parsed.get("resource_group") or "Unknown"
                    region = app.get("location", "global")
                    remed = "Configure Web App siteConfig.minTlsVersion to '1.2'"

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
                            resource_id=app.get("id", ""),
                            region=region,
                            severity="Medium",
                            status="Insecure TLS Configured",
                            current_configuration=f"minTlsVersion: TLS {min_tls_app}",
                            measured_value=f"TLS {min_tls_app}",
                            recommended_configuration="Enforce TLS 1.2 minimum version for all incoming HTTPS traffic",
                            recommendation=f"App Service '{app_name}' accepts connections using legacy TLS {min_tls_app}. {remed}",
                            metric_period="Current configuration",
                            data_source="Microsoft.Web/sites API (2022-09-01)",
                            evidence={
                                "service_name": "Azure App Service",
                                "minimumTlsVersion": f"TLS {min_tls_app}",
                                "configured_tls_version": f"TLS {min_tls_app}",
                                "required": "TLS 1.2",
                                "tls_status": "Insecure TLS Configured",
                                "security_control": "Enforce secure TLS version",
                                "potential_score_increase": "+2.0%",
                            },
                            security_score_impact=2.0,
                            collected_at=now_str
                        )
                    )

            # 3. Azure SQL Servers
            sql_servers = await ResourcesAdapter.get_sql_servers(context.client, sub.subscription_id)
            for s in sql_servers:
                resources_evaluated += 1
                s_name = s.get("name", "Unknown SQL Server")
                props = s.get("properties", {})
                min_tls_sql = props.get("minimalTlsVersion", "1.2")

                if str(min_tls_sql) in ("1.0", "1.1"):
                    parsed = parse_azure_resource_id(s.get("id", ""))
                    rg_name = parsed.get("resource_group") or "Unknown"
                    region = s.get("location", "global")

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
                            resource_id=s.get("id", ""),
                            region=region,
                            severity="High",
                            status="Insecure TLS Configured",
                            current_configuration=f"minimalTlsVersion: TLS {min_tls_sql}",
                            measured_value=f"TLS {min_tls_sql}",
                            recommended_configuration="Set minimalTlsVersion to 1.2 on Azure SQL Server",
                            recommendation=f"Azure SQL Server '{s_name}' allows client connections over deprecated TLS {min_tls_sql}. Upgrade minimalTlsVersion to 1.2.",
                            metric_period="Current configuration",
                            data_source="Microsoft.Sql/servers API (2022-05-01-preview)",
                            evidence={
                                "service_name": "Azure SQL Server",
                                "minimumTlsVersion": f"TLS {min_tls_sql}",
                                "configured_tls_version": f"TLS {min_tls_sql}",
                                "required": "TLS 1.2",
                                "tls_status": "Insecure TLS Configured",
                                "security_control": "Enforce secure TLS version",
                                "potential_score_increase": "+3.0%",
                            },
                            security_score_impact=3.0,
                            collected_at=now_str
                        )
                    )

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
