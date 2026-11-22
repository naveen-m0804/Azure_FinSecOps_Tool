import datetime
import time
from typing import List, Dict, Any, Tuple
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.resources import ResourcesAdapter
from app.utils.resource_ids import parse_azure_resource_id

# Authoritative Microsoft Lifecycle Guidance for Azure Services & Runtimes
RETIRED_AZURE_SERVICES: Dict[str, Dict[str, str]] = {
    "microsoft.dbforpostgresql/servers": {
        "service_name": "Azure Database for PostgreSQL Single Server",
        "support_status": "Retired",
        "end_of_support_date": "2024-09-16",
        "retirement_date": "2024-09-16",
        "recommendation": "Migrate from PostgreSQL Single Server to Azure Database for PostgreSQL Flexible Server."
    },
    "microsoft.dbformysql/servers": {
        "service_name": "Azure Database for MySQL Single Server",
        "support_status": "Retired",
        "end_of_support_date": "2024-09-16",
        "retirement_date": "2024-09-16",
        "recommendation": "Migrate from MySQL Single Server to Azure Database for MySQL Flexible Server."
    },
    "microsoft.classicstorage/storageaccounts": {
        "service_name": "Azure Classic Storage Account (ASM)",
        "support_status": "Retired",
        "end_of_support_date": "2024-08-31",
        "retirement_date": "2024-08-31",
        "recommendation": "Migrate Classic Storage Accounts to Azure Resource Manager (ARM) General Purpose v2."
    },
    "microsoft.classiccompute/virtualmachines": {
        "service_name": "Azure Classic Virtual Machine (ASM)",
        "support_status": "Retired",
        "end_of_support_date": "2024-03-01",
        "retirement_date": "2024-03-01",
        "recommendation": "Migrate Classic VMs to Azure Resource Manager (ARM) IaaS VMs."
    }
}

RETIRED_APP_SERVICE_RUNTIMES: List[Tuple[str, str, str, str]] = [
    # (pattern_in_linux_fx, runtime_display, end_of_support_date, retirement_date)
    ("node|14", "Node.js 14 LTS", "2023-04-30", "2023-04-30"),
    ("node|16", "Node.js 16 LTS", "2023-09-11", "2023-09-11"),
    ("php|7.4", "PHP 7.4", "2022-11-28", "2022-11-28"),
    ("php|7.3", "PHP 7.3", "2021-12-06", "2021-12-06"),
    ("python|3.7", "Python 3.7", "2023-06-27", "2023-06-27"),
    ("python|3.8", "Python 3.8", "2024-10-14", "2024-10-14"),
    ("dotnetcore|3.1", ".NET Core 3.1", "2022-12-13", "2022-12-13"),
    ("dotnetcore|2.1", ".NET Core 2.1", "2021-08-21", "2021-08-21"),
]

class ServiceRetirementAssessment(BaseAssessment):
    assessment_id = "service_retirement"
    code = "SEC-05"
    category = "security"
    name = "Service Retirement"
    description = "Identify Azure services, runtimes, or configurations approaching or past official retirement dates."
    purpose = "Prevent unexpected operational outages and security vulnerabilities from retired platform components."
    required_permissions = ["Microsoft.Resources/subscriptions/resources/read", "Microsoft.Web/sites/read", "Reader"]
    required_data_sources = ["Azure Resource Manager & Microsoft Official Lifecycle Guidance"]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        
        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0

        for sub in context.subscriptions:
            # 1. Query resources across subscription for retired service types
            sub_resources = await ResourcesAdapter.get_subscription_resources(context.client, sub.subscription_id)
            for res in sub_resources:
                resources_evaluated += 1
                res_type_lower = res.get("type", "").lower()

                if res_type_lower in RETIRED_AZURE_SERVICES:
                    meta = RETIRED_AZURE_SERVICES[res_type_lower]
                    res_name = res.get("name", "Unknown")
                    res_id = res.get("id", "")
                    parsed = parse_azure_resource_id(res_id)
                    rg = parsed.get("resource_group") or "Unknown"

                    findings.append(
                        FindingModel(
                            finding_id=f"sec05-{sub.subscription_id[:8]}-{res_name[:12]}",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg,
                            resource_name=res_name,
                            resource_type=res.get("type", ""),
                            resource_id=res_id,
                            region=res.get("location", "global"),
                            severity="High",
                            status="Retired",
                            current_configuration=f"{meta['service_name']} (Official Retirement: {meta['retirement_date']})",
                            measured_value="End of Support / Retired",
                            recommended_configuration=meta["recommendation"],
                            recommendation=f"Azure service '{meta['service_name']}' reached official retirement on {meta['retirement_date']}. {meta['recommendation']}",
                            metric_period="Microsoft Official Lifecycle",
                            data_source="Azure Resource Manager & Microsoft Lifecycle Policy",
                            evidence={
                                "service_name": meta["service_name"],
                                "current_runtime": meta["service_name"],
                                "support_status": meta["support_status"],
                                "end_of_support_date": meta["end_of_support_date"],
                                "retirement_date": meta["retirement_date"]
                            },
                            collected_at=now_str
                        )
                    )

            # 2. Check App Services for deprecated runtimes
            app_services = await ResourcesAdapter.get_app_services(context.client, sub.subscription_id)
            for app in app_services:
                resources_evaluated += 1
                props = app.get("properties", {})
                site_cfg = props.get("siteConfig", {})
                linux_fx = (site_cfg.get("linuxFxVersion") or "").lower()
                net_ver = site_cfg.get("netFrameworkVersion") or ""
                php_ver = site_cfg.get("phpVersion") or ""
                python_ver = site_cfg.get("pythonVersion") or ""
                node_ver = site_cfg.get("nodeVersion") or ""

                app_name = app.get("name", "Unknown")
                app_id = app.get("id", "")
                parsed = parse_azure_resource_id(app_id)
                rg = parsed.get("resource_group") or "Unknown"

                # Check runtime match against retired runtimes
                for pattern, display_rt, eos_date, ret_date in RETIRED_APP_SERVICE_RUNTIMES:
                    if pattern in linux_fx or (pattern.startswith("php") and php_ver.startswith("7")) or (pattern.startswith("python") and python_ver.startswith("3.7")):
                        findings.append(
                            FindingModel(
                                finding_id=f"sec05-{sub.subscription_id[:8]}-{app_name[:10]}-rt",
                                assessment_id=self.assessment_id,
                                category=self.category,
                                subscription_id=sub.subscription_id,
                                subscription_name=sub.display_name,
                                resource_group=rg,
                                resource_name=app_name,
                                resource_type="Microsoft.Web/sites",
                                resource_id=app_id,
                                region=app.get("location", "global"),
                                severity="High",
                                status="End-of-Support",
                                current_configuration=f"Configured Runtime: {display_rt} (Retired {ret_date})",
                                measured_value=f"Retired Runtime: {display_rt}",
                                recommended_configuration=f"Upgrade App Service stack to currently supported LTS runtime",
                                recommendation=f"App Service '{app_name}' is configured with {display_rt}, which reached official End-of-Support on {eos_date}. Upgrade to an actively supported LTS version.",
                                metric_period="Microsoft Lifecycle Policy",
                                data_source="Microsoft.Web/sites siteConfig API",
                                evidence={
                                    "service_name": f"App Service ({display_rt})",
                                    "current_runtime": display_rt,
                                    "support_status": "End-of-Support",
                                    "end_of_support_date": eos_date,
                                    "retirement_date": ret_date
                                },
                                collected_at=now_str
                            )
                        )
                        break

        status = AssessmentStatus.COMPLETED if findings else AssessmentStatus.NO_FINDINGS
        return AssessmentResult(
            assessment_id=self.assessment_id,
            category=self.category,
            name=self.name,
            status=status,
            resources_evaluated=max(resources_evaluated, len(context.subscriptions)),
            findings_count=len(findings),
            findings=findings,
            errors=errors,
            execution_time_seconds=round(time.time() - start_t, 2),
            last_run_time=now_str
        )
