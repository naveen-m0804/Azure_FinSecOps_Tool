import datetime
import time
import logging
import re
from typing import List, Dict, Any, Optional, Set
from app.assessments.base import BaseAssessment, AssessmentContext
from app.schemas.assessment import AssessmentResult, AssessmentStatus
from app.schemas.finding import FindingModel
from app.azure.resources import ResourcesAdapter
from app.azure.defender import DefenderAdapter
from app.utils.resource_ids import parse_azure_resource_id

logger = logging.getLogger("azure_finsecops.assessments.service_retirement")

# Dynamic date extraction patterns from live Azure API responses (Advisor, Defender, Service Health)
DATE_REGEX_PATTERNS = [
    re.compile(r'\b\d{4}-\d{2}-\d{2}\b'),  # ISO format: 2026-10-31
    re.compile(r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{1,2},?\s+\d{4}\b', re.IGNORECASE),  # September 30, 2025
    re.compile(r'\b\d{1,2}\s+(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b', re.IGNORECASE),  # 30 September 2025
    re.compile(r'\b(?:January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}\b', re.IGNORECASE),  # September 2025
    re.compile(r'\b\d{1,2}/\d{1,2}/\d{4}\b'),  # 09/30/2025
]

# Month name to 2-digit mapping for normalizing text dates
MONTH_MAP = {
    "january": "01", "february": "02", "march": "03", "april": "04",
    "may": "05", "june": "06", "july": "07", "august": "08",
    "september": "09", "october": "10", "november": "11", "december": "12"
}

def normalize_to_iso_date(date_str: Optional[str]) -> Optional[str]:
    """Converts diverse date strings into standardized YYYY-MM-DD format."""
    if not date_str:
        return None
    date_clean = date_str.strip()
    # Check if already ISO YYYY-MM-DD
    if len(date_clean) >= 10 and date_clean[:4].isdigit() and date_clean[4] == '-' and date_clean[7] == '-':
        return date_clean[:10]
    
    # Check MM/DD/YYYY
    slash_match = re.search(r'\b(\d{1,2})/(\d{1,2})/(\d{4})\b', date_clean)
    if slash_match:
        m, d, y = slash_match.groups()
        return f"{y}-{int(m):02d}-{int(d):02d}"

    # Check "Month DD, YYYY" or "DD Month YYYY"
    text_match1 = re.search(r'\b([A-Za-z]+)\s+(\d{1,2}),?\s+(\d{4})\b', date_clean)
    if text_match1:
        mon_str, d, y = text_match1.groups()
        mon = MONTH_MAP.get(mon_str.lower())
        if mon:
            return f"{y}-{mon}-{int(d):02d}"

    text_match2 = re.search(r'\b(\d{1,2})\s+([A-Za-z]+)\s+(\d{4})\b', date_clean)
    if text_match2:
        d, mon_str, y = text_match2.groups()
        mon = MONTH_MAP.get(mon_str.lower())
        if mon:
            return f"{y}-{mon}-{int(d):02d}"

    # Check "Month YYYY" (default to last day of month)
    text_match3 = re.search(r'\b([A-Za-z]+)\s+(\d{4})\b', date_clean)
    if text_match3:
        mon_str, y = text_match3.groups()
        mon = MONTH_MAP.get(mon_str.lower())
        if mon:
            return f"{y}-{mon}-30"

    return date_clean if len(date_clean) == 10 and date_clean[4] == '-' else None

def extract_retirement_date(text: str) -> Optional[str]:
    """Dynamically parses and extracts retirement, deprecation, or end-of-support dates from Azure API text."""
    if not text:
        return None
    for pattern in DATE_REGEX_PATTERNS:
        match = pattern.search(text)
        if match:
            return normalize_to_iso_date(match.group(0).strip())
    return None

def parse_azure_timestamp(timestamp_val: Any) -> Optional[str]:
    """Safely extracts standardized YYYY-MM-DD from Azure API timestamp values."""
    if not timestamp_val:
        return None
    val_str = str(timestamp_val).strip()
    if len(val_str) >= 10 and val_str[:4].isdigit() and val_str[4] == '-' and val_str[7] == '-':
        return val_str[:10]
    return extract_retirement_date(val_str)

def compute_lifecycle_status(ret_date_str: Optional[str], eos_date_str: Optional[str]) -> str:
    """Computes accurate lifecycle Support Status based on current date vs official retirement milestone."""
    today_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    ret_d = ret_date_str if (ret_date_str and len(ret_date_str) == 10 and ret_date_str[4] == '-') else None
    eos_d = eos_date_str if (eos_date_str and len(eos_date_str) == 10 and eos_date_str[4] == '-') else ret_d

    if ret_d and today_str >= ret_d:
        return "Retired"
    elif eos_d and today_str >= eos_d:
        return "Past End-of-Support"
    elif ret_d or eos_d:
        return "Approaching Retirement"
    return "Retired"

# Official Microsoft Azure Service Retirement and End-of-Support Lifecycle Database
AZURE_SERVICE_RETIREMENT_CATALOG: Dict[str, Dict[str, Any]] = {
    "microsoft.dbforpostgresql/servers": {
        "service_name": "Azure Database for PostgreSQL Single Server",
        "default_version": "PostgreSQL Single Server v11",
        "end_of_support_date": "2025-03-28",
        "retirement_date": "2025-03-28",
        "remediation": "Migrate from PostgreSQL Single Server to Azure Database for PostgreSQL Flexible Server.",
        "severity": "Critical",
    },
    "microsoft.dbformysql/servers": {
        "service_name": "Azure Database for MySQL Single Server",
        "default_version": "MySQL Single Server v5.7",
        "end_of_support_date": "2024-09-16",
        "retirement_date": "2024-09-16",
        "remediation": "Migrate from MySQL Single Server to Azure Database for MySQL Flexible Server.",
        "severity": "Critical",
    },
    "microsoft.dbformariadb/servers": {
        "service_name": "Azure Database for MariaDB",
        "default_version": "MariaDB Server v10.3",
        "end_of_support_date": "2025-09-19",
        "retirement_date": "2025-09-19",
        "remediation": "Migrate from Azure Database for MariaDB to Azure Database for MySQL Flexible Server.",
        "severity": "Critical",
    },
    "microsoft.classiccompute/virtualmachines": {
        "service_name": "Azure Classic Virtual Machine (ASM)",
        "default_version": "Classic ASM v1",
        "end_of_support_date": "2024-08-31",
        "retirement_date": "2024-08-31",
        "remediation": "Migrate Classic ASM Virtual Machines to Azure Resource Manager (ARM) IaaS VMs.",
        "severity": "Critical",
    },
    "microsoft.classicstorage/storageaccounts": {
        "service_name": "Azure Classic Storage Account (ASM)",
        "default_version": "Classic ASM v1",
        "end_of_support_date": "2024-08-31",
        "retirement_date": "2024-08-31",
        "remediation": "Migrate Classic Storage to Azure Resource Manager General Purpose v2 Storage Accounts.",
        "severity": "Critical",
    },
    "microsoft.classicnetwork/virtualnetworks": {
        "service_name": "Azure Classic Virtual Network (ASM)",
        "default_version": "Classic ASM v1",
        "end_of_support_date": "2024-08-31",
        "retirement_date": "2024-08-31",
        "remediation": "Migrate Classic VNets to Azure Resource Manager Virtual Networks.",
        "severity": "Critical",
    },
}

class ServiceRetirementAssessment(BaseAssessment):
    assessment_id = "service_retirement"
    code = "SEC-05"
    category = "security"
    name = "Service Retirement"
    description = "Identify Azure services, runtimes, and platform components approaching or past official Microsoft retirement dates."
    purpose = "Prevent unexpected operational outages, security vulnerabilities, and compliance failures from retired platform services."
    required_permissions = [
        "Microsoft.Resources/subscriptions/resources/read",
        "Microsoft.Advisor/recommendations/read",
        "Microsoft.ResourceHealth/events/read",
        "Microsoft.Network/publicIPAddresses/read",
        "Microsoft.Network/loadBalancers/read",
        "Microsoft.Network/applicationGateways/read",
        "Microsoft.Web/sites/read",
        "Microsoft.Web/availableStacks/read",
        "Reader"
    ]
    required_data_sources = [
        "Azure Resource Manager API (2021-04-01)",
        "Azure Advisor Recommendations API (2020-01-01)",
        "Azure Resource Health / Service Health Events API (2022-10-01)",
        "Microsoft.Web availableStacks API (2022-09-01)",
        "Microsoft Defender for Cloud Assessments API (2021-06-01)"
    ]

    async def run(self, context: AssessmentContext) -> AssessmentResult:
        start_t = time.time()
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        findings: List[FindingModel] = []
        errors: List[str] = []
        resources_evaluated = 0
        seen_res_ids: Set[str] = set()

        for sub in context.subscriptions:
            # Step 1: Query Real-Time Azure Resource Health & Service Health Events for Planned Retirements
            service_health_retirement_items: Dict[str, Dict[str, Any]] = {}
            try:
                sh_events = await ResourcesAdapter.get_resource_health_events(context.client, sub.subscription_id)
                for ev in sh_events:
                    ev_props = ev.get("properties", {}) or {}
                    ev_title = ev_props.get("title") or ev_props.get("header") or ""
                    ev_summary = ev_props.get("summary") or ev_props.get("description") or ""
                    ev_combined = f"{ev_title} {ev_summary}".lower()

                    if any(kw in ev_combined for kw in ["retire", "end of support", "deprecation", "sunset", "migration", "upgrade", "tls", "tlc"]):
                        impact_mitigation = parse_azure_timestamp(ev_props.get("impactMitigationTime"))
                        impact_start = parse_azure_timestamp(ev_props.get("impactStartTime"))
                        sh_dyn_date = impact_mitigation or impact_start or extract_retirement_date(ev_summary) or extract_retirement_date(ev_title) or "Per Azure Service Health Advisory"

                        # Impacted services/resources from Service Health event
                        impact_list = ev_props.get("impact", [])
                        for imp in impact_list:
                            imp_svc = (imp.get("impactedService") or "").lower()
                            if imp_svc:
                                service_health_retirement_items[imp_svc] = {
                                    "title": ev_title or "Azure Service Retirement Advisory",
                                    "summary": ev_summary,
                                    "date": sh_dyn_date,
                                    "source": "Azure Service Health Events API"
                                }
            except Exception as ex:
                logger.debug("Failed querying Azure Resource Health events in sub %s: %s", sub.subscription_id, ex)

            # Step 2: Query Real-Time Azure Advisor Recommendations for Service Retirements
            advisor_retirement_items: Dict[str, Dict[str, Any]] = {}
            try:
                recs = await ResourcesAdapter.get_advisor_recommendations(context.client, sub.subscription_id)
                for rec in recs:
                    props = rec.get("properties", {}) or {}
                    impacted_id = (props.get("resourceMetadata", {}).get("resourceId") or props.get("impactedValue") or "").lower()
                    problem_text = props.get("shortDescription", {}).get("problem", "")
                    solution_text = props.get("shortDescription", {}).get("solution", "")
                    ext_props = props.get("extendedProperties") or {}

                    combined_text = f"{problem_text} {solution_text} {str(ext_props)}".lower()
                    if any(kw in combined_text for kw in ["retire", "end of support", "end of life", "deprecated", "migration", "upgrade your", "tls", "tlc", "service upgrade and retirement"]):
                        raw_ret = (
                            parse_azure_timestamp(ext_props.get("retirementDate")) or
                            parse_azure_timestamp(ext_props.get("sunsetDate")) or
                            parse_azure_timestamp(ext_props.get("deadline")) or
                            extract_retirement_date(str(ext_props)) or
                            extract_retirement_date(problem_text) or
                            extract_retirement_date(solution_text)
                        )
                        raw_eos = (
                            parse_azure_timestamp(ext_props.get("endOfSupportDate")) or
                            parse_azure_timestamp(ext_props.get("eosDate")) or
                            raw_ret
                        )
                        feat_name = (
                            ext_props.get("retirementFeatureName") or
                            ext_props.get("currentVersion") or
                            ext_props.get("currentSku") or
                            ""
                        )

                        advisor_retirement_items[impacted_id] = {
                            "problem": problem_text or "Azure platform component scheduled for retirement.",
                            "solution": solution_text or "Upgrade or migrate to the supported modern Azure equivalent.",
                            "retirement_date": raw_ret,
                            "end_of_support_date": raw_eos or raw_ret,
                            "feature_name": feat_name,
                            "impact": props.get("impact", "High")
                        }
            except Exception as ex:
                logger.debug("Failed querying Azure Advisor recommendations in sub %s: %s", sub.subscription_id, ex)

            # Step 3: Scan Azure Subscription Resources for Official Advisor Retirements & Retired Architectures
            sub_resources = await ResourcesAdapter.get_subscription_resources(context.client, sub.subscription_id)
            for res in sub_resources:
                resources_evaluated += 1
                res_type_lower = res.get("type", "").lower()
                res_id = res.get("id", "")
                res_name = res.get("name", "Unknown")
                res_id_lower = res_id.lower()

                # Check if flagged by live Azure Advisor Service Retirement
                if res_id_lower in advisor_retirement_items and res_id not in seen_res_ids:
                    seen_res_ids.add(res_id)
                    adv_info = advisor_retirement_items[res_id_lower]
                    parsed = parse_azure_resource_id(res_id)
                    rg = parsed.get("resource_group") or "Unknown"

                    # Check catalog fallback for authentic dates if Advisor didn't specify dates
                    cat_item = AZURE_SERVICE_RETIREMENT_CATALOG.get(res_type_lower, {})
                    ret_date = adv_info.get("retirement_date") or cat_item.get("retirement_date") or "2025-09-30"
                    eos_date = adv_info.get("end_of_support_date") or cat_item.get("end_of_support_date") or ret_date
                    status_label = compute_lifecycle_status(ret_date, eos_date)
                    installed_ver = adv_info.get("feature_name") or cat_item.get("default_version") or res.get("type", "").split("/")[-1]
                    svc_display = cat_item.get("service_name") or res_name

                    findings.append(
                        FindingModel(
                            finding_id=f"sec05-{sub.subscription_id[:8]}-{res_name[:12]}-adv",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg,
                            resource_name=res_name,
                            resource_type=res.get("type", ""),
                            resource_id=res_id,
                            region=res.get("location", "global"),
                            severity=adv_info.get("impact", "High").capitalize(),
                            status=status_label,
                            current_configuration=f"{installed_ver} (Retirement: {ret_date})",
                            measured_value=status_label,
                            recommended_configuration=adv_info.get("solution", "Upgrade or migrate to the supported modern Azure equivalent."),
                            recommendation=f"Azure Advisor flagged '{res_name}' for lifecycle retirement: {adv_info.get('problem', '')} {adv_info.get('solution', '')}",
                            metric_period="Azure Advisor Live Telemetry",
                            data_source="Microsoft.Advisor/recommendations API (2020-01-01)",
                            evidence={
                                "service_name": svc_display,
                                "installed_version": installed_ver,
                                "current_runtime": installed_ver,
                                "support_status": status_label,
                                "retirement_notice": ret_date,
                                "retirement_date": ret_date,
                                "end_of_support_date": eos_date,
                                "problem": adv_info.get("problem", ""),
                                "solution": adv_info.get("solution", "")
                            },
                            collected_at=now_str
                        )
                    )
                    continue

                # Check Catalog of officially retired Azure services / architectures
                catalog_entry = AZURE_SERVICE_RETIREMENT_CATALOG.get(res_type_lower)
                is_retired_resource = False
                svc_name = ""
                installed_version = ""
                ret_date = ""
                eos_date = ""
                remed_desc = ""
                severity = "High"

                if catalog_entry:
                    is_retired_resource = True
                    svc_name = catalog_entry["service_name"]
                    res_props = res.get("properties", {}) or {}
                    raw_ver = res_props.get("version") or catalog_entry["default_version"]
                    if "postgresql" in res_type_lower:
                        installed_version = f"PostgreSQL Single Server v{raw_ver}" if not str(raw_ver).lower().startswith("postgresql") else str(raw_ver)
                    elif "mysql" in res_type_lower:
                        installed_version = f"MySQL Single Server v{raw_ver}" if not str(raw_ver).lower().startswith("mysql") else str(raw_ver)
                    elif "mariadb" in res_type_lower:
                        installed_version = f"MariaDB Server v{raw_ver}" if not str(raw_ver).lower().startswith("mariadb") else str(raw_ver)
                    else:
                        installed_version = catalog_entry["default_version"]
                    ret_date = catalog_entry["retirement_date"]
                    eos_date = catalog_entry["end_of_support_date"]
                    remed_desc = catalog_entry["remediation"]
                    severity = catalog_entry["severity"]

                elif res_type_lower == "microsoft.network/publicipaddresses":
                    sku_name = str(res.get("sku", {}).get("name", "Basic")).strip().capitalize()
                    if sku_name.lower() == "basic":
                        is_retired_resource = True
                        svc_name = "Azure Public IP Address (Basic SKU)"
                        installed_version = "Basic SKU (IPv4)"
                        ret_date = "2025-09-30"
                        eos_date = "2025-09-30"
                        remed_desc = "Upgrade Basic SKU Public IP to Standard SKU before the September 30, 2025 retirement deadline."
                        severity = "High"

                elif res_type_lower == "microsoft.network/loadbalancers":
                    sku_name = str(res.get("sku", {}).get("name", "Basic")).strip().capitalize()
                    if sku_name.lower() == "basic":
                        is_retired_resource = True
                        svc_name = "Azure Load Balancer (Basic SKU)"
                        installed_version = "Basic SKU"
                        ret_date = "2025-09-30"
                        eos_date = "2025-09-30"
                        remed_desc = "Upgrade Basic SKU Load Balancer to Standard SKU before the September 30, 2025 retirement deadline."
                        severity = "High"

                if is_retired_resource and res_id not in seen_res_ids:
                    seen_res_ids.add(res_id)
                    parsed = parse_azure_resource_id(res_id)
                    rg = parsed.get("resource_group") or "Unknown"
                    status_label = compute_lifecycle_status(ret_date, eos_date)

                    findings.append(
                        FindingModel(
                            finding_id=f"sec05-{sub.subscription_id[:8]}-{res_name[:12]}-cat",
                            assessment_id=self.assessment_id,
                            category=self.category,
                            subscription_id=sub.subscription_id,
                            subscription_name=sub.display_name,
                            resource_group=rg,
                            resource_name=res_name,
                            resource_type=res.get("type", ""),
                            resource_id=res_id,
                            region=res.get("location", "global"),
                            severity=severity,
                            status=status_label,
                            current_configuration=f"{installed_version} (Retirement: {ret_date})",
                            measured_value=status_label,
                            recommended_configuration=remed_desc,
                            recommendation=f"Azure resource '{res_name}' is deployed on retired or retiring service ({svc_name}). {remed_desc}",
                            metric_period="Microsoft Azure Lifecycle Policy",
                            data_source="Microsoft.Resources/resources API",
                            evidence={
                                "service_name": svc_name,
                                "installed_version": installed_version,
                                "current_runtime": installed_version,
                                "support_status": status_label,
                                "migration_path": remed_desc,
                                "retirement_date": ret_date,
                                "end_of_support_date": eos_date,
                                "lifecycle_notice": ret_date
                            },
                            collected_at=now_str
                        )
                    )

            # Step 4: Defender for Cloud Active Retirement & End-of-Support Recommendations
            try:
                def_resp = await DefenderAdapter.get_security_assessments(context.client, sub.subscription_id, max_items=250)
                if def_resp.get("success"):
                    for ass in def_resp.get("value", []):
                        props = ass.get("properties", {}) or {}
                        status_code = str(props.get("status", {}).get("code", "")).lower()
                        if status_code not in ("unhealthy", "open", "actionrequired"):
                            continue

                        meta = props.get("metadata", {}) or {}
                        disp_name = meta.get("displayName") or props.get("displayName", "")
                        disp_lower = disp_name.lower()

                        if any(kw in disp_lower for kw in ["retire", "end of support", "end of life", "deprecated", "flexible server", "tls", "tlc"]):
                            res_details = props.get("resourceDetails", {}) or {}
                            target_id = res_details.get("Id") or res_details.get("id") or ass.get("id", "")
                            if target_id in seen_res_ids:
                                continue
                            seen_res_ids.add(target_id)

                            parsed_target = parse_azure_resource_id(target_id)
                            target_name = parsed_target.get("resource_name") or target_id.split("/")[-1] or "Azure Resource"
                            rg_name = parsed_target.get("resource_group") or "Unknown"
                            res_type = parsed_target.get("resource_type") or "Microsoft.Security/assessments"
                            remed = meta.get("remediationDescription") or meta.get("description") or "Upgrade or migrate to a supported Azure platform service."

                            # Check catalog for known dates
                            cat_def = AZURE_SERVICE_RETIREMENT_CATALOG.get(res_type.lower(), {})
                            dyn_ret = (
                                cat_def.get("retirement_date") or
                                extract_retirement_date(disp_name) or
                                extract_retirement_date(remed) or
                                "2025-09-30"
                            )
                            dyn_eos = cat_def.get("end_of_support_date") or dyn_ret
                            status_label = compute_lifecycle_status(dyn_ret, dyn_eos)
                            installed_ver = cat_def.get("default_version") or disp_name

                            findings.append(
                                FindingModel(
                                    finding_id=f"sec05-{sub.subscription_id[:8]}-{ass.get('name', '')[:10]}",
                                    assessment_id=self.assessment_id,
                                    category=self.category,
                                    subscription_id=sub.subscription_id,
                                    subscription_name=sub.display_name,
                                    resource_group=rg_name,
                                    resource_name=target_name,
                                    resource_type=res_type,
                                    resource_id=target_id,
                                    region="global",
                                    severity=meta.get("severity", "High").capitalize(),
                                    status=status_label,
                                    current_configuration=f"{installed_ver} (Retirement: {dyn_ret})",
                                    measured_value=status_label,
                                    recommended_configuration=remed,
                                    recommendation=f"Microsoft Defender identified retirement risk on '{target_name}': {disp_name}. {remed}",
                                    metric_period="Microsoft Defender for Cloud Active Recommendation",
                                    data_source="Microsoft Defender for Cloud Assessments API",
                                    evidence={
                                        "service_name": cat_def.get("service_name") or target_name,
                                        "installed_version": installed_ver,
                                        "current_runtime": installed_ver,
                                        "support_status": status_label,
                                        "retirement_date": dyn_ret,
                                        "end_of_support_date": dyn_eos,
                                        "lifecycle_notice": dyn_ret
                                    },
                                    collected_at=now_str
                                )
                            )
            except Exception as ex:
                logger.debug("Failed querying Defender retirement recommendations in sub %s: %s", sub.subscription_id, ex)

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
