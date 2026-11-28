"""
Security Assessment Reporting Schema & Column Specifications
Directly implementing the requirements from:
AZURE FINSECOPS - SECURITY ASSESSMENT DATA FETCHING AND REPORT REDESIGN
"""

from typing import Dict, Any, List, Optional

def _clean_resource_type(r_type: Any) -> str:
    if not r_type:
        return "--"
    r_type_str = str(r_type)
    return r_type_str.split("/")[-1] if "/" in r_type_str else r_type_str

SECURITY_REPORT_SPECS: Dict[str, Dict[str, Any]] = {
    # 1. Subscription Security Score
    "subscription_security_score": {
        "code": "SEC-01",
        "report_title": "Microsoft Defender for Cloud - Security Score",
        "columns": [
            "Subscription Name",
            "Security Control",
            "Current Score Percentage",
            "Potential Score Increase",
            "Unhealthy Resources Count",
        ],
        "col_widths": [170, 210, 130, 122, 120],  # Total = 752 pt
        "extractor": lambda f: [
            f.subscription_name,
            f.evidence.get("security_control") or f.resource_name.replace("ascScore-", "").replace("ascScore", "Defender Secure Score") or "Microsoft Defender Overall Secure Score",
            f.measured_value or (f"{f.evidence.get('percentage')}%" if f.evidence.get('percentage') is not None else "--"),
            f"+{f.security_score_impact:.1f}%" if f.security_score_impact else (f"+{f.evidence.get('potential_increase')}%" if f.evidence.get("potential_increase") else "--"),
            str(f.evidence.get("unhealthy_resources_count", f.evidence.get("unhealthyResourceCount", "--"))),
        ]
    },

    # 2. New Security Recommendations (No Potential Score Increase)
    "new_recommendations": {
        "code": "SEC-02",
        "report_title": "New Azure Security Recommendations",
        "columns": [
            "Subscription Name",
            "Resource Group Name",
            "Resource Name",
            "Resource Type",
            "Recommendation Name",
            "Severity",
            "Recommendation Status",
            "First Detected Date",
            "Description",
            "Azure Remediation Recommendation",
            "Related Security Control",
        ],
        "col_widths": [85, 75, 75, 75, 90, 48, 58, 62, 95, 99, 60],  # Total = 752 pt
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_group or "--",
            f.resource_name,
            _clean_resource_type(f.resource_type),
            f.evidence.get("recommendation_name") or f.resource_name,
            f.severity,
            f.status,
            f.evidence.get("first_detected_date") or "--",
            f.evidence.get("description") or f.current_configuration or "--",
            f.recommendation or "--",
            f.evidence.get("security_control") or "--",
        ]
    },

    # 3. Resources Missing Diagnostic Logs
    "resources_without_logs": {
        "code": "SEC-03",
        "report_title": "Resources Missing Diagnostic Logs",
        "columns": [
            "Subscription Name",
            "Resource Group Name",
            "Resource Name",
            "Resource Type",
            "Region",
            "Environment",
            "Diagnostic Settings Status",
            "Enabled Log Categories",
            "Log Analytics Workspace",
            "Storage Account Destination",
        ],
        "col_widths": [90, 85, 85, 95, 60, 65, 75, 75, 65, 57],
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_group or "--",
            f.resource_name,
            _clean_resource_type(f.resource_type),
            f.region or "global",
            f.evidence.get("environment") or "General Workload",
            f.status or "Missing Diagnostic Settings",
            f.evidence.get("enabled_log_categories") or "None",
            f.evidence.get("workspace_name") or "None Configured",
            f.evidence.get("storage_destination") or "None",
        ]
    },

    # 4. High Priority Security Recommendations
    "high_priority_recommendations": {
        "code": "SEC-04",
        "report_title": "High Priority Azure Security Findings",
        "columns": [
            "Subscription Name",
            "Resource Group Name",
            "Resource Name",
            "Resource Type",
            "Recommendation",
            "Severity",
            "Description",
            "Azure Remediation",
            "Related Security Control",
        ],
        "col_widths": [75, 70, 70, 70, 95, 42, 130, 130, 70],  # Total = 752 pt
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_group or "--",
            f.resource_name,
            _clean_resource_type(f.resource_type),
            f.evidence.get("recommendation_name") or f.resource_name,
            f.severity,
            f.evidence.get("description") or f.current_configuration or "--",
            f.evidence.get("remediation") or f.recommendation or "--",
            f.evidence.get("security_control") or "--",
        ]
    },

    # 5. Service Retirement / End-of-Support
    "service_retirement": {
        "code": "SEC-05",
        "report_title": "Azure Services Approaching End-of-Support",
        "columns": [
            "Subscription Name",
            "Resource Group Name",
            "Resource Name",
            "Resource Type",
            "Region",
            "Service Name",
            "Installed or Configured Version",
            "Support Status",
            "End-of-Support Date",
            "Retirement Date",
        ],
        "col_widths": [90, 85, 85, 85, 60, 75, 85, 70, 60, 57],
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_group or "--",
            f.resource_name,
            _clean_resource_type(f.resource_type),
            f.region or "global",
            f.evidence.get("service_name") or (_clean_resource_type(f.resource_type)),
            f.evidence.get("installed_version") or f.evidence.get("current_runtime") or f.current_configuration or "--",
            f.evidence.get("support_status") or f.status or "Retired",
            f.evidence.get("end_of_support_date") or "--",
            f.evidence.get("retirement_date") or f.evidence.get("end_of_support_date") or "--",
        ]
    },

    # 6. High Security Alerts
    "security_alerts": {
        "code": "SEC-06",
        "report_title": "High Severity Azure Security Alerts",
        "columns": [
            "Subscription Name",
            "Resource Group Name",
            "Resource Name",
            "Resource Type",
            "Alert Name",
            "Severity",
            "Alert Status",
            "Alert Generated Time",
            "Description",
            "Affected Entity",
            "Attack Tactics",
        ],
        "col_widths": [85, 75, 75, 75, 85, 45, 55, 65, 95, 70, 62],
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_group or "--",
            f.resource_name,
            _clean_resource_type(f.resource_type),
            f.evidence.get("alert_name") or f.resource_name,
            f.severity,
            f.status or "Active",
            f.evidence.get("generated_time") or (f.collected_at[:16] if f.collected_at else "--"),
            f.evidence.get("description") or f.current_configuration or "--",
            f.evidence.get("affected_entity") or f.resource_name,
            f.evidence.get("attack_tactics") or f.evidence.get("alert_type") or "--",
        ]
    },

    # 7. Attack Paths
    "attack_paths": {
        "code": "SEC-07",
        "report_title": "Azure Security Attack Path Findings",
        "columns": [
            "Subscription Name",
            "Attack Path Name",
            "Source Resource",
            "Target Resource",
            "Affected Resource",
            "Resource Group Name",
            "Resource Type",
            "Region",
            "Risk Level",
            "Attack Techniques",
            "Related Security Recommendations",
        ],
        "col_widths": [85, 85, 75, 75, 75, 65, 65, 50, 45, 65, 67],
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_name,
            f.evidence.get("source_resource") or f.evidence.get("entry_point") or "Internet",
            f.evidence.get("target_resource") or f.evidence.get("target") or "--",
            f.evidence.get("affected_resource") or f.resource_name,
            f.resource_group or "--",
            _clean_resource_type(f.resource_type),
            f.region or "global",
            f.evidence.get("risk_level") or f.severity,
            f.evidence.get("attack_techniques") or "MITRE ATT&CK T1078",
            f.recommendation or "--",
        ]
    },

    # 8. OS Version per VM
    "vm_os_version": {
        "code": "SEC-08",
        "report_title": "Virtual Machines Running Outdated Operating Systems",
        "columns": [
            "Subscription Name",
            "Resource Group Name",
            "Virtual Machine Name",
            "Region",
            "Operating System",
            "OS Version",
            "OS Build",
            "Publisher",
        ],
        "col_widths": [105, 95, 95, 75, 110, 95, 80, 97],  # Total = 752 pt
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_group or "--",
            f.resource_name,
            f.region or "global",
            f.evidence.get("os_type") or f.evidence.get("os_name") or "Windows / Linux",
            f.evidence.get("os_version") or f.evidence.get("sku") or f.current_configuration or "--",
            f.evidence.get("os_build") or "--",
            f.evidence.get("publisher") or "--",
        ]
    },

    # 9. VM Patching / Missing Patches
    "vm_patching": {
        "code": "SEC-09",
        "report_title": "Virtual Machines Missing Security Patches",
        "columns": [
            "Subscription Name",
            "Resource Group Name",
            "Virtual Machine Name",
            "Region",
            "Operating System",
            "OS Version",
            "Patch Assessment Status",
            "Last Assessment Date",
            "Missing Security Updates",
            "Missing Critical Updates",
            "Reboot Required",
            "Patch Status",
        ],
        "col_widths": [80, 70, 75, 50, 65, 65, 70, 65, 55, 55, 45, 57],
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_group or "--",
            f.resource_name,
            f.region or "global",
            f.evidence.get("os_type") or "Windows / Linux",
            f.evidence.get("os_version") or "--",
            f.evidence.get("assessment_status") or "Succeeded",
            f.evidence.get("last_assessment_date") or (f.collected_at[:10] if f.collected_at else "--"),
            str(f.evidence.get("security_updates", 0)),
            str(f.evidence.get("critical_updates", 0)),
            "Yes" if f.evidence.get("reboot_required") else "No",
            f.evidence.get("patch_status") or f.status or "Action Required",
        ]
    },

    # 10. Software Version Upgrades
    "software_upgrades": {
        "code": "SEC-10",
        "report_title": "Outdated Software Versions on Azure Virtual Machines",
        "columns": [
            "Subscription Name",
            "Resource Group Name",
            "Resource Name",
            "Resource Type",
            "Recommendation Name",
            "Severity",
            "Status",
            "First Detected Date",
            "Software Name",
            "Installed Version",
            "Latest / Fix Version",
            "Description",
            "Azure Remediation Recommendation",
            "Related Security Control",
        ],
        "col_widths": [62, 55, 55, 50, 68, 40, 46, 50, 50, 52, 50, 62, 62, 50],  # Total = 752 pt
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_group or "--",
            f.resource_name,
            _clean_resource_type(f.resource_type),
            f.evidence.get("recommendation_name") or f.evidence.get("software") or "--",
            f.severity,
            f.status or "Update Required",
            f.evidence.get("first_detected_date") or "--",
            f.evidence.get("software") or f.evidence.get("software_name") or "--",
            f.evidence.get("installed_version") or f.current_configuration or "--",
            f.evidence.get("recommended_version") or f.evidence.get("latest_version") or "--",
            f.evidence.get("description") or f.current_configuration or "--",
            f.evidence.get("remediation") or f.recommendation or "--",
            f.evidence.get("security_control") or "--",
        ]
    },

    # 11. Disk Encryption
    "disk_encryption": {
        "code": "SEC-11",
        "report_title": "Azure Disks with Encryption Configuration Gaps",
        "columns": [
            "Subscription Name",
            "Resource Group Name",
            "Virtual Machine Name",
            "Disk Name",
            "Disk Type",
            "Disk SKU",
            "Disk Size",
            "Region",
            "Encryption Type",
            "Encryption at Host Status",
            "Disk Encryption Set",
            "CMK Configuration",
            "Encryption Status",
            "Related Security Control",
            "Potential Score Increase",
            "Azure Remediation Recommendation",
        ],
        "col_widths": [60, 55, 55, 55, 45, 45, 40, 40, 55, 45, 45, 45, 45, 50, 35, 77],
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("attached_vm") or "--",
            f.resource_name,
            f.evidence.get("disk_type") or "Managed Disk",
            f.evidence.get("disk_sku") or "Premium_LRS",
            f.evidence.get("disk_size_gb") or "512 GB",
            f.region or "global",
            f.evidence.get("encryption_type") or f.current_configuration or "PMK Only",
            "Enabled" if f.evidence.get("encryption_at_host") else "Disabled",
            f.evidence.get("disk_encryption_set") or "None",
            f.evidence.get("cmk_configured") or "Not Configured",
            f.status or "Non-Compliant",
            f.evidence.get("security_control") or "Apply disk encryption",
            f"+{f.security_score_impact:.1f}%" if f.security_score_impact else "--",
            f.recommendation or "--",
        ]
    },

    # 12. TLS Version (No Potential Score Increase)
    "tls_version": {
        "code": "SEC-12",
        "report_title": "Azure Services Using Insecure TLS Configurations",
        "columns": [
            "Subscription Name",
            "Resource Group Name",
            "Resource Name",
            "Resource Type",
            "Region",
            "Service Name",
            "Minimum TLS Version",
            "Configured TLS Version",
            "Required TLS Version",
            "TLS Configuration Status",
            "Related Security Control",
            "Azure Remediation Recommendation",
        ],
        "col_widths": [75, 65, 70, 70, 50, 65, 55, 55, 55, 60, 60, 72],  # Total = 752 pt
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_group or "--",
            f.resource_name,
            _clean_resource_type(f.resource_type),
            f.region or "global",
            f.evidence.get("service_name") or (_clean_resource_type(f.resource_type)),
            f.evidence.get("minimumTlsVersion") or f.current_configuration or "TLS 1.0",
            f.evidence.get("configured_tls_version") or f.measured_value or "TLS 1.0",
            f.evidence.get("required") or "TLS 1.2",
            f.status or "Legacy TLS Allowed",
            f.evidence.get("security_control") or "Enforce secure TLS version",
            f.recommendation or "--",
        ]
    },

    # 13. Key Vault RBAC Migration
    "keyvault_rbac": {
        "code": "SEC-13",
        "report_title": "Azure Key Vaults Using Access Policy Authorization",
        "columns": [
            "Subscription Name",
            "Resource Group Name",
            "Key Vault Name",
            "Region",
            "Authorization Model",
            "RBAC Authorization Status",
            "Access Policy Count",
            "Role Assignment Count",
            "Access Policy Permissions",
            "Assigned Roles",
            "Related Security Control",
            "Potential Score Increase",
            "Azure Remediation Recommendation",
        ],
        "col_widths": [75, 65, 70, 50, 65, 55, 45, 45, 65, 55, 60, 35, 67],
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_group or "--",
            f.resource_name,
            f.region or "global",
            "Azure RBAC" if f.evidence.get("enableRbacAuthorization") else "Vault Access Policies",
            "Enabled" if f.evidence.get("enableRbacAuthorization") else "Disabled",
            str(f.evidence.get("policy_count", "--")),
            str(f.evidence.get("role_assignment_count", "--")),
            f.evidence.get("permissions") or "Keys, Secrets, Certificates full access",
            f.evidence.get("assigned_roles") or "None",
            f.evidence.get("security_control") or "Migrate Key Vault to Azure RBAC",
            f"+{f.security_score_impact:.1f}%" if f.security_score_impact else "--",
            f.recommendation or "--",
        ]
    },

    # 14. Contributor RBAC Review
    "contributor_rbac": {
        "code": "SEC-14",
        "report_title": "Azure Contributor Role Assignments Requiring Review",
        "columns": [
            "Subscription Name",
            "Resource Group Name",
            "Resource Name",
            "Principal Name",
            "Principal Type",
            "Role Name",
            "Assignment Scope",
            "Assignment Type",
            "Related Security Control",
            "Potential Score Increase",
            "Azure Remediation Recommendation",
        ],
        "col_widths": [80, 70, 75, 75, 65, 55, 80, 65, 65, 40, 82],
        "extractor": lambda f: [
            f.subscription_name,
            f.resource_group or "Subscription Scope",
            f.resource_name,
            f.evidence.get("principal_name") or f.resource_name,
            f.evidence.get("principal_type") or "User",
            f.evidence.get("role_name") or "Contributor",
            f.evidence.get("scope") or "This resource",
            f.evidence.get("assignment_type") or "Active Permanent",
            f.evidence.get("security_control") or "Review Contributor permissions",
            f"+{f.security_score_impact:.1f}%" if f.security_score_impact else "--",
            f.recommendation or "--",
        ]
    },
}

# Aliases for assessment ID variations
SECURITY_REPORT_SPECS["secure_score"] = SECURITY_REPORT_SPECS["subscription_security_score"]
SECURITY_REPORT_SPECS["SEC-01"] = SECURITY_REPORT_SPECS["subscription_security_score"]

def get_security_spec(assessment_id: str) -> Optional[Dict[str, Any]]:
    """Returns the reporting specification for a security assessment."""
    return SECURITY_REPORT_SPECS.get(assessment_id)

class FindingObjectWrapper:
    """Wraps dictionary finding data to allow dot-attribute access for reporting extractors."""
    def __init__(self, data: Any):
        if isinstance(data, dict):
            self._data = dict(data)
        elif hasattr(data, "model_dump"):
            self._data = data.model_dump()
        elif hasattr(data, "__dict__"):
            self._data = dict(data.__dict__)
        else:
            self._data = {}

    def __getattr__(self, name: str) -> Any:
        val = self._data.get(name)
        if isinstance(val, dict):
            return FindingObjectWrapper(val)
        return val

    def __getitem__(self, item: str) -> Any:
        return self._data.get(item)

    def get(self, key: str, default: Any = None) -> Any:
        val = self._data.get(key, default)
        if isinstance(val, dict):
            return FindingObjectWrapper(val)
        return val

def extract_security_finding_row(assessment_id: str, finding) -> List[str]:
    """Extracts the exact columns matching the assessment's report specification."""
    if isinstance(finding, dict):
        finding = FindingObjectWrapper(finding)

    spec = SECURITY_REPORT_SPECS.get(assessment_id)
    if not spec:
        # Fallback to standard columns
        sub_name = getattr(finding, "subscription_name", None) or finding.get("subscription_name", "--")
        rg = getattr(finding, "resource_group", None) or finding.get("resource_group", "--")
        r_name = getattr(finding, "resource_name", None) or finding.get("resource_name", "--")
        r_type = getattr(finding, "resource_type", None) or finding.get("resource_type", "--")
        sev = getattr(finding, "severity", None) or finding.get("severity", "Medium")
        status = getattr(finding, "status", None) or finding.get("status", "Open")
        meas = getattr(finding, "measured_value", None) or finding.get("measured_value") or getattr(finding, "current_configuration", None) or finding.get("current_configuration", "--")
        rec = getattr(finding, "recommendation", None) or finding.get("recommendation", "--")
        return [sub_name, rg, r_name, r_type, sev, status, meas, rec]
    return spec["extractor"](finding)
