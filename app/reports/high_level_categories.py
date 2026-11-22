"""
High-Level Executive Category Mappings for Cost and Security Assessments.
Provides business overview aggregation for Executive Summary tables in PDF and Excel deliverables.
"""
from typing import Dict, Any, List

COST_HIGH_LEVEL_CATEGORIES = [
    {
        "s_no": 1,
        "category": "Top Spends",
        "module_ids": [
            "cost_comparison",         # Cost Comparison – Last Month vs. Current Month
            "top_20_opportunities",    # Cost Report – Top 20 (Optimization)
            "vm_license_ahb",          # License Cost on VM – Separate (To Apply AHB)
            "new_unused_resources",    # New and Unused Resources
            "function_apps",           # Function App Execution Time – Frequency (High-Cost Resources)
            "orphan_resources",        # Orphan Resources – Disk, Public IP & NIC
        ]
    },
    {
        "s_no": 2,
        "category": "VM Optimization",
        "module_ids": [
            "auto_shutdown",           # Auto Shutdown – Enable Status
            "disk_space",              # Disk Space Alert
            "auto_start_vm",           # Auto Start VM – Status
            "underutilized_vms",       # Underutilized Virtual Machines
        ]
    },
    {
        "s_no": 3,
        "category": "Disk Optimization",
        "module_ids": [
            "underutilized_os_disks",       # Underutilized OS Disk
            "database_allocated_usage",    # Database Allocated vs. Usage
            "underutilized_data_disks",     # Underutilized Data Disk
        ]
    },
    {
        "s_no": 4,
        "category": "Storage & Database optimization",
        "module_ids": [
            "database_usage",                 # Database Usage – Threshold Limit Reached
            "storage_lifecycle",              # Storage Account LCM – Enabled Status
            "database_sku",                   # Database SKU – Underutilized / Overutilized
            "backup_status",                  # Backup Status / Policy / Retention
            "old_snapshots",                  # Old Snapshot Expired
            "non_lrs_storage_redundancy",     # Non-LRS Storage Redundancy Optimization
        ]
    }
]

SECURITY_HIGH_LEVEL_CATEGORIES = [
    {
        "s_no": 1,
        "category": "Score assessment",
        "module_ids": [
            "subscription_security_score",   # Security Score – Subscription Level
        ]
    },
    {
        "s_no": 2,
        "category": "Security assessment",
        "module_ids": [
            "security_alerts",               # Security Alerts – High
            "attack_paths",                  # Attack Path
        ]
    },
    {
        "s_no": 3,
        "category": "Key recommendations",
        "module_ids": [
            "new_recommendations",           # New Security Recommendations – Notification
            "high_priority_recommendations", # High Priority Recommendations and Solutions to Fix
        ]
    },
    {
        "s_no": 4,
        "category": "VM assessment",
        "module_ids": [
            "vm_os_version",                 # OS Version – Each Machine Repository
            "vm_patching",                   # VM Patching – Number of Patches (Higher)
            "software_upgrades",             # Software Version – Upgrade Details Required
        ]
    },
    {
        "s_no": 5,
        "category": "Retired Services",
        "module_ids": [
            "service_retirement",            # Service Retirement
        ]
    },
    {
        "s_no": 6,
        "category": "Access & Log review",
        "module_ids": [
            "resources_without_logs",        # Resources Missing Diagnostic Logs
            "contributor_rbac",              # RBAC Migration – Contributor Access
        ]
    },
    {
        "s_no": 7,
        "category": "Data Encryption / Access & Log review",
        "module_ids": [
            "disk_encryption",               # Disk Encryption
            "tls_version",                   # TLS Version Upgrade
            "keyvault_rbac",                 # Key Vault RBAC Migration
        ]
    }
]

def extract_module_annual_savings(res: Any) -> float:
    """Helper to extract annual savings float value from result object or dict."""
    if not res:
        return 0.0

    if hasattr(res, "total_annual_savings") and res.total_annual_savings and res.total_annual_savings > 0:
        return float(res.total_annual_savings)
    if isinstance(res, dict) and res.get("total_annual_savings") and res["total_annual_savings"] > 0:
        return float(res["total_annual_savings"])

    # Sum from findings
    findings = res.findings if hasattr(res, "findings") else (res.get("findings", []) if isinstance(res, dict) else [])
    if findings:
        ann = sum(
            float(getattr(f, "estimated_annual_savings", None) or (f.get("estimated_annual_savings") if isinstance(f, dict) else 0.0) or ((getattr(f, "estimated_monthly_savings", 0.0) or (f.get("estimated_monthly_savings") if isinstance(f, dict) else 0.0) or 0.0) * 12.0))
            for f in findings
        )
        if ann > 0:
            return ann

    # Check monthly savings fallback
    m_val = (res.total_monthly_savings or 0.0) if hasattr(res, "total_monthly_savings") else (res.get("total_monthly_savings", 0.0) if isinstance(res, dict) else 0.0)
    if m_val > 0:
        return float(m_val) * 12.0

    return 0.0

def get_cost_high_level_summary(results: Dict[str, Any], curr_symbol: str = "$") -> List[Dict[str, Any]]:
    """
    Computes the 4 high-level cost categories with cumulative savings and opportunities found.
    """
    summary_rows = []
    for cat_def in COST_HIGH_LEVEL_CATEGORIES:
        s_no = cat_def["s_no"]
        cat_name = cat_def["category"]
        m_ids = cat_def["module_ids"]

        total_findings = 0
        total_annual = 0.0
        has_run = False
        has_completed = False

        for mid in m_ids:
            res = results.get(mid)
            if res:
                has_run = True
                cnt = res.findings_count if hasattr(res, "findings_count") else (res.get("findings_count", 0) if isinstance(res, dict) else 0)
                total_findings += cnt
                total_annual += extract_module_annual_savings(res)

                st = getattr(res, "status", None) if not isinstance(res, dict) else res.get("status")
                st_str = st.value if hasattr(st, "value") else str(st or "")
                if st_str in ["Completed", "No Findings"]:
                    has_completed = True

        if not has_run:
            status_display = "Not Run"
        elif total_findings == 0 and has_completed:
            status_display = "No Findings"
        else:
            status_display = "Completed"

        impact_display = f"{curr_symbol}{total_annual:,.2f}" if total_annual > 0 else "--"

        summary_rows.append({
            "s_no": s_no,
            "category": cat_name,
            "opportunities_found": total_findings,
            "status": status_display,
            "annual_savings": total_annual,
            "impact_display": impact_display
        })

    return summary_rows

def get_security_high_level_summary(results: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Computes the 7 high-level security categories with cumulative findings and score potentials.
    """
    summary_rows = []
    for cat_def in SECURITY_HIGH_LEVEL_CATEGORIES:
        s_no = cat_def["s_no"]
        cat_name = cat_def["category"]
        m_ids = cat_def["module_ids"]

        total_findings = 0
        total_impact = 0.0
        has_run = False
        has_completed = False

        for mid in m_ids:
            res = results.get(mid)
            if res:
                has_run = True
                cnt = res.findings_count if hasattr(res, "findings_count") else (res.get("findings_count", 0) if isinstance(res, dict) else 0)
                total_findings += cnt

                # Check security score improvement
                imp = getattr(res, "security_score_improvement", None) if not isinstance(res, dict) else res.get("security_score_improvement")
                if imp:
                    total_impact += float(imp)
                else:
                    findings = res.findings if hasattr(res, "findings") else (res.get("findings", []) if isinstance(res, dict) else [])
                    if findings:
                        for f in findings:
                            imp_f = getattr(f, "security_score_impact", None) if not isinstance(f, dict) else f.get("security_score_impact")
                            if imp_f:
                                try:
                                    total_impact += float(imp_f)
                                except Exception:
                                    pass

                st = getattr(res, "status", None) if not isinstance(res, dict) else res.get("status")
                st_str = st.value if hasattr(st, "value") else str(st or "")
                if st_str in ["Completed", "No Findings"]:
                    has_completed = True

        if not has_run:
            status_display = "Not Run"
        elif total_findings == 0 and has_completed:
            status_display = "No Findings"
        else:
            status_display = "Completed"

        impact_display = f"+{total_impact:.1f}%" if total_impact > 0 else "--"

        summary_rows.append({
            "s_no": s_no,
            "category": cat_name,
            "findings_detected": total_findings,
            "status": status_display,
            "score_potential": total_impact,
            "impact_display": impact_display
        })

    return summary_rows
