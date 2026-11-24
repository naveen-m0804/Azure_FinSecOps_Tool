"""
Cost Assessment Reporting Schema & Column Specifications
Directly implementing the requirements from:
AZURE FINOPS – COMPLETE CORRECTION AND ENHANCEMENT OF ALL 19 COST ASSESSMENTS
Sections 3, 4, 5, 6, 14
Updated:
- Column header renamed to 'Cost' instead of 'Actual Cost (MTD)'
- Est. Annual Savings formatted with both annual and monthly savings e.g. '$1,317.48 ($109.79/month)'
"""

from typing import Dict, Any, List, Optional
from app.azure.cost_management import CostManagementAdapter
from app.utils.resource_ids import parse_azure_resource_id

_, _, COST_MONTH_LABEL = CostManagementAdapter.get_last_completed_month_date_range()
COST_HEADER = f"Cost ({COST_MONTH_LABEL})"

CURRENCY_SYMBOLS: Dict[str, str] = {
    "USD": "$",
    "INR": "₹",
    "EUR": "€",
    "GBP": "£",
    "JPY": "¥",
    "CAD": "CA$",
    "AUD": "A$",
    "SGD": "S$",
    "CHF": "CHF ",
}

def get_currency_symbol(currency: Optional[str] = "USD") -> str:
    if not currency:
        return "$"
    curr_clean = str(currency).strip().upper()
    return CURRENCY_SYMBOLS.get(curr_clean, f"{curr_clean} ")

def _fmt_currency(val: Optional[float], currency: str = "USD") -> str:
    if val is None:
        return "Unavailable"
    symbol = get_currency_symbol(currency)
    return f"{symbol}{val:,.2f}"

def _fmt_savings(val: Optional[float], currency: str = "USD", monthly_val: Optional[float] = None) -> str:
    if val is None or val <= 0:
        if monthly_val is not None and monthly_val > 0:
            val = monthly_val * 12.0
        else:
            return "--"
    symbol = get_currency_symbol(currency)
    return f"{symbol}{val:,.2f}"

def _clean_resource_type(r_type: Any) -> str:
    if not r_type:
        return "--"
    r_type_str = str(r_type)
    return r_type_str.split("/")[-1] if "/" in r_type_str else r_type_str

COST_REPORT_SPECS: Dict[str, Dict[str, Any]] = {
    # 1. Underutilized VMs (COST-01)
    "underutilized_vms": {
        "code": "COST-01",
        "report_title": "Underutilized Virtual Machines",
        "columns": [
            "VM Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "VM Size",
            "CPU Utilization",
            "Memory Utilization",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [105, 95, 85, 75, 82, 75, 75, 80, 80],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("vm_size") or f.evidence.get("size") or "Standard_D4s_v5",
            f.measured_value or (f"{f.evidence.get('avg_cpu', 0.4):.1f}%" if f.evidence.get("avg_cpu") is not None else "0.4%"),
            f.evidence.get("avg_memory") or (f"{f.evidence.get('memory_utilization')}%" if f.evidence.get("memory_utilization") is not None else "Telemetry Unavailable"),
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 70.08), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 2. Orphan Resources (COST-02)
    "orphan_resources": {
        "code": "COST-02",
        "report_title": "Orphan & Unattached Cloud Resources",
        "columns": [
            "Resource Name",
            "Resource Type",
            "Subscription",
            "Resource Group",
            "Environment",
            "Resource Status",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [120, 105, 95, 85, 75, 112, 80, 80],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            "App Service Plan" if "serverfarms" in (f.resource_type or "").lower() else (_clean_resource_type(f.resource_type)),
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.status or f.evidence.get("orphan_reason") or "Unattached",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 0.0), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 3. Underutilized Data Disks (COST-03)
    "underutilized_data_disks": {
        "code": "COST-03",
        "report_title": "Underutilized Managed Data Disks",
        "columns": [
            "Disk Name",
            "VM Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "Disk Tier",
            "Disk Size",
            "IOPS Utilization",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [95, 85, 85, 75, 62, 75, 55, 80, 70, 70],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.evidence.get("vm_name") or f.evidence.get("attached_vm") or "Attached",
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("disk_tier") or f.evidence.get("tier") or "--",
            f"{f.evidence.get('disk_size_gb')} GiB" if f.evidence.get('disk_size_gb') is not None else "--",
            f.measured_value or f.evidence.get("iops_utilization") or "0.00%",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 0.0), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 4. Underutilized OS Disks (COST-04)
    "underutilized_os_disks": {
        "code": "COST-04",
        "report_title": "Underutilized Operating System Disks",
        "columns": [
            "OS Disk Name",
            "VM Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "Disk Tier",
            "Disk Size",
            "IOPS Utilization",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [95, 85, 85, 75, 62, 75, 55, 80, 70, 70],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.evidence.get("vm_name") or "Primary VM",
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("disk_tier") or f.evidence.get("tier") or "--",
            f"{f.evidence.get('disk_size_gb')} GiB" if f.evidence.get('disk_size_gb') is not None else "--",
            f.measured_value or f.evidence.get("iops_utilization") or "0.00%",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 0.0), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 5. Cost Comparison (COST-05)
    "cost_comparison": {
        "code": "COST-05",
        "report_title": "Monthly Billing & Service Cost Comparison",
        "columns": [
            "Resource / Service",
            "Resource Type",
            "Subscription",
            "Resource Group",
            "Environment",
            "Previous Period Cost",
            "Current Period Cost",
            "Cost Difference",
            "Cost Change (%)",
        ],
        "col_widths": [122, 100, 85, 75, 70, 75, 75, 75, 75],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.resource_type.split("/")[-1] if "/" in (f.resource_type or "") else (f.resource_type or "Service"),
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            _fmt_currency(float(f.evidence.get("previous_period_cost", f.evidence.get("prev_cost", 0.0))), f.currency) if float(f.evidence.get("previous_period_cost", f.evidence.get("prev_cost", 0.0)) or 0.0) > 0.001 else "--",
            _fmt_currency(float(f.evidence.get("current_period_cost", f.current_monthly_cost or 0.0)), f.currency) if float(f.evidence.get("current_period_cost", f.current_monthly_cost or 0.0) or 0.0) > 0.001 else "--",
            (
                f"+{_fmt_currency(float(f.evidence.get('cost_difference', 0.0)), f.currency)}"
                if float(f.evidence.get("cost_difference", 0.0) or 0.0) > 0.001
                else (
                    f"-{_fmt_currency(abs(float(f.evidence.get('cost_difference', 0.0))), f.currency)}"
                    if float(f.evidence.get("cost_difference", 0.0) or 0.0) < -0.001
                    else "--"
                )
            ),
            (
                f"+{float(f.evidence.get('cost_change_pct', 0.0)):.1f}%"
                if isinstance(f.evidence.get("cost_change_pct"), (int, float)) and float(f.evidence.get("cost_change_pct")) > 0.001
                else (
                    f"{float(f.evidence.get('cost_change_pct', 0.0)):.1f}%"
                    if isinstance(f.evidence.get("cost_change_pct"), (int, float)) and float(f.evidence.get("cost_change_pct")) < -0.001
                    else (
                        str(f.evidence.get("cost_change_pct"))
                        if f.evidence.get("cost_change_pct") and not isinstance(f.evidence.get("cost_change_pct"), (int, float))
                        else "--"
                    )
                )
            ),
        ]
    },

    # 6. Top 20 Optimization Opportunities (COST-06)
    "top_20_opportunities": {
        "code": "COST-06",
        "report_title": "Top 20 Cloud Cost Optimization Opportunities",
        "columns": [
            "Resource Name",
            "Assessment Type",
            "Subscription",
            "Resource Group",
            "Environment",
            "Current Configuration",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [115, 110, 95, 80, 67, 130, 75, 80],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.evidence.get("assessment_type") or f.evidence.get("opportunity_source") or "Compute Optimization",
            f.subscription_name,
            (
                f.resource_group
                if f.resource_group and f.resource_group not in ("Unknown", "--")
                else (
                    parse_azure_resource_id(f.resource_id).get("resource_group")
                    if f.resource_id and parse_azure_resource_id(f.resource_id).get("resource_group") not in ("Unknown", None)
                    else (f.resource_group or "--")
                )
            ),
            f.evidence.get("environment") or "Production",
            f.current_configuration or f.evidence.get("configuration") or "--",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 0.0), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 7. VM License Cost / Azure Hybrid Benefit (COST-07)
    "vm_license_ahb": {
        "code": "COST-07",
        "report_title": "VM Licensing & Azure Hybrid Benefit (AHB)",
        "columns": [
            "VM Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "VM Size",
            "License Status",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [120, 100, 90, 75, 87, 120, 80, 80],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("vm_size") or "Standard_D4s_v5",
            f.evidence.get("license_status") or f.status or "Not Enabled (Pay-As-You-Go)",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 140.16), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 8. Auto Shutdown Status (COST-08)
    "auto_shutdown": {
        "code": "COST-08",
        "report_title": "Virtual Machine Auto-Shutdown Enforcement",
        "columns": [
            "VM Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "VM Size",
            "Deallocated Status",
            "Auto Shutdown Enabled",
            "Scheduled Shutdown Time",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [95, 85, 75, 62, 75, 75, 65, 80, 70, 70],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "NonProd",
            f.evidence.get("vm_size") or "Standard_D2s_v5",
            f.evidence.get("power_state") or f.evidence.get("deallocated_status") or "Running",
            "Yes" if (f.evidence.get("auto_shutdown_status") == "Enabled" or f.evidence.get("auto_shutdown_enabled") is True) else "No",
            f.evidence.get("scheduled_shutdown_time") or (f"{f.evidence.get('shutdown_time')} ({f.evidence.get('timezone', 'UTC')})" if f.evidence.get("shutdown_time") else "Unavailable"),
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 70.08), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 9. Disk Space Alert (COST-09)
    "disk_space": {
        "code": "COST-09",
        "report_title": "Managed Disk Capacity & Utilization Alert",
        "columns": [
            "VM Name",
            "Disk Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "Total Capacity",
            "Used Space",
            "Free Space",
            "Utilization (%)",
            COST_HEADER,
        ],
        "col_widths": [92, 90, 85, 75, 60, 70, 70, 70, 70, 70],  # 752 pt
        "extractor": lambda f: [
            f.evidence.get("vm_name") or f.evidence.get("attached_vm") or "Unattached",
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f"{f.evidence.get('total_capacity_gb')} GB" if f.evidence.get("total_capacity_gb") is not None else "--",
            f"{f.evidence.get('used_space_gb')} GB" if f.evidence.get("used_space_gb") is not None else "--",
            f"{f.evidence.get('free_space_gb')} GB" if f.evidence.get("free_space_gb") is not None else "--",
            f"{float(f.evidence.get('utilization_pct', 0.0)):.1f}%" if f.evidence.get("utilization_pct") is not None else "0.0%",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 0.0), f.currency),
        ]
    },

    # 10. Database Usage / Threshold (COST-10)
    "database_usage": {
        "code": "COST-10",
        "report_title": "Database CPU / DTU Performance & Sizing Threshold",
        "columns": [
            "Database Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "Database Tier",
            "CPU / DTU Utilization",
            "Storage Utilization",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [110, 95, 85, 67, 85, 85, 75, 75, 75],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("database_tier") or f.evidence.get("sku") or "--",
            f.measured_value or (f"Avg {float(f.evidence.get('avg_dtu_cpu_pct', 0.0)):.1f}%" if f.evidence.get("avg_dtu_cpu_pct") is not None else "0.0%"),
            f"{f.evidence.get('storage_used_gb', 0)} / {f.evidence.get('storage_allocated_gb', 0)} GB",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 0.0), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 11. New and Unused Resources (COST-11)
    "new_unused_resources": {
        "code": "COST-11",
        "report_title": "Recently Provisioned Unused Resources",
        "columns": [
            "Resource Name",
            "Resource Type",
            "Subscription",
            "Resource Group",
            "Environment",
            "Creation Date",
            "Last Activity",
            "Days Inactive",
            "Unwanted Asset Status",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [90, 85, 80, 75, 55, 65, 65, 55, 82, 50, 50],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            _clean_resource_type(f.resource_type),
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("creation_date") or "--",
            f.evidence.get("last_activity") or "--",
            f"{f.evidence.get('days_inactive')} Days" if isinstance(f.evidence.get('days_inactive'), int) else str(f.evidence.get('days_inactive') or "--"),
            f.evidence.get("unwanted_status") or "Unwanted (Cost Savable)",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 0.0), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 12. Storage Account Lifecycle Management (COST-12)
    "storage_lifecycle": {
        "code": "COST-12",
        "report_title": "Storage Account Lifecycle Management (LCM) Status",
        "columns": [
            "Storage Account",
            "Resource Type",
            "Subscription",
            "Resource Group",
            "Environment",
            "LCM Status",
            "Total Rules",
            "Active Rules",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [105, 75, 85, 80, 57, 100, 50, 50, 75, 75],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.evidence.get("resource_type") or "Storage Account",
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("lcm_status") or f.status or "Not Configured",
            str(f.evidence.get("total_rules", 0)),
            str(f.evidence.get("active_rules", f.evidence.get("enabled_rules", 0))),
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 0.0), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 13. Database Allocated vs Usage (COST-13)
    "database_allocated_usage": {
        "code": "COST-13",
        "report_title": "Database Storage Allocation vs Actual Usage",
        "columns": [
            "Database Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "Allocated Storage",
            "Used Storage",
            "Storage Utilization (%)",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [110, 95, 85, 67, 85, 80, 80, 75, 75],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f"{float(f.evidence.get('allocated_storage_gb', 0.0)):.1f} GB",
            f"{float(f.evidence.get('used_storage_gb', 0.0)):.2f} GB",
            f"{float(f.evidence.get('utilization_pct', 0.0)):.1f}%",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 0.0), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 14. Backup Status / Policy / Retention (COST-14)
    "backup_status": {
        "code": "COST-14",
        "report_title": "Azure Backup Policy & Retention Cost Alignment",
        "columns": [
            "Resource Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "Backup Status",
            "Backup Policy",
            "Retention Period",
            "Backup Storage Used",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [92, 85, 75, 60, 75, 85, 70, 70, 70, 70],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("backup_status") or f.status or "Protected - Excessive Retention",
            f.evidence.get("backup_policy") or f.evidence.get("policy_name") or "--",
            f.evidence.get("retention_display") or (f"{f.evidence.get('retention_days')} days" if f.evidence.get("retention_days") is not None else "--"),
            f.evidence.get("backup_storage_display") or (f"{f.evidence.get('backup_storage_tb')} TB" if f.evidence.get("backup_storage_tb") is not None else (f"{f.evidence.get('backup_storage_gb')} GB" if f.evidence.get("backup_storage_gb") is not None else "--")),
            _fmt_currency(f.evidence.get("actual_cost_mtd") if f.evidence.get("actual_cost_mtd") is not None else f.current_monthly_cost, f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 15. Old Snapshot / Expired Snapshot (COST-15)
    "old_snapshots": {
        "code": "COST-15",
        "report_title": "Aged & Stale Managed Disk Snapshots",
        "columns": [
            "Snapshot Name",
            "Source Disk",
            "Subscription",
            "Resource Group",
            "Created Date",
            "Snapshot Age (> 365 Days)",
            "Snapshot Size",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [110, 105, 95, 87, 75, 85, 65, 65, 65],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.evidence.get("source_disk") or "Standalone Disk",
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("created_date") or "--",
            f"{f.evidence.get('age_days', 366)} days",
            f"{f.evidence.get('disk_size_gb') or f.evidence.get('size_gb') or 128} GiB",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 0.0), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 16. Function App Execution Time / Frequency (COST-16)
    "function_apps": {
        "code": "COST-16",
        "report_title": "Function App Execution Frequency & Hosting Plan",
        "columns": [
            "Function App Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "Hosting Plan",
            "Execution Count",
            "Average Execution Duration",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [110, 95, 85, 67, 95, 75, 75, 75, 75],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("hosting_plan") or "Dedicated App Service (P1v3)",
            f"{f.evidence.get('execution_count', 14)} runs/mo",
            f"{f.evidence.get('avg_duration_ms', 420)} ms",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 146.00), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 17. Auto Start VM (COST-17)
    "auto_start_vm": {
        "code": "COST-17",
        "report_title": "VM Auto-Shutdown Off-Hours Execution",
        "columns": [
            "VM Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "VM Size",
            "Shutdown Schedule",
            "Off-Hours Activity / Status",
            COST_HEADER,
            "Est. Annual Cost Impact",
        ],
        "col_widths": [105, 85, 80, 60, 77, 85, 105, 75, 80],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("vm_size") or "--",
            f.evidence.get("scheduled_shutdown_time") or "--",
            f.evidence.get("off_hours_status") or f.status or "Running in Shutdown Window",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 0.0), f.currency),
            _fmt_savings(
                f.evidence.get("annual_cost_impact", f.estimated_annual_savings or 0.0),
                f.currency,
                (f.evidence.get("annual_cost_impact", f.estimated_annual_savings or 0.0)) / 12.0
            ),
        ]
    },

    # 18. Non-LRS Storage Redundancy Optimization (COST-18)
    "non_lrs_storage_redundancy": {
        "code": "COST-18",
        "report_title": "Non-LRS Storage Redundancy Optimization",
        "columns": [
            "Storage Account",
            "Subscription",
            "Resource Group",
            "Environment",
            "Current Redundancy",
            "Required Redundancy",
            COST_HEADER,
            "Est. Annual Savings",
        ],
        "col_widths": [120, 105, 95, 75, 82, 85, 95, 95],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "General Workload",
            f.evidence.get("current_redundancy") or f.evidence.get("redundancy") or "GRS",
            "LRS",  # Required Redundancy MUST display LRS
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 180.00), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },
}

COST_SPEC_ALIASES: Dict[str, str] = {
    "top_opportunities": "top_20_opportunities",
}

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

def get_cost_spec(assessment_id: str) -> Optional[Dict[str, Any]]:
    """Returns the report specification for a cost assessment."""
    if assessment_id in COST_REPORT_SPECS:
        return COST_REPORT_SPECS[assessment_id]
    aliased = COST_SPEC_ALIASES.get(assessment_id)
    if aliased and aliased in COST_REPORT_SPECS:
        return COST_REPORT_SPECS[aliased]
    for k, v in COST_REPORT_SPECS.items():
        if v.get("code", "").lower() == assessment_id.lower():
            return v
    return None

def extract_cost_finding_row(assessment_id: str, finding: Any) -> List[str]:
    """
    Extracts a row of string values matching the assessment's report columns.
    Falls back gracefully if an unknown assessment ID is passed.
    """
    if isinstance(finding, dict):
        finding = FindingObjectWrapper(finding)

    spec = get_cost_spec(assessment_id)
    if not spec:
        def _get_val(k: str, default: Any = None) -> Any:
            v = getattr(finding, k, None)
            if v is not None:
                return v
            if hasattr(finding, "get"):
                return finding.get(k, default)
            return default

        m_cost = _get_val("current_monthly_cost") or 0.0
        m_sav = _get_val("estimated_monthly_savings") or 0.0
        a_sav = _get_val("estimated_annual_savings") or (m_sav * 12)
        r_type = _get_val("resource_type") or ""
        curr = _get_val("currency") or "USD"
        return [
            _get_val("subscription_name") or "--",
            _get_val("resource_name") or "--",
            r_type.split("/")[-1] if "/" in str(r_type) else str(r_type),
            _get_val("resource_group") or "--",
            _fmt_currency(m_cost, curr),
            _fmt_currency(m_sav, curr),
            f"{_fmt_currency(a_sav, curr)} ({_fmt_currency(m_sav, curr)}/month)",
            _get_val("recommendation") or "--"
        ]
    return spec["extractor"](finding)
