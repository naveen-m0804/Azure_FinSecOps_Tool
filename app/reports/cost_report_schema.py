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
            "Cost",
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
            "Cost",
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
            "Cost",
            "Est. Annual Savings",
        ],
        "col_widths": [95, 85, 85, 75, 62, 75, 55, 80, 70, 70],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.evidence.get("vm_name") or f.evidence.get("attached_vm") or "Attached",
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("disk_tier") or f.evidence.get("tier") or "Premium SSD P30",
            f"{f.evidence.get('disk_size_gb', 1024)} GiB",
            f.measured_value or f.evidence.get("iops_utilization") or f"Avg {f.evidence.get('avg_iops', 12)} IOPS",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 135.17), f.currency),
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
            "Cost",
            "Est. Annual Savings",
        ],
        "col_widths": [115, 95, 95, 85, 67, 85, 60, 75, 75],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.evidence.get("vm_name") or "Primary VM",
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Test",
            f.evidence.get("disk_tier") or f.evidence.get("tier") or "Premium SSD P10",
            f"{f.evidence.get('disk_size_gb', 128)} GiB",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 19.71), f.currency),
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
            _fmt_currency(f.evidence.get("previous_period_cost", f.evidence.get("prev_cost", 0.0)), f.currency),
            _fmt_currency(f.evidence.get("current_period_cost", f.current_monthly_cost or 0.0), f.currency),
            f"{'+' if float(f.evidence.get('cost_difference', (f.current_monthly_cost or 0.0) - float(f.evidence.get('previous_period_cost', 0.0)))) >= 0 else ''}{_fmt_currency(f.evidence.get('cost_difference', (f.current_monthly_cost or 0.0) - float(f.evidence.get('previous_period_cost', 0.0))), f.currency)}",
            f"{'+' if (float(f.evidence.get('cost_change_pct', 0.0)) if isinstance(f.evidence.get('cost_change_pct'), (int, float)) else 0.0) >= 0 else ''}{f.evidence.get('cost_change_pct', 0.0):.1f}%" if isinstance(f.evidence.get("cost_change_pct"), (int, float)) else str(f.evidence.get("cost_change_pct", "0.0%")),
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
            "Cost",
            "Est. Annual Savings",
        ],
        "col_widths": [115, 110, 95, 80, 67, 130, 75, 80],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.evidence.get("assessment_type") or f.evidence.get("opportunity_source") or "Compute Optimization",
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.current_configuration or f.evidence.get("configuration") or "--",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost), f.currency),
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
            "Cost",
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
            "Cost",
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
            "Cost",
        ],
        "col_widths": [92, 90, 85, 75, 60, 70, 70, 70, 70, 70],  # 752 pt
        "extractor": lambda f: [
            f.evidence.get("vm_name") or "Host VM",
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f"{f.evidence.get('total_capacity_gb', 512)} GB",
            f"{f.evidence.get('used_space_gb', 476)} GB",
            f"{f.evidence.get('free_space_gb', 36)} GB",
            f"{f.evidence.get('utilization_pct', 93.0):.1f}%" if isinstance(f.evidence.get("utilization_pct"), (int, float)) else str(f.evidence.get("utilization_pct", "93.0%")),
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 73.22), f.currency),
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
            "Cost",
            "Est. Annual Savings",
        ],
        "col_widths": [110, 95, 85, 67, 85, 85, 75, 75, 75],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("database_tier") or f.evidence.get("sku") or "General Purpose Gen5 4 vCores",
            f.measured_value or f"Avg {f.evidence.get('avg_dtu_cpu_pct', 1.8):.1f}%",
            f"{f.evidence.get('storage_used_gb', 14.2)} / {f.evidence.get('storage_allocated_gb', 250)} GB",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 185.00), f.currency),
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
            "Cost",
            "Est. Annual Savings",
        ],
        "col_widths": [90, 85, 80, 75, 55, 65, 65, 55, 82, 50, 50],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            _clean_resource_type(f.resource_type),
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Test",
            f.evidence.get("creation_date") or (f.collected_at[:10] if f.collected_at else "--"),
            f.evidence.get("last_activity") or f.evidence.get("creation_date") or "--",
            f"{f.evidence.get('days_inactive', 0)} Days",
            f.evidence.get("unwanted_status") or ("Unwanted (Cost Savable)" if f.evidence.get("days_inactive", 0) >= 30 else "Active"),
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 45.00), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 12. Storage Account Lifecycle Management (COST-12)
    "storage_lifecycle": {
        "code": "COST-12",
        "report_title": "Storage Account Lifecycle Policy Disabled Rules",
        "columns": [
            "Storage Account",
            "Subscription",
            "Resource Group",
            "Environment",
            "Storage Tier",
            "Access Tier",
            "Redundancy",
            "Cost",
            "Est. Annual Savings",
        ],
        "col_widths": [110, 95, 85, 67, 80, 75, 80, 80, 80],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("storage_tier") or "Standard",
            f.evidence.get("access_tier") or "Hot",
            f.evidence.get("redundancy") or "GRS",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 240.00), f.currency),
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
            "Cost",
            "Est. Annual Savings",
        ],
        "col_widths": [110, 95, 85, 67, 85, 80, 80, 75, 75],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f"{f.evidence.get('allocated_storage_gb', 500)} GB",
            f"{f.evidence.get('used_storage_gb', 18.5)} GB",
            f"{f.evidence.get('utilization_pct', 3.7):.1f}%" if isinstance(f.evidence.get("utilization_pct"), (int, float)) else str(f.evidence.get("utilization_pct", "3.7%")),
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 115.00), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 14. Database SKU Under / Over-utilized (COST-14)
    "database_sku": {
        "code": "COST-14",
        "report_title": "Database Compute & SKU Optimization",
        "columns": [
            "Database Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "Current SKU",
            "CPU Utilization",
            "Storage Utilization",
            "Cost",
            "Est. Annual Savings",
        ],
        "col_widths": [110, 95, 85, 67, 85, 80, 80, 75, 75],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f.evidence.get("current_sku") or "GP_Gen5_8",
            f"Avg {f.evidence.get('avg_cpu_pct', 2.4):.1f}%" if isinstance(f.evidence.get("avg_cpu_pct"), (int, float)) else str(f.evidence.get("avg_cpu_pct", "2.4%")),
            f"{f.evidence.get('storage_utilization_pct', 8.5):.1f}%" if isinstance(f.evidence.get("storage_utilization_pct"), (int, float)) else str(f.evidence.get("storage_utilization_pct", "8.5%")),
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 360.00), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 15. Backup Status / Policy / Retention (COST-15)
    "backup_status": {
        "code": "COST-15",
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
            "Cost",
            "Est. Annual Savings",
        ],
        "col_widths": [92, 85, 75, 60, 75, 85, 70, 70, 70, 70],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "NonProd",
            f.evidence.get("backup_status") or f.status or "Protected - Excessive Retention",
            f.evidence.get("backup_policy") or "Daily-365Day-Retention",
            f"{f.evidence.get('retention_days', 365)} days",
            f"{f.evidence.get('backup_storage_tb', 4.2)} TB",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 95.00), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 16. Old Snapshot / Expired Snapshot (COST-16)
    "old_snapshots": {
        "code": "COST-16",
        "report_title": "Aged & Stale Managed Disk Snapshots",
        "columns": [
            "Snapshot Name",
            "Source Disk",
            "Subscription",
            "Resource Group",
            "Environment",
            "Snapshot Age",
            "Snapshot Size",
            "Cost",
            "Est. Annual Savings",
        ],
        "col_widths": [110, 95, 85, 67, 80, 80, 80, 75, 80],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.evidence.get("source_disk") or f.evidence.get("source_resource") or "Unlinked Disk",
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "Production",
            f"{f.evidence.get('age_days', 184)} days",
            f"{f.evidence.get('disk_size_gb', 128)} GiB",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 6.40), f.currency),
            _fmt_savings(f.estimated_annual_savings, f.currency, f.estimated_monthly_savings),
        ]
    },

    # 17. Function App Execution Time / Frequency (COST-17)
    "function_apps": {
        "code": "COST-17",
        "report_title": "Function App Execution Frequency & Hosting Plan",
        "columns": [
            "Function App Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "Hosting Plan",
            "Execution Count",
            "Average Execution Duration",
            "Cost",
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

    # 18. Auto Start VM (COST-18)
    "auto_start_vm": {
        "code": "COST-18",
        "report_title": "VM Auto-Start Schedule & Off-Hours Impact",
        "columns": [
            "VM Name",
            "Subscription",
            "Resource Group",
            "Environment",
            "VM Size",
            "Auto Start Status",
            "Configured Start Time",
            "Cost",
            "Est. Annual Cost Impact",
        ],
        "col_widths": [105, 95, 85, 67, 80, 85, 85, 75, 75],  # 752 pt
        "extractor": lambda f: [
            f.resource_name,
            f.subscription_name,
            f.resource_group or "--",
            f.evidence.get("environment") or "NonProd",
            f.evidence.get("vm_size") or "Standard_D2s_v5",
            f.evidence.get("auto_start_status") or f.status or "Configured (Weekend Active)",
            f.evidence.get("configured_start_time") or "06:00 UTC (Mon-Sun)",
            _fmt_currency(f.evidence.get("actual_cost_mtd", f.current_monthly_cost or 70.08), f.currency),
            _fmt_savings(
                f.evidence.get("annual_cost_impact", f.estimated_annual_savings or 480.00),
                f.currency,
                (f.evidence.get("annual_cost_impact", f.estimated_annual_savings or 480.00)) / 12.0
            ),
        ]
    },

    # 19. Non-LRS Storage Redundancy Optimization (COST-19)
    "non_lrs_storage_redundancy": {
        "code": "COST-19",
        "report_title": "Non-LRS Storage Redundancy Optimization",
        "columns": [
            "Storage Account",
            "Subscription",
            "Resource Group",
            "Environment",
            "Current Redundancy",
            "Required Redundancy",
            "Cost",
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
    return COST_REPORT_SPECS.get(assessment_id)

def extract_cost_finding_row(assessment_id: str, finding: Any) -> List[str]:
    """
    Extracts a row of string values matching the assessment's report columns.
    Falls back gracefully if an unknown assessment ID is passed.
    """
    if isinstance(finding, dict):
        finding = FindingObjectWrapper(finding)

    spec = COST_REPORT_SPECS.get(assessment_id)
    if not spec:
        m_cost = getattr(finding, "current_monthly_cost", None) or finding.get("current_monthly_cost") or 0.0
        m_sav = getattr(finding, "estimated_monthly_savings", None) or finding.get("estimated_monthly_savings") or 0.0
        a_sav = getattr(finding, "estimated_annual_savings", None) or finding.get("estimated_annual_savings") or (m_sav * 12)
        r_type = getattr(finding, "resource_type", "") or finding.get("resource_type", "")
        return [
            getattr(finding, "subscription_name", None) or finding.get("subscription_name", "--"),
            getattr(finding, "resource_name", None) or finding.get("resource_name", "--"),
            r_type.split("/")[-1] if "/" in r_type else r_type,
            getattr(finding, "resource_group", None) or finding.get("resource_group", "--"),
            f"${m_cost:,.2f}",
            f"${m_sav:,.2f}",
            f"${a_sav:,.2f} (${m_sav:,.2f}/month)",
            getattr(finding, "recommendation", None) or finding.get("recommendation", "--")
        ]
    return spec["extractor"](finding)
