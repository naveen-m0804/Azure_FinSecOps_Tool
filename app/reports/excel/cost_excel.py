import re
import io
import datetime
from typing import Dict, Any
import openpyxl
from openpyxl.utils import get_column_letter
from app.reports.excel.styles import (
    FONT_HEADER, FONT_TITLE, FONT_BOLD, FONT_BODY, FONT_MUTED,
    FONT_SUCCESS, FONT_SUCCESS_BOLD, FONT_DANGER,
    FILL_RED_HEADER, FILL_ZEBRA, FILL_HIGHLIGHT,
    ALIGN_LEFT, ALIGN_CENTER, ALIGN_RIGHT, ALIGN_WRAP, BORDER_BOX
)
from app.assessments.registry import assessment_registry
from app.reports.cost_report_schema import COST_REPORT_SPECS, extract_cost_finding_row

def sanitize_sheet_title(name: str) -> str:
    cleaned = re.sub(r'[/\\?*\[\]:]', '-', name).strip()
    sheet_aliases = {
        "Monthly Billing & Service Analysis": "Monthly Billing & Service",
        "Cost Comparison": "Monthly Billing & Service",
        "Underutilized Virtual Machines": "Underutilized Virtual Machines"[:31],
        "Top 20 Optimization Opportunities": "Top 20 Optimization Opps",
        "VM License Cost / Azure Hybrid Benefit": "VM License Cost & AHB",
        "Storage Account Lifecycle Management": "Storage Lifecycle Management",
        "Database SKU Under/Over Utilization": "Database SKU Utilization",
        "Backup Status / Policy / Retention": "Backup Status & Policy",
        "Function App Execution Time / Frequency": "Function App Execution",
        "Non-LRS Storage Redundancy in Test Environments": "Non-LRS Storage Redundancy",
        "Non-LRS Storage Redundancy Optimization": "Non-LRS Storage Redundancy",
    }
    if name in sheet_aliases:
        return sheet_aliases[name]
    return cleaned[:31].strip()

def generate_cost_excel(job_data: Dict[str, Any], workspace_name: str, tenant_id: str) -> bytes:
    wb = openpyxl.Workbook()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Executive Summary Sheet
    ws_exec = wb.active
    ws_exec.title = "Executive Summary"
    ws_exec.views.sheetView[0].showGridLines = True

    ws_exec.cell(row=2, column=2, value="Azure FinSecOps - Cost Assessment Report").font = FONT_TITLE
    ws_exec.cell(row=3, column=2, value=f"Generated on {now_str} | Workspace: {workspace_name} | Tenant: {tenant_id}").font = FONT_MUTED

    summary = job_data.get("summary", {})
    currency = summary.get("currency", "USD")
    curr_symbol = "$" if not currency or currency == "USD" else f"{currency} "
    tot_monthly = summary.get("total_monthly_savings", summary.get("unique_monthly_savings", 0.0))
    tot_annual = summary.get("total_annual_savings", summary.get("unique_annual_savings", 0.0))
    findings_count = summary.get("cost_findings_count", 0)

    subs_list = job_data.get("subscriptions", [])
    subs_count = len(subs_list) if subs_list else summary.get("subscriptions_count", 1)

    rows_exec = [
        ("Monthly Cost Wastage", f"{curr_symbol}{tot_monthly:,.2f}"),
        ("Annualized Savings Potential", f"{curr_symbol}{tot_annual:,.2f}"),
        ("Cost Optimization Findings", str(findings_count)),
        ("Subscriptions Scanned", str(subs_count)),
        ("Cost Modules Evaluation", "Completed"),
    ]

    # Executive Summary Metrics Table
    ws_exec.merge_cells("B5:C5")
    cell_metric = ws_exec.cell(row=5, column=2, value="Financial Metric")
    cell_metric.font = FONT_HEADER
    cell_metric.fill = FILL_RED_HEADER
    cell_metric.alignment = ALIGN_LEFT
    cell_metric.border = BORDER_BOX
    ws_exec.cell(row=5, column=3).border = BORDER_BOX

    cell_val = ws_exec.cell(row=5, column=4, value="Value")
    cell_val.font = FONT_HEADER
    cell_val.fill = FILL_RED_HEADER
    cell_val.alignment = ALIGN_RIGHT
    cell_val.border = BORDER_BOX

    for idx, (k, v) in enumerate(rows_exec, start=6):
        ws_exec.merge_cells(start_row=idx, start_column=2, end_row=idx, end_column=3)
        c1 = ws_exec.cell(row=idx, column=2, value=k)
        c1.font = FONT_BODY
        c1.border = BORDER_BOX
        ws_exec.cell(row=idx, column=3).border = BORDER_BOX

        c2 = ws_exec.cell(row=idx, column=4, value=v)
        c2.font = FONT_BOLD
        c2.border = BORDER_BOX
        c2.alignment = ALIGN_RIGHT

        if idx % 2 == 0:
            c1.fill = FILL_ZEBRA
            ws_exec.cell(row=idx, column=3).fill = FILL_ZEBRA
            c2.fill = FILL_ZEBRA

    # 2. Cost Optimization Modules Evaluation Status Table - High-Level Business Overview
    status_row_start = 13
    ws_exec.cell(row=status_row_start, column=2, value="Cost Optimization Modules Evaluation Status").font = FONT_TITLE

    status_headers = ["S.No", "Assessment Category", "Opportunities Found", "Evaluation Status", "Est. Annual Savings"]
    for col_idx, h in enumerate(status_headers, start=2):
        cell = ws_exec.cell(row=status_row_start + 1, column=col_idx, value=h)
        cell.font = FONT_HEADER
        cell.fill = FILL_RED_HEADER
        cell.alignment = ALIGN_CENTER if col_idx in (2, 4, 5) else (ALIGN_RIGHT if col_idx == 6 else ALIGN_LEFT)
        cell.border = BORDER_BOX

    results = job_data.get("results", {})
    from app.reports.high_level_categories import get_cost_high_level_summary
    high_level_rows = get_cost_high_level_summary(results, curr_symbol=curr_symbol)

    for idx, row in enumerate(high_level_rows):
        curr_row = status_row_start + 2 + idx
        findings_cnt = row["opportunities_found"]
        status_display = row["status"]
        impact_display = row["impact_display"]
        vals = [row["s_no"], row["category"], findings_cnt, status_display, impact_display]

        for col_idx, v in enumerate(vals, start=2):
            c = ws_exec.cell(row=curr_row, column=col_idx, value=v)
            c.font = FONT_BOLD if col_idx in (2, 3, 4 if findings_cnt > 0 else -1, 5) else FONT_BODY
            c.border = BORDER_BOX
            if col_idx in (2, 4, 5):
                c.alignment = ALIGN_CENTER
            elif col_idx == 6:
                c.alignment = ALIGN_RIGHT
            else:
                c.alignment = ALIGN_LEFT

            if idx % 2 == 1:
                c.fill = FILL_ZEBRA

            if col_idx == 5:
                if status_display in ["Completed", "No Findings"]:
                    c.font = FONT_SUCCESS
                elif status_display in ["Failed", "Error"]:
                    c.font = FONT_DANGER
            elif col_idx == 6 and impact_display != "--":
                c.font = FONT_SUCCESS_BOLD

    ws_exec.column_dimensions["B"].width = 10
    ws_exec.column_dimensions["C"].width = 44
    ws_exec.column_dimensions["D"].width = 22
    ws_exec.column_dimensions["E"].width = 22
    ws_exec.column_dimensions["F"].width = 26

    # 2. Worksheets per Cost Module (Exact Assessment-Specific Columns)
    results = job_data.get("results", {})
    cost_assessments = assessment_registry.get_cost_assessments()
    used_titles = {"Executive Summary"}

    for ass in cost_assessments:
        spec = COST_REPORT_SPECS.get(ass.assessment_id, {})
        columns = spec.get("columns", ["Subscription", "Resource", "Cost", "Est. Annual Savings"])

        res = results.get(ass.assessment_id)
        findings = res.findings if hasattr(res, "findings") else (res.get("findings", []) if isinstance(res, dict) else [])
        base_title = sanitize_sheet_title(ass.name)
        sheet_title = base_title
        counter = 2
        while sheet_title in used_titles:
            suffix = f" ({counter})"
            sheet_title = f"{base_title[:31-len(suffix)]}{suffix}"
            counter += 1
        used_titles.add(sheet_title)

        ws = wb.create_sheet(title=sheet_title)
        ws.views.sheetView[0].showGridLines = True
        ws.freeze_panes = "A2"

        for col_idx, h in enumerate(columns, start=1):
            cell = ws.cell(row=1, column=col_idx, value=h)
            cell.font = FONT_HEADER
            cell.fill = FILL_RED_HEADER
            cell.alignment = ALIGN_LEFT
            cell.border = BORDER_BOX

        for row_idx, f in enumerate(findings, start=2):
            row_vals = extract_cost_finding_row(ass.assessment_id, f)
            for col_idx, val in enumerate(row_vals, start=1):
                cell = ws.cell(row=row_idx, column=col_idx, value=val)
                cell.font = FONT_BODY
                cell.border = BORDER_BOX
                cell.alignment = ALIGN_WRAP
                # Right-align currency and percentage values
                if isinstance(val, str) and (val.startswith("$") or val.endswith("%")):
                    cell.alignment = ALIGN_RIGHT
                if row_idx % 2 == 0:
                    cell.fill = FILL_ZEBRA

        for col in ws.columns:
            max_len = max(len(str(cell.value or "")) for cell in col)
            col_letter = get_column_letter(col[0].column)
            ws.column_dimensions[col_letter].width = min(max(max_len + 3, 14), 45)

    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()
