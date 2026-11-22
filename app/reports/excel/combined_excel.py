import re
import io
import datetime
from typing import Dict, Any
import openpyxl
from openpyxl.utils import get_column_letter
from app.reports.excel.styles import (
    FONT_HEADER, FONT_TITLE, FONT_BOLD, FONT_BODY, FONT_MUTED,
    FONT_SUCCESS, FONT_SUCCESS_BOLD, FONT_DANGER,
    FILL_PURPLE_HEADER, FILL_RED_HEADER, FILL_ZEBRA, FILL_HIGHLIGHT,
    ALIGN_LEFT, ALIGN_CENTER, ALIGN_RIGHT, ALIGN_WRAP, BORDER_BOX
)
from app.assessments.registry import assessment_registry
from app.reports.security_report_schema import SECURITY_REPORT_SPECS, extract_security_finding_row
from app.reports.cost_report_schema import COST_REPORT_SPECS, extract_cost_finding_row
from app.reports.high_level_categories import get_cost_high_level_summary, get_security_high_level_summary

def sanitize_sheet_title(name: str) -> str:
    cleaned = re.sub(r'[/\\?*\[\]:]', '-', name).strip()
    sheet_aliases = {
        "Monthly Billing & Service Analysis": "Monthly Billing & Service",
        "Cost Comparison": "Monthly Billing & Service",
        "Production Resources Without Logs": "Resources Without Logs",
        "Resources Missing Diagnostic Logs": "Resources Without Logs",
        "High Priority Recommendations": "High Priority Recommendations"[:31],
        "VM Patching / Missing Patches": "VM Patching & Missing Patches"[:31],
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

def generate_combined_excel(job_data: Dict[str, Any], workspace_name: str, tenant_id: str) -> bytes:
    wb = openpyxl.Workbook()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Executive Summary & Assessment Status Sheet
    ws_exec = wb.active
    ws_exec.title = "Assessment Status"
    ws_exec.views.sheetView[0].showGridLines = True

    ws_exec.cell(row=2, column=2, value="Azure FinSecOps - Security & Cost Assessment Report").font = FONT_TITLE
    ws_exec.cell(row=3, column=2, value=f"Generated on {now_str} | Workspace: {workspace_name} | Tenant: {tenant_id}").font = FONT_MUTED

    summary = job_data.get("summary", {})
    sec_counts = summary.get("security_severity_counts", {})
    raw_sec_score = summary.get("current_security_score", summary.get("security_score"))
    raw_achievable = summary.get("achievable_security_score")
    sec_score_str = f"{round(raw_sec_score)}%" if raw_sec_score is not None else "--"
    achievable_str = f"{round(raw_achievable)}%" if raw_achievable is not None else "--"
    tot_monthly = summary.get("total_monthly_savings", 0.0)
    tot_annual = summary.get("total_annual_savings", 0.0)
    curr_sym = summary.get("currency", "$")
    curr_prefix = curr_sym + " " if len(curr_sym) > 1 else curr_sym
    subs_count = summary.get("subscriptions_count", len(job_data.get("subscriptions", [])) or 1)

    headers_exec = ["Governance Dimension & Metric", "Assessment Value"]
    rows_exec = [
        ("Current Security Posture Score", sec_score_str),
        ("Achievable Security Posture Score", achievable_str),
        ("Total Security Findings", summary.get("security_findings_count", 0)),
        ("Critical Severity Security Findings", sec_counts.get("Critical", 0)),
        ("High Severity Security Findings", sec_counts.get("High", 0)),
        ("Medium Severity Security Findings", sec_counts.get("Medium", 0)),
        ("Low Severity Security Findings", sec_counts.get("Low", 0)),
        ("Total Monthly Cost Wastage Identified", f"{curr_prefix}{tot_monthly:,.2f}"),
        ("Annualized Savings Potential", f"{curr_prefix}{tot_annual:,.2f}"),
        ("Subscriptions Scanned", subs_count),
        ("Security Assessment Status", "Completed"),
        ("Cost Assessment Status", "Completed"),
    ]

    ws_exec.merge_cells(start_row=5, start_column=2, end_row=5, end_column=4)
    cell_metric = ws_exec.cell(row=5, column=2, value="Governance Dimension & Metric")
    cell_metric.font = FONT_HEADER
    cell_metric.fill = FILL_PURPLE_HEADER
    cell_metric.alignment = ALIGN_LEFT
    cell_metric.border = BORDER_BOX
    ws_exec.cell(row=5, column=3).border = BORDER_BOX
    ws_exec.cell(row=5, column=4).border = BORDER_BOX

    ws_exec.merge_cells(start_row=5, start_column=5, end_row=5, end_column=6)
    cell_val = ws_exec.cell(row=5, column=5, value="Assessment Value")
    cell_val.font = FONT_HEADER
    cell_val.fill = FILL_PURPLE_HEADER
    cell_val.alignment = ALIGN_RIGHT
    cell_val.border = BORDER_BOX
    ws_exec.cell(row=5, column=6).border = BORDER_BOX

    for row_idx, (k, v) in enumerate(rows_exec, start=6):
        ws_exec.merge_cells(start_row=row_idx, start_column=2, end_row=row_idx, end_column=4)
        c1 = ws_exec.cell(row=row_idx, column=2, value=k)
        c1.font = FONT_BODY
        c1.border = BORDER_BOX
        c1.alignment = ALIGN_LEFT
        ws_exec.cell(row=row_idx, column=3).border = BORDER_BOX
        ws_exec.cell(row=row_idx, column=4).border = BORDER_BOX

        ws_exec.merge_cells(start_row=row_idx, start_column=5, end_row=row_idx, end_column=6)
        c2 = ws_exec.cell(row=row_idx, column=5, value=str(v))
        c2.font = FONT_BOLD
        c2.border = BORDER_BOX
        c2.alignment = ALIGN_RIGHT
        ws_exec.cell(row=row_idx, column=6).border = BORDER_BOX

        if row_idx % 2 == 0:
            c1.fill = FILL_ZEBRA
            ws_exec.cell(row=row_idx, column=3).fill = FILL_ZEBRA
            ws_exec.cell(row=row_idx, column=4).fill = FILL_ZEBRA
            c2.fill = FILL_ZEBRA
            ws_exec.cell(row=row_idx, column=6).fill = FILL_ZEBRA

    # Status Overview Table for All Categories - High-Level Business Overview
    status_row_start = 20
    ws_exec.cell(row=status_row_start - 1, column=2, value="All Assessment Modules Evaluation Status").font = FONT_TITLE
    status_headers = ["Pillar", "S.No", "Assessment Category", "Findings Detected", "Evaluation Status", "Score / Est. Annual Savings"]

    for col_idx, h in enumerate(status_headers, start=2):
        cell = ws_exec.cell(row=status_row_start, column=col_idx, value=h)
        cell.font = FONT_HEADER
        cell.fill = FILL_PURPLE_HEADER
        cell.alignment = ALIGN_CENTER if col_idx in (2, 3, 5, 6) else (ALIGN_RIGHT if col_idx == 7 else ALIGN_LEFT)
        cell.border = BORDER_BOX

    results = job_data.get("results", {})
    sec_high_rows = get_security_high_level_summary(results)
    cost_high_rows = get_cost_high_level_summary(results, curr_symbol=curr_prefix)

    curr_row = status_row_start + 1

    # 1. Security Categories (7 high-level business categories)
    for idx, row in enumerate(sec_high_rows):
        findings_cnt = row["findings_detected"]
        status_display = row["status"]
        impact_display = row["impact_display"]
        vals = ["Security", row["s_no"], row["category"], findings_cnt, status_display, impact_display]

        for col_idx, v in enumerate(vals, start=2):
            c = ws_exec.cell(row=curr_row, column=col_idx, value=v)
            c.font = FONT_BOLD if col_idx in (2, 3, 4, 5 if findings_cnt > 0 else -1) else FONT_BODY
            c.border = BORDER_BOX
            if col_idx in (2, 3, 5, 6):
                c.alignment = ALIGN_CENTER
            elif col_idx == 7:
                c.alignment = ALIGN_RIGHT
            else:
                c.alignment = ALIGN_LEFT

            if (curr_row - status_row_start) % 2 == 0:
                c.fill = FILL_ZEBRA

            if col_idx == 6:
                if status_display in ["Completed", "No Findings"]:
                    c.font = FONT_SUCCESS
                elif status_display in ["Failed", "Error"]:
                    c.font = FONT_DANGER
            elif col_idx == 7 and impact_display != "--":
                c.font = FONT_SUCCESS_BOLD

        curr_row += 1

    # 2. Cost Categories (4 high-level business categories)
    for idx, row in enumerate(cost_high_rows):
        findings_cnt = row["opportunities_found"]
        status_display = row["status"]
        impact_display = row["impact_display"]
        vals = ["Cost", row["s_no"], row["category"], findings_cnt, status_display, impact_display]

        for col_idx, v in enumerate(vals, start=2):
            c = ws_exec.cell(row=curr_row, column=col_idx, value=v)
            c.font = FONT_BOLD if col_idx in (2, 3, 4, 5 if findings_cnt > 0 else -1) else FONT_BODY
            c.border = BORDER_BOX
            if col_idx in (2, 3, 5, 6):
                c.alignment = ALIGN_CENTER
            elif col_idx == 7:
                c.alignment = ALIGN_RIGHT
            else:
                c.alignment = ALIGN_LEFT

            if (curr_row - status_row_start) % 2 == 0:
                c.fill = FILL_ZEBRA

            if col_idx == 6:
                if status_display in ["Completed", "No Findings"]:
                    c.font = FONT_SUCCESS
                elif status_display in ["Failed", "Error"]:
                    c.font = FONT_DANGER
            elif col_idx == 7 and impact_display != "--":
                c.font = FONT_SUCCESS_BOLD

        curr_row += 1

    ws_exec.column_dimensions["B"].width = 14
    ws_exec.column_dimensions["C"].width = 8
    ws_exec.column_dimensions["D"].width = 46
    ws_exec.column_dimensions["E"].width = 18
    ws_exec.column_dimensions["F"].width = 18
    ws_exec.column_dimensions["G"].width = 26

    # 2. Security Worksheets (Exact Assessment-Specific Columns)
    used_titles = {"Assessment Status"}
    for ass in assessment_registry.get_security_assessments():
        spec = SECURITY_REPORT_SPECS.get(ass.assessment_id)
        if not spec:
            continue

        res = results.get(ass.assessment_id)
        findings = res.findings if hasattr(res, "findings") else (res.get("findings", []) if isinstance(res, dict) else [])
        columns = spec["columns"]

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

        # Headers
        for col_idx, h in enumerate(columns, start=1):
            cell = ws.cell(row=1, column=col_idx, value=h)
            cell.font = FONT_HEADER
            cell.fill = FILL_PURPLE_HEADER
            cell.alignment = ALIGN_LEFT
            cell.border = BORDER_BOX

        # Data rows
        for row_idx, f in enumerate(findings, start=2):
            row_vals = extract_security_finding_row(ass.assessment_id, f)
            for col_idx, val in enumerate(row_vals, start=1):
                cell = ws.cell(row=row_idx, column=col_idx, value=val)
                cell.font = FONT_BODY
                cell.border = BORDER_BOX
                cell.alignment = ALIGN_WRAP
                if row_idx % 2 == 0:
                    cell.fill = FILL_ZEBRA

        for col in ws.columns:
            col_letter = get_column_letter(col[0].column)
            max_len = 0
            for cell in col:
                val_str = str(cell.value or "")
                max_len = max(max_len, len(val_str))
            ws.column_dimensions[col_letter].width = min(max(max_len + 3, 12), 48)

    # 3. Cost Worksheets (Exact Assessment-Specific Columns)
    for ass in assessment_registry.get_cost_assessments():
        spec = COST_REPORT_SPECS.get(ass.assessment_id, {})
        columns = spec.get("columns", ["Subscription", "Resource", "Cost", "Est. Annual Savings"])

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

        res = results.get(ass.assessment_id)
        findings = res.findings if hasattr(res, "findings") else (res.get("findings", []) if isinstance(res, dict) else [])
        for row_idx, f in enumerate(findings, start=2):
            row_vals = extract_cost_finding_row(ass.assessment_id, f)
            for col_idx, val in enumerate(row_vals, start=1):
                cell = ws.cell(row=row_idx, column=col_idx, value=val)
                cell.font = FONT_BODY
                cell.border = BORDER_BOX
                cell.alignment = ALIGN_WRAP
                if isinstance(val, str) and (val.startswith("$") or val.endswith("%")):
                    cell.alignment = ALIGN_RIGHT
                if row_idx % 2 == 0:
                    cell.fill = FILL_ZEBRA

        for col in ws.columns:
            col_letter = get_column_letter(col[0].column)
            max_len = 0
            for cell in col:
                val_str = str(cell.value or "")
                max_len = max(max_len, len(val_str))
            ws.column_dimensions[col_letter].width = min(max(max_len + 3, 14), 48)

    output = io.BytesIO()
    wb.save(output)
    return output.getvalue()
