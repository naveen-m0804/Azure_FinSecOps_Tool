import re
import io
import datetime
from typing import Dict, Any
import openpyxl
from openpyxl.utils import get_column_letter
from app.reports.excel.styles import (
    FONT_HEADER, FONT_TITLE, FONT_BOLD, FONT_BODY, FONT_MUTED,
    FONT_SUCCESS, FONT_SUCCESS_BOLD, FONT_DANGER,
    FILL_PURPLE_HEADER, FILL_ZEBRA, FILL_HIGHLIGHT,
    ALIGN_LEFT, ALIGN_CENTER, ALIGN_RIGHT, ALIGN_WRAP, BORDER_BOX
)
from app.assessments.registry import assessment_registry
from app.reports.security_report_schema import SECURITY_REPORT_SPECS, extract_security_finding_row

def sanitize_sheet_title(name: str) -> str:
    cleaned = re.sub(r'[/\\?*\[\]:]', '-', name).strip()
    sheet_aliases = {
        "Production Resources Without Logs": "Resources Without Logs",
        "Resources Missing Diagnostic Logs": "Resources Without Logs",
        "High Priority Recommendations": "High Priority Recommendations"[:31],
        "VM Patching / Missing Patches": "VM Patching & Missing Patches"[:31],
    }
    if name in sheet_aliases:
        return sheet_aliases[name]
    return cleaned[:31].strip()

def generate_security_excel(job_data: Dict[str, Any], workspace_name: str, tenant_id: str) -> bytes:
    wb = openpyxl.Workbook()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 1. Executive Summary & Assessment Status Sheet
    ws_exec = wb.active
    ws_exec.title = "Assessment Status"
    ws_exec.views.sheetView[0].showGridLines = True

    ws_exec.cell(row=2, column=2, value="Azure FinSecOps - Security Assessment Report").font = FONT_TITLE
    ws_exec.cell(row=3, column=2, value=f"Generated on {now_str} | Workspace: {workspace_name} | Tenant: {tenant_id}").font = FONT_MUTED

    summary = job_data.get("summary", {})
    sec_counts = summary.get("security_severity_counts", {})
    raw_sec_score = summary.get("current_security_score", summary.get("security_score"))
    raw_achievable = summary.get("achievable_security_score")
    sec_score_str = f"{round(raw_sec_score)}%" if raw_sec_score is not None else "--"
    achievable_str = f"{round(raw_achievable)}%" if raw_achievable is not None else "--"
    subs_count = summary.get("subscriptions_count", len(job_data.get("subscriptions", [])) or 1)

    headers_exec = ["Security Metric", "Value"]
    rows_exec = [
        ("Total Security Findings", summary.get("security_findings_count", 0)),
        ("Critical Severity Findings", sec_counts.get("Critical", 0)),
        ("High Severity Findings", sec_counts.get("High", 0)),
        ("Medium Severity Findings", sec_counts.get("Medium", 0)),
        ("Low Severity Findings", sec_counts.get("Low", 0)),
        ("Current Posture Score", sec_score_str),
        ("Achievable Posture Score", achievable_str),
        ("Subscriptions Scanned", subs_count),
    ]

    ws_exec.merge_cells(start_row=5, start_column=2, end_row=5, end_column=3)
    cell_metric = ws_exec.cell(row=5, column=2, value="Security Posture Dimension & Metric")
    cell_metric.font = FONT_HEADER
    cell_metric.fill = FILL_PURPLE_HEADER
    cell_metric.alignment = ALIGN_LEFT
    cell_metric.border = BORDER_BOX
    ws_exec.cell(row=5, column=3).border = BORDER_BOX

    cell_val = ws_exec.cell(row=5, column=4, value="Assessment Value")
    cell_val.font = FONT_HEADER
    cell_val.fill = FILL_PURPLE_HEADER
    cell_val.alignment = ALIGN_RIGHT
    cell_val.border = BORDER_BOX

    for row_idx, (k, v) in enumerate(rows_exec, start=6):
        ws_exec.merge_cells(start_row=row_idx, start_column=2, end_row=row_idx, end_column=3)
        c1 = ws_exec.cell(row=row_idx, column=2, value=k)
        c1.font = FONT_BODY
        c1.border = BORDER_BOX
        c1.alignment = ALIGN_LEFT
        ws_exec.cell(row=row_idx, column=3).border = BORDER_BOX

        c2 = ws_exec.cell(row=row_idx, column=4, value=str(v))
        c2.font = FONT_BOLD
        c2.border = BORDER_BOX
        c2.alignment = ALIGN_RIGHT

        if row_idx % 2 == 0:
            c1.fill = FILL_ZEBRA
            ws_exec.cell(row=row_idx, column=3).fill = FILL_ZEBRA
            c2.fill = FILL_ZEBRA

    # Overall Modules Status Table - High-Level Business Overview
    status_row_start = 16
    ws_exec.cell(row=status_row_start - 1, column=2, value="Security Assessment Modules Status Overview").font = FONT_TITLE
    status_headers = ["S.No", "Assessment Category", "Findings Detected", "Evaluation Status", "Score Potential"]

    for col_idx, h in enumerate(status_headers, start=2):
        cell = ws_exec.cell(row=status_row_start, column=col_idx, value=h)
        cell.font = FONT_HEADER
        cell.fill = FILL_PURPLE_HEADER
        cell.alignment = ALIGN_CENTER if col_idx in (2, 4, 5) else (ALIGN_RIGHT if col_idx == 6 else ALIGN_LEFT)
        cell.border = BORDER_BOX

    results = job_data.get("results", {})
    sec_assessments = assessment_registry.get_security_assessments()

    from app.reports.high_level_categories import get_security_high_level_summary
    high_level_rows = get_security_high_level_summary(results)

    for idx, row in enumerate(high_level_rows):
        curr_row = status_row_start + 1 + idx
        findings_count = row["findings_detected"]
        status_val = row["status"]
        impact_str = row["impact_display"]

        vals = [row["s_no"], row["category"], findings_count, status_val, impact_str]
        for col_idx, v in enumerate(vals, start=2):
            c = ws_exec.cell(row=curr_row, column=col_idx, value=v)
            c.font = FONT_BOLD if col_idx in (2, 3, 4 if findings_count > 0 else -1) else FONT_BODY
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
                if status_val in ["Completed", "No Findings"]:
                    c.font = FONT_SUCCESS
                elif status_val in ["Failed", "Error"]:
                    c.font = FONT_DANGER
            elif col_idx == 6 and impact_str != "--":
                c.font = FONT_SUCCESS_BOLD

    ws_exec.column_dimensions["B"].width = 10
    ws_exec.column_dimensions["C"].width = 44
    ws_exec.column_dimensions["D"].width = 20
    ws_exec.column_dimensions["E"].width = 22
    ws_exec.column_dimensions["F"].width = 20

    # 2. Assessment-Specific Worksheets (One for each of the 14 security assessments)
    used_titles = {"Assessment Status"}
    for ass in sec_assessments:
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

        # Data rows (Only affected resources / security gaps)
        for row_idx, f in enumerate(findings, start=2):
            row_vals = extract_security_finding_row(ass.assessment_id, f)
            for col_idx, val in enumerate(row_vals, start=1):
                cell = ws.cell(row=row_idx, column=col_idx, value=val)
                cell.font = FONT_BODY
                cell.border = BORDER_BOX
                cell.alignment = ALIGN_WRAP
                if row_idx % 2 == 0:
                    cell.fill = FILL_ZEBRA

        # Auto-fit column widths with readable padding
        for col in ws.columns:
            col_letter = get_column_letter(col[0].column)
            max_len = 0
            for cell in col:
                val_str = str(cell.value or "")
                max_len = max(max_len, len(val_str))
            ws.column_dimensions[col_letter].width = min(max(max_len + 3, 12), 48)

    output = io.BytesIO()
    wb.save(output)
    return output.getvalue()
