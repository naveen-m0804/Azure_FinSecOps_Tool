import io
import datetime
from typing import Dict, Any, List, Optional
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

from app.reports.excel.styles import (
    FONT_HEADER, FONT_TITLE, FONT_BOLD, FONT_BODY, FONT_MUTED,
    FONT_SUCCESS, FONT_SUCCESS_BOLD, FONT_DANGER,
    FILL_PURPLE_HEADER, FILL_RED_HEADER, FILL_ZEBRA,
    BORDER_BOX,
    ALIGN_LEFT, ALIGN_CENTER, ALIGN_RIGHT
)

def sanitize_sheet_title(name: str) -> str:
    invalid_chars = [':', '\\', '/', '?', '*', '[', ']']
    for char in invalid_chars:
        name = name.replace(char, '')
    return name[:31]

BORDER_THIN = BORDER_BOX
BORDER_THICK_BOTTOM = Border(
    left=Side(border_style="thin", color="E2E8F0"),
    right=Side(border_style="thin", color="E2E8F0"),
    top=Side(border_style="thin", color="E2E8F0"),
    bottom=Side(border_style="medium", color="4A5568")
)
from app.reports.security_report_schema import get_security_spec, extract_security_finding_row
from app.reports.cost_report_schema import get_cost_spec, extract_cost_finding_row

def generate_single_excel(
    assessment_def: Any,
    res_data: Dict[str, Any],
    workspace_name: str,
    tenant_id: str,
    subscription_name: Optional[str] = None
) -> bytes:
    """
    Generates a concise, single-assessment Excel deliverable containing:
    - Assessment title and metadata header
    - Formatted findings worksheet directly matching the Inspect Findings modal
    - No multi-tab overhead or unwanted summary pages.
    """
    wb = openpyxl.Workbook()
    ws = wb.active

    aid = getattr(assessment_def, "assessment_id", "module")
    code = getattr(assessment_def, "code", "ASS")
    name = getattr(assessment_def, "name", "Assessment Module")
    is_cost = getattr(assessment_def, "category", "") == "cost"
    fill_header = FILL_RED_HEADER if is_cost else FILL_PURPLE_HEADER

    ws.title = sanitize_sheet_title(f"{code} {name}"[:31])
    ws.views.sheetView[0].showGridLines = True

    now_date = datetime.datetime.now().strftime("%Y-%m-%d")

    # 1. Metadata Block
    ws.cell(row=1, column=1, value=f"AZURE FINSECOPS - [{code}] {name}").font = FONT_TITLE
    ws.cell(row=2, column=1, value=f"Date: {now_date}  |  Workspace: {workspace_name}  |  Tenant: {tenant_id}").font = FONT_MUTED

    # 2. Retrieve findings & spec
    findings = []
    if isinstance(res_data, dict):
        findings = res_data.get("findings", [])
    elif hasattr(res_data, "findings"):
        findings = getattr(res_data, "findings", []) or []

    if is_cost:
        spec = get_cost_spec(aid)
        columns = spec.get("columns", ["Resource", "Type", "Cost", "Est. Annual Savings"]) if spec else ["Resource", "Type", "Cost", "Est. Annual Savings"]
        extractor_fn = lambda f: extract_cost_finding_row(aid, f)
    else:
        spec = get_security_spec(aid)
        columns = spec.get("columns", ["Resource", "Resource Group", "Severity", "Status", "Recommendation"]) if spec else ["Resource", "Resource Group", "Severity", "Status", "Recommendation"]
        extractor_fn = lambda f: extract_security_finding_row(aid, f)

    # 3. Write Column Headers
    header_row_idx = 4
    for col_idx, col_name in enumerate(columns, start=1):
        c = ws.cell(row=header_row_idx, column=col_idx, value=col_name)
        c.font = FONT_HEADER
        c.fill = fill_header
        c.alignment = ALIGN_CENTER if "Status" in col_name or "Date" in col_name or "Days" in col_name or "Severity" in col_name else ALIGN_LEFT
        c.border = BORDER_THICK_BOTTOM

    # 4. Write Data Rows
    current_row = 5
    if findings:
        for f in findings:
            row_vals = extractor_fn(f)
            is_zebra = (current_row % 2 == 0)
            for col_idx, val in enumerate(row_vals, start=1):
                val_str = str(val) if val is not None else "--"
                c = ws.cell(row=current_row, column=col_idx, value=val_str)
                c.border = BORDER_THIN
                if is_zebra:
                    c.fill = FILL_ZEBRA

                # Alignments and colors
                if val_str in ["Critical", "High"]:
                    c.font = FONT_DANGER
                    c.alignment = ALIGN_CENTER
                elif val_str in ["Medium", "Low"]:
                    c.font = FONT_BOLD
                    c.alignment = ALIGN_CENTER
                elif "Savings" in val_str or "$" in val_str or "₹" in val_str or "€" in val_str or "Cost Savable" in val_str:
                    c.font = FONT_SUCCESS_BOLD
                    c.alignment = ALIGN_RIGHT if "$" in val_str or "₹" in val_str else ALIGN_CENTER
                elif "Days" in val_str:
                    c.font = FONT_BOLD
                    c.alignment = ALIGN_CENTER
                else:
                    c.font = FONT_BODY
                    c.alignment = ALIGN_LEFT
            current_row += 1
    else:
        empty_msg = "No security gaps identified. All evaluated resources satisfy compliance benchmarks." if not is_cost else "No financial wastage or optimization candidates identified for this module."
        c = ws.cell(row=current_row, column=1, value=empty_msg)
        c.font = FONT_MUTED
        ws.merge_cells(start_row=current_row, start_column=1, end_row=current_row, end_column=len(columns))

    # Auto-adjust column widths
    for col in ws.columns:
        col_letter = get_column_letter(col[0].column)
        max_len = 0
        for cell in col:
            if cell.row < 4:
                continue
            if cell.value:
                max_len = max(max_len, len(str(cell.value)))
        ws.column_dimensions[col_letter].width = max(max_len + 3, 14)

    buffer = io.BytesIO()
    wb.save(buffer)
    return buffer.getvalue()
