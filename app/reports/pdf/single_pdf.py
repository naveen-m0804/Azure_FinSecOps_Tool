import io
import datetime
import html
from typing import Dict, Any, List, Optional
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from app.reports.pdf.styles import (
    get_report_stylesheet, NumberedCanvas,
    COLOR_PRIMARY_PURPLE, COLOR_PRIMARY_RED, COLOR_LIGHT_BG, COLOR_BORDER, COLOR_WHITE, COLOR_DARK,
    COLOR_SEV_CRITICAL, COLOR_SEV_HIGH, COLOR_SEV_MEDIUM
)
from app.reports.security_report_schema import get_security_spec, extract_security_finding_row
from app.reports.cost_report_schema import get_cost_spec, extract_cost_finding_row

def escape_xml(text: Any) -> str:
    if text is None:
        return "--"
    return html.escape(str(text))

def generate_single_pdf(
    assessment_def: Any,
    res_data: Dict[str, Any],
    workspace_name: str,
    tenant_id: str,
    subscription_name: Optional[str] = None
) -> bytes:
    """
    Generates a concise, single-assessment PDF deliverable containing:
    - Assessment title and metadata banner
    - Assessment-specific findings table directly matching the Inspect Findings modal
    - No multi-page executive summary or unnecessary filler.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(letter),
        leftMargin=30,
        rightMargin=30,
        topMargin=30,
        bottomMargin=36
    )

    total_printable_width = 792 - 60  # 732 pt
    styles = get_report_stylesheet()
    story = []

    now_date = datetime.datetime.now().strftime("%Y-%m-%d")
    is_cost = getattr(assessment_def, "category", "") == "cost"
    primary_color = COLOR_PRIMARY_RED if is_cost else COLOR_PRIMARY_PURPLE
    pillar_title = "COST OPTIMIZATION ASSESSMENT" if is_cost else "SECURITY POSTURE ASSESSMENT"

    # 1. Clean Top Header Banner
    header_data = [
        [
            Paragraph(f"<b>AZURE FINSECOPS - {pillar_title}</b>", styles["CoverTitle"]),
            Paragraph(f"<b>Date:</b> {escape_xml(now_date)}<br/><b>Workspace:</b> {escape_xml(workspace_name)}<br/><b>Tenant:</b> {escape_xml(tenant_id)}", styles["CoverMeta"])
        ]
    ]
    t_header = Table(header_data, colWidths=[480, 252])
    t_header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(t_header)
    story.append(Spacer(1, 10))

    # 2. Assessment Module Title & Overview
    code = getattr(assessment_def, "code", "ASS")
    name = getattr(assessment_def, "name", "Assessment Module")
    desc = getattr(assessment_def, "description", "")

    story.append(Paragraph(f"<b>[{code}] {escape_xml(name)}</b>", styles["SectionHeader"]))
    if desc:
        story.append(Spacer(1, 2))
        story.append(Paragraph(escape_xml(desc), styles["Body"]))
    story.append(Spacer(1, 10))

    # 3. Retrieve findings and spec
    aid = getattr(assessment_def, "assessment_id", "")
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

    col_widths_raw = spec.get("col_widths", [100] * len(columns)) if spec else [100] * len(columns)
    scale = total_printable_width / sum(col_widths_raw)
    normalized_widths = [w * scale for w in col_widths_raw]

    # 4. Build Table
    header_row = [Paragraph(f"<b>{escape_xml(col)}</b>", styles["TableHeaderSmall"]) for col in columns]
    table_data = [header_row]

    if findings:
        for f in findings:
            row_vals = extractor_fn(f)
            formatted_row = []
            for val in row_vals:
                val_str = escape_xml(val)
                if val in ["Critical", "High", "Medium", "Low"]:
                    sev_color = COLOR_SEV_CRITICAL if val == "Critical" else (COLOR_SEV_HIGH if val == "High" else COLOR_SEV_MEDIUM)
                    formatted_row.append(Paragraph(f"<font color='{sev_color.hexval()}'><b>{val_str}</b></font>", styles["TableCellSmallBold"]))
                elif "Savings" in val_str or "$" in val_str or "₹" in val_str or "€" in val_str:
                    formatted_row.append(Paragraph(f"<font color='#047857'><b>{val_str}</b></font>", styles["TableCellSmallBold"]))
                else:
                    formatted_row.append(Paragraph(val_str, styles["TableCellSmall"]))
            table_data.append(formatted_row)
    else:
        empty_msg = "No security gaps identified. All evaluated resources satisfy compliance benchmarks." if not is_cost else "No financial wastage or optimization candidates identified for this module."
        table_data.append([Paragraph(f"<i>{empty_msg}</i>", styles["TableCellSmall"])] + [Paragraph("", styles["TableCellSmall"]) for _ in range(len(columns) - 1)])

    t_findings = Table(table_data, colWidths=normalized_widths, repeatRows=1)
    table_styles = [
        ("BACKGROUND", (0, 0), (-1, 0), primary_color),
        ("BOX", (0, 0), (-1, -1), 1, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    if not findings:
        table_styles.append(("SPAN", (0, 1), (-1, 1)))

    t_findings.setStyle(TableStyle(table_styles))
    for r_idx in range(1, len(table_data)):
        if r_idx % 2 == 0:
            t_findings.setStyle(TableStyle([("BACKGROUND", (0, r_idx), (-1, r_idx), COLOR_LIGHT_BG)]))

    story.append(t_findings)

    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
