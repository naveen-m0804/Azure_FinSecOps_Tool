import io
import datetime
import html
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib import colors
from app.reports.pdf.styles import (
    get_report_stylesheet, NumberedCanvas,
    COLOR_PRIMARY_RED, COLOR_LIGHT_BG, COLOR_BORDER, COLOR_WHITE, COLOR_DARK
)
from app.assessments.registry import assessment_registry
from app.reports.cost_report_schema import COST_REPORT_SPECS, extract_cost_finding_row

def escape_xml(val: Any) -> str:
    if val is None:
        return ""
    return html.escape(str(val))

def generate_cost_pdf(job_data: Dict[str, Any], workspace_name: str, tenant_id: str) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(letter),
        leftMargin=20,
        rightMargin=20,
        topMargin=20,
        bottomMargin=20
    )

    styles = get_report_stylesheet()
    story = []
    now_date = datetime.datetime.now().strftime("%B %d, %Y")
    total_printable_width = 752

    # 1. HEADER (Clean, direct)
    header_data = [
        [
            Paragraph("<b>AZURE FINSECOPS - COST ASSESSMENT REPORT</b>", styles["CoverTitle"]),
            Paragraph(f"<b>Date:</b> {escape_xml(now_date)}<br/><b>Workspace:</b> {escape_xml(workspace_name)}<br/><b>Tenant:</b> {escape_xml(tenant_id)}", styles["CoverMeta"])
        ]
    ]
    t_header = Table(header_data, colWidths=[500, 252])
    t_header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (1, 0), (1, 0), "RIGHT"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
    ]))
    story.append(t_header)
    story.append(Spacer(1, 10))

    summary = job_data.get("summary", {})
    currency = summary.get("currency", "USD")
    curr_symbol = "$" if not currency or currency == "USD" else f"{currency} "
    tot_monthly = summary.get("total_monthly_savings", 0.0)
    tot_annual = summary.get("total_annual_savings", 0.0)
    cost_findings_count = summary.get("cost_findings_count", 0)

    subs_list = job_data.get("subscriptions", [])
    subs_count = len(subs_list) if subs_list else summary.get("subscriptions_count", 1)

    # Executive Financial Summary Card Grid
    exec_stats = [
        [
            Paragraph("<b>Monthly Cost Wastage</b>", styles["TableHeader"]),
            Paragraph("<b>Annualized Savings</b>", styles["TableHeader"]),
            Paragraph("<b>Optimization Findings</b>", styles["TableHeader"]),
            Paragraph("<b>Subscriptions Scanned</b>", styles["TableHeader"]),
        ],
        [
            Paragraph(f"<font color='#DE1A3B'><b>{curr_symbol}{tot_monthly:,.2f}</b></font>", styles["TableCellBold"]),
            Paragraph(f"<font color='#047857'><b>{curr_symbol}{tot_annual:,.2f}</b></font>", styles["TableCellBold"]),
            Paragraph(str(cost_findings_count), styles["TableCellBold"]),
            Paragraph(str(subs_count), styles["TableCellBold"]),
        ]
    ]
    col_w_exec = total_printable_width / 4
    t_exec = Table(exec_stats, colWidths=[col_w_exec] * 4)
    t_exec.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY_RED),
        ("BACKGROUND", (0, 1), (-1, 1), COLOR_LIGHT_BG),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 1, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t_exec)
    story.append(Spacer(1, 12))

    # Overall Cost Status Table - High-Level Business Overview
    story.append(Paragraph("<b>Cost Optimization Modules Evaluation Status</b>", styles["SubSectionHeader"]))
    story.append(Spacer(1, 4))

    status_table_data = [
        [
            Paragraph("<b>S.No</b>", styles["TableHeader"]),
            Paragraph("<b>Assessment Category</b>", styles["TableHeader"]),
            Paragraph("<b>Opportunities Found</b>", styles["TableHeader"]),
            Paragraph("<b>Evaluation Status</b>", styles["TableHeader"]),
            Paragraph("<b>Est. Annual Savings</b>", styles["TableHeader"]),
        ]
    ]

    results = job_data.get("results", {})
    cost_assessments = assessment_registry.get_cost_assessments()

    from app.reports.high_level_categories import get_cost_high_level_summary
    high_level_rows = get_cost_high_level_summary(results, curr_symbol=curr_symbol)

    for row in high_level_rows:
        status_display = row["status"]
        findings_count = row["opportunities_found"]
        impact_display = row["impact_display"]

        status_table_data.append([
            Paragraph(f"<b>{row['s_no']}</b>", styles["TableCellBold"]),
            Paragraph(escape_xml(row["category"]), styles["TableCellBold"]),
            Paragraph(str(findings_count), styles["TableCellBold"] if findings_count > 0 else styles["TableCell"]),
            Paragraph(f"<font color='{'#059669' if status_display in ['Completed', 'No Findings'] else '#DE1A3B'}'>{escape_xml(status_display)}</font>", styles["TableCellBold"]),
            Paragraph(f"<font color='#047857'><b>{impact_display}</b></font>" if impact_display != "--" else "--", styles["TableCellBold"] if impact_display != "--" else styles["TableCell"]),
        ])

    t_status = Table(status_table_data, colWidths=[55, 345, 125, 115, 112])
    t_status.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("ALIGN", (2, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 1, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    for r_idx in range(1, len(status_table_data)):
        if r_idx % 2 == 0:
            t_status.setStyle(TableStyle([("BACKGROUND", (0, r_idx), (-1, r_idx), COLOR_LIGHT_BG)]))
    story.append(t_status)
    story.append(Spacer(1, 14))

    # Detailed Cost Findings per Module (Exact Assessment-Specific Columns)
    for ass in cost_assessments:
        spec = COST_REPORT_SPECS.get(ass.assessment_id, {})
        columns = spec.get("columns", ["Subscription", "Resource", "Cost", "Est. Annual Savings"])
        col_widths = spec.get("col_widths", [188] * len(columns))

        # Normalize col_widths to total 752 pt
        scale = total_printable_width / sum(col_widths)
        normalized_widths = [w * scale for w in col_widths]

        res = results.get(ass.assessment_id)
        findings = res.findings if hasattr(res, "findings") else (res.get("findings", []) if isinstance(res, dict) else [])
        annual_val = 0.0
        if res:
            if hasattr(res, "total_annual_savings") and res.total_annual_savings and res.total_annual_savings > 0:
                annual_val = res.total_annual_savings
            elif isinstance(res, dict) and res.get("total_annual_savings") and res["total_annual_savings"] > 0:
                annual_val = res["total_annual_savings"]
            else:
                findings_list = res.findings if hasattr(res, "findings") else (res.get("findings", []) if isinstance(res, dict) else [])
                annual_val = sum(
                    float(getattr(f, "estimated_annual_savings", None) or (f.get("estimated_annual_savings") if isinstance(f, dict) else 0.0) or ((getattr(f, "estimated_monthly_savings", 0.0) or (f.get("estimated_monthly_savings") if isinstance(f, dict) else 0.0) or 0.0) * 12.0))
                    for f in findings_list
                )
                if annual_val == 0.0:
                    m_val = (res.total_monthly_savings or 0.0) if hasattr(res, "total_monthly_savings") else (res.get("total_monthly_savings", 0.0) if isinstance(res, dict) else 0.0)
                    if m_val > 0:
                        annual_val = m_val * 12.0
        title_amount = f" — Est. Annual Savings: {curr_symbol}{annual_val:,.2f}" if annual_val > 0 else ""

        cost_block = []
        cost_block.append(Paragraph(f"<b>[{ass.code}] {escape_xml(spec.get('report_title', ass.name))}{title_amount}</b>", styles["SubSectionHeader"]))
        cost_block.append(Spacer(1, 2))

        if findings:
            header_row = [Paragraph(f"<b>{escape_xml(c)}</b>", styles["TableHeaderSmall"]) for c in columns]
            table_data = [header_row]

            for f in findings:
                row_vals = extract_cost_finding_row(ass.assessment_id, f)
                formatted_row = []
                for idx, val in enumerate(row_vals):
                    val_str = escape_xml(val)
                    # Highlight savings in dark green
                    if val_str.startswith("$") and ("Savings" in columns[idx] or "Impact" in columns[idx]):
                        formatted_row.append(Paragraph(f"<font color='#047857'><b>{val_str}</b></font>", styles["TableCellSmallBold"]))
                    elif idx == 0:
                        formatted_row.append(Paragraph(val_str, styles["TableCellSmallBold"]))
                    else:
                        formatted_row.append(Paragraph(val_str, styles["TableCellSmall"]))
                table_data.append(formatted_row)

            t_cost = Table(table_data, colWidths=normalized_widths, repeatRows=1)
            t_cost.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY_RED),
                ("BOX", (0, 0), (-1, -1), 1, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            for r_idx in range(1, len(table_data)):
                if r_idx % 2 == 0:
                    t_cost.setStyle(TableStyle([("BACKGROUND", (0, r_idx), (-1, r_idx), COLOR_LIGHT_BG)]))
            cost_block.append(t_cost)
        else:
            cost_block.append(Paragraph("<i>No financial wastage or optimization candidates identified for this module.</i>", styles["TableCellSmall"]))

        cost_block.append(Spacer(1, 8))
        story.append(KeepTogether(cost_block))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
