import io
import datetime
import html
from typing import Dict, Any, List
from reportlab.lib.pagesizes import letter, landscape
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.lib import colors
from app.reports.pdf.styles import (
    get_report_stylesheet, NumberedCanvas,
    COLOR_PRIMARY_PURPLE, COLOR_PRIMARY_RED, COLOR_LIGHT_BG, COLOR_BORDER, COLOR_WHITE, COLOR_DARK,
    COLOR_SEV_CRITICAL, COLOR_SEV_HIGH, COLOR_SEV_MEDIUM
)
from app.assessments.registry import assessment_registry
from app.reports.security_report_schema import SECURITY_REPORT_SPECS, extract_security_finding_row
from app.reports.cost_report_schema import COST_REPORT_SPECS, extract_cost_finding_row

def escape_xml(val: Any) -> str:
    if val is None:
        return ""
    return html.escape(str(val))

def generate_combined_pdf(job_data: Dict[str, Any], workspace_name: str, tenant_id: str) -> bytes:
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
            Paragraph("<b>AZURE FINSECOPS - SECURITY &amp; COST ASSESSMENT REPORT</b>", styles["CoverTitle"]),
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
    raw_sec_score = summary.get("current_security_score", summary.get("security_score"))
    sec_score_str = f"{round(raw_sec_score)}%" if raw_sec_score is not None else "--"
    tot_monthly = summary.get("total_monthly_savings", 0.0)
    tot_annual = summary.get("total_annual_savings", 0.0)
    curr_sym = summary.get("currency", "$")
    curr_prefix = curr_sym + " " if len(curr_sym) > 1 else curr_sym
    sec_findings_count = summary.get("security_findings_count", 0)
    cost_findings_count = summary.get("cost_findings_count", 0)

    # Executive Metrics Card
    exec_stats = [
        [
            Paragraph("<b>Current Security Score</b>", styles["TableHeader"]),
            Paragraph("<b>Security Findings</b>", styles["TableHeader"]),
            Paragraph("<b>Identified Cost Leakage</b>", styles["TableHeader"]),
            Paragraph("<b>Monthly Savings</b>", styles["TableHeader"]),
            Paragraph("<b>Annual Savings</b>", styles["TableHeader"]),
        ],
        [
            Paragraph(f"<b>{sec_score_str}</b>", styles["TableCellBold"]),
            Paragraph(str(sec_findings_count), styles["TableCellBold"]),
            Paragraph(f"<font color='#DE1A3B'><b>{curr_prefix}{tot_monthly:,.2f}</b></font>", styles["TableCellBold"]),
            Paragraph(f"<font color='#059669'><b>{curr_prefix}{tot_monthly:,.2f}</b></font>", styles["TableCellBold"]),
            Paragraph(f"<font color='#047857'><b>{curr_prefix}{tot_annual:,.2f}</b></font>", styles["TableCellBold"]),
        ]
    ]
    col_w_exec = total_printable_width / 5
    t_exec = Table(exec_stats, colWidths=[col_w_exec] * 5)
    t_exec.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
        ("BACKGROUND", (0, 1), (-1, 1), COLOR_LIGHT_BG),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 1, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_exec)
    story.append(Spacer(1, 12))

    # Overall Status Overview Table - High-Level Business Overview
    story.append(Paragraph("<b>All Assessment Modules Execution Status</b>", styles["SubSectionHeader"]))
    story.append(Spacer(1, 4))

    status_table_data = [
        [
            Paragraph("<b>Pillar</b>", styles["TableHeader"]),
            Paragraph("<b>S.No</b>", styles["TableHeader"]),
            Paragraph("<b>Assessment Category</b>", styles["TableHeader"]),
            Paragraph("<b>Findings Detected</b>", styles["TableHeader"]),
            Paragraph("<b>Status</b>", styles["TableHeader"]),
            Paragraph("<b>Score / Est. Annual Savings</b>", styles["TableHeader"]),
        ]
    ]

    results = job_data.get("results", {})
    from app.reports.high_level_categories import get_security_high_level_summary, get_cost_high_level_summary

    sec_high_rows = get_security_high_level_summary(results)
    cost_high_rows = get_cost_high_level_summary(results, curr_symbol=curr_prefix)

    # 1. Security Categories
    for row in sec_high_rows:
        status_display = row["status"]
        status_table_data.append([
            Paragraph("Security", styles["TableCellBold"]),
            Paragraph(str(row["s_no"]), styles["TableCellBold"]),
            Paragraph(escape_xml(row["category"]), styles["TableCellBold"]),
            Paragraph(str(row["findings_detected"]), styles["TableCellBold"] if row["findings_detected"] > 0 else styles["TableCell"]),
            Paragraph(f"<font color='{'#059669' if status_display in ['Completed', 'No Findings'] else '#DE1A3B'}'>{escape_xml(status_display)}</font>", styles["TableCellBold"]),
            Paragraph(row["impact_display"], styles["TableCell"]),
        ])

    # 2. Cost Categories
    for row in cost_high_rows:
        status_display = row["status"]
        status_table_data.append([
            Paragraph("Cost", styles["TableCellBold"]),
            Paragraph(str(row["s_no"]), styles["TableCellBold"]),
            Paragraph(escape_xml(row["category"]), styles["TableCellBold"]),
            Paragraph(str(row["opportunities_found"]), styles["TableCellBold"] if row["opportunities_found"] > 0 else styles["TableCell"]),
            Paragraph(f"<font color='{'#059669' if status_display in ['Completed', 'No Findings'] else '#DE1A3B'}'>{escape_xml(status_display)}</font>", styles["TableCellBold"]),
            Paragraph(f"<font color='#047857'><b>{row['impact_display']}</b></font>" if row["impact_display"] != "--" else "--", styles["TableCellBold"] if row["impact_display"] != "--" else styles["TableCell"]),
        ])

    t_all_status = Table(status_table_data, colWidths=[65, 45, 315, 110, 110, 107])
    t_all_status.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_DARK),
        ("ALIGN", (0, 0), (1, -1), "CENTER"),
        ("ALIGN", (3, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 1, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    for r_idx in range(1, len(status_table_data)):
        if r_idx % 2 == 0:
            t_all_status.setStyle(TableStyle([("BACKGROUND", (0, r_idx), (-1, r_idx), COLOR_LIGHT_BG)]))
    story.append(t_all_status)
    story.append(Spacer(1, 14))

    # 2. DETAILED SECURITY FINDINGS (All 14 Security Modules with specific columns)
    story.append(Paragraph("<b>Pillar 1: Security Assessment Findings</b>", styles["SectionHeader"]))
    sec_assessments = assessment_registry.get_security_assessments()

    for ass in sec_assessments:
        res = results.get(ass.assessment_id)
        findings = res.findings if hasattr(res, "findings") else (res.get("findings", []) if isinstance(res, dict) else [])
        spec = SECURITY_REPORT_SPECS.get(ass.assessment_id)
        if not spec:
            continue

        report_title = spec["report_title"]
        columns = spec["columns"]
        col_widths = spec["col_widths"]

        sum_w = sum(col_widths)
        normalized_widths = [round((w / sum_w) * total_printable_width, 1) for w in col_widths]
        diff = total_printable_width - sum(normalized_widths)
        normalized_widths[-1] += diff

        sec_block = []
        sec_block.append(Paragraph(f"<b>[{ass.code}] {escape_xml(report_title)}</b>", styles["SubSectionHeader"]))
        sec_block.append(Spacer(1, 2))

        # Check if SEC-01: Separate Overall Secure Score from individual controls
        overall_findings = []
        table_findings = findings
        if ass.assessment_id in ("subscription_security_score", "secure_score"):
            overall_findings = [
                f for f in findings
                if (getattr(f, "resource_name", "") == "Microsoft Defender Overall Secure Score"
                    or getattr(f, "finding_id", "").endswith("-ascScore"))
            ]
            table_findings = [f for f in findings if f not in overall_findings]

            if overall_findings:
                for of in overall_findings:
                    score_val = of.measured_value or (f"{of.evidence.get('percentage')}%" if of.evidence.get('percentage') is not None else "--")
                    sub_name = of.subscription_name
                    rec_txt = of.recommended_configuration or of.recommendation or "--"

                    overall_data = [
                        [
                            Paragraph("<b>Subscription</b>", styles["TableHeaderSmall"]),
                            Paragraph("<b>Microsoft Defender Overall Secure Score</b>", styles["TableHeaderSmall"]),
                            Paragraph("<b>Posture Status</b>", styles["TableHeaderSmall"]),
                            Paragraph("<b>Remediation Guidance</b>", styles["TableHeaderSmall"]),
                        ],
                        [
                            Paragraph(f"<b>{escape_xml(sub_name)}</b>", styles["TableCellSmallBold"]),
                            Paragraph(f"<font color='{COLOR_PRIMARY_PURPLE.hexval()}'><b>{escape_xml(score_val)}</b></font>", styles["TableCellSmallBold"]),
                            Paragraph(f"<b>{escape_xml(of.status)}</b>", styles["TableCellSmallBold"]),
                            Paragraph(escape_xml(rec_txt), styles["TableCellSmall"]),
                        ]
                    ]
                    w_ov = [total_printable_width * 0.22, total_printable_width * 0.28, total_printable_width * 0.18, total_printable_width * 0.32]
                    t_overall = Table(overall_data, colWidths=w_ov)
                    t_overall.setStyle(TableStyle([
                        ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY_PURPLE),
                        ("BACKGROUND", (0, 1), (-1, 1), COLOR_LIGHT_BG),
                        ("BOX", (0, 0), (-1, -1), 1.2, COLOR_PRIMARY_PURPLE),
                        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ]))
                    sec_block.append(t_overall)
                    sec_block.append(Spacer(1, 4))

                if table_findings:
                    sec_block.append(Paragraph("<b>Security Controls Breakdown</b>", styles["TableCellBold"]))
                    sec_block.append(Spacer(1, 2))

        if table_findings:
            header_row = [Paragraph(f"<b>{escape_xml(col)}</b>", styles["TableHeaderSmall"]) for col in columns]
            table_data = [header_row]

            for f in table_findings:
                row_vals = extract_security_finding_row(ass.assessment_id, f)
                formatted_row = []
                for val in row_vals:
                    val_str = escape_xml(val)
                    if val in ["Critical", "High", "Medium", "Low"]:
                        sev_color = COLOR_SEV_CRITICAL if val == "Critical" else (COLOR_SEV_HIGH if val == "High" else COLOR_SEV_MEDIUM)
                        formatted_row.append(Paragraph(f"<font color='{sev_color.hexval()}'><b>{val_str}</b></font>", styles["TableCellSmallBold"]))
                    else:
                        formatted_row.append(Paragraph(val_str, styles["TableCellSmall"]))
                table_data.append(formatted_row)

            t_module = Table(table_data, colWidths=normalized_widths, repeatRows=1)
            t_module.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY_PURPLE),
                ("BOX", (0, 0), (-1, -1), 1, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            for r_idx in range(1, len(table_data)):
                if r_idx % 2 == 0:
                    t_module.setStyle(TableStyle([("BACKGROUND", (0, r_idx), (-1, r_idx), COLOR_LIGHT_BG)]))
            sec_block.append(t_module)
        elif not overall_findings:
            sec_block.append(Paragraph("<i>No security gaps identified. All evaluated resources satisfy baseline controls.</i>", styles["TableCellSmall"]))

        sec_block.append(Spacer(1, 8))
        story.append(KeepTogether(sec_block))

    # 3. DETAILED COST OPTIMIZATION FINDINGS (Exact Assessment-Specific Columns)
    story.append(Spacer(1, 10))
    story.append(Paragraph("<b>Pillar 2: Financial Optimization Findings</b>", styles["SectionHeader"]))
    cost_assessments = assessment_registry.get_cost_assessments()

    for ass in cost_assessments:
        spec = COST_REPORT_SPECS.get(ass.assessment_id, {})
        columns = spec.get("columns", ["Subscription", "Resource", "Cost", "Est. Annual Savings"])
        col_widths = spec.get("col_widths", [188] * len(columns))

        scale = total_printable_width / sum(col_widths)
        normalized_widths = [w * scale for w in col_widths]

        res = results.get(ass.assessment_id)
        findings = res.findings if hasattr(res, "findings") else (res.get("findings", []) if isinstance(res, dict) else [])

        cost_block = []
        cost_block.append(Paragraph(f"<b>[{ass.code}] {escape_xml(spec.get('report_title', ass.name))}</b>", styles["SubSectionHeader"]))
        cost_block.append(Spacer(1, 2))

        if findings:
            header_row = [Paragraph(f"<b>{escape_xml(c)}</b>", styles["TableHeaderSmall"]) for c in columns]
            table_data = [header_row]

            for f in findings:
                row_vals = extract_cost_finding_row(ass.assessment_id, f)
                formatted_row = []
                for idx, val in enumerate(row_vals):
                    val_str = escape_xml(val)
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
