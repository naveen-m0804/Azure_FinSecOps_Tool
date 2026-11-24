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
    COLOR_SEV_CRITICAL, COLOR_SEV_HIGH, COLOR_SEV_MEDIUM, COLOR_SEV_LOW
)
from app.assessments.registry import assessment_registry
from app.reports.security_report_schema import SECURITY_REPORT_SPECS, extract_security_finding_row

def escape_xml(val: Any) -> str:
    if val is None:
        return ""
    return html.escape(str(val))

def generate_security_pdf(job_data: Dict[str, Any], workspace_name: str, tenant_id: str) -> bytes:
    buffer = io.BytesIO()
    # Landscape A4/Letter format with minimal 20pt margins so maximum content is visible
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
    total_printable_width = 752  # 792 - 40 pt

    # 1. HEADER & EXECUTIVE SUMMARY (Clean, direct, without unwanted decorative lines)
    header_data = [
        [
            Paragraph("<b>AZURE FINSECOPS - SECURITY ASSESSMENT REPORT</b>", styles["CoverTitle"]),
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
    sec_counts = summary.get("security_severity_counts", {})
    raw_sec_score = summary.get("current_security_score", summary.get("security_score"))
    sec_score_str = f"{round(raw_sec_score)}%" if raw_sec_score is not None else "--"

    # Executive Summary Metrics Card Grid (No unwanted lines under summary)
    exec_stats = [
        [
            Paragraph("<b>Total Security Findings</b>", styles["TableHeader"]),
            Paragraph("<b>Critical Severity</b>", styles["TableHeader"]),
            Paragraph("<b>High Severity</b>", styles["TableHeader"]),
            Paragraph("<b>Medium Severity</b>", styles["TableHeader"]),
            Paragraph("<b>Current Posture Score</b>", styles["TableHeader"]),
        ],
        [
            Paragraph(str(summary.get("security_findings_count", 0)), styles["TableCellBold"]),
            Paragraph(f"<font color='{COLOR_SEV_CRITICAL.hexval()}'><b>{sec_counts.get('Critical', 0)}</b></font>", styles["TableCellBold"]),
            Paragraph(f"<font color='{COLOR_SEV_HIGH.hexval()}'><b>{sec_counts.get('High', 0)}</b></font>", styles["TableCellBold"]),
            Paragraph(f"<font color='{COLOR_SEV_MEDIUM.hexval()}'><b>{sec_counts.get('Medium', 0)}</b></font>", styles["TableCellBold"]),
            Paragraph(f"<b>{sec_score_str}</b>", styles["TableCellBold"]),
        ]
    ]
    col_w_exec = total_printable_width / 5
    t_exec = Table(exec_stats, colWidths=[col_w_exec] * 5)
    t_exec.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), COLOR_PRIMARY_PURPLE),
        ("BACKGROUND", (0, 1), (-1, 1), COLOR_LIGHT_BG),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("BOX", (0, 0), (-1, -1), 1, COLOR_BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_exec)
    story.append(Spacer(1, 12))

    # 2. OVERALL ASSESSMENT STATUS TABLE - High-Level Business Overview
    story.append(Paragraph("<b>Security Assessment Modules Evaluation Status</b>", styles["SubSectionHeader"]))
    story.append(Spacer(1, 4))

    status_table_data = [
        [
            Paragraph("<b>S.No</b>", styles["TableHeader"]),
            Paragraph("<b>Assessment Category</b>", styles["TableHeader"]),
            Paragraph("<b>Findings Detected</b>", styles["TableHeader"]),
            Paragraph("<b>Evaluation Status</b>", styles["TableHeader"]),
            Paragraph("<b>Posture Potential</b>", styles["TableHeader"]),
        ]
    ]

    results = job_data.get("results", {})
    sec_assessments = assessment_registry.get_security_assessments()

    from app.reports.high_level_categories import get_security_high_level_summary
    high_level_rows = get_security_high_level_summary(results)

    for row in high_level_rows:
        status_display = row["status"]
        findings_count = row["findings_detected"]
        impact_display = row["impact_display"]

        status_table_data.append([
            Paragraph(f"<b>{row['s_no']}</b>", styles["TableCellBold"]),
            Paragraph(escape_xml(row["category"]), styles["TableCellBold"]),
            Paragraph(str(findings_count), styles["TableCellBold"] if findings_count > 0 else styles["TableCell"]),
            Paragraph(f"<font color='{'#059669' if status_display in ['Completed', 'No Findings'] else '#DE1A3B'}'>{escape_xml(status_display)}</font>", styles["TableCellBold"]),
            Paragraph(impact_display, styles["TableCell"]),
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

    # 3. INDIVIDUAL ASSESSMENT MODULE SECTIONS (Only resources with security gaps)
    # Each assessment has its own specific columns and headings
    for ass in sec_assessments:
        res = results.get(ass.assessment_id)
        findings = res.findings if hasattr(res, "findings") else (res.get("findings", []) if isinstance(res, dict) else [])
        spec = SECURITY_REPORT_SPECS.get(ass.assessment_id)
        if not spec:
            continue

        report_title = spec["report_title"]
        columns = spec["columns"]
        col_widths = spec["col_widths"]

        # Ensure column widths perfectly equal total_printable_width
        sum_w = sum(col_widths)
        normalized_widths = [round((w / sum_w) * total_printable_width, 1) for w in col_widths]
        # Adjust remainder on last column
        diff = total_printable_width - sum(normalized_widths)
        normalized_widths[-1] += diff

        sec_block = []
        # Module Title (Clean, no 'Purpose' or filler words)
        sec_block.append(Paragraph(f"<b>[{ass.code}] {escape_xml(report_title)}</b>", styles["SubSectionHeader"]))
        sec_block.append(Spacer(1, 3))

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
                    sec_block.append(Spacer(1, 6))

                if table_findings:
                    sec_block.append(Paragraph("<b>Security Controls Breakdown</b>", styles["TableCellBold"]))
                    sec_block.append(Spacer(1, 3))

        if table_findings:
            # Build assessment-specific table
            header_row = [Paragraph(f"<b>{escape_xml(col)}</b>", styles["TableHeaderSmall"]) for col in columns]
            table_data = [header_row]

            for f in table_findings:
                row_vals = extract_security_finding_row(ass.assessment_id, f)
                formatted_row = []
                for val in row_vals:
                    val_str = escape_xml(val)
                    # Color code severities
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

        sec_block.append(Spacer(1, 10))
        story.append(KeepTogether(sec_block))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buffer.getvalue()
