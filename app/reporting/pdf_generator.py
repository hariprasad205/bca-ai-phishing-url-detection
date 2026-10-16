"""Professional PDF Audit Certificate Generator using ReportLab.

Builds downloadable cybersecurity audit reports with metrics, risk scores,
lexical indicators, and academic disclaimers.
"""
import io
from datetime import datetime, timezone, tzinfo
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from app.models import Scan
from app.reporting.timezone import format_local_timestamp


def generate_scan_audit_pdf(
    scan: Scan, local_timezone: tzinfo = timezone.utc
) -> io.BytesIO:
    """Generate a high-resolution, professional PDF audit report for a scan."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )

    story = []
    styles = getSampleStyleSheet()

    # Custom Color Palette: Cybersecurity Navy & Slate
    navy = colors.HexColor("#0f172a")
    blue = colors.HexColor("#1e40af")
    slate = colors.HexColor("#475569")
    light_bg = colors.HexColor("#f8fafc")
    border_color = colors.HexColor("#cbd5e1")

    # Risk badge colors
    if scan.prediction_label == "phishing":
        badge_bg = colors.HexColor("#fee2e2")
        badge_text = colors.HexColor("#991b1b")
    else:
        badge_bg = colors.HexColor("#dcfce7")
        badge_text = colors.HexColor("#166534")

    # Typography Styles
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=navy,
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=slate,
        spaceAfter=15,
    )
    h2_style = ParagraphStyle(
        "SectionHeader",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=blue,
        spaceBefore=12,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
    )
    mono_style = ParagraphStyle(
        "UrlMono",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
    )
    disclaimer_style = ParagraphStyle(
        "Disclaimer",
        parent=styles["Normal"],
        fontName="Helvetica-Oblique",
        fontSize=7.5,
        leading=11,
        textColor=colors.HexColor("#64748b"),
    )

    # Header / Branding
    story.append(Paragraph("AI-BASED PHISHING URL DETECTION SYSTEM", title_style))
    story.append(Paragraph("Automated URL Security Assessment & Lexical Audit Report", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=blue, spaceAfter=15))

    # Audit Metadata Table
    audit_id = f"AUDIT-SCN-{scan.id:06d}-{scan.created_at.strftime('%Y%m%d')}"
    gen_time = format_local_timestamp(datetime.now(timezone.utc), local_timezone)
    scan_time = format_local_timestamp(scan.created_at, local_timezone)
    owner_str = scan.user.username if scan.user else "System"

    meta_data = [
        [Paragraph("<b>Audit Report ID:</b>", body_style), Paragraph(audit_id, body_style),
         Paragraph("<b>Scan Timestamp (Local):</b>", body_style), Paragraph(scan_time, body_style)],
        [Paragraph("<b>Report Owner:</b>", body_style), Paragraph(owner_str, body_style),
         Paragraph("<b>Generated At (Local):</b>", body_style), Paragraph(gen_time, body_style)],
        [Paragraph("<b>Model Version:</b>", body_style), Paragraph(scan.model_version, body_style),
         Paragraph("<b>Inference Latency:</b>", body_style), Paragraph(f"{scan.latency_ms:.2f} ms", body_style)],
    ]
    t_meta = Table(meta_data, colWidths=[110, 155, 110, 155])
    t_meta.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), light_bg),
        ("BOX", (0, 0), (-1, -1), 0.5, border_color),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 12))

    # Target URL Section
    story.append(Paragraph("Target URL Analyzed", h2_style))
    url_table = Table([[Paragraph(scan.url, mono_style)]], colWidths=[530])
    url_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, border_color),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(url_table)
    story.append(Spacer(1, 10))

    # Prediction & Risk Summary
    story.append(Paragraph("Classification & Risk Assessment", h2_style))
    pred_text = f"<b>{scan.prediction_label.upper()}</b>"
    risk_summary_data = [
        [
            Paragraph("<b>Predicted Class</b>", body_style),
            Paragraph("<b>Risk Score</b>", body_style),
            Paragraph("<b>Risk Category</b>", body_style),
            Paragraph("<b>Phishing Probability</b>", body_style),
        ],
        [
            Paragraph(f"<font color='{badge_text}'>{pred_text}</font>", body_style),
            Paragraph(f"<b>{scan.risk_score:.1f} / 100</b>", body_style),
            Paragraph(scan.risk_category, body_style),
            Paragraph(f"{scan.probability * 100:.1f}%", body_style),
        ]
    ]
    t_risk = Table(risk_summary_data, colWidths=[130, 130, 135, 135])
    t_risk.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ("BACKGROUND", (0, 1), (0, 1), badge_bg),
        ("BACKGROUND", (1, 1), (-1, 1), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.5, border_color),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, border_color),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t_risk)
    story.append(Spacer(1, 12))

    # Extracted Lexical Features Table
    features = scan.features
    if features:
        story.append(Paragraph("Extracted Lexical Indicators (Zero Outbound Execution)", h2_style))
        feat_rows = [
            [
                Paragraph("<b>Feature Indicator</b>", body_style),
                Paragraph("<b>Measured Value</b>", body_style),
                Paragraph("<b>Feature Indicator</b>", body_style),
                Paragraph("<b>Measured Value</b>", body_style),
            ],
            [
                Paragraph("URL Total Length", body_style), Paragraph(str(features.url_length), body_style),
                Paragraph("Hostname Length", body_style), Paragraph(str(features.hostname_length), body_style),
            ],
            [
                Paragraph("Dot Count (.)", body_style), Paragraph(str(features.num_dots), body_style),
                Paragraph("Hyphen Count (-)", body_style), Paragraph(str(features.num_hyphens), body_style),
            ],
            [
                Paragraph("Digit Count [0-9]", body_style), Paragraph(str(features.num_digits), body_style),
                Paragraph("Subdomain Count", body_style), Paragraph(str(features.num_subdomains), body_style),
            ],
            [
                Paragraph("HTTPS Scheme", body_style), Paragraph("Yes (1)" if features.is_https else "No (0)", body_style),
                Paragraph("IP-Address Hostname", body_style), Paragraph("Yes (1)" if features.is_ip else "No (0)", body_style),
            ],
            [
                Paragraph("Suspicious Tokens", body_style), Paragraph(str(features.suspicious_token_count), body_style),
                Paragraph("@ Symbol Present", body_style), Paragraph("Yes (1)" if features.has_at_symbol else "No (0)", body_style),
            ],
            [
                Paragraph("URL Path Length", body_style), Paragraph(str(features.path_length), body_style),
                Paragraph("Query String Length", body_style), Paragraph(str(features.query_length), body_style),
            ],
        ]
        t_feat = Table(feat_rows, colWidths=[150, 115, 150, 115])
        t_feat.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 1), (-1, -1), colors.white),
            ("BOX", (0, 0), (-1, -1), 0.5, border_color),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t_feat)
        story.append(Spacer(1, 10))

    # Explainability & Suspicious Signals
    explanation = scan.explanation
    risk_indicators = explanation.get("risk_indicators", [])
    if risk_indicators:
        story.append(Paragraph("Model Explainability Signals", h2_style))
        for ind in risk_indicators:
            story.append(Paragraph(f"• {ind}", body_style))
        story.append(Spacer(1, 8))

    # Academic Disclaimer & Limitations
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=8))
    story.append(Paragraph(
        "<b>LEGAL & TECHNICAL DISCLAIMER:</b> This document is an automated software audit report generated by "
        "the AI-Based Phishing URL Detection System for academic demonstration and cybersecurity educational purposes. "
        "The classification represents a statistical machine-learning prediction derived solely from static lexical features "
        "and does not constitute an absolute guarantee of website safety or threat absence. The presence of HTTPS encryption "
        "secures communication channels but does not guarantee the legitimacy of the destination. Zero server-side HTTP connections "
        "or remote code executions were performed during this audit.",
        disclaimer_style
    ))

    doc.build(story)
    buffer.seek(0)
    return buffer
