"""PDF remediation report generator using reportlab."""
from __future__ import annotations
import io
from datetime import datetime
from typing import Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

PURPLE = colors.HexColor("#4A3E8F")
GOLD = colors.HexColor("#D4AF37")
GREEN = colors.HexColor("#10B981")
RED = colors.HexColor("#EF4444")
DARK = colors.HexColor("#1A1633")


def generate_report(
    batch_results: list[dict[str, Any]],
    policy_text: str,
    source_filename: str = "synthetic demo data"
) -> bytes:
    """Generate a PDF remediation report and return as bytes."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch
    )
    story: list[Any] = []

    # Header
    story.append(Paragraph(
        "<font color='#4A3E8F'><b>SovereignShield</b></font> — "
        "Remediation Report",
        ParagraphStyle("title", fontSize=18, spaceAfter=4,
                       textColor=PURPLE)
    ))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')} | "
        f"Source: {source_filename}",
        ParagraphStyle("meta", fontSize=9, textColor=colors.grey,
                       spaceAfter=12)
    ))
    story.append(HRFlowable(width="100%", color=GOLD, thickness=2))
    story.append(Spacer(1, 12))

    # Summary KPIs
    total = len(batch_results)
    compliant = sum(1 for r in batch_results
                    if r.get("verdict") == "COMPLIANT")
    violations_total = sum(r.get("violations", 0)
                          for r in batch_results)
    mttrs = [r.get("mttr_seconds", 0) for r in batch_results
             if r.get("mttr_seconds", 0) > 0]
    avg_mttr = round(sum(mttrs) / len(mttrs), 1) if mttrs else 0

    story.append(Paragraph(
        "<b>Executive Summary</b>",
        ParagraphStyle("h2", fontSize=13, textColor=PURPLE,
                       spaceAfter=8)
    ))
    kpi_data = [
        ["Total Resources", "Compliant", "Violations", "Avg MTTR"],
        [str(total), str(compliant), str(violations_total),
         f"{avg_mttr}s"]
    ]
    kpi_table = Table(kpi_data, colWidths=[1.5*inch]*4)
    kpi_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), PURPLE),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTSIZE", (0,0), (-1,-1), 10),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1),
         [colors.HexColor("#F5F5F5"), colors.white]),
        ("BOX", (0,0), (-1,-1), 0.5, PURPLE),
        ("INNERGRID", (0,0), (-1,-1), 0.25, colors.lightgrey),
    ]))
    story.append(kpi_table)
    story.append(Spacer(1, 16))

    # Resource detail table
    story.append(Paragraph(
        "<b>Resource Detail</b>",
        ParagraphStyle("h2", fontSize=13, textColor=PURPLE,
                       spaceAfter=8)
    ))
    detail_data = [["Resource ID", "Type", "Verdict",
                    "Violations", "MTTR"]]
    for r in batch_results:
        detail_data.append([
            r.get("resource_id", ""),
            r.get("resource_type", ""),
            r.get("verdict", ""),
            str(r.get("violations", 0)),
            f"{r.get('mttr_seconds', 0)}s"
        ])
    detail_table = Table(
        detail_data,
        colWidths=[2*inch, 1.5*inch, 1.2*inch, 0.9*inch, 0.7*inch]
    )
    detail_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), PURPLE),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,1), (-1,-1),
         [colors.HexColor("#F5F5F5"), colors.white]),
        ("BOX", (0,0), (-1,-1), 0.5, PURPLE),
        ("INNERGRID", (0,0), (-1,-1), 0.25, colors.lightgrey),
    ]))
    story.append(detail_table)
    story.append(Spacer(1, 16))

    # Active policy
    story.append(Paragraph(
        "<b>Active OPA Policy</b>",
        ParagraphStyle("h2", fontSize=13, textColor=PURPLE,
                       spaceAfter=8)
    ))
    story.append(Paragraph(
        f"<font face='Courier' size='8'>"
        f"{policy_text[:1500].replace('<','&lt;').replace('>','&gt;')}"
        f"</font>",
        ParagraphStyle("code", fontSize=8, spaceAfter=8,
                       backColor=colors.HexColor("#F0F0F0"),
                       leftIndent=12, rightIndent=12)
    ))
    story.append(Spacer(1, 16))

    # Footer
    story.append(HRFlowable(width="100%", color=GOLD, thickness=1))
    story.append(Paragraph(
        "reichert-science-intelligence.com | "
        "reichert.starguardai@email.com | "
        "Synthetic data — for demonstration only",
        ParagraphStyle("footer", fontSize=8, textColor=colors.grey,
                       spaceBefore=6)
    ))

    doc.build(story)
    return buffer.getvalue()
