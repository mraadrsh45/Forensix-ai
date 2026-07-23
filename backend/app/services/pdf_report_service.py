import io
import logging
from typing import Dict, Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable

logger = logging.getLogger(__name__)

class PDFReportGenerator:
    @staticmethod
    def generate_pdf(investigation_data: Dict[str, Any]) -> bytes:
        """
        Generates a publication-ready PDF Forensic Investigation Report using ReportLab.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.5 * inch,
            leftMargin=0.5 * inch,
            topMargin=0.5 * inch,
            bottomMargin=0.5 * inch
        )

        styles = getSampleStyleSheet()
        
        # Custom Forensic PDF Styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontSize=22,
            leading=26,
            textColor=colors.HexColor('#0f172a'),
            fontName='Helvetica-Bold',
            spaceAfter=6
        )

        subtitle_style = ParagraphStyle(
            'DocSubTitle',
            parent=styles['Normal'],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#475569'),
            spaceAfter=15
        )

        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading2'],
            fontSize=14,
            leading=18,
            textColor=colors.HexColor('#0284c7'),
            fontName='Helvetica-Bold',
            spaceBefore=12,
            spaceAfter=6
        )

        body_style = ParagraphStyle(
            'BodyTextCustom',
            parent=styles['Normal'],
            fontSize=9.5,
            leading=13,
            textColor=colors.HexColor('#1e293b')
        )

        badge_style = ParagraphStyle(
            'BadgeText',
            parent=styles['Normal'],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor('#dc2626'),
            fontName='Helvetica-Bold'
        )

        elements = []

        # Header Title
        case_name = investigation_data.get("case_name", "Cyber Incident Investigation")
        target_subj = investigation_data.get("target_subject", "Target Infrastructure")
        timestamp = investigation_data.get("timestamp", "")

        elements.append(Paragraph(f"FORENSIX AI — Forensic Investigation Report", title_style))
        elements.append(Paragraph(f"<b>Case:</b> {case_name} &nbsp;|&nbsp; <b>Target:</b> {target_subj} &nbsp;|&nbsp; <b>Generated:</b> {timestamp[:19]}", subtitle_style))
        elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#0284c7'), spaceAfter=12))

        # Risk Rating Box
        risk_score = investigation_data.get("risk_score", 95)
        severity = investigation_data.get("severity_level", "CRITICAL THREAT")
        
        risk_table_data = [
            [
                Paragraph("<b>COMPOSITE RISK RATING</b>", body_style),
                Paragraph(f"<b>{risk_score} / 100</b> ({severity})", badge_style)
            ]
        ]
        risk_table = Table(risk_table_data, colWidths=[2.5 * inch, 4.5 * inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fef2f2')),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#fca5a5')),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 10))

        # Executive Summary Section
        elements.append(Paragraph("1. AI Incident Executive Summary", h2_style))
        summary_text = investigation_data.get("ai_executive_summary", "No summary text generated.")
        elements.append(Paragraph(summary_text.replace("\n", "<br/>"), body_style))
        elements.append(Spacer(1, 10))

        # Super-Timeline Table Section
        elements.append(Paragraph("2. Chronological Attack Timeline", h2_style))
        timeline_items = investigation_data.get("timeline", [])
        t_table_data = [["Time", "Tactic Stage", "Event Summary", "Technical Details"]]
        for t in timeline_items:
            t_table_data.append([
                Paragraph(t.get("time", ""), body_style),
                Paragraph(f"<b>{t.get('stage', '')}</b>", body_style),
                Paragraph(t.get("event", ""), body_style),
                Paragraph(t.get("detail", ""), body_style)
            ])
        t_table = Table(t_table_data, colWidths=[0.9 * inch, 1.4 * inch, 1.8 * inch, 2.9 * inch])
        t_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        elements.append(t_table)
        elements.append(Spacer(1, 12))

        # MITRE ATT&CK Matrix Section
        elements.append(Paragraph("3. MITRE ATT&CK TTP Mapping", h2_style))
        mitre_items = investigation_data.get("mitre_mappings", [])
        m_table_data = [["Tactic", "Technique ID", "Technique Name", "Confidence"]]
        for m in mitre_items:
            m_table_data.append([
                Paragraph(m.get("tactic", ""), body_style),
                Paragraph(f"<b>{m.get('technique_id', '')}</b>", body_style),
                Paragraph(m.get("technique_name", ""), body_style),
                Paragraph(m.get("confidence", ""), body_style)
            ])
        m_table = Table(m_table_data, colWidths=[1.8 * inch, 1.2 * inch, 3.0 * inch, 1.0 * inch])
        m_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0, 0), (-1, -1), 5)
        ]))
        elements.append(m_table)
        elements.append(Spacer(1, 12))

        # Extracted IOCs Section
        elements.append(Paragraph("4. Extracted Indicators of Compromise (IOCs)", h2_style))
        ioc_items = investigation_data.get("iocs", [])
        i_table_data = [["Type", "Indicator Value", "Risk Level", "Category"]]
        for i in ioc_items:
            i_table_data.append([
                Paragraph(i.get("type", ""), body_style),
                Paragraph(f"<font color='#0284c7'><b>{i.get('value', '')}</b></font>", body_style),
                Paragraph(i.get("risk", ""), body_style),
                Paragraph(i.get("category", ""), body_style)
            ])
        i_table = Table(i_table_data, colWidths=[1.2 * inch, 3.2 * inch, 1.0 * inch, 1.6 * inch])
        i_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#cbd5e1')),
            ('PADDING', (0, 0), (-1, -1), 5)
        ]))
        elements.append(i_table)
        elements.append(Spacer(1, 12))

        # Playbook Actions Section
        elements.append(Paragraph("5. Recommended Remediation Playbook", h2_style))
        playbooks = investigation_data.get("playbook_actions", [])
        for p in playbooks:
            p_text = f"• <b>[{p.get('priority', '')}]</b> {p.get('action', '')}"
            elements.append(Paragraph(p_text, body_style))
            elements.append(Spacer(1, 4))

        # Build PDF Document
        doc.build(elements)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

pdf_report_generator = PDFReportGenerator()
