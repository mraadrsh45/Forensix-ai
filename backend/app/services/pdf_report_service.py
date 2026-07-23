import io
import logging
from typing import Dict, Any
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

logger = logging.getLogger(__name__)

def draw_decorations(canvas, doc):
    canvas.saveState()
    # Draw top border header line (cyan branding)
    canvas.setStrokeColor(colors.HexColor('#0891b2'))
    canvas.setLineWidth(2)
    canvas.line(0.5 * inch, 10.3 * inch, 8.0 * inch, 10.3 * inch)
    
    # Draw bottom border footer line
    canvas.setStrokeColor(colors.HexColor('#e2e8f0'))
    canvas.setLineWidth(0.5)
    canvas.line(0.5 * inch, 0.75 * inch, 8.0 * inch, 0.75 * inch)
    
    # Header text
    canvas.setFont('Helvetica-Bold', 8)
    canvas.setFillColor(colors.HexColor('#0f172a'))
    canvas.drawString(0.5 * inch, 10.45 * inch, "FORENSIX AI — CYBER FORENSICS REPORT")
    
    # Footer text
    canvas.setFont('Helvetica', 8)
    canvas.setFillColor(colors.HexColor('#64748b'))
    canvas.drawString(0.5 * inch, 0.55 * inch, "CONFIDENTIAL — FOR INTERNAL USE ONLY")
    canvas.drawRightString(8.0 * inch, 0.55 * inch, f"Page {doc.page}")
    canvas.restoreState()

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
            topMargin=0.9 * inch,
            bottomMargin=0.9 * inch
        )

        styles = getSampleStyleSheet()
        
        # Custom Premium PDF Styles
        title_style = ParagraphStyle(
            'DocTitle',
            parent=styles['Heading1'],
            fontSize=20,
            leading=24,
            textColor=colors.HexColor('#0f172a'),
            fontName='Helvetica-Bold',
            spaceAfter=4
        )

        subtitle_style = ParagraphStyle(
            'DocSubTitle',
            parent=styles['Normal'],
            fontSize=9.5,
            leading=12,
            textColor=colors.HexColor('#475569'),
            spaceAfter=12
        )

        h2_style = ParagraphStyle(
            'SectionH2',
            parent=styles['Heading2'],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor('#0f172a'),
            fontName='Helvetica-Bold',
            spaceBefore=14,
            spaceAfter=8,
            keepWithNext=True
        )

        body_style = ParagraphStyle(
            'BodyTextCustom',
            parent=styles['Normal'],
            fontSize=9,
            leading=13,
            textColor=colors.HexColor('#1e293b')
        )

        badge_style = ParagraphStyle(
            'BadgeText',
            parent=styles['Normal'],
            fontSize=10.5,
            leading=13,
            textColor=colors.HexColor('#b91c1c'),
            fontName='Helvetica-Bold',
            alignment=2 # Right align
        )

        elements = []

        # Header Title
        case_name = investigation_data.get("case_name", "Cyber Incident Investigation")
        target_subj = investigation_data.get("target_subject", "Target Infrastructure")
        timestamp = investigation_data.get("timestamp", "")

        elements.append(Paragraph(f"ForensiX AI Forensic Intelligence Dossier", title_style))
        elements.append(Paragraph(f"<b>Case File:</b> {case_name} &nbsp;|&nbsp; <b>Subject:</b> {target_subj} &nbsp;|&nbsp; <b>Executed:</b> {timestamp[:19]}", subtitle_style))

        # Risk Rating Banner
        risk_score = investigation_data.get("risk_score", 95)
        severity = investigation_data.get("severity_level", "CRITICAL THREAT")
        
        risk_table_data = [
            [
                Paragraph("<font size=9 color='#7f1d1d'><b>FORENSIC RISK ASSESSMENT RATIO</b></font>", body_style),
                Paragraph(f"<font size=11 color='#b91c1c'><b>{risk_score} / 100</b></font> <font size=8.5 color='#b91c1c'>({severity})</font>", badge_style)
            ]
        ]
        risk_table = Table(risk_table_data, colWidths=[3.2 * inch, 4.3 * inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#fef2f2')),
            ('BOX', (0, 0), (-1, -1), 1.5, colors.HexColor('#fca5a5')),
            ('PADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE')
        ]))
        elements.append(risk_table)
        elements.append(Spacer(1, 10))

        # Executive Summary Section
        elements.append(Paragraph("1. Incident Executive Summary & Synthesis", h2_style))
        summary_text = investigation_data.get("ai_executive_summary", "No summary text generated.")
        elements.append(Paragraph(summary_text.replace("\n", "<br/>"), body_style))

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
        t_table = Table(t_table_data, colWidths=[0.85 * inch, 1.45 * inch, 1.9 * inch, 3.3 * inch])
        t_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#0f172a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ])
        for r in range(1, len(t_table_data)):
            if r % 2 == 1:
                t_style.add('BACKGROUND', (0, r), (-1, r), colors.HexColor('#f8fafc'))
        t_table.setStyle(t_style)
        elements.append(t_table)

        # MITRE ATT&CK Matrix Section
        elements.append(Paragraph("3. MITRE ATT&CK TTP Correlation", h2_style))
        mitre_items = investigation_data.get("mitre_mappings", [])
        m_table_data = [["Tactic", "Technique ID", "Technique Name", "Confidence"]]
        for m in mitre_items:
            m_table_data.append([
                Paragraph(m.get("tactic", ""), body_style),
                Paragraph(f"<b>{m.get('technique_id', '')}</b>", body_style),
                Paragraph(m.get("technique_name", ""), body_style),
                Paragraph(m.get("confidence", ""), body_style)
            ])
        m_table = Table(m_table_data, colWidths=[1.8 * inch, 1.3 * inch, 3.3 * inch, 1.1 * inch])
        m_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1e293b')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ])
        for r in range(1, len(m_table_data)):
            if r % 2 == 1:
                m_style.add('BACKGROUND', (0, r), (-1, r), colors.HexColor('#f8fafc'))
        m_table.setStyle(m_style)
        elements.append(m_table)

        # Extracted IOCs Section
        elements.append(Paragraph("4. Extracted Indicators of Compromise (IOCs)", h2_style))
        ioc_items = investigation_data.get("iocs", [])
        i_table_data = [["Type", "Indicator Value", "Risk Level", "Category"]]
        for i in ioc_items:
            # Color code risk value
            risk = i.get("risk", "")
            risk_color = '#ef4444' if 'CRITICAL' in risk or 'HIGH' in risk else '#f97316'
            i_table_data.append([
                Paragraph(i.get("type", ""), body_style),
                Paragraph(f"<font color='#0284c7'><b>{i.get('value', '')}</b></font>", body_style),
                Paragraph(f"<font color='{risk_color}'><b>{risk}</b></font>", body_style),
                Paragraph(i.get("category", ""), body_style)
            ])
        i_table = Table(i_table_data, colWidths=[1.2 * inch, 3.4 * inch, 1.1 * inch, 1.8 * inch])
        i_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#334155')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ])
        for r in range(1, len(i_table_data)):
            if r % 2 == 1:
                i_style.add('BACKGROUND', (0, r), (-1, r), colors.HexColor('#f8fafc'))
        i_table.setStyle(i_style)
        elements.append(i_table)

        # Playbook Actions Section
        elements.append(Paragraph("5. Recommended Remediation Playbook", h2_style))
        playbooks = investigation_data.get("playbook_actions", [])
        playbook_table_data = []
        for p in playbooks:
            priority = p.get('priority', '')
            p_color = '#ef4444' if 'IMMEDIATE' in priority or 'P0' in priority else ('#f97316' if 'HIGH' in priority or 'P1' in priority else '#3b82f6')
            playbook_table_data.append([
                Paragraph(f"<font color='{p_color}'><b>{priority}</b></font>", body_style),
                Paragraph(p.get('action', ''), body_style)
            ])
        
        if playbook_table_data:
            playbook_table = Table(playbook_table_data, colWidths=[1.6 * inch, 5.9 * inch])
            playbook_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8fafc')),
                ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#e2e8f0')),
                ('PADDING', (0, 0), (-1, -1), 6),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('LINEBELOW', (0, 0), (-1, -2), 0.5, colors.HexColor('#e2e8f0'))
            ]))
            elements.append(playbook_table)

        # Build PDF Document with custom headers/footers
        doc.build(elements, onFirstPage=draw_decorations, onLaterPages=draw_decorations)
        pdf_bytes = buffer.getvalue()
        buffer.close()
        return pdf_bytes

pdf_report_generator = PDFReportGenerator()
