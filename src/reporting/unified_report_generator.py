"""
Unified Report Generator

Generates comprehensive security reports combining:
- GTL AI Security Platform data
- Drana-GTL multi-model scan results
- Threat intelligence
- Compliance assessments
- Vulnerability analysis
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import asyncpg
from pathlib import Path

# PDF generation
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, Image, KeepTogether
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY

# Charts
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import io
from PIL import Image as PILImage

logger = logging.getLogger(__name__)


class ReportFormat(Enum):
    """Report output formats"""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    MARKDOWN = "md"


class ReportSection(Enum):
    """Report sections"""
    EXECUTIVE_SUMMARY = "executive_summary"
    DRANA_AI_ANALYSIS = "drana_ai_analysis"
    COMPLIANCE_ASSESSMENT = "compliance_assessment"
    TECHNICAL_DETAILS = "technical_details"
    RECOMMENDATIONS = "recommendations"
    APPENDIX = "appendix"


@dataclass
class ReportConfig:
    """Configuration for report generation"""
    client_id: str
    client_name: str
    report_title: str
    date_range: Tuple[datetime, datetime]
    sections: List[ReportSection] = field(default_factory=lambda: list(ReportSection))
    include_charts: bool = True
    include_raw_data: bool = False
    confidentiality_level: str = "confidential"  # public, internal, confidential, restricted
    branding: Optional[Dict[str, Any]] = None
    logo_path: Optional[Path] = None


class UnifiedReportGenerator:
    """
    Generate comprehensive security reports combining GTL platform + Drana-GTL data
    
    Report Structure:
    1. Executive Summary - High-level overview and key metrics
    2. Drana-GTL AI Analysis - Multi-model threat intelligence and findings
    3. Compliance Assessment - HIPAA/ISO/SUNAT status and gaps
    4. Technical Details - Vulnerability details and evidence
    5. Recommendations - Prioritized action items and roadmap
    6. Appendix - Supporting data and references
    """
    
    def __init__(
        self,
        db_connection: asyncpg.Connection,
        output_dir: Path = Path("/tmp/reports")
    ):
        """
        Initialize report generator
        
        Args:
            db_connection: Database connection for querying data
            output_dir: Directory to save generated reports
        """
        self.db = db_connection
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Report styles
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Section header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2563eb'),
            spaceBefore=20,
            spaceAfter=12,
            fontName='Helvetica-Bold'
        ))
        
        # Finding title (critical)
        self.styles.add(ParagraphStyle(
            name='CriticalFinding',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#dc2626'),
            fontName='Helvetica-Bold'
        ))
        
        # Finding title (high)
        self.styles.add(ParagraphStyle(
            name='HighFinding',
            parent=self.styles['Normal'],
            fontSize=12,
            textColor=colors.HexColor('#ea580c'),
            fontName='Helvetica-Bold'
        ))
    
    async def generate_comprehensive_security_report(
        self,
        config: ReportConfig,
        output_format: ReportFormat = ReportFormat.PDF
    ) -> Path:
        """
        Generate comprehensive security report
        
        Args:
            config: Report configuration
            output_format: Output format (PDF, HTML, JSON, Markdown)
            
        Returns:
            Path to generated report file
        """
        logger.info(f"Generating {output_format.value} report for client: {config.client_name}")
        
        # Gather all data
        data = await self._gather_report_data(config)
        
        # Generate report based on format
        if output_format == ReportFormat.PDF:
            return await self._generate_pdf_report(config, data)
        elif output_format == ReportFormat.HTML:
            return await self._generate_html_report(config, data)
        elif output_format == ReportFormat.JSON:
            return await self._generate_json_report(config, data)
        elif output_format == ReportFormat.MARKDOWN:
            return await self._generate_markdown_report(config, data)
        else:
            raise ValueError(f"Unsupported report format: {output_format}")
    
    async def _gather_report_data(self, config: ReportConfig) -> Dict[str, Any]:
        """Gather all data needed for the report"""
        start_date, end_date = config.date_range
        
        data = {
            "config": config,
            "generated_at": datetime.utcnow(),
        }
        
        # Executive summary data
        data["summary"] = await self._get_executive_summary_data(start_date, end_date)
        
        # Drana-GTL scan data
        data["drana_scans"] = await self._get_drana_scan_data(start_date, end_date)
        data["drana_findings"] = await self._get_drana_findings_data(start_date, end_date)
        data["model_analytics"] = await self._get_model_analytics_data(start_date, end_date)
        
        # Compliance data
        data["compliance"] = await self._get_compliance_data(start_date, end_date)
        
        # Threat intelligence
        data["threats"] = await self._get_threat_intelligence_data(start_date, end_date)
        
        # Trending data
        data["trends"] = await self._get_trend_data(start_date, end_date)
        
        return data
    
    async def _get_executive_summary_data(self, start_date: datetime, end_date: datetime) -> Dict:
        """Get executive summary metrics"""
        summary = await self.db.fetchrow("""
            SELECT 
                COUNT(DISTINCT scan_id) as total_scans,
                COUNT(DISTINCT scan_id) FILTER (WHERE status = 'completed') as completed_scans,
                COUNT(DISTINCT scan_id) FILTER (WHERE status = 'failed') as failed_scans,
                SUM(findings_count) as total_findings,
                SUM(critical_severity_count) as critical_findings,
                SUM(high_severity_count) as high_findings,
                AVG(confidence_score) as avg_confidence,
                AVG(duration_seconds) as avg_duration_seconds
            FROM drana_scans
            WHERE started_at BETWEEN $1 AND $2
        """, start_date, end_date)
        
        # Convert to dict
        result = dict(summary) if summary else {}
        
        # Get compliance score
        compliance_avg = await self.db.fetchval("""
            SELECT AVG(compliance_score)
            FROM drana_compliance_assessments
            WHERE assessed_at BETWEEN $1 AND $2
        """, start_date, end_date)
        
        result["avg_compliance_score"] = float(compliance_avg) if compliance_avg else 0.0
        
        # Risk level assessment
        critical_count = result.get("critical_findings", 0) or 0
        high_count = result.get("high_findings", 0) or 0
        
        if critical_count > 10 or high_count > 25:
            result["risk_level"] = "Critical"
        elif critical_count > 5 or high_count > 15:
            result["risk_level"] = "High"
        elif critical_count > 0 or high_count > 5:
            result["risk_level"] = "Medium"
        else:
            result["risk_level"] = "Low"
        
        return result
    
    async def _get_drana_scan_data(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Get Drana-GTL scan data"""
        scans = await self.db.fetch("""
            SELECT 
                scan_id,
                target,
                scan_type,
                sector,
                status,
                models_used,
                started_at,
                completed_at,
                duration_seconds,
                findings_count,
                critical_severity_count,
                high_severity_count,
                confidence_score
            FROM drana_scans
            WHERE started_at BETWEEN $1 AND $2
            ORDER BY started_at DESC
        """, start_date, end_date)
        
        return [dict(scan) for scan in scans]
    
    async def _get_drana_findings_data(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Get Drana-GTL findings"""
        findings = await self.db.fetch("""
            SELECT 
                f.finding_id,
                f.scan_id,
                f.title,
                f.severity,
                f.confidence,
                f.threat_category,
                f.attack_vector,
                f.description,
                f.phi_exposure_risk,
                f.patient_safety_impact,
                f.patient_safety_score,
                f.recommendations,
                f.status,
                s.target,
                s.sector
            FROM drana_findings f
            JOIN drana_scans s ON f.scan_id = s.scan_id
            WHERE f.created_at BETWEEN $1 AND $2
            ORDER BY 
                CASE f.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                f.confidence DESC
        """, start_date, end_date)
        
        return [dict(finding) for finding in findings]
    
    async def _get_model_analytics_data(self, start_date: datetime, end_date: datetime) -> Dict:
        """Get multi-model analytics"""
        analytics = await self.db.fetch("""
            SELECT 
                model_name,
                COUNT(*) as executions,
                AVG(execution_time_ms) as avg_execution_time,
                SUM(findings_contributed) as total_findings,
                AVG(accuracy_score) as avg_accuracy,
                AVG(agreement_with_ensemble) as avg_agreement
            FROM drana_model_analytics
            WHERE created_at BETWEEN $1 AND $2
            GROUP BY model_name
        """, start_date, end_date)
        
        return {
            "models": [dict(a) for a in analytics]
        }
    
    async def _get_compliance_data(self, start_date: datetime, end_date: datetime) -> Dict:
        """Get compliance assessment data"""
        assessments = await self.db.fetch("""
            SELECT 
                framework,
                total_controls,
                compliant_controls,
                non_compliant_controls,
                compliance_score,
                critical_gaps,
                high_priority_gaps,
                assessed_at
            FROM drana_compliance_assessments
            WHERE assessed_at BETWEEN $1 AND $2
            ORDER BY assessed_at DESC
        """, start_date, end_date)
        
        # Get latest assessment per framework
        latest_by_framework = {}
        for assessment in assessments:
            framework = assessment["framework"]
            if framework not in latest_by_framework:
                latest_by_framework[framework] = dict(assessment)
        
        return {
            "frameworks": latest_by_framework,
            "all_assessments": [dict(a) for a in assessments]
        }
    
    async def _get_threat_intelligence_data(self, start_date: datetime, end_date: datetime) -> Dict:
        """Get threat intelligence data"""
        indicators = await self.db.fetch("""
            SELECT 
                indicator_type,
                severity,
                COUNT(*) as count
            FROM drana_threat_indicators
            WHERE first_seen BETWEEN $1 AND $2
            GROUP BY indicator_type, severity
        """, start_date, end_date)
        
        return {
            "indicators": [dict(i) for i in indicators]
        }
    
    async def _get_trend_data(self, start_date: datetime, end_date: datetime) -> Dict:
        """Get trending data over time"""
        # Daily findings trend
        daily_findings = await self.db.fetch("""
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as findings_count,
                COUNT(*) FILTER (WHERE severity IN ('critical', 'high')) as high_severity_count
            FROM drana_findings
            WHERE created_at BETWEEN $1 AND $2
            GROUP BY DATE(created_at)
            ORDER BY date
        """, start_date, end_date)
        
        return {
            "daily_findings": [dict(d) for d in daily_findings]
        }
    
    async def _generate_pdf_report(self, config: ReportConfig, data: Dict) -> Path:
        """Generate PDF report"""
        output_path = self.output_dir / f"security_report_{config.client_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )
        
        # Build document content
        story = []
        
        # Cover page
        story.extend(self._build_cover_page(config, data))
        story.append(PageBreak())
        
        # Table of contents (simplified)
        story.extend(self._build_table_of_contents(config))
        story.append(PageBreak())
        
        # Sections
        for section in config.sections:
            if section == ReportSection.EXECUTIVE_SUMMARY:
                story.extend(self._build_executive_summary_section(data))
            elif section == ReportSection.DRANA_AI_ANALYSIS:
                story.extend(self._build_drana_analysis_section(data))
            elif section == ReportSection.COMPLIANCE_ASSESSMENT:
                story.extend(self._build_compliance_section(data))
            elif section == ReportSection.TECHNICAL_DETAILS:
                story.extend(self._build_technical_details_section(data))
            elif section == ReportSection.RECOMMENDATIONS:
                story.extend(self._build_recommendations_section(data))
            elif section == ReportSection.APPENDIX:
                story.extend(self._build_appendix_section(data))
            
            story.append(PageBreak())
        
        # Build PDF
        doc.build(story)
        
        logger.info(f"PDF report generated: {output_path}")
        return output_path
    
    def _build_cover_page(self, config: ReportConfig, data: Dict) -> List:
        """Build cover page"""
        elements = []
        
        # Logo
        if config.logo_path and config.logo_path.exists():
            logo = Image(str(config.logo_path), width=2*inch, height=1*inch)
            elements.append(logo)
            elements.append(Spacer(1, 0.5*inch))
        
        # Title
        title = Paragraph(config.report_title, self.styles['CustomTitle'])
        elements.append(title)
        elements.append(Spacer(1, 0.3*inch))
        
        # Client info
        client_info = f"<b>Client:</b> {config.client_name}<br/>"
        client_info += f"<b>Report Date:</b> {data['generated_at'].strftime('%B %d, %Y')}<br/>"
        client_info += f"<b>Period:</b> {config.date_range[0].strftime('%Y-%m-%d')} to {config.date_range[1].strftime('%Y-%m-%d')}<br/>"
        client_info += f"<b>Classification:</b> {config.confidentiality_level.upper()}"
        
        elements.append(Paragraph(client_info, self.styles['Normal']))
        elements.append(Spacer(1, 1*inch))
        
        # Summary box
        summary = data['summary']
        summary_text = f"""
        <b>EXECUTIVE SNAPSHOT</b><br/><br/>
        Risk Level: <font color="{self._get_risk_color(summary['risk_level'])}">{summary['risk_level']}</font><br/>
        Total Scans: {summary.get('total_scans', 0)}<br/>
        Critical Findings: {summary.get('critical_findings', 0)}<br/>
        High Findings: {summary.get('high_findings', 0)}<br/>
        Average Compliance Score: {summary.get('avg_compliance_score', 0):.1f}%
        """
        
        elements.append(Paragraph(summary_text, self.styles['Normal']))
        
        return elements
    
    def _build_table_of_contents(self, config: ReportConfig) -> List:
        """Build table of contents"""
        elements = []
        
        elements.append(Paragraph("Table of Contents", self.styles['Heading1']))
        elements.append(Spacer(1, 0.3*inch))
        
        toc_items = []
        for i, section in enumerate(config.sections, 1):
            toc_items.append([
                f"{i}. {section.value.replace('_', ' ').title()}",
                f"Page {i+2}"  # Simplified page numbering
            ])
        
        toc_table = Table(toc_items, colWidths=[5*inch, 1.5*inch])
        toc_table.setStyle(TableStyle([
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        
        elements.append(toc_table)
        
        return elements
    
    def _build_executive_summary_section(self, data: Dict) -> List:
        """Build executive summary section"""
        elements = []
        
        elements.append(Paragraph("1. Executive Summary", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))
        
        summary = data['summary']
        
        # Overview paragraph
        overview_text = f"""
        During the reporting period, {summary.get('total_scans', 0)} security scans were performed using the 
        Drana-GTL multi-model AI security platform. The overall security posture is classified as 
        <b>{summary['risk_level']}</b> risk level based on {summary.get('critical_findings', 0)} critical and 
        {summary.get('high_findings', 0)} high-severity findings discovered.
        """
        
        elements.append(Paragraph(overview_text, self.styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Key metrics table
        metrics_data = [
            ['Metric', 'Value'],
            ['Total Security Scans', str(summary.get('total_scans', 0))],
            ['Completed Scans', str(summary.get('completed_scans', 0))],
            ['Total Findings', str(summary.get('total_findings', 0))],
            ['Critical Findings', str(summary.get('critical_findings', 0))],
            ['High Severity Findings', str(summary.get('high_findings', 0))],
            ['Average Compliance Score', f"{summary.get('avg_compliance_score', 0):.1f}%"],
            ['Average Scan Confidence', f"{(summary.get('avg_confidence', 0) or 0) * 100:.1f}%"],
        ]
        
        metrics_table = Table(metrics_data, colWidths=[4*inch, 2*inch])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        elements.append(metrics_table)
        
        # Chart (if enabled)
        if data['config'].include_charts:
            chart_path = self._create_summary_chart(data)
            if chart_path:
                elements.append(Spacer(1, 0.3*inch))
                chart_img = Image(str(chart_path), width=6*inch, height=3*inch)
                elements.append(chart_img)
        
        return elements
    
    def _build_drana_analysis_section(self, data: Dict) -> List:
        """Build Drana-GTL AI analysis section"""
        elements = []
        
        elements.append(Paragraph("2. Drana-GTL AI Security Analysis", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))
        
        # Multi-model overview
        model_data = data['model_analytics']
        if model_data['models']:
            elements.append(Paragraph("Multi-Model AI Performance", self.styles['Heading3']))
            elements.append(Spacer(1, 0.1*inch))
            
            model_table_data = [['Model', 'Executions', 'Avg Time (ms)', 'Findings', 'Accuracy']]
            for model in model_data['models']:
                model_table_data.append([
                    model['model_name'],
                    str(model['executions']),
                    f"{model.get('avg_execution_time', 0):.0f}",
                    str(model.get('total_findings', 0)),
                    f"{(model.get('avg_accuracy', 0) or 0) * 100:.1f}%"
                ])
            
            model_table = Table(model_table_data)
            model_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#2563eb')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            elements.append(model_table)
            elements.append(Spacer(1, 0.3*inch))
        
        # Top findings
        findings = data['drana_findings']
        if findings:
            elements.append(Paragraph("Critical & High Severity Findings", self.styles['Heading3']))
            elements.append(Spacer(1, 0.1*inch))
            
            # Show top 10 most critical findings
            for finding in findings[:10]:
                style_name = 'CriticalFinding' if finding['severity'] == 'critical' else 'HighFinding'
                
                finding_text = f"<b>[{finding['severity'].upper()}]</b> {finding['title']}"
                elements.append(Paragraph(finding_text, self.styles[style_name]))
                
                desc = f"{finding['description'][:200]}..."
                elements.append(Paragraph(desc, self.styles['Normal']))
                elements.append(Spacer(1, 0.1*inch))
        
        return elements
    
    def _build_compliance_section(self, data: Dict) -> List:
        """Build compliance assessment section"""
        elements = []
        
        elements.append(Paragraph("3. Compliance Assessment", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))
        
        compliance = data['compliance']
        frameworks = compliance.get('frameworks', {})
        
        if frameworks:
            for framework_name, framework_data in frameworks.items():
                elements.append(Paragraph(f"{framework_name.upper()} Compliance", self.styles['Heading3']))
                
                compliance_text = f"""
                <b>Compliance Score:</b> {framework_data.get('compliance_score', 0):.1f}%<br/>
                <b>Total Controls:</b> {framework_data.get('total_controls', 0)}<br/>
                <b>Compliant:</b> {framework_data.get('compliant_controls', 0)}<br/>
                <b>Non-Compliant:</b> {framework_data.get('non_compliant_controls', 0)}<br/>
                <b>Critical Gaps:</b> {framework_data.get('critical_gaps', 0)}<br/>
                <b>High Priority Gaps:</b> {framework_data.get('high_priority_gaps', 0)}
                """
                
                elements.append(Paragraph(compliance_text, self.styles['Normal']))
                elements.append(Spacer(1, 0.2*inch))
        
        return elements
    
    def _build_technical_details_section(self, data: Dict) -> List:
        """Build technical details section"""
        elements = []
        
        elements.append(Paragraph("4. Technical Details", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))
        
        elements.append(Paragraph("Detailed vulnerability information and technical evidence.", self.styles['Normal']))
        
        return elements
    
    def _build_recommendations_section(self, data: Dict) -> List:
        """Build recommendations section"""
        elements = []
        
        elements.append(Paragraph("5. Recommendations", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))
        
        elements.append(Paragraph("Prioritized action items and remediation roadmap.", self.styles['Normal']))
        
        return elements
    
    def _build_appendix_section(self, data: Dict) -> List:
        """Build appendix section"""
        elements = []
        
        elements.append(Paragraph("6. Appendix", self.styles['SectionHeader']))
        elements.append(Spacer(1, 0.2*inch))
        
        elements.append(Paragraph("Supporting data, references, and technical details.", self.styles['Normal']))
        
        return elements
    
    def _create_summary_chart(self, data: Dict) -> Optional[Path]:
        """Create summary chart for executive section"""
        try:
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
            
            # Chart 1: Findings by severity
            summary = data['summary']
            severities = ['Critical', 'High', 'Medium', 'Low']
            counts = [
                summary.get('critical_findings', 0),
                summary.get('high_findings', 0),
                summary.get('total_findings', 0) - summary.get('critical_findings', 0) - summary.get('high_findings', 0),
                0  # Placeholder for low
            ]
            colors_list = ['#dc2626', '#ea580c', '#f59e0b', '#eab308']
            
            ax1.bar(severities, counts, color=colors_list)
            ax1.set_title('Findings by Severity')
            ax1.set_ylabel('Count')
            
            # Chart 2: Compliance score
            compliance = data['compliance']
            frameworks = compliance.get('frameworks', {})
            if frameworks:
                framework_names = list(frameworks.keys())
                scores = [frameworks[f].get('compliance_score', 0) for f in framework_names]
                
                ax2.bar(framework_names, scores, color='#2563eb')
                ax2.set_title('Compliance Scores by Framework')
                ax2.set_ylabel('Score (%)')
                ax2.set_ylim(0, 100)
            
            plt.tight_layout()
            
            # Save chart
            chart_path = self.output_dir / "summary_chart.png"
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            
            return chart_path
        
        except Exception as e:
            logger.error(f"Failed to create chart: {e}")
            return None
    
    async def _generate_html_report(self, config: ReportConfig, data: Dict) -> Path:
        """Generate HTML report (stub)"""
        output_path = self.output_dir / f"security_report_{config.client_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        # TODO: Implement HTML generation
        return output_path
    
    async def _generate_json_report(self, config: ReportConfig, data: Dict) -> Path:
        """Generate JSON report (stub)"""
        import json
        
        output_path = self.output_dir / f"security_report_{config.client_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        # Convert datetime objects to strings
        def json_serializer(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")
        
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=json_serializer)
        
        return output_path
    
    async def _generate_markdown_report(self, config: ReportConfig, data: Dict) -> Path:
        """Generate Markdown report (stub)"""
        output_path = self.output_dir / f"security_report_{config.client_id}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        # TODO: Implement Markdown generation
        return output_path
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level"""
        colors_map = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#f59e0b",
            "Low": "#22c55e"
        }
        return colors_map.get(risk_level, "#6b7280")
