"""
Compliance Engine - Core Compliance Validation System

Automated assessment against multiple frameworks:
- HIPAA Security Rule (45 controls)
- ISO 27001:2022 (93 controls)
- NIST Cybersecurity Framework 2.0 (23 categories)
- SUNAT Peru customs/tax security
- Ley 29733 Peru personal data protection

Provides gap analysis, scoring, and remediation roadmaps.
"""

from typing import Dict, Any, List, Optional, Set
from enum import Enum
from dataclasses import dataclass, field
import logging
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""
    HIPAA = "HIPAA"
    ISO27001 = "ISO27001"
    NIST_CSF = "NIST_CSF"
    SUNAT_PERU = "SUNAT_PERU"
    LEY_29733_PERU = "LEY_29733_PERU"


class ControlStatus(Enum):
    """Status of compliance control implementation."""
    NOT_IMPLEMENTED = "not_implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    IMPLEMENTED = "implemented"
    NOT_APPLICABLE = "not_applicable"


class RiskLevel(Enum):
    """Risk level for compliance gaps."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ComplianceControl:
    """Represents a single compliance control."""
    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    category: str
    requirements: List[str]
    validation_criteria: List[str]
    status: ControlStatus = ControlStatus.NOT_IMPLEMENTED
    evidence: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.MEDIUM
    remediation_effort_hours: int = 0
    remediation_cost_usd: int = 0
    related_controls: List[str] = field(default_factory=list)


@dataclass
class ComplianceAssessment:
    """Results of a compliance assessment."""
    framework: ComplianceFramework
    assessment_date: datetime
    overall_score: float  # 0-100%
    total_controls: int
    implemented_controls: int
    partial_controls: int
    missing_controls: int
    not_applicable_controls: int
    critical_gaps: int
    high_gaps: int
    medium_gaps: int
    low_gaps: int
    controls: List[ComplianceControl]
    recommendations: List[str] = field(default_factory=list)
    estimated_remediation_hours: int = 0
    estimated_remediation_cost: int = 0
    compliance_level: str = "Non-Compliant"  # Non-Compliant, Partially Compliant, Compliant


class ComplianceEngine:
    """
    Central compliance validation engine.

    Coordinates framework-specific validators and provides unified
    assessment, gap analysis, and remediation planning.
    """

    def __init__(self):
        """Initialize compliance engine."""
        self.frameworks: Dict[ComplianceFramework, Any] = {}
        self._load_frameworks()

        logger.info("Compliance engine initialized with frameworks: " +
                   ", ".join(f.value for f in self.frameworks.keys()))

    def _load_frameworks(self) -> None:
        """Load all compliance framework validators."""
        from .frameworks.hipaa import HIPAAFramework
        from .frameworks.iso27001 import ISO27001Framework
        from .frameworks.nist_csf import NISTCSFFramework
        from .frameworks.sunat_peru import SUNATPeruFramework

        try:
            self.frameworks[ComplianceFramework.HIPAA] = HIPAAFramework()
            logger.info("Loaded HIPAA framework (45 controls)")
        except Exception as e:
            logger.error(f"Failed to load HIPAA framework: {e}")

        try:
            self.frameworks[ComplianceFramework.ISO27001] = ISO27001Framework()
            logger.info("Loaded ISO 27001 framework (93 controls)")
        except Exception as e:
            logger.error(f"Failed to load ISO 27001 framework: {e}")

        try:
            self.frameworks[ComplianceFramework.NIST_CSF] = NISTCSFFramework()
            logger.info("Loaded NIST CSF 2.0 framework (23 categories)")
        except Exception as e:
            logger.error(f"Failed to load NIST CSF framework: {e}")

        try:
            self.frameworks[ComplianceFramework.SUNAT_PERU] = SUNATPeruFramework()
            logger.info("Loaded SUNAT Peru framework")
        except Exception as e:
            logger.error(f"Failed to load SUNAT Peru framework: {e}")

    def assess_framework(
        self,
        framework: ComplianceFramework,
        environment_data: Dict[str, Any],
        sector: str = "GENERAL"
    ) -> ComplianceAssessment:
        """
        Assess compliance against a specific framework.

        Args:
            framework: Target compliance framework
            environment_data: Current environment/control data
            sector: Industry sector for context

        Returns:
            Compliance assessment results
        """
        if framework not in self.frameworks:
            raise ValueError(f"Framework {framework.value} not loaded")

        logger.info(f"Starting {framework.value} compliance assessment for {sector} sector")

        framework_validator = self.frameworks[framework]

        # Get all controls for this framework
        controls = framework_validator.get_all_controls()

        # Assess each control
        assessed_controls = []
        for control in controls:
            assessed_control = self._assess_control(
                control=control,
                environment_data=environment_data,
                sector=sector
            )
            assessed_controls.append(assessed_control)

        # Calculate overall compliance score
        assessment = self._calculate_compliance_score(
            framework=framework,
            controls=assessed_controls
        )

        logger.info(f"{framework.value} assessment complete: {assessment.overall_score:.1f}% compliant")

        return assessment

    def _assess_control(
        self,
        control: ComplianceControl,
        environment_data: Dict[str, Any],
        sector: str
    ) -> ComplianceControl:
        """
        Assess a single compliance control.

        Args:
            control: Control to assess
            environment_data: Environment configuration
            sector: Industry sector

        Returns:
            Assessed control with status and gaps
        """
        # This is a simplified assessment - in production would use:
        # 1. Automated config checks
        # 2. Log analysis
        # 3. Network scans
        # 4. AI-powered evidence collection

        # For now, check if evidence exists in environment_data
        control_key = control.control_id.lower()

        if control_key in environment_data:
            control_data = environment_data[control_key]

            if isinstance(control_data, dict):
                if control_data.get("implemented", False):
                    control.status = ControlStatus.IMPLEMENTED
                    control.evidence = control_data.get("evidence", [])
                elif control_data.get("partial", False):
                    control.status = ControlStatus.PARTIALLY_IMPLEMENTED
                    control.gaps = control_data.get("gaps", [])
                else:
                    control.status = ControlStatus.NOT_IMPLEMENTED
                    control.gaps = ["Control not implemented"]
            else:
                # Simple boolean
                control.status = ControlStatus.IMPLEMENTED if control_data else ControlStatus.NOT_IMPLEMENTED

        else:
            # No data provided, assume not implemented
            control.status = ControlStatus.NOT_IMPLEMENTED
            control.gaps = ["No evidence of implementation found"]

        return control

    def _calculate_compliance_score(
        self,
        framework: ComplianceFramework,
        controls: List[ComplianceControl]
    ) -> ComplianceAssessment:
        """
        Calculate overall compliance score from assessed controls.

        Args:
            framework: Framework being assessed
            controls: List of assessed controls

        Returns:
            Complete compliance assessment
        """
        total = len(controls)
        implemented = sum(1 for c in controls if c.status == ControlStatus.IMPLEMENTED)
        partial = sum(1 for c in controls if c.status == ControlStatus.PARTIALLY_IMPLEMENTED)
        missing = sum(1 for c in controls if c.status == ControlStatus.NOT_IMPLEMENTED)
        not_applicable = sum(1 for c in controls if c.status == ControlStatus.NOT_APPLICABLE)

        # Calculate score (partial counts as 0.5)
        applicable_controls = total - not_applicable
        if applicable_controls == 0:
            score = 100.0
        else:
            score = ((implemented + (partial * 0.5)) / applicable_controls) * 100

        # Count gap severity
        critical = sum(1 for c in controls if c.risk_level == RiskLevel.CRITICAL and c.status != ControlStatus.IMPLEMENTED)
        high = sum(1 for c in controls if c.risk_level == RiskLevel.HIGH and c.status != ControlStatus.IMPLEMENTED)
        medium = sum(1 for c in controls if c.risk_level == RiskLevel.MEDIUM and c.status != ControlStatus.IMPLEMENTED)
        low = sum(1 for c in controls if c.risk_level == RiskLevel.LOW and c.status != ControlStatus.IMPLEMENTED)

        # Determine compliance level
        if score >= 95 and critical == 0:
            compliance_level = "Compliant"
        elif score >= 70:
            compliance_level = "Partially Compliant"
        else:
            compliance_level = "Non-Compliant"

        # Calculate remediation estimates
        total_hours = sum(c.remediation_effort_hours for c in controls if c.status != ControlStatus.IMPLEMENTED)
        total_cost = sum(c.remediation_cost_usd for c in controls if c.status != ControlStatus.IMPLEMENTED)

        # Generate recommendations
        recommendations = self._generate_recommendations(controls)

        return ComplianceAssessment(
            framework=framework,
            assessment_date=datetime.now(),
            overall_score=score,
            total_controls=total,
            implemented_controls=implemented,
            partial_controls=partial,
            missing_controls=missing,
            not_applicable_controls=not_applicable,
            critical_gaps=critical,
            high_gaps=high,
            medium_gaps=medium,
            low_gaps=low,
            controls=controls,
            recommendations=recommendations,
            estimated_remediation_hours=total_hours,
            estimated_remediation_cost=total_cost,
            compliance_level=compliance_level
        )

    def _generate_recommendations(self, controls: List[ComplianceControl]) -> List[str]:
        """Generate prioritized recommendations from control gaps."""
        recommendations = []

        # Critical gaps first
        critical_controls = [c for c in controls
                           if c.status != ControlStatus.IMPLEMENTED
                           and c.risk_level == RiskLevel.CRITICAL]

        if critical_controls:
            recommendations.append(
                f"URGENT: Address {len(critical_controls)} CRITICAL gaps immediately "
                f"({', '.join(c.control_id for c in critical_controls[:3])}...)"
            )

        # High priority gaps
        high_controls = [c for c in controls
                        if c.status != ControlStatus.IMPLEMENTED
                        and c.risk_level == RiskLevel.HIGH]

        if high_controls:
            recommendations.append(
                f"HIGH PRIORITY: Implement {len(high_controls)} high-risk controls "
                f"within 30 days"
            )

        # Quick wins (low effort, high impact)
        quick_wins = [c for c in controls
                     if c.status != ControlStatus.IMPLEMENTED
                     and c.remediation_effort_hours < 8
                     and c.risk_level in [RiskLevel.HIGH, RiskLevel.MEDIUM]]

        if quick_wins:
            recommendations.append(
                f"QUICK WINS: Implement {len(quick_wins)} controls with <8 hours effort each"
            )

        return recommendations

    def assess_all_frameworks(
        self,
        environment_data: Dict[str, Any],
        sector: str = "GENERAL"
    ) -> Dict[ComplianceFramework, ComplianceAssessment]:
        """
        Assess compliance against all loaded frameworks.

        Args:
            environment_data: Current environment/control data
            sector: Industry sector

        Returns:
            Dictionary of framework -> assessment
        """
        results = {}

        for framework in self.frameworks.keys():
            try:
                assessment = self.assess_framework(
                    framework=framework,
                    environment_data=environment_data,
                    sector=sector
                )
                results[framework] = assessment
            except Exception as e:
                logger.error(f"Failed to assess {framework.value}: {e}")

        return results

    def get_framework_summary(self, framework: ComplianceFramework) -> Dict[str, Any]:
        """
        Get summary information about a framework.

        Args:
            framework: Target framework

        Returns:
            Framework summary with control counts and categories
        """
        if framework not in self.frameworks:
            raise ValueError(f"Framework {framework.value} not loaded")

        validator = self.frameworks[framework]
        controls = validator.get_all_controls()

        categories = {}
        for control in controls:
            if control.category not in categories:
                categories[control.category] = 0
            categories[control.category] += 1

        return {
            "framework": framework.value,
            "total_controls": len(controls),
            "categories": categories,
            "description": validator.get_description()
        }

    def export_assessment(
        self,
        assessment: ComplianceAssessment,
        format: str = "json"
    ) -> str:
        """
        Export assessment results.

        Args:
            assessment: Assessment to export
            format: Export format (json, csv, pdf)

        Returns:
            Exported data as string
        """
        if format == "json":
            return self._export_json(assessment)
        elif format == "csv":
            return self._export_csv(assessment)
        else:
            raise ValueError(f"Unsupported export format: {format}")

    def _export_json(self, assessment: ComplianceAssessment) -> str:
        """Export assessment as JSON."""
        data = {
            "framework": assessment.framework.value,
            "assessment_date": assessment.assessment_date.isoformat(),
            "overall_score": assessment.overall_score,
            "compliance_level": assessment.compliance_level,
            "summary": {
                "total_controls": assessment.total_controls,
                "implemented": assessment.implemented_controls,
                "partial": assessment.partial_controls,
                "missing": assessment.missing_controls,
                "not_applicable": assessment.not_applicable_controls
            },
            "gaps": {
                "critical": assessment.critical_gaps,
                "high": assessment.high_gaps,
                "medium": assessment.medium_gaps,
                "low": assessment.low_gaps
            },
            "remediation": {
                "estimated_hours": assessment.estimated_remediation_hours,
                "estimated_cost_usd": assessment.estimated_remediation_cost
            },
            "recommendations": assessment.recommendations,
            "controls": [
                {
                    "id": c.control_id,
                    "title": c.title,
                    "status": c.status.value,
                    "risk_level": c.risk_level.value,
                    "gaps": c.gaps
                }
                for c in assessment.controls
            ]
        }

        return json.dumps(data, indent=2)

    def _export_csv(self, assessment: ComplianceAssessment) -> str:
        """Export assessment as CSV."""
        lines = [
            "Control ID,Title,Category,Status,Risk Level,Gaps"
        ]

        for control in assessment.controls:
            gaps = "; ".join(control.gaps) if control.gaps else "None"
            lines.append(
                f'"{control.control_id}","{control.title}","{control.category}",'
                f'"{control.status.value}","{control.risk_level.value}","{gaps}"'
            )

        return "\n".join(lines)

    def __repr__(self) -> str:
        """String representation."""
        return f"<ComplianceEngine frameworks={len(self.frameworks)}>"
