"""
HIPAA Gap Analysis Engine

Analyzes compliance gaps across all assessed controls and prioritizes
remediation efforts based on risk, impact, and regulatory requirements.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime
from collections import defaultdict

from .control_assessor import (
    ControlAssessment,
    ControlGap,
    GapSeverity,
    AssessmentStatus,
    GapAnalysisReport
)

logger = logging.getLogger(__name__)


class HIPAAGapAnalyzer:
    """
    Analyzes HIPAA compliance gaps and prioritizes remediation.

    Examines all control assessments to identify:
    - Critical gaps requiring immediate action
    - High-priority gaps (30-day remediation)
    - Medium-priority gaps (90-day remediation)
    - Low-priority gaps (ongoing improvement)
    """

    def __init__(self):
        """Initialize gap analyzer."""
        logger.info("HIPAA Gap Analyzer initialized")

    def analyze_gaps(
        self,
        assessments: List[ControlAssessment],
        system_context: Dict[str, Any]
    ) -> GapAnalysisReport:
        """
        Analyze gaps across all control assessments.

        Args:
            assessments: List of control assessments
            system_context: System information

        Returns:
            Comprehensive gap analysis report
        """
        logger.info(f"Analyzing gaps across {len(assessments)} control assessments")

        # Count status distribution
        total_controls = len(assessments)
        controls_passed = sum(1 for a in assessments if a.status == AssessmentStatus.PASSED)
        controls_failed = sum(1 for a in assessments if a.status == AssessmentStatus.FAILED)
        controls_partial = sum(1 for a in assessments if a.status == AssessmentStatus.PARTIAL)
        controls_not_applicable = sum(1 for a in assessments if a.status == AssessmentStatus.NOT_APPLICABLE)

        # Calculate compliance score
        applicable_controls = total_controls - controls_not_applicable
        if applicable_controls > 0:
            # Partial counts as 0.5
            compliance_score = (
                (controls_passed + (controls_partial * 0.5)) / applicable_controls
            ) * 100
        else:
            compliance_score = 100.0

        # Collect all gaps by severity
        all_gaps = []
        for assessment in assessments:
            all_gaps.extend(assessment.gaps)

        # Categorize gaps by severity
        critical_gaps = [g for g in all_gaps if g.severity == GapSeverity.CRITICAL]
        high_gaps = [g for g in all_gaps if g.severity == GapSeverity.HIGH]
        medium_gaps = [g for g in all_gaps if g.severity == GapSeverity.MEDIUM]
        low_gaps = [g for g in all_gaps if g.severity == GapSeverity.LOW]

        # Calculate remediation estimates
        total_hours = 0
        total_cost = 0

        for assessment in assessments:
            for action in assessment.remediation_actions:
                total_hours += action.effort_hours
                total_cost += action.cost_estimate

        # Build report
        report = GapAnalysisReport(
            report_id=f"GAP-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            target_system=system_context.get("system_name", "Unknown"),
            total_controls=total_controls,
            controls_passed=controls_passed,
            controls_failed=controls_failed,
            controls_partial=controls_partial,
            controls_not_applicable=controls_not_applicable,
            overall_compliance_score=compliance_score,
            critical_gaps=critical_gaps,
            high_gaps=high_gaps,
            medium_gaps=medium_gaps,
            low_gaps=low_gaps,
            estimated_remediation_hours=total_hours,
            estimated_remediation_cost=total_cost
        )

        # Log summary
        logger.info(
            f"Gap analysis complete: {compliance_score:.1f}% compliant, "
            f"{len(critical_gaps)} critical gaps, "
            f"{len(high_gaps)} high gaps, "
            f"{len(medium_gaps)} medium gaps, "
            f"{len(low_gaps)} low gaps"
        )

        return report

    def get_patient_safety_gaps(
        self,
        assessments: List[ControlAssessment]
    ) -> List[ControlGap]:
        """
        Get all gaps that impact patient safety.

        Args:
            assessments: List of control assessments

        Returns:
            Gaps with patient safety impact
        """
        patient_safety_gaps = []

        for assessment in assessments:
            for gap in assessment.gaps:
                if gap.patient_safety_impact:
                    patient_safety_gaps.append(gap)

        logger.info(f"Found {len(patient_safety_gaps)} patient safety gaps")
        return patient_safety_gaps

    def get_breach_risk_gaps(
        self,
        assessments: List[ControlAssessment]
    ) -> List[ControlGap]:
        """
        Get all gaps that present breach risk.

        Args:
            assessments: List of control assessments

        Returns:
            Gaps with breach risk
        """
        breach_gaps = []

        for assessment in assessments:
            for gap in assessment.gaps:
                if gap.breach_risk:
                    breach_gaps.append(gap)

        logger.info(f"Found {len(breach_gaps)} breach risk gaps")
        return breach_gaps

    def get_gaps_by_category(
        self,
        assessments: List[ControlAssessment]
    ) -> Dict[str, List[ControlGap]]:
        """
        Group gaps by HIPAA safeguard category.

        Args:
            assessments: List of control assessments

        Returns:
            Dictionary of category -> gaps
        """
        gaps_by_category = defaultdict(list)

        for assessment in assessments:
            # Determine category from control ID
            control_id = assessment.control_id

            if "164.308" in control_id:
                category = "Administrative Safeguards"
            elif "164.310" in control_id:
                category = "Physical Safeguards"
            elif "164.312" in control_id:
                category = "Technical Safeguards"
            elif "164.314" in control_id:
                category = "Organizational Requirements"
            elif "164.316" in control_id:
                category = "Policies and Procedures"
            else:
                category = "Unknown"

            for gap in assessment.gaps:
                gaps_by_category[category].append(gap)

        return dict(gaps_by_category)

    def get_quick_wins(
        self,
        assessments: List[ControlAssessment],
        max_effort_hours: int = 8
    ) -> List[ControlAssessment]:
        """
        Identify "quick wins" - high-impact, low-effort fixes.

        Args:
            assessments: List of control assessments
            max_effort_hours: Maximum effort hours to qualify as quick win

        Returns:
            Assessments with quick win opportunities
        """
        quick_wins = []

        for assessment in assessments:
            if assessment.status in [AssessmentStatus.FAILED, AssessmentStatus.PARTIAL]:
                # Check if any remediation actions are low effort
                has_quick_win = any(
                    action.effort_hours <= max_effort_hours
                    for action in assessment.remediation_actions
                )

                # Check if it's high or critical severity
                has_high_impact = any(
                    gap.severity in [GapSeverity.CRITICAL, GapSeverity.HIGH]
                    for gap in assessment.gaps
                )

                if has_quick_win and has_high_impact:
                    quick_wins.append(assessment)

        logger.info(f"Found {len(quick_wins)} quick win opportunities")
        return quick_wins
