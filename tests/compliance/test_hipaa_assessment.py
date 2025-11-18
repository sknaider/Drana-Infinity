"""
Comprehensive Tests for HIPAA Compliance Assessment Engine

Tests automated HIPAA control assessment, gap analysis, and remediation planning.
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch

from src.compliance.frameworks.hipaa import HIPAAFramework
from src.compliance.control_assessor import (
    HIPAAControlAssessor,
    ControlAssessment,
    ControlGap,
    RemediationAction,
    AssessmentStatus,
    GapSeverity,
    RemediationPriority
)
from src.compliance.gap_analyzer import HIPAAGapAnalyzer, GapAnalysisReport
from src.compliance.remediation_planner import HIPAARemediationPlanner, RemediationRoadmap
from src.compliance.compliance_engine import ComplianceControl, ComplianceFramework, RiskLevel


@pytest.fixture
def sample_control():
    """Sample HIPAA control for testing."""
    return ComplianceControl(
        control_id="HIPAA-164.308(a)(1)(i)",
        framework=ComplianceFramework.HIPAA,
        title="Risk Analysis",
        description="Conduct accurate and thorough assessment of potential risks to ePHI",
        category="Administrative Safeguards",
        requirements=[
            "Identify all systems with ePHI",
            "Document threats and vulnerabilities",
            "Assess likelihood and impact",
            "Document current security measures"
        ],
        validation_criteria=[
            "Risk assessment conducted within last 12 months",
            "All ePHI systems identified",
            "Threats catalogued",
            "Risk levels assigned"
        ],
        risk_level=RiskLevel.CRITICAL,
        remediation_effort_hours=40,
        remediation_cost_usd=8000
    )


@pytest.fixture
def sample_system_config():
    """Sample system configuration."""
    return {
        "system_name": "Medical Records Database",
        "system_type": "Electronic Health Records",
        "data_classification": "Protected Health Information (PHI)",
        "encryption": {
            "at_rest": "AES-256",
            "in_transit": "TLS 1.3"
        },
        "access_control": "RBAC with MFA",
        "audit_logging": True,
        "backup_frequency": "Daily",
        "security_controls": [
            "Firewall",
            "Anti-malware",
            "Intrusion detection",
            "Data loss prevention"
        ]
    }


@pytest.fixture
def sample_evidence():
    """Sample evidence for control validation."""
    return [
        {
            "type": "document",
            "title": "2024 Risk Assessment Report",
            "date": "2024-01-15",
            "findings": [
                "All ePHI systems identified and catalogued",
                "15 threats identified",
                "Risk levels assigned (5 critical, 7 high, 3 medium)"
            ]
        },
        {
            "type": "technical_scan",
            "tool": "vulnerability_scanner",
            "date": "2024-01-20",
            "critical_findings": 2,
            "high_findings": 5
        }
    ]


@pytest.fixture
def mock_claude_client():
    """Mock Claude client."""
    client = Mock()
    client.generate = Mock(return_value="""
    {
        "status": "passed",
        "confidence": 0.85,
        "evidence_found": [
            "Risk assessment dated 2024-01-15 found",
            "All ePHI systems documented",
            "Threat catalog exists"
        ],
        "gaps": [],
        "remediation": [],
        "reasoning": "Control requirements met based on evidence"
    }
    """)
    return client


class TestHIPAAControlAssessor:
    """Test HIPAA control assessment functionality."""

    @pytest.mark.asyncio
    async def test_assess_control_passed(self, sample_control, sample_system_config, sample_evidence, mock_claude_client):
        """Test assessing a control that passes."""
        assessor = HIPAAControlAssessor(mock_claude_client)

        result = await assessor.assess_control(
            control=sample_control,
            system_config=sample_system_config,
            evidence_provided=sample_evidence
        )

        # Verify assessment
        assert isinstance(result, ControlAssessment)
        assert result.control_id == "HIPAA-164.308(a)(1)(i)"
        assert result.status == AssessmentStatus.PASSED
        assert result.confidence_score > 0.8
        assert len(result.gaps) == 0
        assert len(result.evidence_found) > 0

    @pytest.mark.asyncio
    async def test_assess_control_failed(self, sample_control, sample_system_config, mock_claude_client):
        """Test assessing a control that fails."""
        # Mock failure response
        mock_claude_client.generate = Mock(return_value="""
        {
            "status": "failed",
            "confidence": 0.9,
            "evidence_found": [],
            "gaps": [
                {
                    "gap_id": "GAP-001",
                    "severity": "critical",
                    "description": "No risk assessment conducted in past 12 months",
                    "patient_safety_impact": false,
                    "breach_risk": true
                }
            ],
            "remediation": [
                {
                    "action": "Conduct comprehensive risk assessment",
                    "effort_hours": 40,
                    "cost_estimate": 8000,
                    "priority": "immediate"
                }
            ],
            "reasoning": "No evidence of recent risk assessment"
        }
        """)

        assessor = HIPAAControlAssessor(mock_claude_client)

        result = await assessor.assess_control(
            control=sample_control,
            system_config=sample_system_config,
            evidence_provided=[]
        )

        # Verify failure assessment
        assert result.status == AssessmentStatus.FAILED
        assert len(result.gaps) > 0
        assert result.gaps[0].severity == GapSeverity.CRITICAL
        assert len(result.remediation_actions) > 0
        assert result.remediation_actions[0].priority == RemediationPriority.IMMEDIATE

    @pytest.mark.asyncio
    async def test_assess_control_partial(self, sample_control, sample_system_config, mock_claude_client):
        """Test assessing a control that is partially compliant."""
        mock_claude_client.generate = Mock(return_value="""
        {
            "status": "partial",
            "confidence": 0.75,
            "evidence_found": [
                "Risk assessment exists but outdated (18 months old)"
            ],
            "gaps": [
                {
                    "gap_id": "GAP-002",
                    "severity": "high",
                    "description": "Risk assessment not updated within required timeframe",
                    "patient_safety_impact": false,
                    "breach_risk": true
                }
            ],
            "remediation": [
                {
                    "action": "Update risk assessment to current standards",
                    "effort_hours": 20,
                    "cost_estimate": 4000,
                    "priority": "days_30"
                }
            ],
            "reasoning": "Partial compliance - assessment exists but outdated"
        }
        """)

        assessor = HIPAAControlAssessor(mock_claude_client)

        result = await assessor.assess_control(
            control=sample_control,
            system_config=sample_system_config,
            evidence_provided=[]
        )

        assert result.status == AssessmentStatus.PARTIAL
        assert len(result.gaps) > 0
        assert result.gaps[0].severity == GapSeverity.HIGH

    @pytest.mark.asyncio
    async def test_medical_ai_specific_assessment(self, sample_control, mock_claude_client):
        """Test assessment with medical AI specific context."""
        medical_ai_context = {
            "sector": "MEDICAL_AI",
            "ai_models": [
                {
                    "model_name": "diagnostic_classifier",
                    "purpose": "chest_xray_analysis",
                    "training_data": "NIH ChestX-ray14",
                    "fda_classification": "Class II"
                }
            ],
            "gpu_infrastructure": "RTX 5090 (32GB VRAM)",
            "phi_exposure": "High - model trained on patient imaging data"
        }

        assessor = HIPAAControlAssessor(mock_claude_client)

        result = await assessor.assess_control(
            control=sample_control,
            system_config={"system_name": "Medical AI Platform"},
            evidence_provided=[],
            system_context=medical_ai_context
        )

        # Verify Claude was called with medical AI context
        assert mock_claude_client.generate.called
        call_args = mock_claude_client.generate.call_args[0][0]
        assert "Medical AI" in call_args or "RTX 5090" in call_args


class TestHIPAAGapAnalyzer:
    """Test gap analysis functionality."""

    def test_analyze_gaps_basic(self):
        """Test basic gap analysis."""
        analyzer = HIPAAGapAnalyzer()

        # Create sample assessments
        assessments = [
            ControlAssessment(
                control_id="HIPAA-164.308(a)(1)(i)",
                assessment_date=datetime.now(),
                status=AssessmentStatus.PASSED,
                confidence_score=0.9,
                gaps=[],
                remediation_actions=[],
                evidence_found=["Assessment completed"]
            ),
            ControlAssessment(
                control_id="HIPAA-164.308(a)(2)",
                assessment_date=datetime.now(),
                status=AssessmentStatus.FAILED,
                confidence_score=0.85,
                gaps=[
                    ControlGap(
                        gap_id="GAP-001",
                        control_id="HIPAA-164.308(a)(2)",
                        severity=GapSeverity.CRITICAL,
                        description="No security official assigned",
                        patient_safety_impact=False,
                        breach_risk=True
                    )
                ],
                remediation_actions=[],
                evidence_found=[]
            ),
            ControlAssessment(
                control_id="HIPAA-164.312(a)(1)",
                assessment_date=datetime.now(),
                status=AssessmentStatus.PARTIAL,
                confidence_score=0.7,
                gaps=[
                    ControlGap(
                        gap_id="GAP-002",
                        control_id="HIPAA-164.312(a)(1)",
                        severity=GapSeverity.HIGH,
                        description="MFA not enforced for all users",
                        patient_safety_impact=False,
                        breach_risk=True
                    )
                ],
                remediation_actions=[],
                evidence_found=["Partial MFA deployment"]
            )
        ]

        system_context = {"system_name": "Test System"}

        report = analyzer.analyze_gaps(assessments, system_context)

        # Verify report
        assert isinstance(report, GapAnalysisReport)
        assert report.total_controls == 3
        assert report.controls_passed == 1
        assert report.controls_failed == 1
        assert report.controls_partial == 1
        assert len(report.critical_gaps) == 1
        assert len(report.high_gaps) == 1

        # Verify compliance score calculation
        # (1 passed + 0.5 partial) / 3 = 50%
        assert 45.0 <= report.overall_compliance_score <= 55.0

    def test_get_patient_safety_gaps(self):
        """Test filtering patient safety gaps."""
        analyzer = HIPAAGapAnalyzer()

        assessments = [
            ControlAssessment(
                control_id="TEST-001",
                assessment_date=datetime.now(),
                status=AssessmentStatus.FAILED,
                confidence_score=0.9,
                gaps=[
                    ControlGap(
                        gap_id="GAP-SAFETY-001",
                        control_id="TEST-001",
                        severity=GapSeverity.CRITICAL,
                        description="Patient data encryption missing",
                        patient_safety_impact=True,
                        breach_risk=True
                    ),
                    ControlGap(
                        gap_id="GAP-002",
                        control_id="TEST-001",
                        severity=GapSeverity.MEDIUM,
                        description="Policy documentation incomplete",
                        patient_safety_impact=False,
                        breach_risk=False
                    )
                ],
                remediation_actions=[],
                evidence_found=[]
            )
        ]

        safety_gaps = analyzer.get_patient_safety_gaps(assessments)

        assert len(safety_gaps) == 1
        assert safety_gaps[0].patient_safety_impact is True

    def test_get_quick_wins(self):
        """Test identifying quick win opportunities."""
        analyzer = HIPAAGapAnalyzer()

        assessments = [
            ControlAssessment(
                control_id="QUICK-WIN",
                assessment_date=datetime.now(),
                status=AssessmentStatus.FAILED,
                confidence_score=0.9,
                gaps=[
                    ControlGap(
                        gap_id="GAP-QW-001",
                        control_id="QUICK-WIN",
                        severity=GapSeverity.CRITICAL,
                        description="Quick fix needed",
                        patient_safety_impact=False,
                        breach_risk=True
                    )
                ],
                remediation_actions=[
                    RemediationAction(
                        action_id="ACT-001",
                        gap_id="GAP-QW-001",
                        action="Enable audit logging",
                        effort_hours=4,  # Low effort
                        cost_estimate=500,
                        priority=RemediationPriority.IMMEDIATE
                    )
                ],
                evidence_found=[]
            ),
            ControlAssessment(
                control_id="LONG-PROJECT",
                assessment_date=datetime.now(),
                status=AssessmentStatus.FAILED,
                confidence_score=0.85,
                gaps=[
                    ControlGap(
                        gap_id="GAP-LP-001",
                        control_id="LONG-PROJECT",
                        severity=GapSeverity.CRITICAL,
                        description="Major overhaul needed",
                        patient_safety_impact=False,
                        breach_risk=True
                    )
                ],
                remediation_actions=[
                    RemediationAction(
                        action_id="ACT-002",
                        gap_id="GAP-LP-001",
                        action="Redesign entire auth system",
                        effort_hours=200,  # High effort
                        cost_estimate=40000,
                        priority=RemediationPriority.IMMEDIATE
                    )
                ],
                evidence_found=[]
            )
        ]

        quick_wins = analyzer.get_quick_wins(assessments, max_effort_hours=8)

        assert len(quick_wins) == 1
        assert quick_wins[0].control_id == "QUICK-WIN"


class TestHIPAARemediationPlanner:
    """Test remediation planning functionality."""

    @pytest.mark.asyncio
    async def test_generate_roadmap_with_claude(self, mock_claude_client):
        """Test roadmap generation using Claude."""
        # Mock Claude roadmap response
        mock_claude_client.generate = Mock(return_value="""
        {
            "phases": [
                {
                    "phase_number": 1,
                    "phase_name": "Critical Gaps & Immediate Actions",
                    "duration_days": 30,
                    "actions": [
                        {
                            "action_id": "action-1",
                            "description": "Implement MFA for all users",
                            "control_id": "164.312(d)",
                            "effort_hours": 40,
                            "cost": 8000,
                            "assigned_to": "IT Security Team",
                            "success_criteria": ["MFA enabled", "100% user adoption"],
                            "dependencies": []
                        }
                    ],
                    "phase_success_criteria": ["All critical gaps addressed"]
                },
                {
                    "phase_number": 2,
                    "phase_name": "High Priority Improvements",
                    "duration_days": 60,
                    "actions": [
                        {
                            "action_id": "action-2",
                            "description": "Implement comprehensive audit logging",
                            "control_id": "164.312(b)",
                            "effort_hours": 60,
                            "cost": 12000,
                            "assigned_to": "Platform Team",
                            "success_criteria": ["Logs capture all ePHI access"],
                            "dependencies": ["action-1"]
                        }
                    ],
                    "phase_success_criteria": ["High priority gaps resolved"]
                }
            ],
            "resource_requirements": {
                "full_time_staff": 2,
                "consultants": 1,
                "tools_and_software": ["MFA solution", "SIEM platform"],
                "training_needs": ["HIPAA security awareness"]
            },
            "risk_mitigation": [
                "Weekly progress reviews",
                "Executive sponsorship secured"
            ],
            "key_milestones": [
                {
                    "milestone": "MFA deployment complete",
                    "target_date_offset_days": 30,
                    "success_criteria": ["100% coverage"]
                }
            ]
        }
        """)

        planner = HIPAARemediationPlanner(mock_claude_client)

        # Create gap report
        gap_report = GapAnalysisReport(
            report_id="GAP-TEST-001",
            target_system="Test System",
            total_controls=45,
            controls_passed=30,
            controls_failed=10,
            controls_partial=5,
            controls_not_applicable=0,
            overall_compliance_score=72.2,
            critical_gaps=[],
            high_gaps=[],
            medium_gaps=[],
            low_gaps=[],
            estimated_remediation_hours=200,
            estimated_remediation_cost=40000
        )

        roadmap = await planner.generate_roadmap(
            gap_report=gap_report,
            assessments=[],
            constraints={"budget_usd": 50000, "timeline_weeks": 26}
        )

        # Verify roadmap
        assert isinstance(roadmap, RemediationRoadmap)
        assert len(roadmap.phases) == 2
        assert roadmap.phases[0].phase_number == 1
        assert roadmap.phases[0].duration_days == 30
        assert len(roadmap.phases[0].actions) > 0
        assert roadmap.total_duration_days == 90

    @pytest.mark.asyncio
    async def test_generate_basic_roadmap_fallback(self):
        """Test fallback roadmap generation without Claude."""
        planner = HIPAARemediationPlanner()

        # Create sample assessments with remediation actions
        assessments = [
            ControlAssessment(
                control_id="TEST-001",
                assessment_date=datetime.now(),
                status=AssessmentStatus.FAILED,
                confidence_score=0.9,
                gaps=[],
                remediation_actions=[
                    RemediationAction(
                        action_id="ACT-001",
                        gap_id="GAP-001",
                        action="Immediate fix",
                        effort_hours=10,
                        cost_estimate=2000,
                        priority=RemediationPriority.IMMEDIATE
                    )
                ],
                evidence_found=[]
            )
        ]

        gap_report = GapAnalysisReport(
            report_id="GAP-TEST-002",
            target_system="Test System",
            total_controls=45,
            controls_passed=30,
            controls_failed=15,
            controls_partial=0,
            controls_not_applicable=0,
            overall_compliance_score=66.7,
            critical_gaps=[],
            high_gaps=[],
            medium_gaps=[],
            low_gaps=[],
            estimated_remediation_hours=50,
            estimated_remediation_cost=10000
        )

        # This should use fallback method
        roadmap = planner._generate_basic_roadmap(
            gap_report=gap_report,
            assessments=assessments,
            constraints={}
        )

        assert isinstance(roadmap, RemediationRoadmap)
        assert len(roadmap.phases) > 0


class TestHIPAAFrameworkIntegration:
    """Test integrated HIPAA framework functionality."""

    @pytest.mark.asyncio
    async def test_full_assessment_workflow(self, mock_claude_client, sample_system_config):
        """Test complete assessment workflow."""
        framework = HIPAAFramework(claude_client=mock_claude_client)

        # Limit to first 3 controls for test speed
        framework.controls = framework.controls[:3]

        result = await framework.assess_compliance(
            system_config=sample_system_config,
            evidence={},
            system_context={"sector": "MEDICAL_AI"}
        )

        # Verify results
        assert "assessments" in result
        assert "gap_report" in result
        assert "summary" in result
        assert len(result["assessments"]) == 3
        assert isinstance(result["gap_report"], GapAnalysisReport)
        assert "compliance_score" in result["summary"]

    def test_get_controls_by_category(self):
        """Test filtering controls by category."""
        framework = HIPAAFramework()

        admin_controls = framework.get_controls_by_category("Administrative Safeguards")
        physical_controls = framework.get_controls_by_category("Physical Safeguards")
        technical_controls = framework.get_controls_by_category("Technical Safeguards")

        assert len(admin_controls) > 0
        assert len(physical_controls) > 0
        assert len(technical_controls) > 0

        # Verify they're all correct category
        assert all(c.category == "Administrative Safeguards" for c in admin_controls)

    def test_get_control_by_id(self):
        """Test retrieving specific control."""
        framework = HIPAAFramework()

        control = framework.get_control_by_id("HIPAA-164.308(a)(1)(i)")

        assert control is not None
        assert control.title == "Risk Analysis"
        assert control.risk_level == RiskLevel.CRITICAL

        # Non-existent control
        missing = framework.get_control_by_id("HIPAA-INVALID")
        assert missing is None


@pytest.mark.integration
class TestE2EHIPAAAssessment:
    """End-to-end integration tests for HIPAA assessment."""

    @pytest.mark.asyncio
    async def test_complete_assessment_and_remediation(self, mock_claude_client):
        """Test complete workflow from assessment to remediation plan."""
        # Initialize framework
        framework = HIPAAFramework(claude_client=mock_claude_client)

        # Limit controls for test
        framework.controls = framework.controls[:5]

        # System config
        system_config = {
            "system_name": "Patient Portal",
            "data_types": ["PHI", "PII"],
            "encryption": {"at_rest": "AES-256", "in_transit": "TLS 1.3"},
            "authentication": "OAuth2 + MFA"
        }

        # Step 1: Assess compliance
        assessment_result = await framework.assess_compliance(
            system_config=system_config,
            evidence={},
            system_context={"sector": "MEDICAL_AI", "deployment": "Cloud"}
        )

        gap_report = assessment_result["gap_report"]
        assessments = assessment_result["assessments"]

        # Step 2: Generate remediation plan
        constraints = {
            "budget_usd": 100000,
            "timeline_weeks": 26,
            "team_size": 3,
            "available_hours_per_week": 120
        }

        roadmap = await framework.generate_remediation_plan(
            gap_report=gap_report,
            assessments=assessments,
            constraints=constraints
        )

        # Verify complete workflow
        assert gap_report.total_controls == 5
        assert isinstance(roadmap, RemediationRoadmap)
        assert len(roadmap.phases) > 0
        assert roadmap.total_cost <= constraints["budget_usd"] * 1.2  # Allow 20% buffer


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
