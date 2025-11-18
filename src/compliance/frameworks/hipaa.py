"""
HIPAA Security Rule Framework

Implements the 45 security controls from HIPAA Security Rule:
- Administrative Safeguards (9 standards)
- Physical Safeguards (4 standards)
- Technical Safeguards (5 standards)
- Organizational Requirements (2 standards)
- Policies and Procedures (1 standard)

Reference: 45 CFR Parts 160, 162, and 164 (Security Rule)
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from ..compliance_engine import (
    ComplianceControl,
    ComplianceFramework,
    ControlStatus,
    RiskLevel
)
from ..control_assessor import HIPAAControlAssessor, ControlAssessment
from ..gap_analyzer import HIPAAGapAnalyzer, GapAnalysisReport
from ..remediation_planner import HIPAARemediationPlanner, RemediationRoadmap
from ...integrations.claude_client import ClaudeClient

logger = logging.getLogger(__name__)


class HIPAAFramework:
    """HIPAA Security Rule compliance framework with automated assessment."""

    def __init__(self, claude_client: Optional[ClaudeClient] = None):
        """
        Initialize HIPAA framework with all 45 controls.

        Args:
            claude_client: Optional Claude client for automated assessment
        """
        self.controls = self._define_controls()
        self.assessor = HIPAAControlAssessor(claude_client) if claude_client else None
        self.gap_analyzer = HIPAAGapAnalyzer()
        self.remediation_planner = HIPAARemediationPlanner(claude_client) if claude_client else None

    def get_description(self) -> str:
        """Get framework description."""
        return "HIPAA Security Rule - Healthcare data protection and privacy controls (45 CFR Parts 160, 162, and 164)"

    def get_all_controls(self) -> List[ComplianceControl]:
        """Get all HIPAA controls."""
        return self.controls

    async def assess_compliance(
        self,
        system_config: Dict[str, Any],
        evidence: Optional[Dict[str, List[Dict[str, Any]]]] = None,
        system_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform automated HIPAA compliance assessment.

        Args:
            system_config: System configuration details
            evidence: Evidence organized by control ID
            system_context: Additional system context

        Returns:
            Comprehensive assessment results
        """
        if not self.assessor:
            raise ValueError("Claude client required for automated assessment")

        logger.info("Starting automated HIPAA compliance assessment")

        # Assess all controls
        assessments = []
        evidence = evidence or {}

        for control in self.controls:
            control_evidence = evidence.get(control.control_id, [])

            try:
                assessment = await self.assessor.assess_control(
                    control=control,
                    system_config=system_config,
                    evidence_provided=control_evidence,
                    system_context=system_context
                )
                assessments.append(assessment)

            except Exception as e:
                logger.error(f"Failed to assess {control.control_id}: {e}")
                continue

        # Analyze gaps
        gap_report = self.gap_analyzer.analyze_gaps(
            assessments=assessments,
            system_context=system_context or {}
        )

        logger.info(
            f"Assessment complete: {gap_report.overall_compliance_score:.1f}% compliant, "
            f"{len(gap_report.critical_gaps)} critical gaps"
        )

        return {
            "assessments": assessments,
            "gap_report": gap_report,
            "summary": {
                "total_controls": gap_report.total_controls,
                "compliance_score": gap_report.overall_compliance_score,
                "critical_gaps": len(gap_report.critical_gaps),
                "high_gaps": len(gap_report.high_gaps),
                "medium_gaps": len(gap_report.medium_gaps),
                "low_gaps": len(gap_report.low_gaps)
            }
        }

    async def generate_remediation_plan(
        self,
        gap_report: GapAnalysisReport,
        assessments: List[ControlAssessment],
        constraints: Optional[Dict[str, Any]] = None
    ) -> RemediationRoadmap:
        """
        Generate phased remediation roadmap.

        Args:
            gap_report: Gap analysis report
            assessments: Control assessments
            constraints: Budget, timeline, resource constraints

        Returns:
            Remediation roadmap
        """
        if not self.remediation_planner:
            raise ValueError("Claude client required for remediation planning")

        return await self.remediation_planner.generate_roadmap(
            gap_report=gap_report,
            assessments=assessments,
            constraints=constraints
        )

    def get_controls_by_category(self, category: str) -> List[ComplianceControl]:
        """Get controls by category."""
        return [c for c in self.controls if c.category == category]

    def get_control_by_id(self, control_id: str) -> Optional[ComplianceControl]:
        """Get specific control by ID."""
        for control in self.controls:
            if control.control_id == control_id:
                return control
        return None

    def _define_controls(self) -> List[ComplianceControl]:
        """Define all HIPAA Security Rule controls."""
        controls = []

        # === ADMINISTRATIVE SAFEGUARDS (164.308) ===

        # Security Management Process (164.308(a)(1))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.308(a)(1)(i)",
                framework=ComplianceFramework.HIPAA,
                title="Risk Analysis",
                description="Conduct an accurate and thorough assessment of potential risks and vulnerabilities to ePHI",
                category="Administrative Safeguards",
                requirements=[
                    "Identify all systems that create, receive, maintain, or transmit ePHI",
                    "Document potential threats and vulnerabilities",
                    "Assess likelihood and impact of threats",
                    "Document current security measures"
                ],
                validation_criteria=[
                    "Risk assessment conducted within last 12 months",
                    "All ePHI systems identified and documented",
                    "Threats and vulnerabilities catalogued",
                    "Risk levels assigned to each threat"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(1)(ii)(A)",
                framework=ComplianceFramework.HIPAA,
                title="Risk Management",
                description="Implement security measures to reduce risks and vulnerabilities to a reasonable and appropriate level",
                category="Administrative Safeguards",
                requirements=[
                    "Implement controls to mitigate identified risks",
                    "Prioritize high-risk vulnerabilities",
                    "Document risk mitigation decisions",
                    "Establish acceptable risk threshold"
                ],
                validation_criteria=[
                    "Risk mitigation plan documented",
                    "High and critical risks addressed",
                    "Residual risks accepted by management",
                    "Controls implemented and tested"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=80,
                remediation_cost_usd=15000
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(1)(ii)(B)",
                framework=ComplianceFramework.HIPAA,
                title="Sanction Policy",
                description="Apply appropriate sanctions against workforce members who fail to comply with security policies",
                category="Administrative Safeguards",
                requirements=[
                    "Documented sanctions policy",
                    "Progressive discipline procedures",
                    "Enforcement mechanisms",
                    "Documentation of sanctions applied"
                ],
                validation_criteria=[
                    "Written sanction policy exists",
                    "Policy communicated to workforce",
                    "Evidence of policy enforcement",
                    "Sanctions documented in personnel files"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=8,
                remediation_cost_usd=1500
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(1)(ii)(C)",
                framework=ComplianceFramework.HIPAA,
                title="Information System Activity Review",
                description="Implement procedures to regularly review records of information system activity",
                category="Administrative Safeguards",
                requirements=[
                    "Audit logs enabled for all ePHI systems",
                    "Regular review of audit logs",
                    "Incident detection procedures",
                    "Review frequency documented"
                ],
                validation_criteria=[
                    "Audit logging enabled",
                    "Logs reviewed at least monthly",
                    "Anomalies investigated and documented",
                    "Automated alerting configured"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=24,
                remediation_cost_usd=5000
            )
        ])

        # Assigned Security Responsibility (164.308(a)(2))
        controls.append(
            ComplianceControl(
                control_id="HIPAA-164.308(a)(2)",
                framework=ComplianceFramework.HIPAA,
                title="Assigned Security Responsibility",
                description="Identify security official responsible for developing and implementing security policies",
                category="Administrative Safeguards",
                requirements=[
                    "Designated Security Official identified",
                    "Responsibilities documented",
                    "Authority granted to implement controls",
                    "Reporting structure established"
                ],
                validation_criteria=[
                    "Security Official formally appointed",
                    "Job description includes security duties",
                    "Official has necessary authority and resources",
                    "Reports to senior management"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=4,
                remediation_cost_usd=500
            )
        )

        # Workforce Security (164.308(a)(3))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.308(a)(3)(i)",
                framework=ComplianceFramework.HIPAA,
                title="Workforce Authorization and Supervision",
                description="Implement procedures for authorization and supervision of workforce members accessing ePHI",
                category="Administrative Safeguards",
                requirements=[
                    "Access authorization procedures",
                    "Least privilege principle applied",
                    "Supervision of workforce with ePHI access",
                    "Access approval documentation"
                ],
                validation_criteria=[
                    "Access request/approval process documented",
                    "Access limited to minimum necessary",
                    "Supervisory review of access",
                    "Access decisions documented"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(3)(ii)(A)",
                framework=ComplianceFramework.HIPAA,
                title="Workforce Clearance Procedure",
                description="Implement procedures to determine appropriate access to ePHI for workforce members",
                category="Administrative Safeguards",
                requirements=[
                    "Background check procedures",
                    "Access clearance levels defined",
                    "Screening appropriate to access level",
                    "Clearance documented"
                ],
                validation_criteria=[
                    "Background check policy exists",
                    "Checks completed for all workforce members",
                    "Results documented and retained",
                    "Access granted based on clearance"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=12,
                remediation_cost_usd=2500,
                related_controls=["HIPAA-164.308(a)(3)(i)"]
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(3)(ii)(B)",
                framework=ComplianceFramework.HIPAA,
                title="Termination Procedures",
                description="Implement procedures for terminating access to ePHI when employment ends",
                category="Administrative Safeguards",
                requirements=[
                    "Access termination procedures",
                    "Immediate revocation upon termination",
                    "Return of access credentials and devices",
                    "Exit interview addressing confidentiality"
                ],
                validation_criteria=[
                    "Termination checklist exists",
                    "Access revoked same day as termination",
                    "Physical access cards/keys returned",
                    "Exit process documented"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=8,
                remediation_cost_usd=1500
            )
        ])

        # Information Access Management (164.308(a)(4))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.308(a)(4)(i)",
                framework=ComplianceFramework.HIPAA,
                title="Access Authorization",
                description="Implement policies and procedures for authorizing access to ePHI",
                category="Administrative Safeguards",
                requirements=[
                    "Access authorization policies",
                    "Role-based access control (RBAC)",
                    "Minimum necessary access",
                    "Access review procedures"
                ],
                validation_criteria=[
                    "Access policies documented",
                    "Roles and permissions defined",
                    "Access reviews conducted quarterly",
                    "Excessive access removed"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(4)(ii)(B)",
                framework=ComplianceFramework.HIPAA,
                title="Access Establishment and Modification",
                description="Implement procedures for granting, modifying, and removing access to ePHI",
                category="Administrative Safeguards",
                requirements=[
                    "Access provisioning procedures",
                    "Access modification procedures",
                    "Access removal procedures",
                    "Change logging and approval"
                ],
                validation_criteria=[
                    "Provisioning process documented",
                    "All changes approved and logged",
                    "Timely removal of unnecessary access",
                    "Audit trail of access changes"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            )
        ])

        # Security Awareness and Training (164.308(a)(5))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.308(a)(5)(i)",
                framework=ComplianceFramework.HIPAA,
                title="Security Awareness and Training",
                description="Implement security awareness and training program for all workforce members",
                category="Administrative Safeguards",
                requirements=[
                    "Annual security training",
                    "Training for new employees within 30 days",
                    "Training on HIPAA policies",
                    "Training documentation"
                ],
                validation_criteria=[
                    "Training program established",
                    "All workforce trained annually",
                    "Training completion documented",
                    "Training content includes HIPAA basics"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=24,
                remediation_cost_usd=4000
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(5)(ii)(A)",
                framework=ComplianceFramework.HIPAA,
                title="Security Reminders",
                description="Implement periodic security updates and reminders",
                category="Administrative Safeguards",
                requirements=[
                    "Regular security communications",
                    "Threat awareness updates",
                    "Policy reminder notifications",
                    "Communication frequency documented"
                ],
                validation_criteria=[
                    "Security reminders sent quarterly",
                    "Topics include current threats",
                    "Communication tracked",
                    "Engagement metrics monitored"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=8,
                remediation_cost_usd=1000
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(5)(ii)(B)",
                framework=ComplianceFramework.HIPAA,
                title="Protection from Malicious Software",
                description="Implement procedures for guarding against, detecting, and reporting malicious software",
                category="Administrative Safeguards",
                requirements=[
                    "Anti-malware software deployed",
                    "Regular signature updates",
                    "Malware incident response procedures",
                    "User training on malware threats"
                ],
                validation_criteria=[
                    "Anti-malware on all systems",
                    "Definitions updated daily",
                    "Incident response plan exists",
                    "Users trained on phishing/malware"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(5)(ii)(C)",
                framework=ComplianceFramework.HIPAA,
                title="Log-in Monitoring",
                description="Implement procedures for monitoring log-in attempts and reporting discrepancies",
                category="Administrative Safeguards",
                requirements=[
                    "Failed login monitoring",
                    "Account lockout after failed attempts",
                    "Suspicious activity alerting",
                    "Log review procedures"
                ],
                validation_criteria=[
                    "Login monitoring enabled",
                    "Account lockout configured (5-10 attempts)",
                    "Alerts generated for anomalies",
                    "Logs reviewed regularly"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=12,
                remediation_cost_usd=2000
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(5)(ii)(D)",
                framework=ComplianceFramework.HIPAA,
                title="Password Management",
                description="Implement procedures for creating, changing, and safeguarding passwords",
                category="Administrative Safeguards",
                requirements=[
                    "Password complexity requirements",
                    "Password expiration policy",
                    "Password history requirements",
                    "Secure password storage"
                ],
                validation_criteria=[
                    "Minimum 12 character passwords",
                    "Passwords expire every 90 days",
                    "Last 12 passwords cannot be reused",
                    "Passwords hashed and salted"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=8,
                remediation_cost_usd=1500
            )
        ])

        # Security Incident Procedures (164.308(a)(6))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.308(a)(6)(i)",
                framework=ComplianceFramework.HIPAA,
                title="Security Incident Response and Reporting",
                description="Implement procedures to identify, respond to, and report security incidents",
                category="Administrative Safeguards",
                requirements=[
                    "Incident response plan",
                    "Incident classification procedures",
                    "Incident response team",
                    "Incident reporting procedures"
                ],
                validation_criteria=[
                    "Incident response plan documented",
                    "Response team identified and trained",
                    "Incidents classified by severity",
                    "All incidents documented and reviewed"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(6)(ii)",
                framework=ComplianceFramework.HIPAA,
                title="Breach Notification",
                description="Implement procedures to notify affected individuals and authorities of breaches",
                category="Administrative Safeguards",
                requirements=[
                    "Breach assessment procedures",
                    "Notification timelines (60 days)",
                    "HHS breach reporting process",
                    "Individual notification procedures"
                ],
                validation_criteria=[
                    "Breach assessment process documented",
                    "Notification templates prepared",
                    "Timelines met for all breaches",
                    "Breach log maintained"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=24,
                remediation_cost_usd=5000
            )
        ])

        # Contingency Plan (164.308(a)(7))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.308(a)(7)(i)",
                framework=ComplianceFramework.HIPAA,
                title="Contingency Plan",
                description="Establish procedures for responding to emergencies or system failures",
                category="Administrative Safeguards",
                requirements=[
                    "Data backup plan",
                    "Disaster recovery plan",
                    "Emergency mode operation plan",
                    "Testing and revision procedures"
                ],
                validation_criteria=[
                    "Contingency plan documented",
                    "Plan tested annually",
                    "Backup and recovery procedures defined",
                    "Plan updated after tests"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(7)(ii)(A)",
                framework=ComplianceFramework.HIPAA,
                title="Data Backup Plan",
                description="Establish and implement procedures to create and maintain retrievable exact copies of ePHI",
                category="Administrative Safeguards",
                requirements=[
                    "Automated daily backups",
                    "Offsite backup storage",
                    "Backup encryption",
                    "Backup testing procedures"
                ],
                validation_criteria=[
                    "Backups run daily",
                    "Backups stored offsite/cloud",
                    "Backups encrypted in transit and at rest",
                    "Restore tested quarterly"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=24,
                remediation_cost_usd=5000
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(7)(ii)(B)",
                framework=ComplianceFramework.HIPAA,
                title="Disaster Recovery Plan",
                description="Establish procedures to restore lost data",
                category="Administrative Safeguards",
                requirements=[
                    "Recovery procedures documented",
                    "Recovery time objectives (RTO)",
                    "Recovery point objectives (RPO)",
                    "Disaster scenarios identified"
                ],
                validation_criteria=[
                    "Disaster recovery plan exists",
                    "RTO < 4 hours for critical systems",
                    "RPO < 1 hour for ePHI",
                    "Plan tested annually"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            ),
            ComplianceControl(
                control_id="HIPAA-164.308(a)(7)(ii)(C)",
                framework=ComplianceFramework.HIPAA,
                title="Emergency Mode Operation Plan",
                description="Establish procedures to enable continuation of critical business processes while operating in emergency mode",
                category="Administrative Safeguards",
                requirements=[
                    "Critical functions identified",
                    "Emergency procedures documented",
                    "Alternate processing site",
                    "Emergency mode testing"
                ],
                validation_criteria=[
                    "Critical functions prioritized",
                    "Emergency procedures documented",
                    "Failover capabilities exist",
                    "Emergency mode tested annually"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=24,
                remediation_cost_usd=4000
            )
        ])

        # Evaluation (164.308(a)(8))
        controls.append(
            ComplianceControl(
                control_id="HIPAA-164.308(a)(8)",
                framework=ComplianceFramework.HIPAA,
                title="Evaluation",
                description="Perform periodic technical and non-technical evaluation of security controls",
                category="Administrative Safeguards",
                requirements=[
                    "Annual security evaluation",
                    "Evaluation of technical safeguards",
                    "Evaluation of policies and procedures",
                    "Gap remediation plan"
                ],
                validation_criteria=[
                    "Evaluation conducted annually",
                    "All safeguards assessed",
                    "Gaps identified and prioritized",
                    "Remediation plan with timelines"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            )
        )

        # === PHYSICAL SAFEGUARDS (164.310) ===

        # Facility Access Controls (164.310(a)(1))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.310(a)(1)",
                framework=ComplianceFramework.HIPAA,
                title="Facility Access Controls",
                description="Implement policies and procedures to limit physical access to electronic information systems and facilities",
                category="Physical Safeguards",
                requirements=[
                    "Physical access controls",
                    "Visitor logs",
                    "Access authorization",
                    "Facility security procedures"
                ],
                validation_criteria=[
                    "Access control systems deployed",
                    "Visitors logged and escorted",
                    "Access limited to authorized personnel",
                    "Security procedures documented"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=32,
                remediation_cost_usd=10000
            ),
            ComplianceControl(
                control_id="HIPAA-164.310(a)(2)(ii)",
                framework=ComplianceFramework.HIPAA,
                title="Facility Security Plan",
                description="Implement policies and procedures to safeguard facilities from unauthorized physical access",
                category="Physical Safeguards",
                requirements=[
                    "Facility security plan",
                    "Physical barriers",
                    "Surveillance systems",
                    "Security personnel procedures"
                ],
                validation_criteria=[
                    "Security plan documented",
                    "Locked doors, badge access",
                    "CCTV monitoring critical areas",
                    "Security guard procedures defined"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=24,
                remediation_cost_usd=8000
            ),
            ComplianceControl(
                control_id="HIPAA-164.310(a)(2)(iii)",
                framework=ComplianceFramework.HIPAA,
                title="Access Control and Validation Procedures",
                description="Implement procedures to control and validate physical access to facilities",
                category="Physical Safeguards",
                requirements=[
                    "Access validation procedures",
                    "Badge/key card systems",
                    "Access log review",
                    "Visitor management"
                ],
                validation_criteria=[
                    "Electronic access control system",
                    "Access logs reviewed monthly",
                    "Visitor sign-in required",
                    "Tailgating prevention measures"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=16,
                remediation_cost_usd=5000
            ),
            ComplianceControl(
                control_id="HIPAA-164.310(a)(2)(iv)",
                framework=ComplianceFramework.HIPAA,
                title="Maintenance Records",
                description="Implement procedures to document facility repairs and modifications",
                category="Physical Safeguards",
                requirements=[
                    "Maintenance documentation",
                    "Visitor logs for maintenance personnel",
                    "Escort procedures",
                    "Security review after maintenance"
                ],
                validation_criteria=[
                    "Maintenance logged",
                    "Contractors escorted",
                    "Work reviewed by security",
                    "Access revoked after work complete"
                ],
                risk_level=RiskLevel.LOW,
                remediation_effort_hours=8,
                remediation_cost_usd=1000
            )
        ])

        # Workstation Use and Security (164.310(b), (c))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.310(b)",
                framework=ComplianceFramework.HIPAA,
                title="Workstation Use",
                description="Implement policies specifying proper functions and physical attributes of workstations",
                category="Physical Safeguards",
                requirements=[
                    "Workstation use policies",
                    "Physical positioning guidelines",
                    "Screen privacy filters",
                    "Acceptable use training"
                ],
                validation_criteria=[
                    "Workstation policy documented",
                    "Screens positioned away from public view",
                    "Privacy filters on public-facing workstations",
                    "Users trained on proper use"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=12,
                remediation_cost_usd=2000
            ),
            ComplianceControl(
                control_id="HIPAA-164.310(c)",
                framework=ComplianceFramework.HIPAA,
                title="Workstation Security",
                description="Implement physical safeguards for workstations accessing ePHI",
                category="Physical Safeguards",
                requirements=[
                    "Workstation security controls",
                    "Auto-lock after inactivity",
                    "Cable locks for laptops",
                    "Clean desk policy"
                ],
                validation_criteria=[
                    "Auto-lock after 5 minutes",
                    "Laptops secured with cable locks",
                    "Clean desk policy enforced",
                    "Physical security controls deployed"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            )
        ])

        # Device and Media Controls (164.310(d)(1))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.310(d)(1)",
                framework=ComplianceFramework.HIPAA,
                title="Device and Media Controls",
                description="Implement policies and procedures governing receipt and removal of hardware and electronic media",
                category="Physical Safeguards",
                requirements=[
                    "Media handling procedures",
                    "Disposal and destruction procedures",
                    "Media reuse procedures",
                    "Accountability and tracking"
                ],
                validation_criteria=[
                    "Media handling policy documented",
                    "Secure disposal process (shred/degauss)",
                    "Media sanitization before reuse",
                    "Media inventory and tracking"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            ),
            ComplianceControl(
                control_id="HIPAA-164.310(d)(2)(i)",
                framework=ComplianceFramework.HIPAA,
                title="Disposal",
                description="Implement policies for final disposition of ePHI and hardware/media",
                category="Physical Safeguards",
                requirements=[
                    "Secure disposal procedures",
                    "Data destruction methods",
                    "Certificate of destruction",
                    "Vendor agreements for disposal"
                ],
                validation_criteria=[
                    "Disposal policy documented",
                    "Physical destruction or cryptographic erasure",
                    "Destruction certificates retained",
                    "Vendor contracts include data destruction"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=12,
                remediation_cost_usd=2000
            ),
            ComplianceControl(
                control_id="HIPAA-164.310(d)(2)(ii)",
                framework=ComplianceFramework.HIPAA,
                title="Media Re-use",
                description="Implement procedures for removal of ePHI before media reuse",
                category="Physical Safeguards",
                requirements=[
                    "Media sanitization procedures",
                    "Data wiping tools",
                    "Verification of data removal",
                    "Documentation of sanitization"
                ],
                validation_criteria=[
                    "Sanitization process documented",
                    "DOD 5220.22-M or similar standard used",
                    "Sanitization verified and logged",
                    "Media tracking includes sanitization status"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=12,
                remediation_cost_usd=2000
            )
        ])

        # === TECHNICAL SAFEGUARDS (164.312) ===

        # Access Control (164.312(a)(1))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.312(a)(1)",
                framework=ComplianceFramework.HIPAA,
                title="Access Control",
                description="Implement technical policies and procedures to allow only authorized access to ePHI",
                category="Technical Safeguards",
                requirements=[
                    "Unique user identification",
                    "Emergency access procedures",
                    "Automatic logoff",
                    "Encryption and decryption"
                ],
                validation_criteria=[
                    "Each user has unique ID",
                    "Emergency access documented",
                    "Auto-logoff after inactivity",
                    "Encryption deployed for ePHI"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(a)(2)(i)",
                framework=ComplianceFramework.HIPAA,
                title="Unique User Identification",
                description="Assign unique name/number for identifying and tracking user identity",
                category="Technical Safeguards",
                requirements=[
                    "Unique user IDs",
                    "No shared accounts",
                    "Service account management",
                    "User ID standards"
                ],
                validation_criteria=[
                    "All users have unique IDs",
                    "Shared accounts prohibited",
                    "Service accounts documented and controlled",
                    "User ID naming convention enforced"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(a)(2)(ii)",
                framework=ComplianceFramework.HIPAA,
                title="Emergency Access Procedure",
                description="Establish procedures for obtaining necessary ePHI during emergency",
                category="Technical Safeguards",
                requirements=[
                    "Break-glass procedures",
                    "Emergency account management",
                    "Monitoring of emergency access",
                    "Post-emergency review"
                ],
                validation_criteria=[
                    "Emergency access procedures documented",
                    "Break-glass accounts exist and controlled",
                    "Emergency access logged and alerted",
                    "Usage reviewed after emergencies"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(a)(2)(iii)",
                framework=ComplianceFramework.HIPAA,
                title="Automatic Logoff",
                description="Implement electronic procedures that terminate session after predetermined inactivity",
                category="Technical Safeguards",
                requirements=[
                    "Session timeout configuration",
                    "Workstation auto-lock",
                    "Application timeouts",
                    "Timeout standards documented"
                ],
                validation_criteria=[
                    "Sessions timeout after 15 minutes",
                    "Workstations lock after 5 minutes",
                    "Timeouts enforced across all systems",
                    "Timeout settings documented"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=8,
                remediation_cost_usd=1500
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(a)(2)(iv)",
                framework=ComplianceFramework.HIPAA,
                title="Encryption and Decryption",
                description="Implement mechanism to encrypt and decrypt ePHI",
                category="Technical Safeguards",
                requirements=[
                    "Encryption at rest",
                    "Encryption in transit",
                    "Strong encryption algorithms (AES-256)",
                    "Key management procedures"
                ],
                validation_criteria=[
                    "All ePHI encrypted at rest",
                    "TLS 1.2+ for data in transit",
                    "AES-256 or equivalent used",
                    "Encryption keys managed securely"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            )
        ])

        # Audit Controls (164.312(b))
        controls.append(
            ComplianceControl(
                control_id="HIPAA-164.312(b)",
                framework=ComplianceFramework.HIPAA,
                title="Audit Controls",
                description="Implement hardware, software, and procedural mechanisms to record and examine access and activity in systems with ePHI",
                category="Technical Safeguards",
                requirements=[
                    "Comprehensive audit logging",
                    "Log protection",
                    "Log retention (6 years minimum)",
                    "Log review procedures"
                ],
                validation_criteria=[
                    "All ePHI access logged",
                    "Logs protected from tampering",
                    "Logs retained for 6+ years",
                    "Logs reviewed monthly"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=24,
                remediation_cost_usd=5000
            )
        )

        # Integrity Controls (164.312(c)(1))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.312(c)(1)",
                framework=ComplianceFramework.HIPAA,
                title="Integrity Controls",
                description="Implement policies and procedures to protect ePHI from improper alteration or destruction",
                category="Technical Safeguards",
                requirements=[
                    "Data integrity verification",
                    "Change detection mechanisms",
                    "Version control",
                    "Checksums/digital signatures"
                ],
                validation_criteria=[
                    "Integrity checks implemented",
                    "Unauthorized changes detected",
                    "Version history maintained",
                    "Digital signatures used where appropriate"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=24,
                remediation_cost_usd=4000
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(c)(2)",
                framework=ComplianceFramework.HIPAA,
                title="Mechanism to Authenticate ePHI",
                description="Implement electronic mechanisms to corroborate that ePHI has not been altered or destroyed",
                category="Technical Safeguards",
                requirements=[
                    "Cryptographic hash functions",
                    "Digital signatures",
                    "Audit trails for modifications",
                    "Integrity verification procedures"
                ],
                validation_criteria=[
                    "Hash functions or digital signatures used",
                    "Modifications logged with user/timestamp",
                    "Integrity verified regularly",
                    "Tampering alerts configured"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            )
        ])

        # Person or Entity Authentication (164.312(d))
        controls.append(
            ComplianceControl(
                control_id="HIPAA-164.312(d)",
                framework=ComplianceFramework.HIPAA,
                title="Person or Entity Authentication",
                description="Implement procedures to verify that person or entity seeking access to ePHI is the one claimed",
                category="Technical Safeguards",
                requirements=[
                    "Multi-factor authentication",
                    "Strong authentication mechanisms",
                    "Authentication for system-to-system access",
                    "Biometric authentication (optional)"
                ],
                validation_criteria=[
                    "MFA required for remote access",
                    "MFA required for privileged access",
                    "Service accounts use certificates/keys",
                    "Authentication strength documented"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            )
        )

        # Transmission Security (164.312(e)(1))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.312(e)(1)",
                framework=ComplianceFramework.HIPAA,
                title="Transmission Security",
                description="Implement technical security measures to guard against unauthorized access to ePHI transmitted over networks",
                category="Technical Safeguards",
                requirements=[
                    "Encryption in transit",
                    "Network segmentation",
                    "VPN for remote access",
                    "Secure email for ePHI"
                ],
                validation_criteria=[
                    "TLS 1.2+ for all ePHI transmission",
                    "ePHI networks segmented",
                    "VPN required for remote access",
                    "Secure email (encrypted) used for ePHI"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(e)(2)(i)",
                framework=ComplianceFramework.HIPAA,
                title="Integrity Controls for Transmission",
                description="Implement security measures to ensure ePHI is not improperly modified during transmission",
                category="Technical Safeguards",
                requirements=[
                    "Message authentication codes",
                    "Digital signatures for transmitted data",
                    "Checksums for file transfers",
                    "Transmission error detection"
                ],
                validation_criteria=[
                    "TLS provides integrity via MAC",
                    "File transfers verified with checksums",
                    "Transmission errors detected",
                    "Corrupted transmissions rejected"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            ),
            ComplianceControl(
                control_id="HIPAA-164.312(e)(2)(ii)",
                framework=ComplianceFramework.HIPAA,
                title="Encryption for Transmission",
                description="Implement mechanism to encrypt ePHI during transmission",
                category="Technical Safeguards",
                requirements=[
                    "End-to-end encryption",
                    "Strong cipher suites",
                    "Certificate validation",
                    "No transmission of ePHI over unencrypted channels"
                ],
                validation_criteria=[
                    "All ePHI encrypted in transit",
                    "Strong ciphers configured (AES-256)",
                    "Certificates validated",
                    "Weak protocols disabled (SSL, TLS <1.2)"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=24,
                remediation_cost_usd=4000
            )
        ])

        # === ORGANIZATIONAL REQUIREMENTS (164.314) ===

        # Business Associate Contracts (164.314(a))
        controls.append(
            ComplianceControl(
                control_id="HIPAA-164.314(a)(1)",
                framework=ComplianceFramework.HIPAA,
                title="Business Associate Contracts",
                description="Ensure Business Associate Agreements (BAAs) are in place with all business associates",
                category="Organizational Requirements",
                requirements=[
                    "BAA with all business associates",
                    "Required contract provisions",
                    "Vendor risk assessments",
                    "Contract monitoring"
                ],
                validation_criteria=[
                    "BAA executed with all BAs",
                    "Contracts include required provisions",
                    "Vendor assessments documented",
                    "Compliance monitored annually"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=24,
                remediation_cost_usd=4000
            )
        )

        # === POLICIES AND PROCEDURES (164.316) ===

        # Policies and Procedures (164.316(a))
        controls.extend([
            ComplianceControl(
                control_id="HIPAA-164.316(a)",
                framework=ComplianceFramework.HIPAA,
                title="Policies and Procedures",
                description="Implement reasonable and appropriate policies and procedures to comply with HIPAA Security Rule",
                category="Policies and Procedures",
                requirements=[
                    "Documented security policies",
                    "Policy review and update procedures",
                    "Policy distribution",
                    "Policy acknowledgment"
                ],
                validation_criteria=[
                    "All required policies documented",
                    "Policies reviewed annually",
                    "Policies accessible to workforce",
                    "Policy acknowledgments on file"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            ),
            ComplianceControl(
                control_id="HIPAA-164.316(b)(1)",
                framework=ComplianceFramework.HIPAA,
                title="Documentation",
                description="Maintain written policies and procedures and documentation of required actions, activities, and assessments",
                category="Policies and Procedures",
                requirements=[
                    "Written policies and procedures",
                    "Documentation of compliance activities",
                    "Documentation retention (6 years)",
                    "Version control"
                ],
                validation_criteria=[
                    "All policies in writing",
                    "Compliance activities documented",
                    "Documents retained for 6+ years",
                    "Document versions tracked"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            ),
            ComplianceControl(
                control_id="HIPAA-164.316(b)(2)(i)",
                framework=ComplianceFramework.HIPAA,
                title="Time Limit for Documentation",
                description="Retain documentation for 6 years from date created or last in effect",
                category="Policies and Procedures",
                requirements=[
                    "6-year retention policy",
                    "Document archival procedures",
                    "Secure storage of archived docs",
                    "Disposal after retention period"
                ],
                validation_criteria=[
                    "Retention policy documented",
                    "Documents retained for 6 years minimum",
                    "Archived documents accessible",
                    "Secure disposal after retention"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=12,
                remediation_cost_usd=2000
            ),
            ComplianceControl(
                control_id="HIPAA-164.316(b)(2)(ii)",
                framework=ComplianceFramework.HIPAA,
                title="Availability of Documentation",
                description="Make documentation available to those responsible for implementing procedures",
                category="Policies and Procedures",
                requirements=[
                    "Centralized policy repository",
                    "Role-based access to policies",
                    "Policy distribution procedures",
                    "Policy acknowledgment tracking"
                ],
                validation_criteria=[
                    "Policy portal or repository exists",
                    "Policies accessible to relevant workforce",
                    "New policies distributed promptly",
                    "Acknowledgments documented"
                ],
                risk_level=RiskLevel.LOW,
                remediation_effort_hours=8,
                remediation_cost_usd=1000
            ),
            ComplianceControl(
                control_id="HIPAA-164.316(b)(2)(iii)",
                framework=ComplianceFramework.HIPAA,
                title="Updates to Documentation",
                description="Review and update documentation as needed in response to environmental or operational changes",
                category="Policies and Procedures",
                requirements=[
                    "Annual policy review",
                    "Change-driven updates",
                    "Version control",
                    "Communication of changes"
                ],
                validation_criteria=[
                    "Policies reviewed annually",
                    "Updates triggered by changes",
                    "Version history maintained",
                    "Changes communicated to workforce"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=12,
                remediation_cost_usd=2000
            )
        ])

        return controls
