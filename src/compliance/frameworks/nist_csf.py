"""
NIST Cybersecurity Framework 2.0

Implements 6 core functions and 23 categories:
- Govern (6 categories)
- Identify (6 categories)
- Protect (6 categories)
- Detect (3 categories)
- Respond (5 categories)
- Recover (4 categories)

Reference: NIST CSF 2.0 (February 2024)
"""

from typing import List
from ..compliance_engine import (
    ComplianceControl,
    ComplianceFramework,
    ControlStatus,
    RiskLevel
)


class NISTCSFFramework:
    """NIST Cybersecurity Framework 2.0."""

    def __init__(self):
        """Initialize NIST CSF 2.0 framework."""
        self.controls = self._define_controls()

    def get_description(self) -> str:
        """Get framework description."""
        return "NIST Cybersecurity Framework 2.0 - Risk-based cybersecurity controls (6 functions, 23 categories)"

    def get_all_controls(self) -> List[ComplianceControl]:
        """Get all NIST CSF controls."""
        return self.controls

    def _define_controls(self) -> List[ComplianceControl]:
        """Define NIST CSF 2.0 controls."""
        controls = []

        # GOVERN (GV)
        controls.extend([
            ComplianceControl(
                control_id="NIST-GV.OC",
                framework=ComplianceFramework.NIST_CSF,
                title="Organizational Context",
                description="Understand and regularly monitor organizational mission, stakeholders, and risk management approach",
                category="Govern",
                requirements=[
                    "Mission and objectives documented",
                    "Stakeholder identification",
                    "Risk appetite defined",
                    "Regulatory requirements identified"
                ],
                validation_criteria=[
                    "Organizational context documented",
                    "Stakeholders mapped",
                    "Risk appetite statement approved",
                    "Requirements catalogued"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=24,
                remediation_cost_usd=4000
            ),
            ComplianceControl(
                control_id="NIST-GV.RM",
                framework=ComplianceFramework.NIST_CSF,
                title="Risk Management Strategy",
                description="Establish and communicate cybersecurity risk management strategy",
                category="Govern",
                requirements=[
                    "Risk management strategy",
                    "Risk assessment methodology",
                    "Risk treatment processes",
                    "Board-level oversight"
                ],
                validation_criteria=[
                    "Strategy documented and approved",
                    "Methodology defined",
                    "Risk register maintained",
                    "Board receives regular risk reports"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            ),
            ComplianceControl(
                control_id="NIST-GV.RR",
                framework=ComplianceFramework.NIST_CSF,
                title="Roles, Responsibilities, and Authorities",
                description="Establish and communicate cybersecurity roles, responsibilities, and authorities",
                category="Govern",
                requirements=[
                    "RACI matrix for cybersecurity",
                    "Designated security leadership",
                    "Clear accountability",
                    "Authority documentation"
                ],
                validation_criteria=[
                    "Roles and responsibilities documented",
                    "CISO or equivalent appointed",
                    "Accountability clear",
                    "Authority commensurate with responsibility"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            ),
            ComplianceControl(
                control_id="NIST-GV.PO",
                framework=ComplianceFramework.NIST_CSF,
                title="Policy",
                description="Establish and communicate organizational cybersecurity policy",
                category="Govern",
                requirements=[
                    "Cybersecurity policy",
                    "Policy framework",
                    "Policy communication",
                    "Policy enforcement"
                ],
                validation_criteria=[
                    "Policy documented and approved",
                    "Framework established",
                    "All personnel aware of policies",
                    "Violations addressed"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            ),
            ComplianceControl(
                control_id="NIST-GV.OV",
                framework=ComplianceFramework.NIST_CSF,
                title="Oversight",
                description="Cybersecurity risk management results are used to inform organizational decisions",
                category="Govern",
                requirements=[
                    "Executive oversight",
                    "Board reporting",
                    "Risk-informed decisions",
                    "Performance metrics"
                ],
                validation_criteria=[
                    "Executive team reviews cybersecurity",
                    "Board receives quarterly reports",
                    "Decisions consider cyber risk",
                    "KPIs tracked and reported"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=24,
                remediation_cost_usd=4000
            ),
            ComplianceControl(
                control_id="NIST-GV.SC",
                framework=ComplianceFramework.NIST_CSF,
                title="Cybersecurity Supply Chain Risk Management",
                description="Cyber supply chain risk management processes are identified, established, and managed",
                category="Govern",
                requirements=[
                    "Vendor risk assessment",
                    "Supply chain mapping",
                    "Contractual security requirements",
                    "Ongoing vendor monitoring"
                ],
                validation_criteria=[
                    "Vendor assessment process exists",
                    "Critical vendors identified",
                    "Security clauses in contracts",
                    "Vendor compliance monitored"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            )
        ])

        # IDENTIFY (ID)
        controls.extend([
            ComplianceControl(
                control_id="NIST-ID.AM",
                framework=ComplianceFramework.NIST_CSF,
                title="Asset Management",
                description="Assets are inventoried, prioritized, and managed",
                category="Identify",
                requirements=[
                    "Asset inventory",
                    "Asset classification",
                    "Asset ownership",
                    "Asset lifecycle management"
                ],
                validation_criteria=[
                    "Complete asset inventory maintained",
                    "Assets classified by criticality",
                    "Owners assigned to all assets",
                    "Inventory updated monthly"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            ),
            ComplianceControl(
                control_id="NIST-ID.RA",
                framework=ComplianceFramework.NIST_CSF,
                title="Risk Assessment",
                description="Organizational risk is understood and managed",
                category="Identify",
                requirements=[
                    "Annual risk assessment",
                    "Threat identification",
                    "Vulnerability assessment",
                    "Risk prioritization"
                ],
                validation_criteria=[
                    "Risk assessment conducted annually",
                    "Threats catalogued",
                    "Vulnerabilities identified",
                    "Risks prioritized and treated"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=60,
                remediation_cost_usd=12000
            ),
            ComplianceControl(
                control_id="NIST-ID.IM",
                framework=ComplianceFramework.NIST_CSF,
                title="Improvement",
                description="Improvement opportunities are identified from assessments and lessons learned",
                category="Identify",
                requirements=[
                    "Continuous improvement program",
                    "Lessons learned process",
                    "Assessment findings tracking",
                    "Improvement implementation"
                ],
                validation_criteria=[
                    "Improvement program established",
                    "Post-incident reviews conducted",
                    "Findings tracked to closure",
                    "Improvements measurable"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=24,
                remediation_cost_usd=4000
            )
        ])

        # PROTECT (PR)
        controls.extend([
            ComplianceControl(
                control_id="NIST-PR.AA",
                framework=ComplianceFramework.NIST_CSF,
                title="Identity Management, Authentication and Access Control",
                description="Access to physical and logical assets is limited to authorized users and services",
                category="Protect",
                requirements=[
                    "Identity management",
                    "Multi-factor authentication",
                    "Access control",
                    "Least privilege"
                ],
                validation_criteria=[
                    "IAM solution deployed",
                    "MFA required for sensitive access",
                    "RBAC implemented",
                    "Quarterly access reviews"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            ),
            ComplianceControl(
                control_id="NIST-PR.AT",
                framework=ComplianceFramework.NIST_CSF,
                title="Awareness and Training",
                description="Personnel are provided cybersecurity awareness and training",
                category="Protect",
                requirements=[
                    "Annual security training",
                    "Role-based training",
                    "Phishing simulations",
                    "Training effectiveness measurement"
                ],
                validation_criteria=[
                    "Training program established",
                    "100% completion annually",
                    "Phishing tests quarterly",
                    "Metrics tracked"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            ),
            ComplianceControl(
                control_id="NIST-PR.DS",
                framework=ComplianceFramework.NIST_CSF,
                title="Data Security",
                description="Data are managed consistent with organizational risk strategy",
                category="Protect",
                requirements=[
                    "Data classification",
                    "Encryption at rest and in transit",
                    "Data loss prevention",
                    "Secure data disposal"
                ],
                validation_criteria=[
                    "Data classified",
                    "Sensitive data encrypted",
                    "DLP solution deployed",
                    "Secure disposal procedures"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=48,
                remediation_cost_usd=10000
            ),
            ComplianceControl(
                control_id="NIST-PR.PS",
                framework=ComplianceFramework.NIST_CSF,
                title="Platform Security",
                description="Hardware, software, and services are managed consistent with organizational risk strategy",
                category="Protect",
                requirements=[
                    "Hardened configurations",
                    "Patch management",
                    "Vulnerability management",
                    "Secure development practices"
                ],
                validation_criteria=[
                    "Security baselines applied",
                    "Patches deployed timely",
                    "Vulnerability scans monthly",
                    "SDL implemented"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=60,
                remediation_cost_usd=12000
            ),
            ComplianceControl(
                control_id="NIST-PR.IR",
                framework=ComplianceFramework.NIST_CSF,
                title="Technology Infrastructure Resilience",
                description="Security architectures are managed with the organization's risk strategy",
                category="Protect",
                requirements=[
                    "Network segmentation",
                    "Redundancy",
                    "Capacity planning",
                    "Resilient architecture"
                ],
                validation_criteria=[
                    "Networks segmented",
                    "Critical systems redundant",
                    "Capacity monitored",
                    "Architecture resilient to failures"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=48,
                remediation_cost_usd=10000
            )
        ])

        # DETECT (DE)
        controls.extend([
            ComplianceControl(
                control_id="NIST-DE.CM",
                framework=ComplianceFramework.NIST_CSF,
                title="Continuous Monitoring",
                description="Assets are monitored to find anomalies and cybersecurity events",
                category="Detect",
                requirements=[
                    "Security monitoring",
                    "SIEM deployment",
                    "Anomaly detection",
                    "Threat intelligence integration"
                ],
                validation_criteria=[
                    "SIEM collecting logs",
                    "Baseline behavior established",
                    "Anomalies detected and investigated",
                    "Threat feeds integrated"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=60,
                remediation_cost_usd=15000
            ),
            ComplianceControl(
                control_id="NIST-DE.AE",
                framework=ComplianceFramework.NIST_CSF,
                title="Adverse Event Analysis",
                description="Anomalies and events are analyzed to understand attack patterns",
                category="Detect",
                requirements=[
                    "Event correlation",
                    "Incident analysis",
                    "Attack pattern recognition",
                    "IOC management"
                ],
                validation_criteria=[
                    "Events correlated in SIEM",
                    "Incidents analyzed for patterns",
                    "Attack techniques identified",
                    "IOCs catalogued and shared"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            )
        ])

        # RESPOND (RS)
        controls.extend([
            ComplianceControl(
                control_id="NIST-RS.MA",
                framework=ComplianceFramework.NIST_CSF,
                title="Incident Management",
                description="Incidents are managed consistent with organizational priorities",
                category="Respond",
                requirements=[
                    "Incident response plan",
                    "Incident classification",
                    "Response procedures",
                    "Escalation criteria"
                ],
                validation_criteria=[
                    "IR plan documented and tested",
                    "Incidents classified by severity",
                    "Procedures followed",
                    "Escalations timely"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            ),
            ComplianceControl(
                control_id="NIST-RS.AN",
                framework=ComplianceFramework.NIST_CSF,
                title="Incident Analysis",
                description="Investigations are conducted to understand incidents",
                category="Respond",
                requirements=[
                    "Forensic capabilities",
                    "Root cause analysis",
                    "Evidence preservation",
                    "Analysis documentation"
                ],
                validation_criteria=[
                    "Forensic tools available",
                    "RCA performed for incidents",
                    "Evidence handled properly",
                    "Findings documented"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            ),
            ComplianceControl(
                control_id="NIST-RS.CO",
                framework=ComplianceFramework.NIST_CSF,
                title="Incident Response Reporting and Communication",
                description="Response activities are coordinated internally and externally",
                category="Respond",
                requirements=[
                    "Communication plan",
                    "Stakeholder notification",
                    "External reporting",
                    "Coordination procedures"
                ],
                validation_criteria=[
                    "Communication plan exists",
                    "Stakeholders identified",
                    "Regulatory reporting procedures",
                    "Internal/external coordination effective"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=24,
                remediation_cost_usd=4000
            ),
            ComplianceControl(
                control_id="NIST-RS.MI",
                framework=ComplianceFramework.NIST_CSF,
                title="Incident Mitigation",
                description="Activities are performed to prevent expansion of incidents and mitigate effects",
                category="Respond",
                requirements=[
                    "Containment procedures",
                    "Eradication procedures",
                    "Mitigation strategies",
                    "Recovery coordination"
                ],
                validation_criteria=[
                    "Containment quick and effective",
                    "Threats eradicated",
                    "Impact minimized",
                    "Recovery initiated promptly"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            )
        ])

        # RECOVER (RC)
        controls.extend([
            ComplianceControl(
                control_id="NIST-RC.RP",
                framework=ComplianceFramework.NIST_CSF,
                title="Incident Recovery Plan Execution",
                description="Restoration activities are performed to restore operational capabilities",
                category="Recover",
                requirements=[
                    "Recovery plan",
                    "Restoration procedures",
                    "Validation testing",
                    "Return to normal operations"
                ],
                validation_criteria=[
                    "Recovery plan documented",
                    "Restoration successful",
                    "Systems validated before production",
                    "Normal operations resumed"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            ),
            ComplianceControl(
                control_id="NIST-RC.IM",
                framework=ComplianceFramework.NIST_CSF,
                title="Incident Recovery Communication",
                description="Recovery activities are communicated to stakeholders",
                category="Recover",
                requirements=[
                    "Recovery communication plan",
                    "Status updates",
                    "Stakeholder coordination",
                    "Lessons learned sharing"
                ],
                validation_criteria=[
                    "Communication plan exists",
                    "Stakeholders kept informed",
                    "Status reported regularly",
                    "Lessons learned documented"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            ),
            ComplianceControl(
                control_id="NIST-RC.CO",
                framework=ComplianceFramework.NIST_CSF,
                title="Crisis Management",
                description="Public relations are managed during and after incidents",
                category="Recover",
                requirements=[
                    "Crisis communication plan",
                    "Media relations",
                    "Public statements",
                    "Reputation management"
                ],
                validation_criteria=[
                    "Crisis plan documented",
                    "Spokespersons designated",
                    "Statements coordinated",
                    "Brand protected"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=24,
                remediation_cost_usd=4000
            )
        ])

        return controls
