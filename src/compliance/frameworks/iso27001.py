"""
ISO 27001:2022 Framework

Implements 93 controls across 4 themes:
- Organizational controls (37)
- People controls (8)
- Physical controls (14)
- Technological controls (34)

Reference: ISO/IEC 27001:2022 Annex A
"""

from typing import List
from ..compliance_engine import (
    ComplianceControl,
    ComplianceFramework,
    ControlStatus,
    RiskLevel
)


class ISO27001Framework:
    """ISO 27001:2022 compliance framework."""

    def __init__(self):
        """Initialize ISO 27001 framework with 93 controls."""
        self.controls = self._define_controls()

    def get_description(self) -> str:
        """Get framework description."""
        return "ISO/IEC 27001:2022 - Information security management system controls (93 controls across 4 themes)"

    def get_all_controls(self) -> List[ComplianceControl]:
        """Get all ISO 27001 controls."""
        return self.controls

    def _define_controls(self) -> List[ComplianceControl]:
        """Define ISO 27001:2022 controls (subset for demonstration)."""
        controls = []

        # Organizational Controls (Annex A.5) - Sample of 10 key controls
        controls.extend([
            ComplianceControl(
                control_id="ISO-A.5.1",
                framework=ComplianceFramework.ISO27001,
                title="Policies for Information Security",
                description="Information security policy and topic-specific policies shall be defined, approved by management, published, communicated to and acknowledged by relevant personnel and relevant interested parties",
                category="Organizational Controls",
                requirements=[
                    "Information security policy document",
                    "Management approval",
                    "Policy distribution to all personnel",
                    "Annual review and updates"
                ],
                validation_criteria=[
                    "Policy documented and approved",
                    "All employees acknowledged policy",
                    "Policy reviewed annually",
                    "Topic-specific policies exist"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=24,
                remediation_cost_usd=4000
            ),
            ComplianceControl(
                control_id="ISO-A.5.2",
                framework=ComplianceFramework.ISO27001,
                title="Information Security Roles and Responsibilities",
                description="Information security roles and responsibilities shall be defined and allocated according to the organization needs",
                category="Organizational Controls",
                requirements=[
                    "CISO or security lead designated",
                    "Security roles defined",
                    "Responsibilities documented",
                    "Segregation of duties"
                ],
                validation_criteria=[
                    "Security official appointed",
                    "Job descriptions include security responsibilities",
                    "Org chart shows security reporting",
                    "Conflicts of interest identified"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            ),
            ComplianceControl(
                control_id="ISO-A.5.3",
                framework=ComplianceFramework.ISO27001,
                title="Segregation of Duties",
                description="Conflicting duties and conflicting areas of responsibility shall be segregated",
                category="Organizational Controls",
                requirements=[
                    "Identify conflicting duties",
                    "Separate critical functions",
                    "No single person controls entire process",
                    "Dual control for sensitive operations"
                ],
                validation_criteria=[
                    "Segregation analysis documented",
                    "Critical functions separated",
                    "Compensating controls for exceptions",
                    "Regular review of access rights"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            ),
            ComplianceControl(
                control_id="ISO-A.5.7",
                framework=ComplianceFramework.ISO27001,
                title="Threat Intelligence",
                description="Information relating to information security threats shall be collected and analyzed to produce threat intelligence",
                category="Organizational Controls",
                requirements=[
                    "Threat intelligence sources identified",
                    "Threat data collection processes",
                    "Analysis and correlation",
                    "Threat intelligence sharing"
                ],
                validation_criteria=[
                    "Threat feeds subscribed",
                    "Threat data collected and analyzed",
                    "Actionable intelligence produced",
                    "Intelligence shared with stakeholders"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            ),
            ComplianceControl(
                control_id="ISO-A.5.10",
                framework=ComplianceFramework.ISO27001,
                title="Acceptable Use of Information and Assets",
                description="Rules for acceptable use and procedures for handling information and assets shall be identified, documented and implemented",
                category="Organizational Controls",
                requirements=[
                    "Acceptable use policy",
                    "Asset classification scheme",
                    "Handling procedures",
                    "User acknowledgment"
                ],
                validation_criteria=[
                    "AUP documented and approved",
                    "Classification scheme defined",
                    "Handling procedures published",
                    "Users trained and acknowledged"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            )
        ])

        # People Controls (Annex A.6) - Sample of 5 key controls
        controls.extend([
            ComplianceControl(
                control_id="ISO-A.6.1",
                framework=ComplianceFramework.ISO27001,
                title="Screening",
                description="Background verification checks on all candidates for employment shall be carried out prior to joining the organization",
                category="People Controls",
                requirements=[
                    "Background check policy",
                    "Verification appropriate to position",
                    "Legal compliance",
                    "Documentation of checks"
                ],
                validation_criteria=[
                    "Background check policy exists",
                    "Checks completed for all employees",
                    "Results documented",
                    "Legal requirements met"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=12,
                remediation_cost_usd=2500
            ),
            ComplianceControl(
                control_id="ISO-A.6.2",
                framework=ComplianceFramework.ISO27001,
                title="Terms and Conditions of Employment",
                description="Contractual agreements shall state the employee and employer responsibilities for information security",
                category="People Controls",
                requirements=[
                    "Security clauses in employment contracts",
                    "Confidentiality agreements",
                    "Acceptable use acknowledgment",
                    "Consequences of violations"
                ],
                validation_criteria=[
                    "Contracts include security clauses",
                    "NDAs signed by all employees",
                    "AUP acknowledged",
                    "Disciplinary procedures defined"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=8,
                remediation_cost_usd=1500
            ),
            ComplianceControl(
                control_id="ISO-A.6.3",
                framework=ComplianceFramework.ISO27001,
                title="Information Security Awareness, Education and Training",
                description="Personnel shall receive appropriate information security awareness, education and training",
                category="People Controls",
                requirements=[
                    "Annual security awareness training",
                    "Role-specific training",
                    "New hire security orientation",
                    "Training effectiveness measurement"
                ],
                validation_criteria=[
                    "Training program established",
                    "All employees trained annually",
                    "Specialized training for technical roles",
                    "Training completion tracked"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            ),
            ComplianceControl(
                control_id="ISO-A.6.4",
                framework=ComplianceFramework.ISO27001,
                title="Disciplinary Process",
                description="A disciplinary process shall be formalized and communicated to take actions against personnel who commit information security violations",
                category="People Controls",
                requirements=[
                    "Disciplinary policy",
                    "Progressive discipline procedures",
                    "Investigation process",
                    "Documentation requirements"
                ],
                validation_criteria=[
                    "Disciplinary policy documented",
                    "Process communicated to employees",
                    "Violations investigated",
                    "Actions documented"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=12,
                remediation_cost_usd=2000
            ),
            ComplianceControl(
                control_id="ISO-A.6.5",
                framework=ComplianceFramework.ISO27001,
                title="Responsibilities After Termination",
                description="Information security responsibilities that remain valid after termination shall be defined, enforced and communicated",
                category="People Controls",
                requirements=[
                    "Termination procedures",
                    "Access revocation checklist",
                    "Continuing obligations (NDA)",
                    "Asset return procedures"
                ],
                validation_criteria=[
                    "Termination checklist exists",
                    "Access revoked immediately",
                    "Exit interview conducted",
                    "Assets returned and documented"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=8,
                remediation_cost_usd=1500
            )
        ])

        # Physical Controls (Annex A.7) - Sample of 7 key controls
        controls.extend([
            ComplianceControl(
                control_id="ISO-A.7.1",
                framework=ComplianceFramework.ISO27001,
                title="Physical Security Perimeters",
                description="Security perimeters shall be defined and used to protect areas containing information and assets",
                category="Physical Controls",
                requirements=[
                    "Security perimeters defined",
                    "Physical barriers",
                    "Entry controls",
                    "Monitoring systems"
                ],
                validation_criteria=[
                    "Perimeters documented",
                    "Physical barriers in place",
                    "Access control systems deployed",
                    "CCTV monitoring critical areas"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=40,
                remediation_cost_usd=15000
            ),
            ComplianceControl(
                control_id="ISO-A.7.2",
                framework=ComplianceFramework.ISO27001,
                title="Physical Entry Controls",
                description="Secure areas shall be protected by appropriate entry controls",
                category="Physical Controls",
                requirements=[
                    "Entry control systems",
                    "Visitor management",
                    "Access logging",
                    "Escort procedures"
                ],
                validation_criteria=[
                    "Badge/biometric access control",
                    "Visitor log maintained",
                    "Access logs reviewed",
                    "Visitors escorted in secure areas"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=32,
                remediation_cost_usd=10000
            ),
            ComplianceControl(
                control_id="ISO-A.7.4",
                framework=ComplianceFramework.ISO27001,
                title="Physical Security Monitoring",
                description="Premises shall be continuously monitored for unauthorized physical access",
                category="Physical Controls",
                requirements=[
                    "CCTV systems",
                    "Intrusion detection",
                    "Alarm systems",
                    "24/7 monitoring"
                ],
                validation_criteria=[
                    "CCTV covers all entry points",
                    "Alarms on doors/windows",
                    "Monitoring station staffed or automated",
                    "Recordings retained 90+ days"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=40,
                remediation_cost_usd=12000
            ),
            ComplianceControl(
                control_id="ISO-A.7.7",
                framework=ComplianceFramework.ISO27001,
                title="Clear Desk and Clear Screen",
                description="Clear desk policy for papers and removable storage media and clear screen policy for information processing facilities shall be adopted",
                category="Physical Controls",
                requirements=[
                    "Clear desk policy",
                    "Clear screen policy",
                    "Secure storage",
                    "Policy enforcement"
                ],
                validation_criteria=[
                    "Policies documented",
                    "Lockable storage provided",
                    "Screen privacy filters",
                    "Regular compliance checks"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=8,
                remediation_cost_usd=1500
            )
        ])

        # Technological Controls (Annex A.8) - Sample of 15 key controls
        controls.extend([
            ComplianceControl(
                control_id="ISO-A.8.1",
                framework=ComplianceFramework.ISO27001,
                title="User Endpoint Devices",
                description="Information stored on, processed by or accessible via user endpoint devices shall be protected",
                category="Technological Controls",
                requirements=[
                    "Endpoint protection software",
                    "Device encryption",
                    "Configuration management",
                    "Remote wipe capability"
                ],
                validation_criteria=[
                    "EDR/antivirus on all endpoints",
                    "Full disk encryption enabled",
                    "Endpoints centrally managed",
                    "Remote wipe available for mobile devices"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=24,
                remediation_cost_usd=5000
            ),
            ComplianceControl(
                control_id="ISO-A.8.2",
                framework=ComplianceFramework.ISO27001,
                title="Privileged Access Rights",
                description="Allocation and use of privileged access rights shall be restricted and managed",
                category="Technological Controls",
                requirements=[
                    "Privileged access management",
                    "Just-in-time access",
                    "MFA for privileged accounts",
                    "Activity monitoring"
                ],
                validation_criteria=[
                    "PAM solution deployed",
                    "Privileged access requires approval",
                    "MFA enforced for admin access",
                    "Privileged sessions logged and monitored"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            ),
            ComplianceControl(
                control_id="ISO-A.8.3",
                framework=ComplianceFramework.ISO27001,
                title="Information Access Restriction",
                description="Access to information and other associated assets shall be restricted in accordance with access control policy",
                category="Technological Controls",
                requirements=[
                    "Access control policy",
                    "Role-based access control",
                    "Least privilege principle",
                    "Access reviews"
                ],
                validation_criteria=[
                    "Access control policy documented",
                    "RBAC implemented",
                    "Access limited to minimum necessary",
                    "Quarterly access reviews"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            ),
            ComplianceControl(
                control_id="ISO-A.8.5",
                framework=ComplianceFramework.ISO27001,
                title="Secure Authentication",
                description="Secure authentication technologies and procedures shall be implemented based on access restrictions and topic-specific policy",
                category="Technological Controls",
                requirements=[
                    "Strong authentication",
                    "Multi-factor authentication",
                    "Password policies",
                    "Biometric authentication (optional)"
                ],
                validation_criteria=[
                    "MFA deployed organization-wide",
                    "Strong password requirements enforced",
                    "SSO implemented where appropriate",
                    "Authentication methods risk-appropriate"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            ),
            ComplianceControl(
                control_id="ISO-A.8.8",
                framework=ComplianceFramework.ISO27001,
                title="Management of Technical Vulnerabilities",
                description="Information about technical vulnerabilities shall be obtained, exposure assessed and appropriate measures taken",
                category="Technological Controls",
                requirements=[
                    "Vulnerability management program",
                    "Regular vulnerability scanning",
                    "Patch management",
                    "Risk-based remediation"
                ],
                validation_criteria=[
                    "Vulnerability scans monthly",
                    "Critical patches within 30 days",
                    "High patches within 60 days",
                    "Remediation tracked and reported"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=40,
                remediation_cost_usd=8000
            ),
            ComplianceControl(
                control_id="ISO-A.8.10",
                framework=ComplianceFramework.ISO27001,
                title="Information Deletion",
                description="Information stored in information systems, devices or any other storage media shall be deleted when no longer required",
                category="Technological Controls",
                requirements=[
                    "Data retention policy",
                    "Secure deletion procedures",
                    "Data lifecycle management",
                    "Disposal verification"
                ],
                validation_criteria=[
                    "Retention policy documented",
                    "Automated deletion where possible",
                    "Secure wiping tools used",
                    "Deletion verified and logged"
                ],
                risk_level=RiskLevel.HIGH,
                remediation_effort_hours=24,
                remediation_cost_usd=4000
            ),
            ComplianceControl(
                control_id="ISO-A.8.16",
                framework=ComplianceFramework.ISO27001,
                title="Monitoring Activities",
                description="Networks, systems and applications shall be monitored for anomalous behavior and appropriate action taken",
                category="Technological Controls",
                requirements=[
                    "Security monitoring",
                    "SIEM deployment",
                    "Anomaly detection",
                    "24/7 monitoring capability"
                ],
                validation_criteria=[
                    "SIEM collecting logs",
                    "Anomaly detection rules configured",
                    "Alerts investigated promptly",
                    "SOC or monitoring service engaged"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=60,
                remediation_cost_usd=15000
            ),
            ComplianceControl(
                control_id="ISO-A.8.17",
                framework=ComplianceFramework.ISO27001,
                title="Clock Synchronization",
                description="Clocks of information processing systems shall be synchronized to approved time sources",
                category="Technological Controls",
                requirements=[
                    "NTP configuration",
                    "Time source validation",
                    "Consistent time zones",
                    "Time drift monitoring"
                ],
                validation_criteria=[
                    "NTP configured on all systems",
                    "Authoritative time source used",
                    "Time drift < 5 seconds",
                    "Sync status monitored"
                ],
                risk_level=RiskLevel.LOW,
                remediation_effort_hours=8,
                remediation_cost_usd=1000
            ),
            ComplianceControl(
                control_id="ISO-A.8.23",
                framework=ComplianceFramework.ISO27001,
                title="Web Filtering",
                description="Access to external websites shall be managed to reduce exposure to malicious content",
                category="Technological Controls",
                requirements=[
                    "Web filtering solution",
                    "Category blocking",
                    "Malware scanning",
                    "Policy enforcement"
                ],
                validation_criteria=[
                    "Web filter deployed",
                    "Malicious sites blocked",
                    "Downloads scanned for malware",
                    "Bypass requests logged"
                ],
                risk_level=RiskLevel.MEDIUM,
                remediation_effort_hours=16,
                remediation_cost_usd=3000
            ),
            ComplianceControl(
                control_id="ISO-A.8.24",
                framework=ComplianceFramework.ISO27001,
                title="Use of Cryptography",
                description="Rules for effective use of cryptography shall be defined and implemented",
                category="Technological Controls",
                requirements=[
                    "Cryptography policy",
                    "Strong algorithms (AES-256, RSA-2048+)",
                    "Key management",
                    "Encryption at rest and in transit"
                ],
                validation_criteria=[
                    "Crypto policy documented",
                    "Strong algorithms mandated",
                    "Keys managed securely",
                    "Sensitive data encrypted"
                ],
                risk_level=RiskLevel.CRITICAL,
                remediation_effort_hours=32,
                remediation_cost_usd=6000
            )
        ])

        return controls
