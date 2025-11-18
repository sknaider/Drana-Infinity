"""
HIPAA Control Assessment Engine

Automated assessment of HIPAA Security Rule controls using Claude AI
for intelligent evaluation, gap analysis, and remediation planning.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import uuid

from ...integrations.claude_client import ClaudeClient
from ...core.config_manager import get_config

logger = logging.getLogger(__name__)


class AssessmentStatus(Enum):
    """Assessment status for a control."""
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class GapSeverity(Enum):
    """Severity level for compliance gaps."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RemediationPriority(Enum):
    """Priority for remediation actions."""
    IMMEDIATE = "immediate"
    DAYS_30 = "30days"
    DAYS_90 = "90days"
    ONGOING = "ongoing"


@dataclass
class ControlGap:
    """Represents a gap in HIPAA control implementation."""
    gap_id: str
    control_id: str
    description: str
    severity: GapSeverity
    patient_safety_impact: bool
    breach_risk: bool
    root_cause: str
    affected_systems: List[str] = field(default_factory=list)
    regulatory_citations: List[str] = field(default_factory=list)


@dataclass
class RemediationAction:
    """Remediation action for a gap."""
    action_id: str
    gap_id: str
    action: str
    effort_hours: int
    cost_estimate: int
    priority: RemediationPriority
    dependencies: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)
    assigned_to: Optional[str] = None
    target_completion: Optional[datetime] = None
    status: str = "pending"


@dataclass
class ControlAssessment:
    """Assessment result for a single HIPAA control."""
    assessment_id: str
    control_id: str
    status: AssessmentStatus
    confidence_score: float
    evidence_found: List[str] = field(default_factory=list)
    evidence_missing: List[str] = field(default_factory=list)
    gaps: List[ControlGap] = field(default_factory=list)
    remediation_actions: List[RemediationAction] = field(default_factory=list)
    assessed_at: datetime = field(default_factory=datetime.now)
    assessed_by: str = "Claude AI"
    notes: str = ""
    regulatory_notes: str = ""


@dataclass
class GapAnalysisReport:
    """Comprehensive gap analysis across all controls."""
    report_id: str
    target_system: str
    total_controls: int
    controls_passed: int
    controls_failed: int
    controls_partial: int
    controls_not_applicable: int
    overall_compliance_score: float
    critical_gaps: List[ControlGap]
    high_gaps: List[ControlGap]
    medium_gaps: List[ControlGap]
    low_gaps: List[ControlGap]
    estimated_remediation_hours: int
    estimated_remediation_cost: int
    generated_at: datetime = field(default_factory=datetime.now)


@dataclass
class RemediationPhase:
    """Phased remediation plan."""
    phase_number: int
    phase_name: str
    duration_days: int
    actions: List[RemediationAction]
    total_effort_hours: int
    total_cost: int
    success_criteria: List[str]


@dataclass
class RemediationRoadmap:
    """Complete remediation roadmap."""
    roadmap_id: str
    target_system: str
    phases: List[RemediationPhase]
    total_duration_days: int
    total_effort_hours: int
    total_cost: int
    resource_requirements: Dict[str, Any]
    constraints: Dict[str, Any]
    generated_at: datetime = field(default_factory=datetime.now)


class HIPAAControlAssessor:
    """
    Claude-powered HIPAA control assessment engine.

    Uses Claude AI to intelligently assess system compliance against
    HIPAA Security Rule requirements.
    """

    # Claude prompt template for control assessment
    ASSESSMENT_PROMPT_TEMPLATE = """You are a certified HIPAA compliance auditor with expertise in the HIPAA Security Rule.

Assess the following HIPAA control:

**CONTROL**: {control_id} - {title}
**TYPE**: {safeguard_type} - {implementation_spec}

**DESCRIPTION**:
{description}

**REQUIREMENTS**:
{requirements}

**TESTING PROCEDURES**:
{testing_procedures}

**EVIDENCE REQUIRED**:
{evidence_required}

**SYSTEM CONFIGURATION**:
{system_config}

**EVIDENCE PROVIDED**:
{evidence}

**SYSTEM CONTEXT**:
- System Type: {system_type}
- Handles PHI: {handles_phi}
- Sector: {sector}

**TASK**:
Thoroughly assess if this system meets the HIPAA control requirements. Be specific and evidence-based.

Provide your assessment in the following JSON format:
{{
    "status": "passed|failed|partial|not_applicable",
    "confidence": 0.0-1.0,
    "evidence_found": ["specific evidence supporting compliance"],
    "evidence_missing": ["missing required evidence"],
    "gaps": [
        {{
            "description": "specific gap identified",
            "severity": "critical|high|medium|low",
            "patient_safety_impact": true|false,
            "breach_risk": true|false,
            "root_cause": "underlying reason for gap",
            "affected_systems": ["list of affected systems"]
        }}
    ],
    "remediation": [
        {{
            "action": "specific action to take",
            "effort_hours": estimated_hours,
            "cost_estimate": estimated_cost_usd,
            "priority": "immediate|30days|90days|ongoing",
            "dependencies": ["prerequisites"],
            "success_criteria": ["how to verify completion"]
        }}
    ],
    "regulatory_notes": "relevant HHS guidance, common failures, or case studies"
}}

Be thorough and specific. Focus on patient safety and breach prevention."""

    def __init__(self, claude_client: Optional[ClaudeClient] = None):
        """
        Initialize HIPAA assessor.

        Args:
            claude_client: Optional Claude client instance
        """
        if claude_client:
            self.claude = claude_client
        else:
            # Initialize from config
            config = get_config()
            if config.ai_models["claude"].enabled and config.ai_models["claude"].api_key:
                self.claude = ClaudeClient(
                    api_key=config.ai_models["claude"].api_key,
                    model=config.ai_models["claude"].model_name
                )
            else:
                raise ValueError("Claude API required for HIPAA assessment")

        logger.info("HIPAA Control Assessor initialized")

    async def assess_control(
        self,
        control: Any,  # HIPAAControl from hipaa.py
        system_config: Dict[str, Any],
        evidence_provided: List[Dict[str, Any]],
        system_context: Optional[Dict[str, Any]] = None
    ) -> ControlAssessment:
        """
        Assess a single HIPAA control using Claude AI.

        Args:
            control: HIPAA control to assess
            system_config: Current system configuration
            evidence_provided: Evidence of compliance
            system_context: Additional system context

        Returns:
            ControlAssessment with status, gaps, and remediation
        """
        logger.info(f"Assessing control: {control.control_id}")

        # Prepare context
        context = system_context or {}
        system_type = context.get("system_type", "unknown")
        handles_phi = context.get("handles_phi", True)
        sector = context.get("sector", "healthcare")

        # Format requirements as string
        requirements_str = "\n".join(f"- {req}" for req in control.requirements)

        # Format validation criteria as testing procedures
        testing_procedures_str = "\n".join(
            f"- {proc}" for proc in control.validation_criteria
        )

        # Format evidence required
        evidence_required_str = "\n".join(
            f"- {ev}" for ev in getattr(control, 'evidence_required', control.validation_criteria)
        )

        # Format evidence provided
        if evidence_provided:
            evidence_str = "\n".join(
                f"- {ev.get('type', 'Evidence')}: {ev.get('description', 'N/A')}"
                for ev in evidence_provided
            )
        else:
            evidence_str = "No evidence provided"

        # Format system config
        system_config_str = self._format_system_config(system_config)

        # Build prompt
        prompt = self.ASSESSMENT_PROMPT_TEMPLATE.format(
            control_id=control.control_id,
            title=control.title,
            safeguard_type=control.category,
            implementation_spec=getattr(control, 'implementation_spec', 'Required'),
            description=control.description,
            requirements=requirements_str,
            testing_procedures=testing_procedures_str,
            evidence_required=evidence_required_str,
            system_config=system_config_str,
            evidence=evidence_str,
            system_type=system_type,
            handles_phi=handles_phi,
            sector=sector
        )

        # Query Claude
        try:
            response = await asyncio.to_thread(
                self.claude.generate,
                prompt,
                temperature=0.3  # Low temperature for factual assessment
            )

            # Parse response
            assessment_data = self._parse_claude_response(response)

            # Build assessment object
            assessment = self._build_assessment(
                control_id=control.control_id,
                assessment_data=assessment_data
            )

            logger.info(
                f"Control {control.control_id} assessed: "
                f"{assessment.status.value} (confidence: {assessment.confidence_score:.2f})"
            )

            return assessment

        except Exception as e:
            logger.error(f"Assessment failed for {control.control_id}: {e}")

            # Return failed assessment
            return ControlAssessment(
                assessment_id=str(uuid.uuid4()),
                control_id=control.control_id,
                status=AssessmentStatus.NOT_ASSESSED,
                confidence_score=0.0,
                notes=f"Assessment error: {str(e)}"
            )

    def _format_system_config(self, system_config: Dict[str, Any]) -> str:
        """Format system configuration for prompt."""
        if not system_config:
            return "No system configuration provided"

        lines = []
        for key, value in system_config.items():
            if isinstance(value, dict):
                lines.append(f"**{key}**:")
                for sub_key, sub_value in value.items():
                    lines.append(f"  - {sub_key}: {sub_value}")
            elif isinstance(value, list):
                lines.append(f"**{key}**: {', '.join(str(v) for v in value)}")
            else:
                lines.append(f"**{key}**: {value}")

        return "\n".join(lines)

    def _parse_claude_response(self, response: str) -> Dict[str, Any]:
        """Parse Claude's JSON response."""
        import json

        # Try to extract JSON
        try:
            # Look for JSON block
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1

            if start_idx != -1 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                data = json.loads(json_str)
                return data
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse JSON from Claude response: {e}")

        # Fallback: return minimal structure
        return {
            "status": "not_assessed",
            "confidence": 0.0,
            "evidence_found": [],
            "evidence_missing": [],
            "gaps": [],
            "remediation": [],
            "regulatory_notes": response[:500]  # Save first part of response
        }

    def _build_assessment(
        self,
        control_id: str,
        assessment_data: Dict[str, Any]
    ) -> ControlAssessment:
        """Build ControlAssessment object from Claude response."""
        # Parse status
        status_str = assessment_data.get("status", "not_assessed")
        try:
            status = AssessmentStatus(status_str.lower())
        except ValueError:
            status = AssessmentStatus.NOT_ASSESSED

        # Parse gaps
        gaps = []
        for gap_data in assessment_data.get("gaps", []):
            try:
                severity_str = gap_data.get("severity", "medium")
                severity = GapSeverity(severity_str.lower())

                gap = ControlGap(
                    gap_id=str(uuid.uuid4()),
                    control_id=control_id,
                    description=gap_data.get("description", ""),
                    severity=severity,
                    patient_safety_impact=gap_data.get("patient_safety_impact", False),
                    breach_risk=gap_data.get("breach_risk", False),
                    root_cause=gap_data.get("root_cause", ""),
                    affected_systems=gap_data.get("affected_systems", []),
                    regulatory_citations=[]
                )
                gaps.append(gap)
            except Exception as e:
                logger.warning(f"Failed to parse gap: {e}")

        # Parse remediation actions
        remediation_actions = []
        for rem_data in assessment_data.get("remediation", []):
            try:
                priority_str = rem_data.get("priority", "ongoing")
                # Map priority string to enum
                priority_map = {
                    "immediate": RemediationPriority.IMMEDIATE,
                    "30days": RemediationPriority.DAYS_30,
                    "90days": RemediationPriority.DAYS_90,
                    "ongoing": RemediationPriority.ONGOING
                }
                priority = priority_map.get(priority_str, RemediationPriority.ONGOING)

                action = RemediationAction(
                    action_id=str(uuid.uuid4()),
                    gap_id=gaps[0].gap_id if gaps else "",
                    action=rem_data.get("action", ""),
                    effort_hours=rem_data.get("effort_hours", 0),
                    cost_estimate=rem_data.get("cost_estimate", 0),
                    priority=priority,
                    dependencies=rem_data.get("dependencies", []),
                    success_criteria=rem_data.get("success_criteria", [])
                )
                remediation_actions.append(action)
            except Exception as e:
                logger.warning(f"Failed to parse remediation action: {e}")

        # Build assessment
        assessment = ControlAssessment(
            assessment_id=str(uuid.uuid4()),
            control_id=control_id,
            status=status,
            confidence_score=float(assessment_data.get("confidence", 0.0)),
            evidence_found=assessment_data.get("evidence_found", []),
            evidence_missing=assessment_data.get("evidence_missing", []),
            gaps=gaps,
            remediation_actions=remediation_actions,
            regulatory_notes=assessment_data.get("regulatory_notes", "")
        )

        return assessment
