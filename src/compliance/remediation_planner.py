"""
HIPAA Remediation Planning Engine

Generates phased remediation roadmaps with prioritization, resource
allocation, and timeline planning using Claude AI.
"""

import asyncio
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from .control_assessor import (
    ControlAssessment,
    RemediationAction,
    RemediationPriority,
    RemediationPhase,
    RemediationRoadmap,
    GapSeverity
)
from .gap_analyzer import GapAnalysisReport
from ...integrations.claude_client import ClaudeClient
from ...core.config_manager import get_config

logger = logging.getLogger(__name__)


class HIPAARemediationPlanner:
    """
    Generates prioritized HIPAA remediation roadmaps using Claude AI.

    Creates phased implementation plans with:
    - Phase 1 (0-30 days): Critical gaps
    - Phase 2 (30-90 days): High-priority gaps
    - Phase 3 (90-180 days): Medium-priority gaps
    - Phase 4 (Ongoing): Continuous improvement
    """

    ROADMAP_PROMPT_TEMPLATE = """You are a HIPAA compliance consultant creating a remediation roadmap.

**CURRENT STATE**:
- Overall Compliance: {compliance_score:.1f}%
- Critical Gaps: {critical_count}
- High Priority Gaps: {high_count}
- Medium Priority Gaps: {medium_count}
- Low Priority Gaps: {low_count}

**GAPS SUMMARY**:
{gaps_summary}

**PATIENT SAFETY GAPS**:
{patient_safety_gaps}

**BREACH RISK GAPS**:
{breach_risk_gaps}

**CONSTRAINTS**:
- Budget: ${budget:,} USD
- Timeline: {timeline_weeks} weeks
- Team Size: {team_size} people
- Available Hours/Week: {available_hours} hours

**TASK**:
Create a phased remediation roadmap that:
1. Prioritizes patient safety and breach prevention
2. Addresses critical gaps in Phase 1 (0-30 days)
3. Fits within budget and timeline constraints
4. Balances quick wins with strategic improvements
5. Considers resource availability

Provide roadmap in JSON format:
{{
    "phases": [
        {{
            "phase_number": 1,
            "phase_name": "Critical Gaps & Immediate Actions",
            "duration_days": 30,
            "actions": [
                {{
                    "action_id": "action-1",
                    "description": "specific action",
                    "control_id": "164.xxx",
                    "effort_hours": hours,
                    "cost": cost_usd,
                    "assigned_to": "role or team",
                    "success_criteria": ["measurable outcome"],
                    "dependencies": ["prerequisite actions"]
                }}
            ],
            "phase_success_criteria": ["overall phase goals"]
        }}
    ],
    "resource_requirements": {{
        "full_time_staff": number,
        "consultants": number,
        "tools_and_software": ["list"],
        "training_needs": ["list"]
    }},
    "risk_mitigation": ["risks and mitigation strategies"],
    "key_milestones": [
        {{
            "milestone": "description",
            "target_date_offset_days": days_from_start,
            "success_criteria": ["criteria"]
        }}
    ]
}}

Be specific and actionable. Ensure realistic timelines."""

    def __init__(self, claude_client: Optional[ClaudeClient] = None):
        """
        Initialize remediation planner.

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
                raise ValueError("Claude API required for remediation planning")

        logger.info("HIPAA Remediation Planner initialized")

    async def generate_roadmap(
        self,
        gap_report: GapAnalysisReport,
        assessments: List[ControlAssessment],
        constraints: Optional[Dict[str, Any]] = None
    ) -> RemediationRoadmap:
        """
        Generate comprehensive remediation roadmap.

        Args:
            gap_report: Gap analysis report
            assessments: All control assessments
            constraints: Budget, timeline, resource constraints

        Returns:
            Complete remediation roadmap
        """
        logger.info("Generating HIPAA remediation roadmap")

        # Apply default constraints if not provided
        constraints = constraints or {}
        budget = constraints.get("budget_usd", 50000)
        timeline_weeks = constraints.get("timeline_weeks", 26)  # 6 months
        team_size = constraints.get("team_size", 2)
        available_hours = constraints.get("available_hours_per_week", 40)

        # Prepare gaps summary
        gaps_summary = self._format_gaps_summary(gap_report)

        # Get patient safety and breach risk gaps
        patient_safety_gaps = [
            g for g in (gap_report.critical_gaps + gap_report.high_gaps)
            if g.patient_safety_impact
        ]

        breach_risk_gaps = [
            g for g in (gap_report.critical_gaps + gap_report.high_gaps)
            if g.breach_risk
        ]

        patient_safety_summary = "\n".join(
            f"- {g.description} (Control: {g.control_id})"
            for g in patient_safety_gaps[:5]
        ) or "None identified"

        breach_risk_summary = "\n".join(
            f"- {g.description} (Control: {g.control_id})"
            for g in breach_risk_gaps[:5]
        ) or "None identified"

        # Build prompt
        prompt = self.ROADMAP_PROMPT_TEMPLATE.format(
            compliance_score=gap_report.overall_compliance_score,
            critical_count=len(gap_report.critical_gaps),
            high_count=len(gap_report.high_gaps),
            medium_count=len(gap_report.medium_gaps),
            low_count=len(gap_report.low_gaps),
            gaps_summary=gaps_summary,
            patient_safety_gaps=patient_safety_summary,
            breach_risk_gaps=breach_risk_summary,
            budget=budget,
            timeline_weeks=timeline_weeks,
            team_size=team_size,
            available_hours=available_hours
        )

        # Query Claude
        try:
            response = await asyncio.to_thread(
                self.claude.generate,
                prompt,
                temperature=0.4  # Balanced creativity and consistency
            )

            # Parse response
            roadmap_data = self._parse_claude_roadmap(response)

            # Build roadmap object
            roadmap = self._build_roadmap(
                gap_report=gap_report,
                assessments=assessments,
                roadmap_data=roadmap_data,
                constraints=constraints
            )

            logger.info(
                f"Roadmap generated: {len(roadmap.phases)} phases, "
                f"{roadmap.total_duration_days} days, "
                f"{roadmap.total_effort_hours} hours"
            )

            return roadmap

        except Exception as e:
            logger.error(f"Roadmap generation failed: {e}")

            # Return basic roadmap
            return self._generate_basic_roadmap(gap_report, assessments, constraints)

    def _format_gaps_summary(self, gap_report: GapAnalysisReport) -> str:
        """Format gaps for prompt."""
        lines = []

        if gap_report.critical_gaps:
            lines.append("**CRITICAL GAPS:**")
            for gap in gap_report.critical_gaps[:3]:
                lines.append(f"- {gap.description} (Control: {gap.control_id})")

        if gap_report.high_gaps:
            lines.append("\n**HIGH PRIORITY GAPS:**")
            for gap in gap_report.high_gaps[:5]:
                lines.append(f"- {gap.description} (Control: {gap.control_id})")

        if gap_report.medium_gaps:
            lines.append(f"\n**MEDIUM PRIORITY**: {len(gap_report.medium_gaps)} gaps")

        if gap_report.low_gaps:
            lines.append(f"**LOW PRIORITY**: {len(gap_report.low_gaps)} gaps")

        return "\n".join(lines)

    def _parse_claude_roadmap(self, response: str) -> Dict[str, Any]:
        """Parse Claude's JSON roadmap response."""
        import json

        try:
            # Extract JSON
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1

            if start_idx != -1 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                data = json.loads(json_str)
                return data
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse roadmap JSON: {e}")

        # Fallback
        return {"phases": []}

    def _build_roadmap(
        self,
        gap_report: GapAnalysisReport,
        assessments: List[ControlAssessment],
        roadmap_data: Dict[str, Any],
        constraints: Dict[str, Any]
    ) -> RemediationRoadmap:
        """Build RemediationRoadmap object."""
        phases = []
        total_effort = 0
        total_cost = 0

        # Process phases from Claude
        for phase_data in roadmap_data.get("phases", []):
            actions = []

            for action_data in phase_data.get("actions", []):
                # Find corresponding remediation action
                effort = action_data.get("effort_hours", 0)
                cost = action_data.get("cost", 0)

                action = RemediationAction(
                    action_id=action_data.get("action_id", f"action-{len(actions)}"),
                    gap_id="",  # Would link to specific gap
                    action=action_data.get("description", ""),
                    effort_hours=effort,
                    cost_estimate=cost,
                    priority=RemediationPriority.IMMEDIATE,  # Based on phase
                    dependencies=action_data.get("dependencies", []),
                    success_criteria=action_data.get("success_criteria", []),
                    assigned_to=action_data.get("assigned_to")
                )
                actions.append(action)

            phase_effort = sum(a.effort_hours for a in actions)
            phase_cost = sum(a.cost_estimate for a in actions)

            phase = RemediationPhase(
                phase_number=phase_data.get("phase_number", len(phases) + 1),
                phase_name=phase_data.get("phase_name", f"Phase {len(phases) + 1}"),
                duration_days=phase_data.get("duration_days", 30),
                actions=actions,
                total_effort_hours=phase_effort,
                total_cost=phase_cost,
                success_criteria=phase_data.get("phase_success_criteria", [])
            )
            phases.append(phase)

            total_effort += phase_effort
            total_cost += phase_cost

        # Calculate total duration
        total_duration = sum(p.duration_days for p in phases)

        # Build roadmap
        roadmap = RemediationRoadmap(
            roadmap_id=f"ROADMAP-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            target_system=gap_report.target_system,
            phases=phases,
            total_duration_days=total_duration,
            total_effort_hours=total_effort,
            total_cost=total_cost,
            resource_requirements=roadmap_data.get("resource_requirements", {}),
            constraints=constraints
        )

        return roadmap

    def _generate_basic_roadmap(
        self,
        gap_report: GapAnalysisReport,
        assessments: List[ControlAssessment],
        constraints: Dict[str, Any]
    ) -> RemediationRoadmap:
        """Generate basic roadmap without Claude (fallback)."""
        phases = []

        # Phase 1: Critical gaps (0-30 days)
        critical_actions = []
        for assessment in assessments:
            for action in assessment.remediation_actions:
                if action.priority == RemediationPriority.IMMEDIATE:
                    critical_actions.append(action)

        if critical_actions:
            phase1 = RemediationPhase(
                phase_number=1,
                phase_name="Critical Gaps & Immediate Actions",
                duration_days=30,
                actions=critical_actions,
                total_effort_hours=sum(a.effort_hours for a in critical_actions),
                total_cost=sum(a.cost_estimate for a in critical_actions),
                success_criteria=["All critical gaps addressed"]
            )
            phases.append(phase1)

        # Phase 2: High priority (30-90 days)
        high_actions = []
        for assessment in assessments:
            for action in assessment.remediation_actions:
                if action.priority == RemediationPriority.DAYS_30:
                    high_actions.append(action)

        if high_actions:
            phase2 = RemediationPhase(
                phase_number=2,
                phase_name="High Priority Improvements",
                duration_days=60,
                actions=high_actions,
                total_effort_hours=sum(a.effort_hours for a in high_actions),
                total_cost=sum(a.cost_estimate for a in high_actions),
                success_criteria=["All high priority gaps addressed"]
            )
            phases.append(phase2)

        # Calculate totals
        total_effort = sum(p.total_effort_hours for p in phases)
        total_cost = sum(p.total_cost for p in phases)
        total_duration = sum(p.duration_days for p in phases)

        roadmap = RemediationRoadmap(
            roadmap_id=f"ROADMAP-BASIC-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            target_system=gap_report.target_system,
            phases=phases,
            total_duration_days=total_duration,
            total_effort_hours=total_effort,
            total_cost=total_cost,
            resource_requirements={},
            constraints=constraints
        )

        return roadmap
