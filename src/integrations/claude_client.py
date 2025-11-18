"""
Claude AI Client (Anthropic API)

Wrapper for Claude Sonnet 4.5 API integration.
Specialized for compliance reasoning, deep security analysis, and policy interpretation.
"""

import anthropic
from typing import Dict, Any, List, Optional, AsyncIterator
import logging
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)


@dataclass
class ClaudeMessage:
    """Represents a message in Claude chat format."""
    role: str  # 'user' or 'assistant' (system is separate)
    content: str


class ClaudeClient:
    """
    Client for Anthropic Claude API.

    Optimized for:
    - Compliance framework analysis (HIPAA, ISO 27001, NIST CSF)
    - Deep threat assessment with reasoning
    - Policy interpretation and gap analysis
    - Complex security architecture review
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-5-20250929",
        max_tokens: int = 8192,
        timeout: int = 180
    ):
        """
        Initialize Claude client.

        Args:
            api_key: Anthropic API key
            model: Claude model identifier
            max_tokens: Maximum tokens to generate
            timeout: Request timeout in seconds
        """
        if not api_key:
            raise ValueError("Anthropic API key is required")

        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self.max_tokens = max_tokens
        self.timeout = timeout

        logger.info(f"Claude client initialized with model: {model}")

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.5,
        max_tokens: Optional[int] = None
    ) -> str:
        """
        Generate response from Claude.

        Args:
            prompt: User prompt
            system_prompt: System prompt for context
            temperature: Sampling temperature (0.0-1.0)
            max_tokens: Override default max tokens

        Returns:
            Generated response text
        """
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens or self.max_tokens,
                temperature=temperature,
                system=system_prompt or "",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            # Extract text from response
            response_text = ""
            for block in message.content:
                if hasattr(block, 'text'):
                    response_text += block.text

            return response_text

        except Exception as e:
            logger.error(f"Claude generation failed: {e}")
            raise RuntimeError(f"Failed to generate Claude response: {e}")

    def chat(
        self,
        messages: List[ClaudeMessage],
        system_prompt: Optional[str] = None,
        temperature: float = 0.5,
        max_tokens: Optional[int] = None
    ) -> str:
        """
        Multi-turn chat with Claude.

        Args:
            messages: Conversation history
            system_prompt: System prompt
            temperature: Sampling temperature
            max_tokens: Override default max tokens

        Returns:
            Assistant's response
        """
        try:
            formatted_messages = [
                {"role": msg.role, "content": msg.content}
                for msg in messages
            ]

            message = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens or self.max_tokens,
                temperature=temperature,
                system=system_prompt or "",
                messages=formatted_messages
            )

            # Extract text from response
            response_text = ""
            for block in message.content:
                if hasattr(block, 'text'):
                    response_text += block.text

            return response_text

        except Exception as e:
            logger.error(f"Claude chat failed: {e}")
            raise RuntimeError(f"Failed to chat with Claude: {e}")

    async def chat_stream_async(
        self,
        messages: List[ClaudeMessage],
        system_prompt: Optional[str] = None,
        temperature: float = 0.5,
        max_tokens: Optional[int] = None
    ) -> AsyncIterator[str]:
        """
        Async streaming chat with Claude.

        Args:
            messages: Conversation history
            system_prompt: System prompt
            temperature: Sampling temperature
            max_tokens: Override default max tokens

        Yields:
            Chunks of assistant's response
        """
        try:
            formatted_messages = [
                {"role": msg.role, "content": msg.content}
                for msg in messages
            ]

            async with self.client.messages.stream(
                model=self.model,
                max_tokens=max_tokens or self.max_tokens,
                temperature=temperature,
                system=system_prompt or "",
                messages=formatted_messages
            ) as stream:
                async for text in stream.text_stream:
                    yield text

        except Exception as e:
            logger.error(f"Claude streaming failed: {e}")
            raise RuntimeError(f"Failed to stream Claude response: {e}")

    def analyze_compliance_gap(
        self,
        framework: str,
        current_controls: Dict[str, Any],
        target_sector: str = "GENERAL"
    ) -> Dict[str, Any]:
        """
        Specialized compliance gap analysis using Claude's reasoning capabilities.

        Args:
            framework: Compliance framework (HIPAA, ISO27001, NIST_CSF, etc.)
            current_controls: Current security controls in place
            target_sector: Industry sector

        Returns:
            Structured gap analysis with remediation recommendations
        """
        system_prompt = f"""You are an expert compliance auditor and cybersecurity consultant specializing in {framework} compliance for the {target_sector} sector.

Your task is to perform a comprehensive gap analysis comparing current security controls against {framework} requirements.

Provide your analysis in the following structured format:

1. COMPLIANCE SCORE: Overall percentage (0-100%)
2. CRITICAL GAPS: Controls that are missing or inadequate with HIGH risk
3. MODERATE GAPS: Controls that need improvement with MEDIUM risk
4. MINOR GAPS: Controls that are partial or have LOW risk
5. STRENGTHS: Controls that meet or exceed requirements
6. PRIORITIZED REMEDIATION ROADMAP: Step-by-step action plan with effort estimates
7. COST ESTIMATE: Approximate investment needed for compliance
8. TIMELINE: Realistic timeline to achieve compliance

Be specific, actionable, and consider industry best practices."""

        controls_json = json.dumps(current_controls, indent=2)

        user_prompt = f"""Framework: {framework}
Sector: {target_sector}

Current Security Controls:
{controls_json}

Perform comprehensive gap analysis and provide remediation roadmap."""

        response = self.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.3  # Low temperature for factual compliance analysis
        )

        return {
            "framework": framework,
            "sector": target_sector,
            "analysis": response,
            "model": self.model,
            "current_controls": current_controls
        }

    def analyze_threat_deep(
        self,
        threat_data: str,
        context: Optional[str] = None,
        sector: str = "GENERAL",
        include_mitre_mapping: bool = True
    ) -> Dict[str, Any]:
        """
        Deep threat analysis with Claude's advanced reasoning.

        Args:
            threat_data: Threat information (logs, IOCs, etc.)
            context: Environmental context
            sector: Target sector
            include_mitre_mapping: Map to MITRE ATT&CK framework

        Returns:
            Comprehensive threat analysis
        """
        system_prompt = f"""You are an elite threat intelligence analyst with expertise in {sector} sector cybersecurity.

Analyze the provided threat data with deep reasoning and provide:

1. THREAT CLASSIFICATION: Type, sophistication level, likely threat actor profile
2. ATTACK CHAIN ANALYSIS: Step-by-step breakdown of the attack
3. SEVERITY ASSESSMENT: CRITICAL/HIGH/MEDIUM/LOW with justification
4. BUSINESS IMPACT: Specific impacts to {sector} operations
5. TECHNICAL INDICATORS: IOCs, TTPs, affected systems
{f'6. MITRE ATT&CK MAPPING: Techniques and sub-techniques used' if include_mitre_mapping else ''}
7. IMMEDIATE ACTIONS: Urgent containment steps
8. LONG-TERM REMEDIATION: Strategic improvements
9. THREAT HUNTING RECOMMENDATIONS: How to find similar threats

Provide evidence-based analysis with confidence levels."""

        user_prompt = f"""Threat Data:
{threat_data}

{f'Context: {context}' if context else ''}

Perform deep threat analysis."""

        response = self.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.4
        )

        return {
            "analysis": response,
            "model": self.model,
            "sector": sector,
            "threat_data": threat_data,
            "mitre_mapping_included": include_mitre_mapping
        }

    def interpret_security_policy(
        self,
        policy_text: str,
        policy_type: str,
        organization_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Interpret complex security policies and translate to actionable controls.

        Args:
            policy_text: Security policy document text
            policy_type: Type of policy (access_control, data_protection, incident_response, etc.)
            organization_context: Organization-specific context

        Returns:
            Policy interpretation with implementation guidance
        """
        system_prompt = f"""You are a cybersecurity policy expert specializing in {policy_type} policies.

Analyze the provided security policy and provide:

1. POLICY SUMMARY: High-level overview of requirements
2. MANDATORY CONTROLS: Must-implement security controls
3. RECOMMENDED CONTROLS: Best practice additions
4. IMPLEMENTATION STEPS: How to operationalize the policy
5. COMPLIANCE MAPPING: Relevant frameworks (HIPAA, ISO 27001, etc.)
6. GAPS AND AMBIGUITIES: Unclear requirements needing clarification
7. ENFORCEMENT MECHANISMS: How to monitor and enforce compliance
8. TRAINING REQUIREMENTS: What staff need to know

Be practical and implementation-focused."""

        user_prompt = f"""Policy Type: {policy_type}

{f'Organization Context: {organization_context}' if organization_context else ''}

Policy Document:
{policy_text}

Interpret and provide implementation guidance."""

        response = self.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.3
        )

        return {
            "policy_type": policy_type,
            "interpretation": response,
            "model": self.model
        }

    def generate_security_recommendations(
        self,
        assessment_data: Dict[str, Any],
        budget_level: str = "MODERATE",
        timeline_weeks: int = 12
    ) -> Dict[str, Any]:
        """
        Generate prioritized security improvement recommendations.

        Args:
            assessment_data: Security assessment results
            budget_level: Budget constraint (LOW, MODERATE, HIGH)
            timeline_weeks: Implementation timeline

        Returns:
            Prioritized recommendations with implementation plan
        """
        system_prompt = f"""You are a CISO advisor providing strategic security recommendations.

Given security assessment findings, budget constraints ({budget_level}), and timeline ({timeline_weeks} weeks), provide:

1. EXECUTIVE SUMMARY: Key findings and top 3 priorities
2. QUICK WINS: High-impact, low-effort improvements (0-4 weeks)
3. SHORT-TERM INITIATIVES: Medium complexity (4-8 weeks)
4. LONG-TERM STRATEGIC: Major investments (8-12+ weeks)
5. RISK PRIORITIZATION: What to tackle first and why
6. RESOURCE REQUIREMENTS: People, tools, budget needed
7. METRICS AND KPIs: How to measure success
8. ROI ANALYSIS: Value delivered vs investment

Be realistic about budget and timeline constraints."""

        assessment_json = json.dumps(assessment_data, indent=2)

        user_prompt = f"""Budget Level: {budget_level}
Timeline: {timeline_weeks} weeks

Security Assessment Data:
{assessment_json}

Generate prioritized recommendations with implementation plan."""

        response = self.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.4
        )

        return {
            "recommendations": response,
            "budget_level": budget_level,
            "timeline_weeks": timeline_weeks,
            "model": self.model
        }

    def check_health(self) -> bool:
        """
        Check if Claude API is accessible.

        Returns:
            True if healthy, False otherwise
        """
        try:
            # Simple test query
            self.generate("Hello", max_tokens=10)
            return True
        except:
            return False

    def __repr__(self) -> str:
        """String representation."""
        return f"<ClaudeClient model={self.model}>"
