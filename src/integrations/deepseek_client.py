"""
DeepSeek-R1 Client

Wrapper for DeepSeek-R1 model optimized for medical AI security analysis.
Specialized in adversarial ML, model safety, and healthcare AI threats.
"""

import requests
import json
from typing import Dict, Any, List, Optional, Iterator
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DeepSeekMessage:
    """Represents a message in DeepSeek chat format."""
    role: str  # 'system', 'user', or 'assistant'
    content: str


class DeepSeekClient:
    """
    Client for DeepSeek-R1 model.

    Optimized for:
    - Medical AI security analysis
    - Adversarial machine learning threats
    - Model inversion and data poisoning detection
    - Healthcare-specific threat scenarios
    - FDA AI/ML guidance compliance
    """

    def __init__(
        self,
        endpoint_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        model_name: str = "deepseek-r1",
        timeout: int = 180
    ):
        """
        Initialize DeepSeek client.

        Args:
            endpoint_url: DeepSeek API endpoint
            api_key: Optional API key (if using hosted service)
            model_name: Model identifier
            timeout: Request timeout in seconds
        """
        self.endpoint_url = endpoint_url.rstrip('/')
        self.api_key = api_key
        self.model_name = model_name
        self.timeout = timeout

        logger.info(f"DeepSeek client initialized: {model_name} at {endpoint_url}")

    def _get_headers(self) -> Dict[str, str]:
        """Get HTTP headers with optional API key."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        temperature: float = 0.6,
        max_tokens: int = 8192
    ) -> str:
        """
        Generate response from DeepSeek.

        Args:
            prompt: User prompt
            system_prompt: System prompt
            temperature: Sampling temperature
            max_tokens: Maximum tokens

        Returns:
            Generated response
        """
        url = f"{self.endpoint_url}/v1/chat/completions"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.model_name,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False
        }

        try:
            response = requests.post(
                url,
                headers=self._get_headers(),
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            return data["choices"][0]["message"]["content"]

        except requests.RequestException as e:
            logger.error(f"DeepSeek generation failed: {e}")
            raise RuntimeError(f"Failed to generate DeepSeek response: {e}")

    def chat(
        self,
        messages: List[DeepSeekMessage],
        temperature: float = 0.6,
        max_tokens: int = 8192
    ) -> str:
        """
        Multi-turn chat with DeepSeek.

        Args:
            messages: Conversation history
            temperature: Sampling temperature
            max_tokens: Maximum tokens

        Returns:
            Assistant response
        """
        url = f"{self.endpoint_url}/v1/chat/completions"

        formatted_messages = [
            {"role": msg.role, "content": msg.content}
            for msg in messages
        ]

        payload = {
            "model": self.model_name,
            "messages": formatted_messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "stream": False
        }

        try:
            response = requests.post(
                url,
                headers=self._get_headers(),
                json=payload,
                timeout=self.timeout
            )
            response.raise_for_status()

            data = response.json()
            return data["choices"][0]["message"]["content"]

        except requests.RequestException as e:
            logger.error(f"DeepSeek chat failed: {e}")
            raise RuntimeError(f"Failed to chat with DeepSeek: {e}")

    def analyze_medical_ai_threat(
        self,
        model_type: str,
        threat_scenario: str,
        context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Specialized medical AI threat analysis.

        Args:
            model_type: Type of medical AI model (diagnostic, predictive, generative, etc.)
            threat_scenario: Threat description (adversarial examples, data poisoning, etc.)
            context: Additional context (deployment environment, data types, etc.)

        Returns:
            Comprehensive medical AI security analysis
        """
        system_prompt = f"""You are an expert in medical AI security and adversarial machine learning.

Analyze the provided threat scenario for a {model_type} medical AI model.

Provide comprehensive analysis covering:

1. THREAT ASSESSMENT:
   - Attack vector and feasibility
   - Required attacker capabilities
   - Likelihood in real-world medical settings

2. PATIENT SAFETY IMPACT:
   - Direct risks to patient care
   - Potential for misdiagnosis or incorrect treatment
   - Severity of clinical consequences

3. FDA AI/ML GUIDANCE COMPLIANCE:
   - Relevant FDA requirements
   - Compliance gaps exposed by this threat
   - Regulatory reporting obligations

4. TECHNICAL MITIGATIONS:
   - Model hardening techniques
   - Input validation and sanitization
   - Adversarial training recommendations
   - Ensemble methods and redundancy

5. OPERATIONAL MITIGATIONS:
   - Human-in-the-loop safeguards
   - Clinical validation processes
   - Monitoring and alerting

6. HIPAA CONSIDERATIONS:
   - PHI exposure risks
   - Privacy implications
   - Security Rule compliance

7. DETECTION STRATEGIES:
   - How to identify this attack in production
   - Monitoring metrics and anomaly detection
   - Incident response procedures

Be medically informed and prioritize patient safety."""

        user_prompt = f"""Model Type: {model_type}

Threat Scenario:
{threat_scenario}

{f'Context: {context}' if context else ''}

Analyze medical AI security threat."""

        response = self.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.5
        )

        return {
            "analysis": response,
            "model_type": model_type,
            "threat_scenario": threat_scenario,
            "model": self.model_name
        }

    def assess_model_robustness(
        self,
        model_architecture: str,
        training_data_description: str,
        deployment_environment: str
    ) -> Dict[str, Any]:
        """
        Assess ML model robustness against adversarial attacks.

        Args:
            model_architecture: Neural network architecture
            training_data_description: Description of training data
            deployment_environment: Where model will be deployed

        Returns:
            Robustness assessment with recommendations
        """
        system_prompt = """You are an expert in adversarial machine learning and model security.

Assess the robustness of the described ML model against adversarial attacks.

Provide detailed analysis of:

1. ATTACK SURFACE ANALYSIS:
   - Input manipulation vulnerabilities
   - Training data poisoning risks
   - Model extraction threats
   - Membership inference risks

2. ADVERSARIAL ROBUSTNESS:
   - Susceptibility to adversarial examples
   - Perturbation sensitivity
   - Transfer attack vulnerabilities

3. DATA POISONING RISKS:
   - Training data validation gaps
   - Backdoor attack feasibility
   - Data integrity requirements

4. MODEL INVERSION RISKS:
   - Privacy leakage potential
   - Reconstruction attack feasibility
   - Sensitive information exposure

5. HARDENING RECOMMENDATIONS:
   - Adversarial training strategies
   - Input preprocessing and validation
   - Ensemble methods and voting
   - Certified defenses (if applicable)

6. MONITORING AND DETECTION:
   - Runtime anomaly detection
   - Distribution shift monitoring
   - Performance degradation alerts

Be technically rigorous and provide actionable recommendations."""

        user_prompt = f"""Model Architecture:
{model_architecture}

Training Data:
{training_data_description}

Deployment Environment:
{deployment_environment}

Assess model robustness and provide hardening recommendations."""

        response = self.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.5
        )

        return {
            "assessment": response,
            "model_architecture": model_architecture,
            "deployment_environment": deployment_environment,
            "model": self.model_name
        }

    def analyze_prompt_injection(
        self,
        llm_application_description: str,
        attack_vector: str,
        mitigation_context: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Analyze prompt injection and jailbreak vulnerabilities in LLM applications.

        Args:
            llm_application_description: Description of LLM application
            attack_vector: Prompt injection attack vector
            mitigation_context: Existing mitigations in place

        Returns:
            Prompt injection analysis and defenses
        """
        system_prompt = """You are an expert in large language model security, specializing in prompt injection and jailbreak attacks.

Analyze the provided prompt injection attack vector and provide:

1. ATTACK ANALYSIS:
   - Attack mechanism and objectives
   - Effectiveness assessment
   - Required attacker knowledge

2. BYPASS TECHNIQUES:
   - How this attack circumvents defenses
   - Variations and evasion methods
   - Chaining with other attack vectors

3. IMPACT ASSESSMENT:
   - Data exfiltration risks
   - Unauthorized actions
   - System compromise potential
   - Reputation damage

4. DEFENSE MECHANISMS:
   - Input validation and sanitization
   - Output filtering and safety checks
   - Context isolation techniques
   - Structured prompting strategies
   - Model-level defenses

5. SECURE DESIGN PATTERNS:
   - Principle of least privilege for LLMs
   - Sandboxing and containment
   - Human-in-the-loop for sensitive actions
   - Audit logging and monitoring

6. TESTING RECOMMENDATIONS:
   - Red team test cases
   - Automated security testing
   - Continuous monitoring strategies

Provide practical, implementable defenses."""

        user_prompt = f"""LLM Application:
{llm_application_description}

Attack Vector:
{attack_vector}

{f'Existing Mitigations: {mitigation_context}' if mitigation_context else ''}

Analyze prompt injection vulnerability and provide defenses."""

        response = self.generate(
            prompt=user_prompt,
            system_prompt=system_prompt,
            temperature=0.5
        )

        return {
            "analysis": response,
            "application": llm_application_description,
            "attack_vector": attack_vector,
            "model": self.model_name
        }

    def check_health(self) -> bool:
        """
        Check if DeepSeek service is healthy.

        Returns:
            True if healthy, False otherwise
        """
        try:
            # Simple health check
            response = requests.get(f"{self.endpoint_url}/health", timeout=5)
            return response.status_code == 200
        except:
            # If no dedicated health endpoint, try a simple generation
            try:
                self.generate("Test", max_tokens=10)
                return True
            except:
                return False

    def __repr__(self) -> str:
        """String representation."""
        return f"<DeepSeekClient model={self.model_name} endpoint={self.endpoint_url}>"
