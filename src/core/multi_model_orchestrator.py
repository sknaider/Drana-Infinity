"""
Multi-Model AI Orchestrator

Intelligently routes requests to the most appropriate AI model:
- Ollama (drana-infinity-v1): General cybersecurity, fast responses, local processing
- Claude Sonnet 4.5: Compliance analysis, deep reasoning, policy interpretation
- DeepSeek-R1: Medical AI security, adversarial ML, healthcare threats

Implements fallback mechanisms, load balancing, and response synthesis.
"""

from typing import Dict, Any, List, Optional, Union
from enum import Enum
import logging
from dataclasses import dataclass
import asyncio
from concurrent.futures import ThreadPoolExecutor
import time

from ..integrations.ollama_client import OllamaClient, OllamaMessage
from ..integrations.claude_client import ClaudeClient, ClaudeMessage
from ..integrations.deepseek_client import DeepSeekClient, DeepSeekMessage
from .config_manager import ConfigManager

logger = logging.getLogger(__name__)


class TaskType(Enum):
    """Types of security analysis tasks."""
    GENERAL_THREAT = "general_threat"
    COMPLIANCE_ANALYSIS = "compliance_analysis"
    MEDICAL_AI_SECURITY = "medical_ai_security"
    VULNERABILITY_ASSESSMENT = "vulnerability_assessment"
    POLICY_INTERPRETATION = "policy_interpretation"
    THREAT_INTELLIGENCE = "threat_intelligence"
    INCIDENT_RESPONSE = "incident_response"
    PENETRATION_TEST = "penetration_test"
    ADVERSARIAL_ML = "adversarial_ml"
    SECURITY_ARCHITECTURE = "security_architecture"


class ModelPreference(Enum):
    """Model selection preferences."""
    SPEED = "speed"  # Prefer fastest model
    ACCURACY = "accuracy"  # Prefer most accurate model
    COST = "cost"  # Prefer cheapest model (local > API)
    BALANCED = "balanced"  # Balance speed/accuracy/cost


@dataclass
class ModelCapability:
    """Defines capabilities and performance of each model."""
    name: str
    strengths: List[TaskType]
    avg_latency_seconds: float
    cost_per_1k_tokens: float
    local: bool
    priority: int


@dataclass
class OrchestratorResponse:
    """Response from orchestrator with metadata."""
    content: str
    primary_model: str
    fallback_used: bool
    latency_seconds: float
    task_type: TaskType
    confidence_score: float  # 0.0-1.0


class MultiModelOrchestrator:
    """
    Orchestrates multiple AI models for optimal security analysis.

    Routing Strategy:
    1. Analyzes task requirements
    2. Selects best model based on capabilities and preferences
    3. Implements fallback if primary model fails
    4. Can combine outputs from multiple models for critical tasks
    """

    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize multi-model orchestrator.

        Args:
            config: Configuration manager instance
        """
        from .config_manager import get_config
        self.config = config or get_config()

        # Initialize AI clients
        self._init_clients()

        # Define model capabilities
        self._define_capabilities()

        # Health check
        self._check_model_health()

        logger.info("Multi-model orchestrator initialized successfully")

    def _init_clients(self) -> None:
        """Initialize AI model clients based on configuration."""
        self.clients: Dict[str, Union[OllamaClient, ClaudeClient, DeepSeekClient]] = {}

        # Initialize Ollama
        if self.config.ai_models["ollama"].enabled:
            try:
                ollama_config = self.config.ai_models["ollama"]
                self.clients["ollama"] = OllamaClient(
                    endpoint_url=ollama_config.endpoint_url,
                    model_name=ollama_config.model_name,
                    timeout=ollama_config.timeout_seconds
                )
                logger.info("Ollama client initialized")
            except Exception as e:
                logger.error(f"Failed to initialize Ollama: {e}")

        # Initialize Claude
        if self.config.ai_models["claude"].enabled:
            try:
                claude_config = self.config.ai_models["claude"]
                if claude_config.api_key:
                    self.clients["claude"] = ClaudeClient(
                        api_key=claude_config.api_key,
                        model=claude_config.model_name,
                        max_tokens=claude_config.max_tokens,
                        timeout=claude_config.timeout_seconds
                    )
                    logger.info("Claude client initialized")
                else:
                    logger.warning("Claude API key not provided, skipping initialization")
            except Exception as e:
                logger.error(f"Failed to initialize Claude: {e}")

        # Initialize DeepSeek
        if self.config.ai_models["deepseek"].enabled:
            try:
                deepseek_config = self.config.ai_models["deepseek"]
                self.clients["deepseek"] = DeepSeekClient(
                    endpoint_url=deepseek_config.endpoint_url,
                    api_key=deepseek_config.api_key,
                    model_name=deepseek_config.model_name,
                    timeout=deepseek_config.timeout_seconds
                )
                logger.info("DeepSeek client initialized")
            except Exception as e:
                logger.error(f"Failed to initialize DeepSeek: {e}")

    def _define_capabilities(self) -> None:
        """Define capabilities and characteristics of each model."""
        self.model_capabilities = {
            "ollama": ModelCapability(
                name="Ollama (drana-infinity-v1)",
                strengths=[
                    TaskType.GENERAL_THREAT,
                    TaskType.VULNERABILITY_ASSESSMENT,
                    TaskType.THREAT_INTELLIGENCE,
                    TaskType.INCIDENT_RESPONSE,
                    TaskType.PENETRATION_TEST
                ],
                avg_latency_seconds=2.0,
                cost_per_1k_tokens=0.0,  # Local, no cost
                local=True,
                priority=1
            ),
            "claude": ModelCapability(
                name="Claude Sonnet 4.5",
                strengths=[
                    TaskType.COMPLIANCE_ANALYSIS,
                    TaskType.POLICY_INTERPRETATION,
                    TaskType.SECURITY_ARCHITECTURE,
                    TaskType.GENERAL_THREAT  # Deep analysis variant
                ],
                avg_latency_seconds=3.5,
                cost_per_1k_tokens=0.003,  # $3 per million tokens
                local=False,
                priority=2
            ),
            "deepseek": ModelCapability(
                name="DeepSeek-R1",
                strengths=[
                    TaskType.MEDICAL_AI_SECURITY,
                    TaskType.ADVERSARIAL_ML,
                ],
                avg_latency_seconds=3.0,
                cost_per_1k_tokens=0.001,  # Estimate
                local=False,  # Can be local or API
                priority=3
            )
        }

    def _check_model_health(self) -> None:
        """Check health status of all configured models."""
        self.model_health: Dict[str, bool] = {}

        for model_name, client in self.clients.items():
            try:
                health = client.check_health()
                self.model_health[model_name] = health
                status = "healthy" if health else "unhealthy"
                logger.info(f"Model {model_name}: {status}")
            except Exception as e:
                self.model_health[model_name] = False
                logger.warning(f"Health check failed for {model_name}: {e}")

    def select_model(
        self,
        task_type: TaskType,
        preference: ModelPreference = ModelPreference.BALANCED,
        sector: str = "GENERAL"
    ) -> str:
        """
        Select the best model for a given task.

        Args:
            task_type: Type of analysis task
            preference: Model selection preference
            sector: Target sector (influences selection)

        Returns:
            Selected model name
        """
        # Special case: Medical AI tasks always use DeepSeek if available
        if task_type in [TaskType.MEDICAL_AI_SECURITY, TaskType.ADVERSARIAL_ML]:
            if "deepseek" in self.clients and self.model_health.get("deepseek", False):
                return "deepseek"

        # Compliance and policy tasks prefer Claude
        if task_type in [TaskType.COMPLIANCE_ANALYSIS, TaskType.POLICY_INTERPRETATION]:
            if "claude" in self.clients and self.model_health.get("claude", False):
                return "claude"

        # Apply preference-based selection
        if preference == ModelPreference.SPEED:
            # Prefer local, fast models
            if "ollama" in self.clients and self.model_health.get("ollama", False):
                return "ollama"

        elif preference == ModelPreference.COST:
            # Prefer free/local models
            if "ollama" in self.clients and self.model_health.get("ollama", False):
                return "ollama"

        elif preference == ModelPreference.ACCURACY:
            # Prefer Claude for deep analysis
            if "claude" in self.clients and self.model_health.get("claude", False):
                return "claude"

        # Balanced: select based on task type strengths
        candidates = []
        for model_name, capability in self.model_capabilities.items():
            if model_name in self.clients and self.model_health.get(model_name, False):
                if task_type in capability.strengths:
                    candidates.append((model_name, capability.priority))

        if candidates:
            # Sort by priority (lower is better)
            candidates.sort(key=lambda x: x[1])
            return candidates[0][0]

        # Fallback: return first available healthy model
        for model_name in ["ollama", "claude", "deepseek"]:
            if model_name in self.clients and self.model_health.get(model_name, False):
                logger.warning(f"Using fallback model {model_name} for {task_type}")
                return model_name

        raise RuntimeError("No healthy AI models available")

    def analyze(
        self,
        prompt: str,
        task_type: TaskType = TaskType.GENERAL_THREAT,
        context: Optional[str] = None,
        sector: str = "GENERAL",
        preference: ModelPreference = ModelPreference.BALANCED,
        enable_fallback: bool = True
    ) -> OrchestratorResponse:
        """
        Analyze security data using the most appropriate AI model.

        Args:
            prompt: Analysis prompt
            task_type: Type of task
            context: Additional context
            sector: Target sector
            preference: Model selection preference
            enable_fallback: Enable fallback to alternate models on failure

        Returns:
            Orchestrator response with analysis
        """
        start_time = time.time()

        # Select primary model
        primary_model = self.select_model(task_type, preference, sector)
        logger.info(f"Selected {primary_model} for {task_type.value}")

        # Attempt analysis with primary model
        try:
            response_text = self._execute_analysis(
                model_name=primary_model,
                prompt=prompt,
                context=context,
                sector=sector,
                task_type=task_type
            )

            latency = time.time() - start_time

            return OrchestratorResponse(
                content=response_text,
                primary_model=primary_model,
                fallback_used=False,
                latency_seconds=latency,
                task_type=task_type,
                confidence_score=0.9  # High confidence on primary model
            )

        except Exception as e:
            logger.error(f"Primary model {primary_model} failed: {e}")

            if not enable_fallback:
                raise

            # Attempt fallback
            return self._execute_fallback(
                prompt=prompt,
                context=context,
                sector=sector,
                task_type=task_type,
                failed_model=primary_model,
                start_time=start_time
            )

    def _execute_analysis(
        self,
        model_name: str,
        prompt: str,
        context: Optional[str],
        sector: str,
        task_type: TaskType
    ) -> str:
        """Execute analysis on specified model."""
        client = self.clients[model_name]

        # Build full prompt with context
        full_prompt = prompt
        if context:
            full_prompt = f"Context: {context}\n\n{prompt}"

        # Execute based on model type
        if model_name == "ollama":
            system_prompt = f"You are Drana-Infinity, an expert cybersecurity AI specializing in {sector} sector security."
            return client.generate(full_prompt, system_prompt=system_prompt)

        elif model_name == "claude":
            system_prompt = f"You are an expert cybersecurity consultant specializing in {task_type.value} for the {sector} sector."
            return client.generate(full_prompt, system_prompt=system_prompt)

        elif model_name == "deepseek":
            system_prompt = f"You are an expert in {task_type.value} with deep knowledge of {sector} sector threats."
            return client.generate(full_prompt, system_prompt=system_prompt)

        else:
            raise ValueError(f"Unknown model: {model_name}")

    def _execute_fallback(
        self,
        prompt: str,
        context: Optional[str],
        sector: str,
        task_type: TaskType,
        failed_model: str,
        start_time: float
    ) -> OrchestratorResponse:
        """Execute fallback to alternate models."""
        # Try other healthy models
        for model_name in ["ollama", "claude", "deepseek"]:
            if model_name == failed_model:
                continue

            if model_name in self.clients and self.model_health.get(model_name, False):
                logger.info(f"Attempting fallback to {model_name}")

                try:
                    response_text = self._execute_analysis(
                        model_name=model_name,
                        prompt=prompt,
                        context=context,
                        sector=sector,
                        task_type=task_type
                    )

                    latency = time.time() - start_time

                    return OrchestratorResponse(
                        content=response_text,
                        primary_model=model_name,
                        fallback_used=True,
                        latency_seconds=latency,
                        task_type=task_type,
                        confidence_score=0.7  # Lower confidence on fallback
                    )

                except Exception as e:
                    logger.error(f"Fallback model {model_name} also failed: {e}")
                    continue

        raise RuntimeError(f"All models failed for task {task_type.value}")

    def analyze_multi_model(
        self,
        prompt: str,
        task_type: TaskType = TaskType.GENERAL_THREAT,
        context: Optional[str] = None,
        sector: str = "GENERAL",
        models: Optional[List[str]] = None
    ) -> Dict[str, OrchestratorResponse]:
        """
        Analyze using multiple models simultaneously for critical tasks.

        Args:
            prompt: Analysis prompt
            task_type: Type of task
            context: Additional context
            sector: Target sector
            models: Specific models to use (default: all healthy models)

        Returns:
            Dictionary of model_name -> response
        """
        if models is None:
            models = [m for m in self.clients.keys() if self.model_health.get(m, False)]

        results = {}

        # Execute in parallel using ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=len(models)) as executor:
            futures = {}

            for model_name in models:
                if model_name not in self.clients:
                    continue

                future = executor.submit(
                    self.analyze,
                    prompt=prompt,
                    task_type=task_type,
                    context=context,
                    sector=sector,
                    preference=ModelPreference.BALANCED,
                    enable_fallback=False
                )
                futures[model_name] = future

            # Collect results
            for model_name, future in futures.items():
                try:
                    results[model_name] = future.result(timeout=180)
                except Exception as e:
                    logger.error(f"Multi-model analysis failed for {model_name}: {e}")

        return results

    def synthesize_responses(
        self,
        responses: Dict[str, OrchestratorResponse],
        synthesis_model: str = "claude"
    ) -> str:
        """
        Synthesize multiple model responses into a unified analysis.

        Args:
            responses: Dictionary of model responses
            synthesis_model: Model to use for synthesis (default: Claude)

        Returns:
            Synthesized analysis
        """
        if synthesis_model not in self.clients:
            raise ValueError(f"Synthesis model {synthesis_model} not available")

        # Compile all responses
        compiled = "Multiple AI models have analyzed this security issue:\n\n"

        for model_name, response in responses.items():
            compiled += f"## {self.model_capabilities[model_name].name}\n"
            compiled += f"{response.content}\n\n"

        # Ask synthesis model to combine insights
        synthesis_prompt = f"""You are synthesizing security analysis from multiple AI models.

{compiled}

Provide a unified, comprehensive analysis that:
1. Combines unique insights from each model
2. Resolves any contradictions with explanation
3. Provides consensus severity assessment
4. Consolidates all recommended actions
5. Highlights areas of agreement and disagreement

Deliver a clear, actionable synthesis."""

        client = self.clients[synthesis_model]
        return client.generate(synthesis_prompt)

    def get_model_stats(self) -> Dict[str, Any]:
        """
        Get statistics about model usage and health.

        Returns:
            Dictionary of model statistics
        """
        stats = {
            "total_models": len(self.clients),
            "healthy_models": sum(1 for h in self.model_health.values() if h),
            "models": {}
        }

        for model_name, client in self.clients.items():
            stats["models"][model_name] = {
                "healthy": self.model_health.get(model_name, False),
                "capabilities": self.model_capabilities[model_name].strengths,
                "local": self.model_capabilities[model_name].local,
                "priority": self.model_capabilities[model_name].priority
            }

        return stats

    def __repr__(self) -> str:
        """String representation."""
        healthy = sum(1 for h in self.model_health.values() if h)
        return f"<MultiModelOrchestrator models={len(self.clients)} healthy={healthy}>"
