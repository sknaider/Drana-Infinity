"""
Enhanced Multi-Model AI Orchestrator

Sophisticated orchestration layer with:
- Intelligent routing based on query complexity and severity
- Parallel execution with asyncio
- Result synthesis and deduplication
- Confidence scoring based on model agreement
- Advanced error handling with partial results
"""

import asyncio
import hashlib
import json
import logging
import time
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import asdict

from ..integrations.ollama_client import OllamaClient, OllamaMessage
from ..integrations.claude_client import ClaudeClient, ClaudeMessage
from ..integrations.deepseek_client import DeepSeekClient, DeepSeekMessage
from .config_manager import ConfigManager, get_config
from .threat_analysis_models import (
    ThreatAnalysisRequest,
    ThreatAnalysisResponse,
    Finding,
    Recommendation,
    ComplianceImpact,
    ModelPerformanceMetrics,
    Severity,
    Priority,
    ScanType
)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class EnhancedMultiModelOrchestrator:
    """
    Advanced orchestrator for multi-model threat analysis.

    Features:
    - Intelligent routing based on scan type, priority, and sector
    - Parallel execution with configurable timeouts
    - Result synthesis with deduplication and confidence scoring
    - Graceful degradation on partial failures
    - Performance monitoring and metrics
    """

    # Model timeouts (seconds)
    OLLAMA_TIMEOUT = 30
    CLAUDE_TIMEOUT = 60
    DEEPSEEK_TIMEOUT = 90

    # Severity scoring for prioritization
    SEVERITY_SCORES = {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 2,
        "info": 1
    }

    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize enhanced orchestrator.

        Args:
            config: Configuration manager instance
        """
        self.config = config or get_config()

        # Initialize model clients
        self.clients: Dict[str, Any] = {}
        self.model_health: Dict[str, bool] = {}
        self._init_clients()

        # Performance tracking
        self.metrics: List[ModelPerformanceMetrics] = []

        logger.info("Enhanced Multi-Model Orchestrator initialized")

    def _init_clients(self) -> None:
        """Initialize AI model clients with error handling."""
        # Initialize Ollama
        if self.config.ai_models["ollama"].enabled:
            try:
                ollama_config = self.config.ai_models["ollama"]
                self.clients["ollama"] = OllamaClient(
                    endpoint_url=ollama_config.endpoint_url,
                    model_name=ollama_config.model_name,
                    timeout=ollama_config.timeout_seconds
                )
                self.model_health["ollama"] = self.clients["ollama"].check_health()
                logger.info(f"Ollama client initialized: {self.model_health['ollama']}")
            except Exception as e:
                logger.error(f"Failed to initialize Ollama: {e}")
                self.model_health["ollama"] = False

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
                    self.model_health["claude"] = self.clients["claude"].check_health()
                    logger.info(f"Claude client initialized: {self.model_health['claude']}")
                else:
                    logger.warning("Claude API key not provided")
                    self.model_health["claude"] = False
            except Exception as e:
                logger.error(f"Failed to initialize Claude: {e}")
                self.model_health["claude"] = False

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
                self.model_health["deepseek"] = self.clients["deepseek"].check_health()
                logger.info(f"DeepSeek client initialized: {self.model_health['deepseek']}")
            except Exception as e:
                logger.error(f"Failed to initialize DeepSeek: {e}")
                self.model_health["deepseek"] = False

    def determine_routing_strategy(
        self,
        request: ThreatAnalysisRequest
    ) -> List[str]:
        """
        Determine which models to use based on request parameters.

        Routing Logic:
        - Critical priority → All healthy models
        - High/Medium priority → Ollama + Claude
        - Low priority → Ollama only
        - Medical AI scan → Always include DeepSeek
        - Compliance scan → Always include Claude
        - Quick scans → Ollama only

        Args:
            request: Threat analysis request

        Returns:
            List of model names to use
        """
        models = []
        priority = request.priority.lower()
        scan_type = request.scan_type.lower()
        sector = request.sector.upper()

        logger.debug(
            f"Determining routing: priority={priority}, "
            f"scan_type={scan_type}, sector={sector}"
        )

        # Critical priority: use all available models
        if priority == "critical":
            models = [m for m in ["ollama", "claude", "deepseek"]
                     if self.model_health.get(m, False)]
            logger.info(f"Critical priority: using all models {models}")

        # Medical AI: always include DeepSeek if available
        elif scan_type == "medical_ai" or sector == "MEDICAL_AI":
            if self.model_health.get("deepseek", False):
                models.append("deepseek")
            if self.model_health.get("claude", False):
                models.append("claude")
            if self.model_health.get("ollama", False):
                models.append("ollama")
            logger.info(f"Medical AI scan: using {models}")

        # Compliance: always include Claude
        elif scan_type == "compliance" or request.compliance_frameworks:
            if self.model_health.get("claude", False):
                models.append("claude")
            if self.model_health.get("ollama", False):
                models.append("ollama")
            logger.info(f"Compliance scan: using {models}")

        # High/Medium priority: Ollama + Claude
        elif priority in ["high", "medium"]:
            if self.model_health.get("ollama", False):
                models.append("ollama")
            if self.model_health.get("claude", False):
                models.append("claude")
            logger.info(f"{priority.upper()} priority: using {models}")

        # Low priority or default: Ollama only
        else:
            if self.model_health.get("ollama", False):
                models.append("ollama")
            logger.info(f"Low priority: using {models}")

        # Limit to max_models
        if len(models) > request.max_models:
            models = models[:request.max_models]
            logger.debug(f"Limited to {request.max_models} models: {models}")

        # Fallback if no models available
        if not models:
            # Try any healthy model
            for model_name in ["ollama", "claude", "deepseek"]:
                if self.model_health.get(model_name, False):
                    models.append(model_name)
                    logger.warning(f"Using fallback model: {model_name}")
                    break

        if not models:
            raise RuntimeError("No healthy AI models available")

        return models

    def _build_sector_prompt(self, request: ThreatAnalysisRequest) -> str:
        """
        Build sector-specific system prompt.

        Args:
            request: Threat analysis request

        Returns:
            System prompt customized for sector
        """
        sector = request.sector.upper()
        scan_type = request.scan_type

        if sector == "LOGISTICS":
            return f"""You are an elite cybersecurity analyst specializing in logistics and
supply chain security, with deep expertise in:
- EDI protocol security and injection attacks
- SUNAT Peru customs systems and electronic invoices
- Commercial trade data protection
- Supply chain attack vectors
- API security for logistics platforms

Analyze the {scan_type} scan for security threats, vulnerabilities, and compliance gaps.
Focus on logistics-specific attack vectors and SUNAT Peru regulations.

Provide your analysis in structured JSON format with findings, severity, and recommendations."""

        elif sector == "MEDICAL_AI":
            return f"""You are a healthcare cybersecurity expert specializing in medical AI
systems and HIPAA compliance, with expertise in:
- HIPAA Security Rule (45 CFR 164.312)
- FDA AI/ML guidance for medical devices
- Medical AI attack vectors (model inversion, data poisoning, adversarial examples)
- PHI protection and breach prevention
- Medical device cybersecurity

Analyze the {scan_type} scan considering patient safety and regulatory implications.

Provide your analysis in structured JSON format with findings, severity, and HIPAA impact."""

        else:
            return f"""You are an expert cybersecurity analyst specializing in {scan_type} security analysis.

Analyze the provided target for security threats, vulnerabilities, and compliance gaps.
Focus on actionable findings with clear severity ratings and remediation steps.

Provide your analysis in structured JSON format with findings, severity, CVE references, and recommendations."""

    async def _query_ollama(
        self,
        request: ThreatAnalysisRequest,
        system_prompt: str
    ) -> Optional[Dict[str, Any]]:
        """
        Query Ollama model asynchronously.

        Args:
            request: Analysis request
            system_prompt: System prompt

        Returns:
            Parsed response or None on failure
        """
        start_time = time.time()
        model_name = "ollama"

        try:
            client = self.clients.get(model_name)
            if not client:
                logger.warning(f"{model_name} client not available")
                return None

            # Build query
            query = f"""Target: {request.target}
Scan Type: {request.scan_type}
Sector: {request.sector}
Compliance Frameworks: {', '.join(request.compliance_frameworks)}
Priority: {request.priority}

Additional Context: {json.dumps(request.context, indent=2)}

Perform comprehensive security analysis and identify all threats, vulnerabilities,
and compliance issues. Provide detailed remediation recommendations."""

            logger.info(f"Querying {model_name} for target: {request.target}")

            # Execute with timeout
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    client.generate,
                    query,
                    system_prompt=system_prompt,
                    temperature=0.5
                ),
                timeout=self.OLLAMA_TIMEOUT
            )

            response_time = time.time() - start_time

            # Record metrics
            self.metrics.append(ModelPerformanceMetrics(
                model_name=model_name,
                success=True,
                response_time=response_time,
                token_count=len(response.split())
            ))

            logger.info(f"{model_name} responded in {response_time:.2f}s")

            # Parse response (attempt JSON extraction)
            return self._parse_model_response(response, model_name)

        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            logger.error(f"{model_name} timeout after {response_time:.2f}s")
            self.metrics.append(ModelPerformanceMetrics(
                model_name=model_name,
                success=False,
                response_time=response_time,
                error_message="Timeout"
            ))
            return None

        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"{model_name} error: {e}")
            self.metrics.append(ModelPerformanceMetrics(
                model_name=model_name,
                success=False,
                response_time=response_time,
                error_message=str(e)
            ))
            return None

    async def _query_claude(
        self,
        request: ThreatAnalysisRequest,
        system_prompt: str
    ) -> Optional[Dict[str, Any]]:
        """
        Query Claude model asynchronously.

        Args:
            request: Analysis request
            system_prompt: System prompt

        Returns:
            Parsed response or None on failure
        """
        start_time = time.time()
        model_name = "claude"

        try:
            client = self.clients.get(model_name)
            if not client:
                logger.warning(f"{model_name} client not available")
                return None

            # Build enhanced query for Claude's reasoning capabilities
            query = f"""Perform a comprehensive security analysis:

**Target:** {request.target}
**Scan Type:** {request.scan_type}
**Sector:** {request.sector}
**Priority:** {request.priority}

**Compliance Frameworks:** {', '.join(request.compliance_frameworks)}

**Context:**
{json.dumps(request.context, indent=2)}

**Analysis Requirements:**
1. Identify all security findings with severity classification (CRITICAL/HIGH/MEDIUM/LOW)
2. Map findings to relevant compliance controls
3. Assess compliance impact for each framework
4. Provide prioritized remediation recommendations
5. Include CVE references where applicable
6. Consider sector-specific attack vectors

**Output Format:** Structured JSON with the following schema:
{{
    "findings": [
        {{
            "severity": "CRITICAL|HIGH|MEDIUM|LOW",
            "title": "Brief title",
            "description": "Detailed description",
            "cve_ids": ["CVE-YYYY-NNNNN"],
            "affected_components": ["component1"],
            "attack_vectors": ["vector1"],
            "remediation": "Detailed steps",
            "mitre_tactics": ["TA0001"],
            "mitre_techniques": ["T1190"]
        }}
    ],
    "recommendations": [
        {{
            "priority": "critical|high|medium|low",
            "title": "Recommendation title",
            "description": "Detailed recommendation",
            "effort_hours": 8,
            "timeline": "immediate"
        }}
    ],
    "compliance_impact": {{
        "HIPAA": {{
            "affected_controls": ["164.312(a)(1)"],
            "gaps": ["Gap description"]
        }}
    }}
}}"""

            logger.info(f"Querying {model_name} for target: {request.target}")

            # Execute with timeout
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    client.generate,
                    query,
                    system_prompt=system_prompt,
                    temperature=0.3  # Lower temperature for factual analysis
                ),
                timeout=self.CLAUDE_TIMEOUT
            )

            response_time = time.time() - start_time

            # Record metrics
            self.metrics.append(ModelPerformanceMetrics(
                model_name=model_name,
                success=True,
                response_time=response_time,
                token_count=len(response.split())
            ))

            logger.info(f"{model_name} responded in {response_time:.2f}s")

            return self._parse_model_response(response, model_name)

        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            logger.error(f"{model_name} timeout after {response_time:.2f}s")
            self.metrics.append(ModelPerformanceMetrics(
                model_name=model_name,
                success=False,
                response_time=response_time,
                error_message="Timeout"
            ))
            return None

        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"{model_name} error: {e}")
            self.metrics.append(ModelPerformanceMetrics(
                model_name=model_name,
                success=False,
                response_time=response_time,
                error_message=str(e)
            ))
            return None

    async def _query_deepseek(
        self,
        request: ThreatAnalysisRequest,
        system_prompt: str
    ) -> Optional[Dict[str, Any]]:
        """
        Query DeepSeek model asynchronously.

        Args:
            request: Analysis request
            system_prompt: System prompt

        Returns:
            Parsed response or None on failure
        """
        start_time = time.time()
        model_name = "deepseek"

        try:
            client = self.clients.get(model_name)
            if not client:
                logger.warning(f"{model_name} client not available")
                return None

            # Build medical AI specific query
            query = f"""Medical AI Security Analysis:

**Target System:** {request.target}
**Scan Type:** {request.scan_type}
**Medical AI Context:** {request.context.get('medical_ai_type', 'Unknown')}

**Analysis Focus:**
1. Adversarial machine learning vulnerabilities
2. Model inversion and data extraction risks
3. Training data poisoning threats
4. Prompt injection vulnerabilities (if LLM-based)
5. PHI exposure risks
6. FDA AI/ML guidance compliance

**Context:**
{json.dumps(request.context, indent=2)}

Provide detailed security analysis with focus on medical AI specific threats.
Include patient safety implications and HIPAA compliance impact."""

            logger.info(f"Querying {model_name} for target: {request.target}")

            # Execute with timeout
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    client.generate,
                    query,
                    system_prompt=system_prompt,
                    temperature=0.5
                ),
                timeout=self.DEEPSEEK_TIMEOUT
            )

            response_time = time.time() - start_time

            # Record metrics
            self.metrics.append(ModelPerformanceMetrics(
                model_name=model_name,
                success=True,
                response_time=response_time,
                token_count=len(response.split())
            ))

            logger.info(f"{model_name} responded in {response_time:.2f}s")

            return self._parse_model_response(response, model_name)

        except asyncio.TimeoutError:
            response_time = time.time() - start_time
            logger.error(f"{model_name} timeout after {response_time:.2f}s")
            self.metrics.append(ModelPerformanceMetrics(
                model_name=model_name,
                success=False,
                response_time=response_time,
                error_message="Timeout"
            ))
            return None

        except Exception as e:
            response_time = time.time() - start_time
            logger.error(f"{model_name} error: {e}")
            self.metrics.append(ModelPerformanceMetrics(
                model_name=model_name,
                success=False,
                response_time=response_time,
                error_message=str(e)
            ))
            return None

    def _parse_model_response(
        self,
        response: str,
        model_name: str
    ) -> Dict[str, Any]:
        """
        Parse model response, attempting JSON extraction.

        Args:
            response: Raw model response
            model_name: Name of model

        Returns:
            Parsed response dict
        """
        # Try to extract JSON from response
        try:
            # Look for JSON block
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1

            if start_idx != -1 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                parsed = json.loads(json_str)
                logger.debug(f"Successfully parsed JSON from {model_name}")
                return parsed
        except json.JSONDecodeError:
            logger.debug(f"No valid JSON found in {model_name} response")

        # Fallback: return raw response
        return {
            "raw_response": response,
            "findings": [],
            "recommendations": [],
            "source": model_name
        }

    async def analyze_parallel(
        self,
        request: ThreatAnalysisRequest
    ) -> ThreatAnalysisResponse:
        """
        Perform parallel threat analysis using multiple models.

        Args:
            request: Threat analysis request

        Returns:
            Synthesized threat analysis response

        Raises:
            RuntimeError: If all models fail
        """
        overall_start = time.time()

        # Generate unique threat ID
        threat_id = str(uuid.uuid4())

        logger.info(
            f"Starting parallel analysis [ID: {threat_id}] "
            f"for target: {request.target}"
        )

        # Determine routing strategy
        models_to_use = self.determine_routing_strategy(request)

        if not models_to_use:
            raise RuntimeError("No models available for analysis")

        # Build sector-specific prompt
        system_prompt = self._build_sector_prompt(request)

        # Execute queries in parallel
        tasks = []
        model_map = {}

        for model_name in models_to_use:
            if model_name == "ollama":
                task = self._query_ollama(request, system_prompt)
            elif model_name == "claude":
                task = self._query_claude(request, system_prompt)
            elif model_name == "deepseek":
                task = self._query_deepseek(request, system_prompt)
            else:
                continue

            tasks.append(task)
            model_map[len(tasks) - 1] = model_name

        # Wait for all tasks with overall timeout
        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=request.timeout
            )
        except asyncio.TimeoutError:
            logger.error(f"Overall timeout exceeded: {request.timeout}s")
            results = [None] * len(tasks)

        # Collect successful responses
        model_responses = {}
        for idx, result in enumerate(results):
            model_name = model_map.get(idx)
            if model_name and result and not isinstance(result, Exception):
                model_responses[model_name] = result
                logger.info(f"Received response from {model_name}")
            elif isinstance(result, Exception):
                logger.error(f"Model {model_map.get(idx)} raised exception: {result}")

        if not model_responses:
            raise RuntimeError("All models failed to respond")

        # Synthesize results
        synthesized_response = self._synthesize_results(
            model_responses=model_responses,
            request=request,
            threat_id=threat_id,
            execution_time=time.time() - overall_start
        )

        logger.info(
            f"Analysis complete [ID: {threat_id}] in "
            f"{synthesized_response.execution_time:.2f}s using "
            f"{len(synthesized_response.models_used)} models"
        )

        return synthesized_response

    def _synthesize_results(
        self,
        model_responses: Dict[str, Dict[str, Any]],
        request: ThreatAnalysisRequest,
        threat_id: str,
        execution_time: float
    ) -> ThreatAnalysisResponse:
        """
        Synthesize results from multiple models.

        Strategy:
        1. Aggregate findings from all models
        2. Deduplicate by similarity
        3. Calculate confidence based on model agreement
        4. Prioritize by severity * confidence
        5. Merge recommendations
        6. Assess compliance impact

        Args:
            model_responses: Responses from each model
            request: Original request
            threat_id: Unique threat identifier
            execution_time: Total execution time

        Returns:
            Synthesized threat analysis response
        """
        logger.debug(f"Synthesizing results from {len(model_responses)} models")

        # Extract findings from all models
        all_findings = []
        all_recommendations = []

        for model_name, response in model_responses.items():
            # Extract findings
            findings_data = response.get("findings", [])
            for finding_data in findings_data:
                if isinstance(finding_data, dict):
                    # Create Finding object
                    try:
                        finding = Finding(
                            finding_id=str(uuid.uuid4()),
                            severity=finding_data.get("severity", "medium").lower(),
                            title=finding_data.get("title", "Unknown finding"),
                            description=finding_data.get("description", ""),
                            cve_ids=finding_data.get("cve_ids", []),
                            affected_components=finding_data.get("affected_components", []),
                            attack_vectors=finding_data.get("attack_vectors", []),
                            remediation=finding_data.get("remediation", ""),
                            confidence=0.0,  # Will calculate later
                            sources=[model_name],
                            references=finding_data.get("references", []),
                            mitre_tactics=finding_data.get("mitre_tactics", []),
                            mitre_techniques=finding_data.get("mitre_techniques", [])
                        )
                        all_findings.append(finding)
                    except Exception as e:
                        logger.warning(f"Failed to parse finding from {model_name}: {e}")

            # Extract recommendations
            recs_data = response.get("recommendations", [])
            for rec_data in recs_data:
                if isinstance(rec_data, dict):
                    try:
                        rec = Recommendation(
                            recommendation_id=str(uuid.uuid4()),
                            priority=rec_data.get("priority", "medium").lower(),
                            title=rec_data.get("title", ""),
                            description=rec_data.get("description", ""),
                            effort_hours=rec_data.get("effort_hours", 0),
                            cost_estimate=rec_data.get("cost_estimate", 0),
                            timeline=rec_data.get("timeline", "30 days")
                        )
                        all_recommendations.append(rec)
                    except Exception as e:
                        logger.warning(f"Failed to parse recommendation from {model_name}: {e}")

        # Deduplicate findings
        unique_findings = self._deduplicate_findings(all_findings)

        # Calculate confidence scores
        for finding in unique_findings:
            finding.confidence = self._calculate_confidence(
                finding,
                all_findings,
                len(model_responses)
            )

        # Sort findings by priority (severity * confidence)
        unique_findings.sort(
            key=lambda f: (
                self.SEVERITY_SCORES.get(f.severity, 1) * f.confidence
            ),
            reverse=True
        )

        # Deduplicate recommendations
        unique_recommendations = self._deduplicate_recommendations(all_recommendations)

        # Calculate overall confidence
        if unique_findings:
            overall_confidence = sum(f.confidence for f in unique_findings) / len(unique_findings)
        else:
            overall_confidence = 0.0

        # Build compliance impact (if Claude was used)
        compliance_impact = {}
        if "claude" in model_responses:
            compliance_data = model_responses["claude"].get("compliance_impact", {})
            for framework, impact_data in compliance_data.items():
                if isinstance(impact_data, dict):
                    compliance_impact[framework] = ComplianceImpact(
                        framework=framework,
                        affected_controls=impact_data.get("affected_controls", []),
                        critical_gaps=impact_data.get("gaps", [])
                    )

        # Create response
        response = ThreatAnalysisResponse(
            threat_id=threat_id,
            target=request.target,
            scan_type=request.scan_type,
            timestamp=datetime.now(),
            models_used=list(model_responses.keys()),
            findings=unique_findings,
            recommendations=unique_recommendations,
            compliance_impact=compliance_impact,
            confidence_score=overall_confidence,
            execution_time=execution_time,
            model_responses=model_responses,
            metadata={
                "sector": request.sector,
                "priority": request.priority,
                "compliance_frameworks": request.compliance_frameworks
            }
        )

        return response

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """
        Deduplicate findings based on similarity.

        Args:
            findings: List of findings from all models

        Returns:
            Deduplicated findings with merged sources
        """
        if not findings:
            return []

        # Group by similarity
        unique_findings = []
        seen_hashes = set()

        for finding in findings:
            # Create hash based on severity + title + CVEs
            finding_signature = f"{finding.severity}|{finding.title.lower()}|{'|'.join(sorted(finding.cve_ids))}"
            finding_hash = hashlib.md5(finding_signature.encode()).hexdigest()

            if finding_hash not in seen_hashes:
                seen_hashes.add(finding_hash)
                unique_findings.append(finding)
            else:
                # Merge sources
                for uf in unique_findings:
                    uf_sig = f"{uf.severity}|{uf.title.lower()}|{'|'.join(sorted(uf.cve_ids))}"
                    uf_hash = hashlib.md5(uf_sig.encode()).hexdigest()
                    if uf_hash == finding_hash:
                        # Merge sources
                        for source in finding.sources:
                            if source not in uf.sources:
                                uf.sources.append(source)
                        # Merge other fields
                        uf.attack_vectors = list(set(uf.attack_vectors + finding.attack_vectors))
                        uf.affected_components = list(set(uf.affected_components + finding.affected_components))
                        break

        logger.debug(f"Deduplicated {len(findings)} findings to {len(unique_findings)} unique")
        return unique_findings

    def _deduplicate_recommendations(
        self,
        recommendations: List[Recommendation]
    ) -> List[Recommendation]:
        """
        Deduplicate recommendations based on similarity.

        Args:
            recommendations: List of recommendations

        Returns:
            Deduplicated recommendations
        """
        if not recommendations:
            return []

        unique_recs = []
        seen_titles = set()

        for rec in recommendations:
            title_lower = rec.title.lower()
            if title_lower not in seen_titles:
                seen_titles.add(title_lower)
                unique_recs.append(rec)

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique_recs.sort(key=lambda r: priority_order.get(r.priority, 4))

        logger.debug(f"Deduplicated {len(recommendations)} recommendations to {len(unique_recs)} unique")
        return unique_recs

    def _calculate_confidence(
        self,
        finding: Finding,
        all_findings: List[Finding],
        total_models: int
    ) -> float:
        """
        Calculate confidence score based on model agreement.

        Confidence = (number of models that identified this finding) / (total models)

        Args:
            finding: Finding to calculate confidence for
            all_findings: All findings from all models
            total_models: Total number of models queried

        Returns:
            Confidence score (0.0-1.0)
        """
        # Count how many models identified this finding
        models_agree = len(finding.sources)

        # Calculate confidence
        confidence = models_agree / total_models

        # Boost confidence for CVE-backed findings
        if finding.cve_ids:
            confidence = min(1.0, confidence + 0.1)

        # Boost confidence for critical severity with multiple models
        if finding.severity == "critical" and models_agree >= 2:
            confidence = min(1.0, confidence + 0.15)

        return round(confidence, 2)

    async def analyze(
        self,
        target: str,
        scan_type: str = "network",
        sector: str = "GENERAL",
        compliance_frameworks: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
        priority: str = "medium",
        max_models: int = 3,
        timeout: int = 120
    ) -> ThreatAnalysisResponse:
        """
        Convenient wrapper for parallel analysis.

        Args:
            target: Target to analyze
            scan_type: Type of scan
            sector: Industry sector
            compliance_frameworks: Applicable frameworks
            context: Additional context
            priority: Analysis priority
            max_models: Maximum concurrent models
            timeout: Overall timeout

        Returns:
            Threat analysis response
        """
        request = ThreatAnalysisRequest(
            target=target,
            scan_type=scan_type,
            sector=sector,
            compliance_frameworks=compliance_frameworks or [],
            context=context or {},
            priority=priority,
            max_models=max_models,
            timeout=timeout
        )

        return await self.analyze_parallel(request)

    def get_metrics(self) -> List[Dict[str, Any]]:
        """
        Get performance metrics for all model executions.

        Returns:
            List of metric dictionaries
        """
        return [asdict(m) for m in self.metrics]

    def clear_metrics(self) -> None:
        """Clear performance metrics."""
        self.metrics = []
        logger.info("Performance metrics cleared")
