"""
Threat Analysis Data Models

Defines request/response schemas for multi-model threat analysis.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class ScanType(Enum):
    """Types of security scans."""
    NETWORK = "network"
    APPLICATION = "application"
    COMPLIANCE = "compliance"
    MEDICAL_AI = "medical_ai"
    API_SECURITY = "api_security"
    SUPPLY_CHAIN = "supply_chain"


class Priority(Enum):
    """Priority levels for analysis."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ThreatAnalysisRequest:
    """
    Request schema for multi-model threat analysis.

    Attributes:
        target: IP, domain, or system identifier to analyze
        scan_type: Type of security scan to perform
        sector: Industry sector for context
        compliance_frameworks: Applicable compliance frameworks
        context: Additional context for analysis
        priority: Analysis priority level
        max_models: Maximum number of models to use concurrently
        timeout: Overall timeout in seconds
    """
    target: str
    scan_type: str
    sector: str = "GENERAL"
    compliance_frameworks: List[str] = field(default_factory=lambda: ["ISO27001"])
    context: Dict[str, Any] = field(default_factory=dict)
    priority: str = "medium"
    max_models: int = 3
    timeout: int = 120

    def __post_init__(self):
        """Validate request parameters."""
        # Normalize scan_type
        if isinstance(self.scan_type, str):
            try:
                ScanType(self.scan_type.lower())
            except ValueError:
                raise ValueError(f"Invalid scan_type: {self.scan_type}")

        # Normalize priority
        if isinstance(self.priority, str):
            try:
                Priority(self.priority.lower())
            except ValueError:
                raise ValueError(f"Invalid priority: {self.priority}")

        # Validate max_models
        if not 1 <= self.max_models <= 3:
            raise ValueError("max_models must be between 1 and 3")

        # Validate timeout
        if not 10 <= self.timeout <= 600:
            raise ValueError("timeout must be between 10 and 600 seconds")


@dataclass
class Finding:
    """
    Security finding from threat analysis.

    Attributes:
        finding_id: Unique identifier for this finding
        severity: Severity level
        title: Short description
        description: Detailed description
        cve_ids: Related CVE identifiers
        affected_components: List of affected systems/components
        attack_vectors: Possible attack vectors
        remediation: Recommended remediation steps
        confidence: Confidence score (0.0-1.0)
        sources: Which models identified this finding
        references: External references (URLs, documents)
    """
    finding_id: str
    severity: str
    title: str
    description: str
    cve_ids: List[str] = field(default_factory=list)
    affected_components: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    remediation: str = ""
    confidence: float = 0.0
    sources: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Validate finding data."""
        # Validate severity
        try:
            Severity(self.severity.lower())
        except ValueError:
            raise ValueError(f"Invalid severity: {self.severity}")

        # Validate confidence
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0.0 and 1.0")


@dataclass
class Recommendation:
    """
    Security recommendation.

    Attributes:
        recommendation_id: Unique identifier
        priority: Implementation priority
        title: Short description
        description: Detailed recommendation
        effort_hours: Estimated implementation effort
        cost_estimate: Estimated cost in USD
        timeline: Recommended timeline (e.g., "immediate", "30 days")
        dependencies: Prerequisites for implementation
        success_criteria: How to measure success
    """
    recommendation_id: str
    priority: str
    title: str
    description: str
    effort_hours: int = 0
    cost_estimate: int = 0
    timeline: str = "30 days"
    dependencies: List[str] = field(default_factory=list)
    success_criteria: List[str] = field(default_factory=list)


@dataclass
class ComplianceImpact:
    """
    Compliance impact assessment.

    Attributes:
        framework: Compliance framework (e.g., "HIPAA", "ISO27001")
        affected_controls: List of affected control IDs
        current_compliance_score: Current score (0-100)
        projected_compliance_score: Score after remediation
        critical_gaps: Critical compliance gaps
        remediation_priority: Prioritized remediation list
    """
    framework: str
    affected_controls: List[str] = field(default_factory=list)
    current_compliance_score: float = 0.0
    projected_compliance_score: float = 0.0
    critical_gaps: List[str] = field(default_factory=list)
    remediation_priority: List[str] = field(default_factory=list)


@dataclass
class ThreatAnalysisResponse:
    """
    Response schema for multi-model threat analysis.

    Attributes:
        threat_id: Unique identifier for this analysis
        target: Analyzed target
        scan_type: Type of scan performed
        timestamp: Analysis timestamp
        models_used: List of AI models that contributed
        findings: Aggregated security findings
        recommendations: Prioritized recommendations
        compliance_impact: Compliance impact per framework
        confidence_score: Overall confidence (0.0-1.0)
        execution_time: Total execution time in seconds
        model_responses: Raw responses from each model
        metadata: Additional metadata
    """
    threat_id: str
    target: str
    scan_type: str
    timestamp: datetime
    models_used: List[str]
    findings: List[Finding]
    recommendations: List[Recommendation]
    compliance_impact: Dict[str, ComplianceImpact] = field(default_factory=dict)
    confidence_score: float = 0.0
    execution_time: float = 0.0
    model_responses: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Validate response data."""
        if not 0.0 <= self.confidence_score <= 1.0:
            raise ValueError("confidence_score must be between 0.0 and 1.0")


@dataclass
class ModelPerformanceMetrics:
    """
    Performance metrics for a model execution.

    Attributes:
        model_name: Name of the model
        success: Whether execution succeeded
        response_time: Response time in seconds
        token_count: Number of tokens processed
        error_message: Error message if failed
        retry_count: Number of retries attempted
    """
    model_name: str
    success: bool
    response_time: float
    token_count: int = 0
    error_message: Optional[str] = None
    retry_count: int = 0
