# Multi-Model AI Orchestrator - User Guide

## Overview

The Enhanced Multi-Model Orchestrator is the core intelligence layer of Drana-Infinity GTL Edition. It coordinates multiple AI models (Ollama, Claude Sonnet 4.5, DeepSeek-R1) to provide comprehensive, high-confidence security analysis.

## Key Features

### 1. Intelligent Routing

The orchestrator automatically selects the optimal model(s) based on:

- **Query Priority**: Critical queries use all models
- **Scan Type**: Compliance scans prefer Claude, Medical AI prefers DeepSeek
- **Sector**: Logistics and Medical AI get specialized prompts
- **Performance Requirements**: Low priority = fast (Ollama only)

### 2. Parallel Execution

- Multiple models run concurrently using `asyncio`
- Individual timeouts per model (30s/60s/90s)
- Overall timeout enforcement
- Graceful degradation on partial failures

### 3. Result Synthesis

- **Deduplication**: Merges identical findings from different models
- **Confidence Scoring**: Based on model agreement (0.0-1.0)
- **Prioritization**: Findings ranked by `severity × confidence`
- **Consensus Building**: Highlights areas of agreement/disagreement

### 4. Sector Specialization

- **Logistics**: EDI security, SUNAT Peru compliance, supply chain
- **Medical AI**: HIPAA, FDA guidance, adversarial ML, PHI protection
- **General**: Standard cybersecurity analysis

---

## Quick Start

### Basic Usage

```python
import asyncio
from src.core.multi_model_orchestrator_v2 import EnhancedMultiModelOrchestrator

# Initialize
orchestrator = EnhancedMultiModelOrchestrator()

# Simple analysis
async def analyze():
    result = await orchestrator.analyze(
        target="192.168.1.100",
        scan_type="network",
        priority="high"
    )

    print(f"Found {len(result.findings)} security issues")
    print(f"Confidence: {result.confidence_score:.1%}")

    for finding in result.findings[:5]:
        print(f"[{finding.severity.upper()}] {finding.title}")

# Run
asyncio.run(analyze())
```

### Advanced Usage with Full Request

```python
from src.core.threat_analysis_models import ThreatAnalysisRequest

# Create detailed request
request = ThreatAnalysisRequest(
    target="prod-web-server",
    scan_type="application",
    sector="MEDICAL_AI",
    compliance_frameworks=["HIPAA", "ISO27001"],
    priority="critical",
    context={
        "application_type": "Patient Portal",
        "tech_stack": ["React", "Node.js", "PostgreSQL"],
        "data_types": ["PHI", "PII"],
        "known_vulnerabilities": []
    },
    max_models=3,
    timeout=120
)

# Execute
result = await orchestrator.analyze_parallel(request)

# Access detailed results
print(f"Threat ID: {result.threat_id}")
print(f"Models Used: {', '.join(result.models_used)}")
print(f"Execution Time: {result.execution_time:.2f}s")

# Findings with confidence
for finding in result.findings:
    print(f"\n[{finding.severity}] {finding.title}")
    print(f"Confidence: {finding.confidence:.0%}")
    print(f"Identified by: {', '.join(finding.sources)}")
    if finding.cve_ids:
        print(f"CVEs: {', '.join(finding.cve_ids)}")
    print(f"Remediation: {finding.remediation}")

# Compliance impact
for framework, impact in result.compliance_impact.items():
    print(f"\n{framework} Impact:")
    print(f"  Affected Controls: {len(impact.affected_controls)}")
    print(f"  Critical Gaps: {len(impact.critical_gaps)}")
```

---

## Routing Strategy

### Priority-Based Routing

| Priority | Models Used | Use Case | Response Time |
|----------|-------------|----------|---------------|
| **Low** | Ollama only | Quick triage, dev systems | <5s |
| **Medium** | Ollama + Claude | Production systems | <10s |
| **High** | Ollama + Claude | Critical systems | <12s |
| **Critical** | All 3 models | Suspected breach, compliance audit | <15s |

### Scan Type Routing

| Scan Type | Required Models | Rationale |
|-----------|----------------|-----------|
| `network` | Ollama (default) | Fast pattern matching |
| `application` | Ollama + Claude | Code/config analysis |
| `compliance` | Claude (required) | Compliance reasoning |
| `medical_ai` | DeepSeek + Claude | ML security expertise |
| `api_security` | Ollama + Claude | API threat patterns |

### Sector-Specific Routing

**Logistics Sector:**
- Always includes Claude for SUNAT compliance
- Specialized prompts for EDI security
- Focus on supply chain attack vectors

**Medical AI Sector:**
- Always includes DeepSeek (if available)
- HIPAA-aware analysis from Claude
- PHI leakage prevention

---

## Result Synthesis Algorithm

### 1. Deduplication

Findings are deduplicated based on:
- Severity + Title + CVE IDs hash
- Sources are merged for duplicates
- Attack vectors and components aggregated

### 2. Confidence Calculation

```
Confidence = (models_agreeing / total_models) + boosts

Boosts:
- CVE-backed finding: +0.1
- Critical severity with 2+ models: +0.15
- Maximum confidence: 1.0
```

### 3. Prioritization

Findings sorted by:
```
Priority Score = severity_score × confidence

Severity Scores:
- CRITICAL: 10
- HIGH: 7
- MEDIUM: 4
- LOW: 2
- INFO: 1
```

---

## Performance Optimization

### Timeouts

```python
# Per-model timeouts
OLLAMA_TIMEOUT = 30s   # Fast local model
CLAUDE_TIMEOUT = 60s   # API with reasoning
DEEPSEEK_TIMEOUT = 90s # Local inference may be slower

# Overall request timeout (configurable)
request.timeout = 120s  # Default
```

### Parallel Execution

Models execute concurrently:
```
Total Time ≈ max(model_times) + synthesis_overhead

Example:
- Ollama: 3s
- Claude: 8s
- DeepSeek: 12s
- Synthesis: 1s
Total: ~13s (not 24s sequential)
```

### Memory Usage

- Orchestrator baseline: <500MB
- Per model active query: ~500MB-1GB
- Peak with 3 concurrent: <2GB

---

## Error Handling

### Partial Failures

If some models fail, orchestrator:
1. Logs the failure
2. Records performance metrics
3. Continues with successful models
4. Returns partial results with warning

```python
result = await orchestrator.analyze_parallel(request)

# Check which models succeeded
if len(result.models_used) < expected_models:
    print(f"⚠ Only {len(result.models_used)} models responded")
    print(f"Confidence may be lower than expected")
```

### Timeout Handling

```python
try:
    result = await orchestrator.analyze_parallel(request)
except RuntimeError as e:
    if "timeout" in str(e).lower():
        print("Analysis timed out - try increasing timeout or reducing priority")
```

### Model Unavailable

```python
# Check model health before analysis
if not orchestrator.model_health.get("claude"):
    print("⚠ Claude unavailable - compliance analysis may be limited")
```

---

## Metrics and Monitoring

### Performance Metrics

```python
# Get metrics after analysis
metrics = orchestrator.get_metrics()

for metric in metrics:
    print(f"{metric['model_name']}: {metric['response_time']:.2f}s")
    if not metric['success']:
        print(f"  Error: {metric['error_message']}")

# Clear metrics
orchestrator.clear_metrics()
```

### Recommended Monitoring

- **Response Times**: Alert if >20s for critical queries
- **Model Health**: Check `model_health` dict regularly
- **Failure Rates**: Track `success` in metrics
- **Confidence Scores**: Alert if consistently <0.5

---

## Best Practices

### 1. Priority Selection

```python
# Use appropriate priority for context
priority_guidelines = {
    "critical": "Active incident, suspected breach, compliance audit",
    "high": "Production systems, scheduled security review",
    "medium": "Staging environments, routine scans",
    "low": "Development systems, quick checks"
}
```

### 2. Timeout Configuration

```python
# Adjust timeout based on expected analysis depth
timeout_recommendations = {
    "quick_scan": 30,      # Low priority
    "standard": 60,        # Medium priority
    "deep_analysis": 120,  # High/Critical priority
    "comprehensive": 180   # Full compliance audit
}
```

### 3. Context Enrichment

Provide rich context for better analysis:

```python
context = {
    # System info
    "os": "Ubuntu 22.04",
    "services": ["nginx", "postgresql", "redis"],

    # Security controls
    "firewall": "enabled",
    "encryption": "TLS 1.3",
    "authentication": "OAuth2 + MFA",

    # Compliance
    "compliance_frameworks": ["HIPAA", "ISO27001"],
    "data_classification": "PHI",

    # Recent changes
    "last_patch": "2024-01-15",
    "recent_deployments": ["API v2.1", "Updated auth module"],

    # Known issues
    "known_vulnerabilities": [],
    "pending_patches": ["CVE-2024-1234"]
}
```

### 4. Result Interpretation

```python
# High confidence findings (>0.7) with critical severity
critical_high_confidence = [
    f for f in result.findings
    if f.severity == "critical" and f.confidence > 0.7
]

# Act on these immediately
for finding in critical_high_confidence:
    print(f"URGENT: {finding.title}")
    print(f"Action: {finding.remediation}")

# Lower confidence findings for review
uncertain_findings = [
    f for f in result.findings
    if f.confidence < 0.5
]

# Investigate these with human expertise
for finding in uncertain_findings:
    print(f"REVIEW NEEDED: {finding.title}")
    print(f"Only {len(finding.sources)}/{len(result.models_used)} models agree")
```

---

## Troubleshooting

### Issue: All Models Timeout

**Cause**: Network issues, models overloaded, or query too complex

**Solution**:
```python
# Increase timeout
request.timeout = 300  # 5 minutes

# Reduce priority to use fewer models
request.priority = "medium"  # Use 2 models instead of 3

# Check model health
for model, healthy in orchestrator.model_health.items():
    if not healthy:
        print(f"{model} is unhealthy - check logs")
```

### Issue: Low Confidence Scores

**Cause**: Models disagree, insufficient context, or rare threat

**Solution**:
```python
# Provide more context
request.context = {
    "detailed_logs": "...",
    "system_baseline": "...",
    "recent_changes": "..."
}

# Use critical priority for more models
request.priority = "critical"

# Review disagreements manually
if result.confidence_score < 0.6:
    print("Models disagree - human review recommended")
    # Check model_responses for raw output
    for model, response in result.model_responses.items():
        print(f"\n{model} analysis:")
        print(response.get("raw_response", ""))
```

### Issue: Missing Compliance Impact

**Cause**: Claude not used, or no compliance frameworks specified

**Solution**:
```python
# Ensure Claude is available
if not orchestrator.model_health.get("claude"):
    print("Claude required for compliance analysis")

# Specify frameworks in request
request.compliance_frameworks = ["HIPAA", "ISO27001", "NIST_CSF"]
request.scan_type = "compliance"  # Ensures Claude is used
```

---

## API Reference

### Classes

#### `EnhancedMultiModelOrchestrator`

Main orchestrator class.

**Methods:**

- `__init__(config: Optional[ConfigManager])` - Initialize orchestrator
- `async analyze_parallel(request: ThreatAnalysisRequest)` - Execute analysis
- `async analyze(...)` - Convenience wrapper
- `determine_routing_strategy(request)` - Get model selection
- `get_metrics()` - Get performance metrics
- `clear_metrics()` - Clear metrics

#### `ThreatAnalysisRequest`

Request schema.

**Fields:**

- `target: str` - Target to analyze
- `scan_type: str` - Type of scan
- `sector: str` - Industry sector
- `compliance_frameworks: List[str]` - Frameworks
- `context: Dict[str, Any]` - Additional context
- `priority: str` - Priority level
- `max_models: int` - Max concurrent models
- `timeout: int` - Timeout in seconds

#### `ThreatAnalysisResponse`

Response schema.

**Fields:**

- `threat_id: str` - Unique ID
- `target: str` - Analyzed target
- `models_used: List[str]` - Models that responded
- `findings: List[Finding]` - Security findings
- `recommendations: List[Recommendation]` - Recommendations
- `compliance_impact: Dict` - Compliance assessment
- `confidence_score: float` - Overall confidence
- `execution_time: float` - Total time in seconds

---

## Examples

See `/examples/orchestrator_demo.py` for comprehensive demos:

1. **Critical Threat Analysis** - Suspected server compromise
2. **HIPAA Compliance** - Medical records system audit
3. **Medical AI Security** - Diagnostic classifier assessment
4. **Logistics EDI Security** - SUNAT integration analysis
5. **Performance Comparison** - Priority level benchmarks

Run demos:
```bash
python examples/orchestrator_demo.py
```

---

## Testing

### Unit Tests

```bash
pytest tests/unit/test_multi_model_orchestrator.py -v
```

### Integration Tests

```bash
pytest tests/integration/test_orchestrator_integration.py -v -m integration
```

### Performance Benchmarks

```bash
pytest tests/integration/test_orchestrator_integration.py::TestPerformanceBenchmarks -v
```

---

## Support

**Issues**: Report bugs at https://github.com/sknaider/Drana-Infinity/issues
**Enterprise Support**: enterprise@gtl-consulting.com
**Documentation**: https://docs.gtl-consulting.com/drana-gtl

---

**Version**: 1.0.0-gtl
**Last Updated**: 2025-01-18
**Author**: GTL Consulting
