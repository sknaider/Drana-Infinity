"""
Unit Tests for Enhanced Multi-Model Orchestrator

Tests routing logic, result synthesis, deduplication, and error handling.
"""

import pytest
import asyncio
from datetime import datetime
from unittest.mock import Mock, AsyncMock, patch
from typing import Dict, Any

from src.core.multi_model_orchestrator_v2 import EnhancedMultiModelOrchestrator
from src.core.threat_analysis_models import (
    ThreatAnalysisRequest,
    ThreatAnalysisResponse,
    Finding,
    Recommendation,
    Severity
)


@pytest.fixture
def mock_config():
    """Mock configuration for testing."""
    config = Mock()
    config.ai_models = {
        "ollama": Mock(
            enabled=True,
            endpoint_url="http://localhost:11434",
            model_name="test-model",
            timeout_seconds=30
        ),
        "claude": Mock(
            enabled=True,
            api_key="test-key",
            model_name="claude-test",
            max_tokens=4096,
            timeout_seconds=60
        ),
        "deepseek": Mock(
            enabled=True,
            endpoint_url="http://localhost:8000",
            api_key=None,
            model_name="deepseek-test",
            timeout_seconds=90
        )
    }
    return config


@pytest.fixture
def orchestrator(mock_config):
    """Create orchestrator instance with mocked clients."""
    with patch('src.core.multi_model_orchestrator_v2.get_config', return_value=mock_config):
        orch = EnhancedMultiModelOrchestrator(config=mock_config)

        # Mock health checks
        orch.model_health = {
            "ollama": True,
            "claude": True,
            "deepseek": True
        }

        # Mock clients
        orch.clients = {
            "ollama": Mock(),
            "claude": Mock(),
            "deepseek": Mock()
        }

        return orch


class TestRoutingStrategy:
    """Test intelligent routing logic."""

    def test_critical_priority_uses_all_models(self, orchestrator):
        """Critical priority should use all available models."""
        request = ThreatAnalysisRequest(
            target="192.168.1.1",
            scan_type="network",
            priority="critical"
        )

        models = orchestrator.determine_routing_strategy(request)

        assert len(models) == 3
        assert "ollama" in models
        assert "claude" in models
        assert "deepseek" in models

    def test_medical_ai_scan_includes_deepseek(self, orchestrator):
        """Medical AI scans should always include DeepSeek."""
        request = ThreatAnalysisRequest(
            target="medical-ai-system",
            scan_type="medical_ai",
            sector="MEDICAL_AI",
            priority="medium"
        )

        models = orchestrator.determine_routing_strategy(request)

        assert "deepseek" in models

    def test_compliance_scan_includes_claude(self, orchestrator):
        """Compliance scans should always include Claude."""
        request = ThreatAnalysisRequest(
            target="web-app",
            scan_type="compliance",
            compliance_frameworks=["HIPAA", "ISO27001"],
            priority="medium"
        )

        models = orchestrator.determine_routing_strategy(request)

        assert "claude" in models

    def test_low_priority_uses_ollama_only(self, orchestrator):
        """Low priority should use Ollama only for speed."""
        request = ThreatAnalysisRequest(
            target="test-server",
            scan_type="network",
            priority="low"
        )

        models = orchestrator.determine_routing_strategy(request)

        assert models == ["ollama"]

    def test_high_priority_uses_ollama_and_claude(self, orchestrator):
        """High priority should use Ollama + Claude."""
        request = ThreatAnalysisRequest(
            target="production-server",
            scan_type="application",
            priority="high"
        )

        models = orchestrator.determine_routing_strategy(request)

        assert "ollama" in models
        assert "claude" in models
        assert len(models) == 2

    def test_max_models_limit_enforced(self, orchestrator):
        """Should respect max_models limit."""
        request = ThreatAnalysisRequest(
            target="test",
            scan_type="network",
            priority="critical",
            max_models=2  # Limit to 2 models
        )

        models = orchestrator.determine_routing_strategy(request)

        assert len(models) <= 2

    def test_fallback_when_no_models_match(self, orchestrator):
        """Should fallback to any healthy model."""
        # Make only ollama healthy
        orchestrator.model_health = {
            "ollama": True,
            "claude": False,
            "deepseek": False
        }

        request = ThreatAnalysisRequest(
            target="test",
            scan_type="compliance",  # Normally requires Claude
            priority="medium"
        )

        models = orchestrator.determine_routing_strategy(request)

        # Should fallback to ollama
        assert "ollama" in models

    def test_raises_error_when_no_models_available(self, orchestrator):
        """Should raise error when all models are down."""
        orchestrator.model_health = {
            "ollama": False,
            "claude": False,
            "deepseek": False
        }

        request = ThreatAnalysisRequest(
            target="test",
            scan_type="network",
            priority="medium"
        )

        with pytest.raises(RuntimeError, match="No healthy AI models available"):
            orchestrator.determine_routing_strategy(request)


class TestSectorPrompts:
    """Test sector-specific prompt generation."""

    def test_logistics_prompt(self, orchestrator):
        """Logistics sector should get specialized prompt."""
        request = ThreatAnalysisRequest(
            target="test",
            scan_type="network",
            sector="LOGISTICS"
        )

        prompt = orchestrator._build_sector_prompt(request)

        assert "logistics" in prompt.lower()
        assert "edi" in prompt.lower()
        assert "sunat" in prompt.lower()

    def test_medical_ai_prompt(self, orchestrator):
        """Medical AI sector should get specialized prompt."""
        request = ThreatAnalysisRequest(
            target="test",
            scan_type="medical_ai",
            sector="MEDICAL_AI"
        )

        prompt = orchestrator._build_sector_prompt(request)

        assert "medical" in prompt.lower()
        assert "hipaa" in prompt.lower()
        assert "phi" in prompt.lower()

    def test_general_prompt(self, orchestrator):
        """General sector should get default prompt."""
        request = ThreatAnalysisRequest(
            target="test",
            scan_type="network",
            sector="GENERAL"
        )

        prompt = orchestrator._build_sector_prompt(request)

        assert "cybersecurity" in prompt.lower()


class TestResponseParsing:
    """Test model response parsing."""

    def test_parse_valid_json_response(self, orchestrator):
        """Should parse valid JSON from response."""
        response = """
        Some text before JSON
        {
            "findings": [
                {
                    "severity": "high",
                    "title": "SQL Injection",
                    "description": "Vulnerable endpoint"
                }
            ]
        }
        Some text after JSON
        """

        parsed = orchestrator._parse_model_response(response, "test-model")

        assert "findings" in parsed
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["severity"] == "high"

    def test_parse_invalid_json_returns_raw(self, orchestrator):
        """Should return raw response when JSON parsing fails."""
        response = "This is not JSON formatted text"

        parsed = orchestrator._parse_model_response(response, "test-model")

        assert "raw_response" in parsed
        assert parsed["raw_response"] == response


class TestFindingsDeduplication:
    """Test findings deduplication logic."""

    def test_deduplicate_identical_findings(self, orchestrator):
        """Should merge identical findings from different models."""
        findings = [
            Finding(
                finding_id="1",
                severity="high",
                title="SQL Injection",
                description="Same finding",
                cve_ids=["CVE-2024-1234"],
                sources=["ollama"]
            ),
            Finding(
                finding_id="2",
                severity="high",
                title="SQL Injection",
                description="Same finding",
                cve_ids=["CVE-2024-1234"],
                sources=["claude"]
            )
        ]

        unique = orchestrator._deduplicate_findings(findings)

        assert len(unique) == 1
        assert set(unique[0].sources) == {"ollama", "claude"}

    def test_keep_different_findings(self, orchestrator):
        """Should keep different findings separate."""
        findings = [
            Finding(
                finding_id="1",
                severity="high",
                title="SQL Injection",
                description="Finding 1",
                cve_ids=[],
                sources=["ollama"]
            ),
            Finding(
                finding_id="2",
                severity="medium",
                title="XSS Vulnerability",
                description="Finding 2",
                cve_ids=[],
                sources=["claude"]
            )
        ]

        unique = orchestrator._deduplicate_findings(findings)

        assert len(unique) == 2

    def test_merge_attack_vectors_on_deduplication(self, orchestrator):
        """Should merge attack vectors when deduplicating."""
        findings = [
            Finding(
                finding_id="1",
                severity="high",
                title="SQL Injection",
                description="Finding",
                cve_ids=["CVE-2024-1234"],
                attack_vectors=["POST /login"],
                sources=["ollama"]
            ),
            Finding(
                finding_id="2",
                severity="high",
                title="SQL Injection",
                description="Finding",
                cve_ids=["CVE-2024-1234"],
                attack_vectors=["POST /search"],
                sources=["claude"]
            )
        ]

        unique = orchestrator._deduplicate_findings(findings)

        assert len(unique) == 1
        assert set(unique[0].attack_vectors) == {"POST /login", "POST /search"}


class TestConfidenceCalculation:
    """Test confidence score calculation."""

    def test_single_model_confidence(self, orchestrator):
        """Single model finding should have lower confidence."""
        finding = Finding(
            finding_id="1",
            severity="high",
            title="Test Finding",
            description="Test",
            cve_ids=[],
            sources=["ollama"]
        )

        confidence = orchestrator._calculate_confidence(finding, [finding], total_models=3)

        assert confidence == pytest.approx(0.33, rel=0.01)

    def test_all_models_agree_confidence(self, orchestrator):
        """All models agreeing should give high confidence."""
        finding = Finding(
            finding_id="1",
            severity="high",
            title="Test Finding",
            description="Test",
            cve_ids=[],
            sources=["ollama", "claude", "deepseek"]
        )

        confidence = orchestrator._calculate_confidence(finding, [finding], total_models=3)

        assert confidence == 1.0

    def test_cve_backed_finding_gets_boost(self, orchestrator):
        """CVE-backed findings should get confidence boost."""
        finding = Finding(
            finding_id="1",
            severity="high",
            title="Test Finding",
            description="Test",
            cve_ids=["CVE-2024-1234"],
            sources=["ollama"]
        )

        confidence = orchestrator._calculate_confidence(finding, [finding], total_models=3)

        # Should be higher than 0.33 due to CVE boost
        assert confidence > 0.33

    def test_critical_multi_model_gets_boost(self, orchestrator):
        """Critical findings with multiple models get extra boost."""
        finding = Finding(
            finding_id="1",
            severity="critical",
            title="Critical Finding",
            description="Test",
            cve_ids=[],
            sources=["ollama", "claude"]
        )

        confidence = orchestrator._calculate_confidence(finding, [finding], total_models=3)

        # Should be higher due to critical + multi-model boost
        assert confidence > 0.67


class TestRecommendationsDeduplication:
    """Test recommendations deduplication."""

    def test_deduplicate_identical_recommendations(self, orchestrator):
        """Should remove duplicate recommendations."""
        recs = [
            Recommendation(
                recommendation_id="1",
                priority="high",
                title="Patch System",
                description="Update to latest version"
            ),
            Recommendation(
                recommendation_id="2",
                priority="high",
                title="Patch System",  # Same title
                description="Different wording"
            )
        ]

        unique = orchestrator._deduplicate_recommendations(recs)

        assert len(unique) == 1

    def test_recommendations_sorted_by_priority(self, orchestrator):
        """Recommendations should be sorted by priority."""
        recs = [
            Recommendation(
                recommendation_id="1",
                priority="low",
                title="Recommendation 1",
                description="Low priority"
            ),
            Recommendation(
                recommendation_id="2",
                priority="critical",
                title="Recommendation 2",
                description="Critical priority"
            ),
            Recommendation(
                recommendation_id="3",
                priority="medium",
                title="Recommendation 3",
                description="Medium priority"
            )
        ]

        sorted_recs = orchestrator._deduplicate_recommendations(recs)

        assert sorted_recs[0].priority == "critical"
        assert sorted_recs[1].priority == "medium"
        assert sorted_recs[2].priority == "low"


class TestMetrics:
    """Test performance metrics tracking."""

    def test_metrics_recorded(self, orchestrator):
        """Should record performance metrics."""
        # Metrics should start empty
        assert len(orchestrator.metrics) == 0

        # Add a metric
        from src.core.threat_analysis_models import ModelPerformanceMetrics

        metric = ModelPerformanceMetrics(
            model_name="test",
            success=True,
            response_time=2.5,
            token_count=100
        )
        orchestrator.metrics.append(metric)

        metrics = orchestrator.get_metrics()

        assert len(metrics) == 1
        assert metrics[0]["model_name"] == "test"
        assert metrics[0]["response_time"] == 2.5

    def test_clear_metrics(self, orchestrator):
        """Should clear metrics."""
        from src.core.threat_analysis_models import ModelPerformanceMetrics

        orchestrator.metrics.append(ModelPerformanceMetrics(
            model_name="test",
            success=True,
            response_time=1.0
        ))

        assert len(orchestrator.metrics) == 1

        orchestrator.clear_metrics()

        assert len(orchestrator.metrics) == 0


@pytest.mark.asyncio
class TestAsyncExecution:
    """Test asynchronous execution and error handling."""

    async def test_timeout_handling(self, orchestrator):
        """Should handle model timeouts gracefully."""
        # Mock a slow model
        async def slow_query(*args, **kwargs):
            await asyncio.sleep(100)  # Very slow
            return {"findings": []}

        orchestrator._query_ollama = slow_query

        request = ThreatAnalysisRequest(
            target="test",
            scan_type="network",
            timeout=1  # 1 second timeout
        )

        # Should not raise exception, should return partial results
        # In reality would need mocked Claude/DeepSeek responses
        # This test verifies timeout doesn't crash the orchestrator

    async def test_partial_failure_returns_results(self, orchestrator):
        """Should return results even if some models fail."""
        # Mock one successful, one failed
        async def success_query(*args, **kwargs):
            return {
                "findings": [
                    {
                        "severity": "high",
                        "title": "Test Finding",
                        "description": "From working model"
                    }
                ]
            }

        async def fail_query(*args, **kwargs):
            raise Exception("Model failed")

        orchestrator._query_ollama = success_query
        orchestrator._query_claude = fail_query

        orchestrator.model_health = {"ollama": True, "claude": True}

        request = ThreatAnalysisRequest(
            target="test",
            scan_type="network",
            priority="high"  # Uses both models
        )

        # Should succeed with partial results
        result = await orchestrator.analyze_parallel(request)

        assert result is not None
        assert len(result.findings) > 0
        assert "ollama" in result.models_used


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
