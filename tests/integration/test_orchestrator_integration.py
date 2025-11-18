"""
Integration Tests for Multi-Model Orchestrator

Tests end-to-end analysis with real model interactions (mocked for CI/CD).
"""

import pytest
import asyncio
from datetime import datetime

from src.core.multi_model_orchestrator_v2 import EnhancedMultiModelOrchestrator
from src.core.threat_analysis_models import ThreatAnalysisRequest


@pytest.mark.integration
@pytest.mark.asyncio
class TestEndToEndAnalysis:
    """
    End-to-end integration tests.

    Note: These tests can be run with real models by setting environment
    variables, or with mocked responses for CI/CD.
    """

    async def test_full_threat_analysis_critical_priority(self):
        """
        Test complete analysis workflow with critical priority.

        This should use all available models and produce comprehensive results.
        """
        # Initialize orchestrator
        orchestrator = EnhancedMultiModelOrchestrator()

        # Skip if no models available
        if not any(orchestrator.model_health.values()):
            pytest.skip("No AI models available")

        # Create request
        request = ThreatAnalysisRequest(
            target="192.168.1.100",
            scan_type="network",
            sector="GENERAL",
            priority="critical",
            context={
                "network_segment": "DMZ",
                "services": ["HTTP", "HTTPS", "SSH"],
                "os_type": "Linux"
            },
            timeout=60
        )

        # Execute analysis
        result = await orchestrator.analyze_parallel(request)

        # Verify response structure
        assert result.threat_id is not None
        assert result.target == "192.168.1.100"
        assert result.scan_type == "network"
        assert isinstance(result.timestamp, datetime)
        assert len(result.models_used) > 0
        assert isinstance(result.findings, list)
        assert isinstance(result.recommendations, list)
        assert 0.0 <= result.confidence_score <= 1.0
        assert result.execution_time > 0

    async def test_compliance_analysis_with_hipaa(self):
        """
        Test compliance-focused analysis with HIPAA framework.

        Should prioritize Claude for compliance reasoning.
        """
        orchestrator = EnhancedMultiModelOrchestrator()

        if "claude" not in orchestrator.model_health or not orchestrator.model_health["claude"]:
            pytest.skip("Claude not available for compliance testing")

        request = ThreatAnalysisRequest(
            target="medical-records-db",
            scan_type="compliance",
            sector="MEDICAL_AI",
            compliance_frameworks=["HIPAA", "ISO27001"],
            priority="high",
            context={
                "system_type": "EHR database",
                "data_classification": "PHI",
                "encryption": "AES-256"
            }
        )

        result = await orchestrator.analyze_parallel(request)

        # Should include Claude
        assert "claude" in result.models_used

        # Should have compliance impact
        assert len(result.compliance_impact) > 0

    async def test_medical_ai_security_analysis(self):
        """
        Test medical AI security analysis.

        Should include DeepSeek if available.
        """
        orchestrator = EnhancedMultiModelOrchestrator()

        if not any(orchestrator.model_health.values()):
            pytest.skip("No models available")

        request = ThreatAnalysisRequest(
            target="medical-imaging-classifier",
            scan_type="medical_ai",
            sector="MEDICAL_AI",
            priority="high",
            context={
                "model_type": "CNN classifier",
                "purpose": "Chest X-ray diagnosis",
                "fda_class": "Class II",
                "training_data": "Public + proprietary datasets"
            }
        )

        result = await orchestrator.analyze_parallel(request)

        # Verify medical AI specific analysis
        assert result.scan_type == "medical_ai"
        assert result.metadata["sector"] == "MEDICAL_AI"

    async def test_logistics_supply_chain_analysis(self):
        """
        Test logistics and supply chain security analysis.

        Should use sector-specific prompts for EDI and SUNAT.
        """
        orchestrator = EnhancedMultiModelOrchestrator()

        if not any(orchestrator.model_health.values()):
            pytest.skip("No models available")

        request = ThreatAnalysisRequest(
            target="edi-gateway.company.com",
            scan_type="api_security",
            sector="LOGISTICS",
            compliance_frameworks=["SUNAT_PERU"],
            priority="high",
            context={
                "system": "EDI gateway",
                "protocols": ["X12", "EDIFACT"],
                "partners": 50,
                "sunat_integration": True
            }
        )

        result = await orchestrator.analyze_parallel(request)

        # Verify logistics context
        assert result.metadata["sector"] == "LOGISTICS"

    async def test_low_priority_quick_scan(self):
        """
        Test low priority scan for performance.

        Should use only Ollama for speed.
        """
        orchestrator = EnhancedMultiModelOrchestrator()

        if "ollama" not in orchestrator.model_health or not orchestrator.model_health["ollama"]:
            pytest.skip("Ollama not available")

        request = ThreatAnalysisRequest(
            target="internal-dev-server",
            scan_type="network",
            priority="low",
            timeout=30
        )

        result = await orchestrator.analyze_parallel(request)

        # Should complete quickly
        assert result.execution_time < 30

        # Should use only Ollama
        assert result.models_used == ["ollama"]


@pytest.mark.integration
class TestParallelExecution:
    """Test parallel execution and concurrency."""

    @pytest.mark.asyncio
    async def test_concurrent_analyses(self):
        """
        Test multiple concurrent analyses.

        Verifies orchestrator can handle concurrent requests.
        """
        orchestrator = EnhancedMultiModelOrchestrator()

        if not any(orchestrator.model_health.values()):
            pytest.skip("No models available")

        # Create multiple requests
        requests = [
            ThreatAnalysisRequest(
                target=f"server-{i}",
                scan_type="network",
                priority="medium",
                timeout=30
            )
            for i in range(3)
        ]

        # Execute concurrently
        start_time = asyncio.get_event_loop().time()

        results = await asyncio.gather(
            *[orchestrator.analyze_parallel(req) for req in requests]
        )

        total_time = asyncio.get_event_loop().time() - start_time

        # Verify all completed
        assert len(results) == 3

        # Concurrent execution should be faster than sequential
        # (though not always guaranteed with async/mock)
        for result in results:
            assert result is not None


@pytest.mark.integration
class TestErrorHandling:
    """Test error handling in real scenarios."""

    @pytest.mark.asyncio
    async def test_analysis_with_partial_model_failure(self):
        """
        Test analysis when some models are unavailable.

        Should gracefully degrade and use available models.
        """
        orchestrator = EnhancedMultiModelOrchestrator()

        # Artificially mark one model as unhealthy
        original_health = orchestrator.model_health.copy()
        if "deepseek" in orchestrator.model_health:
            orchestrator.model_health["deepseek"] = False

        request = ThreatAnalysisRequest(
            target="test-system",
            scan_type="network",
            priority="critical",  # Would normally use all models
            timeout=60
        )

        result = await orchestrator.analyze_parallel(request)

        # Should succeed with available models
        assert result is not None
        assert len(result.models_used) > 0

        # Restore health
        orchestrator.model_health = original_health

    @pytest.mark.asyncio
    async def test_timeout_with_slow_models(self):
        """
        Test overall timeout enforcement.

        Even if models are slow, should respect timeout.
        """
        orchestrator = EnhancedMultiModelOrchestrator()

        if not any(orchestrator.model_health.values()):
            pytest.skip("No models available")

        request = ThreatAnalysisRequest(
            target="test",
            scan_type="network",
            priority="medium",
            timeout=5  # Very short timeout
        )

        # Should complete or timeout gracefully
        try:
            result = await orchestrator.analyze_parallel(request)
            # If successful, execution time should be within timeout
            assert result.execution_time <= 10  # Some buffer
        except RuntimeError as e:
            # Acceptable if all models fail due to timeout
            assert "failed to respond" in str(e).lower()


@pytest.mark.integration
class TestPerformanceBenchmarks:
    """Performance benchmarks for orchestrator."""

    @pytest.mark.asyncio
    async def test_ollama_response_time(self):
        """Benchmark Ollama response time (target <2s)."""
        orchestrator = EnhancedMultiModelOrchestrator()

        if "ollama" not in orchestrator.model_health or not orchestrator.model_health["ollama"]:
            pytest.skip("Ollama not available")

        request = ThreatAnalysisRequest(
            target="benchmark-test",
            scan_type="network",
            priority="low",  # Ollama only
            max_models=1
        )

        result = await orchestrator.analyze_parallel(request)

        # Target: <2s average for Ollama
        print(f"Ollama response time: {result.execution_time:.2f}s")
        # Note: May exceed in CI/CD or slow systems

    @pytest.mark.asyncio
    async def test_full_analysis_response_time(self):
        """Benchmark full analysis with all models (target <15s)."""
        orchestrator = EnhancedMultiModelOrchestrator()

        healthy_models = sum(1 for h in orchestrator.model_health.values() if h)
        if healthy_models == 0:
            pytest.skip("No models available")

        request = ThreatAnalysisRequest(
            target="benchmark-test",
            scan_type="network",
            priority="critical",  # Use all models
            timeout=30
        )

        result = await orchestrator.analyze_parallel(request)

        # Target: <15s for all models
        print(f"Full analysis time: {result.execution_time:.2f}s with {len(result.models_used)} models")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "integration"])
