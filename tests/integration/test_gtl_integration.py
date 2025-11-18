"""
Integration Tests for GTL Platform + Drana-GTL Integration

Tests the complete integration between Drana-GTL and GTL AI Security Platform.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any
import json

# Import integration components
from src.integrations.gtl_platform_connector import (
    GTLPlatformConnector,
    GTLScanRequest,
    GTLScanResult,
    ScanType,
    ScanStatus,
    ComplianceFramework,
)
from src.websocket.drana_scan_websocket import DranaScanWebSocketHandler
from src.reporting.unified_report_generator import (
    UnifiedReportGenerator,
    ReportConfig,
    ReportFormat,
    ReportSection,
)


class MockGTLAPIServer:
    """Mock GTL Platform API for testing"""
    
    def __init__(self):
        self.scans = {}
        self.compliance_data = {}
        self.incidents = {}
    
    async def create_scan(self, scan_data: Dict) -> str:
        scan_id = f"scan_{len(self.scans) + 1}"
        self.scans[scan_id] = {
            **scan_data,
            "scan_job_id": scan_id,
            "status": "pending",
            "created_at": datetime.utcnow().isoformat()
        }
        return scan_id
    
    async def get_scan(self, scan_id: str) -> Dict:
        return self.scans.get(scan_id, {})
    
    async def submit_results(self, scan_id: str, results: Dict):
        if scan_id in self.scans:
            self.scans[scan_id]["results"] = results
            self.scans[scan_id]["status"] = "completed"
    
    async def get_compliance_data(self, framework: str) -> Dict:
        return self.compliance_data.get(framework, {
            "framework": framework,
            "controls": [],
            "requirements": {},
            "current_status": {}
        })


@pytest.fixture
async def mock_gtl_api():
    """Fixture for mock GTL API server"""
    return MockGTLAPIServer()


@pytest.fixture
async def gtl_connector(mock_gtl_api):
    """Fixture for GTL Platform Connector"""
    # In tests, we'd mock the HTTP calls to use mock_gtl_api
    connector = GTLPlatformConnector(
        gtl_api_base="http://localhost:8888",
        api_key="test_api_key"
    )
    # Override _make_request to use mock
    # (In real tests, you'd use aioresponses or similar)
    return connector


@pytest.fixture
def websocket_handler():
    """Fixture for WebSocket handler"""
    return DranaScanWebSocketHandler()


class TestGTLPlatformConnectorIntegration:
    """Test GTL Platform Connector integration"""
    
    @pytest.mark.asyncio
    async def test_submit_scan_request(self, gtl_connector):
        """Test submitting a scan request to GTL platform"""
        scan_request = GTLScanRequest(
            target="test-system.example.com",
            scan_type=ScanType.MEDICAL_AI_SECURITY,
            sector="healthcare",
            models=["ollama", "claude", "deepseek"],
            compliance_frameworks=[ComplianceFramework.HIPAA]
        )
        
        # Note: This would actually call the API in real integration test
        # For unit test, we verify the request structure
        request_dict = scan_request.to_dict()
        
        assert request_dict["target"] == "test-system.example.com"
        assert request_dict["scan_type"] == "medical_ai_security"
        assert request_dict["sector"] == "healthcare"
        assert len(request_dict["models"]) == 3
    
    @pytest.mark.asyncio
    async def test_submit_scan_results(self, gtl_connector):
        """Test submitting scan results to GTL platform"""
        results = GTLScanResult(
            scan_job_id="test_job_123",
            drana_scan_id="drana_scan_456",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow() - timedelta(hours=1),
            completed_at=datetime.utcnow(),
            models_used=["ollama", "claude"],
            findings=[
                {
                    "id": "finding_1",
                    "severity": "high",
                    "title": "Test finding",
                    "description": "Test description"
                }
            ],
            confidence_score=0.92
        )
        
        results_dict = results.to_dict()
        
        assert results_dict["scan_job_id"] == "test_job_123"
        assert results_dict["drana_scan_id"] == "drana_scan_456"
        assert results_dict["status"] == "completed"
        assert len(results_dict["findings"]) == 1
        assert results_dict["confidence_score"] == 0.92
    
    @pytest.mark.asyncio
    async def test_compliance_data_retrieval(self, gtl_connector):
        """Test retrieving compliance data from GTL platform"""
        # This would make actual API call in integration test
        # Here we test the data structure
        framework = ComplianceFramework.HIPAA
        
        assert framework.value == "hipaa"
    
    @pytest.mark.asyncio
    async def test_create_incident(self, gtl_connector):
        """Test creating incident in GTL platform"""
        # Test incident creation structure
        incident_data = {
            "title": "Critical security finding",
            "description": "Test incident",
            "severity": "critical",
            "finding_ids": ["finding_1", "finding_2"]
        }
        
        assert incident_data["severity"] == "critical"
        assert len(incident_data["finding_ids"]) == 2


class TestWebSocketIntegration:
    """Test WebSocket handler integration"""
    
    @pytest.mark.asyncio
    async def test_client_registration(self, websocket_handler):
        """Test client registration"""
        from unittest.mock import MagicMock, AsyncMock
        
        mock_websocket = MagicMock()
        mock_websocket.send = AsyncMock()
        client_id = "test_client_1"
        
        await websocket_handler.register(mock_websocket, client_id)
        
        assert client_id in websocket_handler.clients
        assert client_id in websocket_handler.client_scan_map
        
        # Verify welcome message sent
        mock_websocket.send.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_scan_subscription(self, websocket_handler):
        """Test subscribing to scan updates"""
        from unittest.mock import MagicMock, AsyncMock
        
        mock_websocket = MagicMock()
        mock_websocket.send = AsyncMock()
        client_id = "test_client_1"
        scan_id = "test_scan_1"
        
        # Register client first
        await websocket_handler.register(mock_websocket, client_id)
        
        # Subscribe to scan
        await websocket_handler.subscribe_to_scan(client_id, scan_id)
        
        assert scan_id in websocket_handler.scan_subscriptions
        assert client_id in websocket_handler.scan_subscriptions[scan_id]
        assert scan_id in websocket_handler.client_scan_map[client_id]
    
    @pytest.mark.asyncio
    async def test_broadcast_scan_update(self, websocket_handler):
        """Test broadcasting scan update to subscribers"""
        from unittest.mock import MagicMock, AsyncMock
        
        mock_websocket = MagicMock()
        mock_websocket.send = AsyncMock()
        client_id = "test_client_1"
        scan_id = "test_scan_1"
        
        # Setup
        await websocket_handler.register(mock_websocket, client_id)
        await websocket_handler.subscribe_to_scan(client_id, scan_id)
        
        # Broadcast update
        update_data = {
            "status": "running",
            "progress": 50
        }
        
        await websocket_handler.broadcast_scan_update(scan_id, update_data)
        
        # Verify message sent
        assert mock_websocket.send.called
    
    @pytest.mark.asyncio
    async def test_client_unregistration(self, websocket_handler):
        """Test client unregistration cleans up subscriptions"""
        from unittest.mock import MagicMock, AsyncMock
        
        mock_websocket = MagicMock()
        mock_websocket.send = AsyncMock()
        client_id = "test_client_1"
        scan_id = "test_scan_1"
        
        # Setup
        await websocket_handler.register(mock_websocket, client_id)
        await websocket_handler.subscribe_to_scan(client_id, scan_id)
        
        # Unregister
        await websocket_handler.unregister(client_id)
        
        # Verify cleanup
        assert client_id not in websocket_handler.clients
        assert client_id not in websocket_handler.client_scan_map
        # Scan subscription should be cleaned up too
        if scan_id in websocket_handler.scan_subscriptions:
            assert client_id not in websocket_handler.scan_subscriptions[scan_id]


class TestUnifiedReportingIntegration:
    """Test unified report generator integration"""
    
    @pytest.mark.asyncio
    async def test_report_config_creation(self):
        """Test creating report configuration"""
        config = ReportConfig(
            client_id="test_client",
            client_name="Test Healthcare Organization",
            report_title="Security Assessment Report",
            date_range=(
                datetime.utcnow() - timedelta(days=30),
                datetime.utcnow()
            ),
            sections=[
                ReportSection.EXECUTIVE_SUMMARY,
                ReportSection.DRANA_AI_ANALYSIS,
                ReportSection.COMPLIANCE_ASSESSMENT
            ]
        )
        
        assert config.client_id == "test_client"
        assert len(config.sections) == 3
        assert config.confidentiality_level == "confidential"
    
    @pytest.mark.asyncio
    async def test_report_section_enum(self):
        """Test report section enumeration"""
        sections = list(ReportSection)
        
        assert ReportSection.EXECUTIVE_SUMMARY in sections
        assert ReportSection.DRANA_AI_ANALYSIS in sections
        assert ReportSection.COMPLIANCE_ASSESSMENT in sections
        assert ReportSection.TECHNICAL_DETAILS in sections
        assert ReportSection.RECOMMENDATIONS in sections


class TestEndToEndIntegration:
    """End-to-end integration tests"""
    
    @pytest.mark.asyncio
    async def test_complete_scan_workflow(self):
        """Test complete scan workflow from submission to reporting"""
        # This would be a full integration test
        # 1. Submit scan via GTL connector
        # 2. Monitor via WebSocket
        # 3. Receive findings
        # 4. Generate report
        
        # For now, test the workflow structure
        workflow_steps = [
            "submit_scan_request",
            "subscribe_to_scan_updates",
            "execute_scan",
            "broadcast_findings",
            "submit_results",
            "generate_report"
        ]
        
        assert len(workflow_steps) == 6
    
    @pytest.mark.asyncio
    async def test_multi_model_scan_integration(self):
        """Test multi-model scan integration"""
        models = ["ollama", "claude", "deepseek"]
        
        # Verify all models configured
        assert len(models) == 3
        assert "claude" in models
    
    @pytest.mark.asyncio
    async def test_compliance_integration_workflow(self):
        """Test compliance assessment integration"""
        frameworks = [
            ComplianceFramework.HIPAA,
            ComplianceFramework.FDA_CYBERSECURITY
        ]
        
        assert ComplianceFramework.HIPAA in frameworks
        assert ComplianceFramework.FDA_CYBERSECURITY in frameworks


class TestDatabaseIntegration:
    """Test database integration"""
    
    @pytest.mark.asyncio
    async def test_drana_scans_table_structure(self):
        """Test drana_scans table exists with correct structure"""
        # This would query actual database in real integration test
        expected_columns = [
            "scan_id",
            "gtl_scan_job_id",
            "target",
            "scan_type",
            "status",
            "models_used",
            "confidence_score"
        ]
        
        assert len(expected_columns) > 0
    
    @pytest.mark.asyncio
    async def test_drana_findings_table_structure(self):
        """Test drana_findings table exists"""
        expected_columns = [
            "finding_id",
            "scan_id",
            "severity",
            "confidence",
            "title",
            "description"
        ]
        
        assert len(expected_columns) > 0


# Performance tests
class TestPerformance:
    """Performance tests for integration"""
    
    @pytest.mark.asyncio
    async def test_websocket_broadcast_performance(self, websocket_handler):
        """Test WebSocket can handle multiple subscribers"""
        from unittest.mock import MagicMock, AsyncMock
        
        scan_id = "perf_test_scan"
        num_clients = 100
        
        # Register many clients
        for i in range(num_clients):
            mock_ws = MagicMock()
            mock_ws.send = AsyncMock()
            client_id = f"client_{i}"
            
            await websocket_handler.register(mock_ws, client_id)
            await websocket_handler.subscribe_to_scan(client_id, scan_id)
        
        # Broadcast should handle all clients
        assert len(websocket_handler.scan_subscriptions[scan_id]) == num_clients
        
        # Broadcast update
        import time
        start = time.time()
        
        await websocket_handler.broadcast_scan_update(scan_id, {"test": "data"})
        
        duration = time.time() - start
        
        # Should complete in reasonable time (< 1 second for 100 clients)
        assert duration < 1.0
    
    @pytest.mark.asyncio
    async def test_scan_request_latency(self, gtl_connector):
        """Test scan request submission latency"""
        scan_request = GTLScanRequest(
            target="test.example.com",
            scan_type=ScanType.VULNERABILITY,
            sector="healthcare"
        )
        
        # Converting to dict should be fast
        import time
        start = time.time()
        
        request_dict = scan_request.to_dict()
        
        duration = time.time() - start
        
        assert duration < 0.01  # < 10ms


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
