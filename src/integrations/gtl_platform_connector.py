"""
GTL AI Security Platform Connector

Integrates Drana-GTL Edition with the existing GTL AI Security Platform
for unified security operations, compliance management, and reporting.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum
import aiohttp
from aiohttp import ClientSession, ClientTimeout, TCPConnector
import jwt


logger = logging.getLogger(__name__)


class ScanStatus(Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(Enum):
    """Scan type enumeration"""
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    THREAT_INTEL = "threat_intelligence"
    PENETRATION_TEST = "penetration_test"
    CONFIGURATION_AUDIT = "configuration_audit"
    MEDICAL_AI_SECURITY = "medical_ai_security"


class ComplianceFramework(Enum):
    """Supported compliance frameworks"""
    HIPAA = "hipaa"
    ISO27001 = "iso27001"
    SOC2 = "soc2"
    SUNAT = "sunat"
    GDPR = "gdpr"
    PCI_DSS = "pci_dss"
    NIST_CSF = "nist_csf"
    FDA_CYBERSECURITY = "fda_cybersecurity"


class GTLIntegrationError(Exception):
    """Base exception for GTL platform integration errors"""
    pass


class GTLAuthenticationError(GTLIntegrationError):
    """Authentication failed with GTL platform"""
    pass


class GTLAPIError(GTLIntegrationError):
    """API request to GTL platform failed"""
    pass


@dataclass
class GTLScanRequest:
    """Request to initiate a scan via GTL platform"""
    target: str
    scan_type: ScanType
    sector: str  # healthcare, finance, logistics, etc.
    scanner_engine: str = "drana-gtl"
    models: Optional[List[str]] = None  # ['ollama', 'claude', 'deepseek']
    priority: str = "normal"  # low, normal, high, critical
    scheduled_time: Optional[datetime] = None
    compliance_frameworks: Optional[List[ComplianceFramework]] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API submission"""
        data = {
            "target": self.target,
            "scan_type": self.scan_type.value,
            "sector": self.sector,
            "scanner_engine": self.scanner_engine,
            "priority": self.priority,
        }
        
        if self.models:
            data["models"] = self.models
        
        if self.scheduled_time:
            data["scheduled_time"] = self.scheduled_time.isoformat()
        
        if self.compliance_frameworks:
            data["compliance_frameworks"] = [f.value for f in self.compliance_frameworks]
        
        if self.metadata:
            data["metadata"] = self.metadata
        
        return data


@dataclass
class GTLScanResult:
    """Results from a Drana-GTL scan to submit to GTL platform"""
    scan_job_id: str
    drana_scan_id: str
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime]
    models_used: List[str]
    findings: List[Dict[str, Any]]
    confidence_score: float
    compliance_impact: Optional[Dict[str, Any]] = None
    threat_indicators: Optional[List[Dict[str, Any]]] = None
    recommendations: Optional[List[Dict[str, Any]]] = None
    metadata: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for API submission"""
        data = {
            "drana_scan_id": self.drana_scan_id,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "models_used": self.models_used,
            "findings": self.findings,
            "confidence_score": self.confidence_score,
        }
        
        if self.completed_at:
            data["completed_at"] = self.completed_at.isoformat()
        
        if self.compliance_impact:
            data["compliance_impact"] = self.compliance_impact
        
        if self.threat_indicators:
            data["threat_indicators"] = self.threat_indicators
        
        if self.recommendations:
            data["recommendations"] = self.recommendations
        
        if self.metadata:
            data["metadata"] = self.metadata
        
        return data


@dataclass
class GTLComplianceData:
    """Compliance control data from GTL platform"""
    framework: ComplianceFramework
    controls: List[Dict[str, Any]]
    requirements: Dict[str, Any]
    current_status: Dict[str, Any]
    last_assessment: Optional[datetime]
    next_assessment_due: Optional[datetime]
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'GTLComplianceData':
        """Create from API response dictionary"""
        return cls(
            framework=ComplianceFramework(data["framework"]),
            controls=data.get("controls", []),
            requirements=data.get("requirements", {}),
            current_status=data.get("current_status", {}),
            last_assessment=datetime.fromisoformat(data["last_assessment"]) if data.get("last_assessment") else None,
            next_assessment_due=datetime.fromisoformat(data["next_assessment_due"]) if data.get("next_assessment_due") else None,
        )


class GTLPlatformConnector:
    """
    Connector to integrate Drana-GTL Edition with GTL AI Security Platform
    
    Provides:
    - Scan request submission and result reporting
    - Compliance data synchronization
    - Incident management integration
    - Real-time status updates via WebSocket
    - Unified authentication via JWT
    """
    
    def __init__(
        self,
        gtl_api_base: str,
        api_key: str,
        client_id: Optional[str] = None,
        timeout: int = 30,
        max_retries: int = 3,
        verify_ssl: bool = True,
    ):
        """
        Initialize GTL Platform Connector
        
        Args:
            gtl_api_base: Base URL for GTL platform API (e.g., https://gtl-platform.com)
            api_key: API key for authentication
            client_id: Optional client ID for multi-tenant deployments
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts for failed requests
            verify_ssl: Whether to verify SSL certificates
        """
        self.gtl_api_base = gtl_api_base.rstrip('/')
        self.api_key = api_key
        self.client_id = client_id
        self.timeout = ClientTimeout(total=timeout)
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        
        self._session: Optional[ClientSession] = None
        self._jwt_token: Optional[str] = None
        self._token_expires_at: Optional[datetime] = None
        
        logger.info(f"GTL Platform Connector initialized for {gtl_api_base}")
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
    
    async def _ensure_session(self):
        """Ensure aiohttp session is created"""
        if self._session is None or self._session.closed:
            connector = TCPConnector(ssl=self.verify_ssl, limit=100)
            self._session = ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers={"User-Agent": "Drana-GTL/1.0"}
            )
            logger.debug("Created new aiohttp session")
    
    async def close(self):
        """Close the aiohttp session"""
        if self._session and not self._session.closed:
            await self._session.close()
            logger.debug("Closed aiohttp session")
    
    async def _get_jwt_token(self) -> str:
        """
        Authenticate with GTL platform and get JWT token
        
        Returns:
            JWT token string
            
        Raises:
            GTLAuthenticationError: If authentication fails
        """
        # Check if we have a valid cached token
        if self._jwt_token and self._token_expires_at:
            if datetime.utcnow() < self._token_expires_at - timedelta(minutes=5):
                return self._jwt_token
        
        # Authenticate to get new token
        await self._ensure_session()
        
        try:
            auth_data = {"api_key": self.api_key}
            if self.client_id:
                auth_data["client_id"] = self.client_id
            
            async with self._session.post(
                f"{self.gtl_api_base}/api/v1/auth/token",
                json=auth_data
            ) as response:
                if response.status == 401:
                    raise GTLAuthenticationError("Invalid API key")
                
                response.raise_for_status()
                data = await response.json()
                
                self._jwt_token = data["token"]
                
                # Decode token to get expiration
                decoded = jwt.decode(self._jwt_token, options={"verify_signature": False})
                self._token_expires_at = datetime.utcfromtimestamp(decoded["exp"])
                
                logger.info("Successfully authenticated with GTL platform")
                return self._jwt_token
        
        except aiohttp.ClientError as e:
            raise GTLAuthenticationError(f"Authentication failed: {str(e)}")
    
    async def _make_request(
        self,
        method: str,
        endpoint: str,
        json_data: Optional[Dict] = None,
        params: Optional[Dict] = None,
        retry_count: int = 0,
    ) -> Dict:
        """
        Make authenticated request to GTL platform API with retry logic
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint (without base URL)
            json_data: JSON payload for request body
            params: Query parameters
            retry_count: Current retry attempt number
            
        Returns:
            Response data as dictionary
            
        Raises:
            GTLAPIError: If request fails after all retries
        """
        await self._ensure_session()
        token = await self._get_jwt_token()
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        
        url = f"{self.gtl_api_base}{endpoint}"
        
        try:
            async with self._session.request(
                method,
                url,
                json=json_data,
                params=params,
                headers=headers
            ) as response:
                # Handle authentication expiration
                if response.status == 401:
                    if retry_count < self.max_retries:
                        logger.warning("Token expired, re-authenticating...")
                        self._jwt_token = None
                        return await self._make_request(method, endpoint, json_data, params, retry_count + 1)
                    raise GTLAPIError("Authentication failed after retries")
                
                response.raise_for_status()
                return await response.json()
        
        except aiohttp.ClientError as e:
            if retry_count < self.max_retries:
                wait_time = 2 ** retry_count  # Exponential backoff
                logger.warning(f"Request failed, retrying in {wait_time}s... (attempt {retry_count + 1}/{self.max_retries})")
                await asyncio.sleep(wait_time)
                return await self._make_request(method, endpoint, json_data, params, retry_count + 1)
            
            raise GTLAPIError(f"Request failed after {self.max_retries} retries: {str(e)}")
    
    async def submit_scan_request(self, scan_request: GTLScanRequest) -> str:
        """
        Submit scan request to GTL platform
        
        Args:
            scan_request: Scan request details
            
        Returns:
            GTL platform scan job ID
            
        Raises:
            GTLAPIError: If submission fails
        """
        logger.info(f"Submitting scan request for target: {scan_request.target}")
        
        response = await self._make_request(
            "POST",
            "/api/v1/scans",
            json_data=scan_request.to_dict()
        )
        
        scan_job_id = response["scan_job_id"]
        logger.info(f"Scan request submitted successfully: {scan_job_id}")
        
        return scan_job_id
    
    async def get_scan_status(self, scan_job_id: str) -> Dict:
        """
        Get status of a scan job
        
        Args:
            scan_job_id: GTL platform scan job ID
            
        Returns:
            Scan status information
        """
        logger.debug(f"Fetching scan status for: {scan_job_id}")
        
        return await self._make_request(
            "GET",
            f"/api/v1/scans/{scan_job_id}"
        )
    
    async def submit_scan_results(
        self,
        scan_job_id: str,
        results: GTLScanResult
    ):
        """
        Submit Drana-GTL scan results back to GTL platform
        
        Args:
            scan_job_id: GTL platform scan job ID
            results: Scan results from Drana-GTL
            
        Raises:
            GTLAPIError: If submission fails
        """
        logger.info(f"Submitting scan results for job: {scan_job_id}")
        
        await self._make_request(
            "POST",
            f"/api/v1/scans/{scan_job_id}/results",
            json_data=results.to_dict()
        )
        
        logger.info(f"Scan results submitted successfully for job: {scan_job_id}")
    
    async def update_scan_progress(
        self,
        scan_job_id: str,
        progress_percentage: int,
        current_step: str,
        metadata: Optional[Dict] = None
    ):
        """
        Update scan progress in real-time
        
        Args:
            scan_job_id: GTL platform scan job ID
            progress_percentage: Progress from 0-100
            current_step: Description of current step
            metadata: Additional progress metadata
        """
        update_data = {
            "progress": progress_percentage,
            "current_step": current_step,
            "updated_at": datetime.utcnow().isoformat()
        }
        
        if metadata:
            update_data["metadata"] = metadata
        
        await self._make_request(
            "PATCH",
            f"/api/v1/scans/{scan_job_id}/progress",
            json_data=update_data
        )
        
        logger.debug(f"Updated scan progress: {scan_job_id} - {progress_percentage}% - {current_step}")
    
    async def get_compliance_data(
        self,
        framework: ComplianceFramework,
        include_controls: bool = True,
        include_status: bool = True
    ) -> GTLComplianceData:
        """
        Retrieve compliance controls and requirements from GTL platform
        
        Args:
            framework: Compliance framework to retrieve
            include_controls: Include detailed control definitions
            include_status: Include current compliance status
            
        Returns:
            Compliance data for the framework
            
        Raises:
            GTLAPIError: If retrieval fails
        """
        logger.info(f"Fetching compliance data for framework: {framework.value}")
        
        params = {
            "include_controls": include_controls,
            "include_status": include_status
        }
        
        response = await self._make_request(
            "GET",
            f"/api/v1/compliance/frameworks/{framework.value}",
            params=params
        )
        
        compliance_data = GTLComplianceData.from_dict(response)
        logger.info(f"Retrieved {len(compliance_data.controls)} controls for {framework.value}")
        
        return compliance_data
    
    async def submit_compliance_assessment(
        self,
        framework: ComplianceFramework,
        assessment_results: Dict[str, Any],
        assessed_by: str,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Submit compliance assessment results to GTL platform
        
        Args:
            framework: Compliance framework assessed
            assessment_results: Assessment results by control ID
            assessed_by: Identifier for who/what performed assessment
            metadata: Additional assessment metadata
            
        Returns:
            Assessment ID
        """
        logger.info(f"Submitting compliance assessment for: {framework.value}")
        
        assessment_data = {
            "framework": framework.value,
            "results": assessment_results,
            "assessed_by": assessed_by,
            "assessed_at": datetime.utcnow().isoformat(),
        }
        
        if metadata:
            assessment_data["metadata"] = metadata
        
        response = await self._make_request(
            "POST",
            "/api/v1/compliance/assessments",
            json_data=assessment_data
        )
        
        assessment_id = response["assessment_id"]
        logger.info(f"Compliance assessment submitted: {assessment_id}")
        
        return assessment_id
    
    async def create_incident(
        self,
        title: str,
        description: str,
        severity: str,
        finding_ids: Optional[List[str]] = None,
        threat_indicators: Optional[List[Dict]] = None,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Create incident in GTL platform from Drana-GTL findings
        
        Args:
            title: Incident title
            description: Detailed description
            severity: Incident severity (low, medium, high, critical)
            finding_ids: List of Drana finding IDs
            threat_indicators: Associated threat indicators
            metadata: Additional incident metadata
            
        Returns:
            GTL platform incident ID
        """
        logger.info(f"Creating incident: {title}")
        
        incident_data = {
            "title": title,
            "description": description,
            "severity": severity,
            "source": "drana-gtl",
            "created_at": datetime.utcnow().isoformat(),
        }
        
        if finding_ids:
            incident_data["drana_finding_ids"] = finding_ids
        
        if threat_indicators:
            incident_data["threat_indicators"] = threat_indicators
        
        if metadata:
            incident_data["metadata"] = metadata
        
        response = await self._make_request(
            "POST",
            "/api/v1/incidents",
            json_data=incident_data
        )
        
        incident_id = response["incident_id"]
        logger.info(f"Incident created: {incident_id}")
        
        return incident_id
    
    async def update_incident(
        self,
        incident_id: str,
        status: Optional[str] = None,
        updates: Optional[Dict] = None
    ):
        """
        Update an existing incident
        
        Args:
            incident_id: GTL platform incident ID
            status: New status (open, investigating, resolved, closed)
            updates: Additional fields to update
        """
        update_data = {"updated_at": datetime.utcnow().isoformat()}
        
        if status:
            update_data["status"] = status
        
        if updates:
            update_data.update(updates)
        
        await self._make_request(
            "PATCH",
            f"/api/v1/incidents/{incident_id}",
            json_data=update_data
        )
        
        logger.info(f"Incident updated: {incident_id}")
    
    async def get_threat_intelligence(
        self,
        lookback_hours: int = 24,
        sectors: Optional[List[str]] = None,
        severity_min: Optional[str] = None
    ) -> List[Dict]:
        """
        Retrieve threat intelligence from GTL platform
        
        Args:
            lookback_hours: How many hours back to fetch threats
            sectors: Filter by specific sectors
            severity_min: Minimum severity level
            
        Returns:
            List of threat indicators
        """
        logger.info(f"Fetching threat intelligence (lookback: {lookback_hours}h)")
        
        params = {"lookback_hours": lookback_hours}
        
        if sectors:
            params["sectors"] = ",".join(sectors)
        
        if severity_min:
            params["severity_min"] = severity_min
        
        response = await self._make_request(
            "GET",
            "/api/v1/threat-intelligence",
            params=params
        )
        
        threats = response.get("threats", [])
        logger.info(f"Retrieved {len(threats)} threat indicators")
        
        return threats
    
    async def submit_threat_indicators(
        self,
        indicators: List[Dict[str, Any]],
        source: str = "drana-gtl"
    ):
        """
        Submit threat indicators discovered by Drana-GTL to GTL platform
        
        Args:
            indicators: List of threat indicators
            source: Source identifier
        """
        logger.info(f"Submitting {len(indicators)} threat indicators")
        
        submission_data = {
            "indicators": indicators,
            "source": source,
            "submitted_at": datetime.utcnow().isoformat()
        }
        
        await self._make_request(
            "POST",
            "/api/v1/threat-intelligence/indicators",
            json_data=submission_data
        )
        
        logger.info("Threat indicators submitted successfully")
    
    async def get_client_configuration(self) -> Dict:
        """
        Retrieve client-specific configuration from GTL platform
        
        Returns:
            Configuration dictionary
        """
        logger.info("Fetching client configuration")
        
        endpoint = "/api/v1/configuration"
        if self.client_id:
            endpoint += f"?client_id={self.client_id}"
        
        config = await self._make_request("GET", endpoint)
        
        logger.info("Client configuration retrieved")
        return config
    
    async def health_check(self) -> Dict:
        """
        Check health status of GTL platform connection
        
        Returns:
            Health check results
        """
        try:
            response = await self._make_request("GET", "/api/v1/health")
            
            return {
                "status": "healthy",
                "gtl_platform": response.get("status", "unknown"),
                "connection": "ok",
                "authenticated": self._jwt_token is not None,
                "timestamp": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return {
                "status": "unhealthy",
                "error": str(e),
                "connection": "failed",
                "authenticated": False,
                "timestamp": datetime.utcnow().isoformat()
            }


# Example usage
async def main():
    """Example usage of GTL Platform Connector"""
    
    connector = GTLPlatformConnector(
        gtl_api_base="https://gtl-platform.example.com",
        api_key="your-api-key-here"
    )
    
    async with connector:
        # Check health
        health = await connector.health_check()
        print(f"Health check: {health}")
        
        # Submit scan request
        scan_request = GTLScanRequest(
            target="medical-ai-system.hospital.com",
            scan_type=ScanType.MEDICAL_AI_SECURITY,
            sector="healthcare",
            models=["ollama", "claude", "deepseek"],
            compliance_frameworks=[ComplianceFramework.HIPAA, ComplianceFramework.FDA_CYBERSECURITY]
        )
        
        scan_job_id = await connector.submit_scan_request(scan_request)
        print(f"Scan job submitted: {scan_job_id}")
        
        # Get compliance data
        hipaa_data = await connector.get_compliance_data(ComplianceFramework.HIPAA)
        print(f"HIPAA controls: {len(hipaa_data.controls)}")
        
        # Submit results (example)
        results = GTLScanResult(
            scan_job_id=scan_job_id,
            drana_scan_id="drana-12345",
            status=ScanStatus.COMPLETED,
            started_at=datetime.utcnow() - timedelta(hours=1),
            completed_at=datetime.utcnow(),
            models_used=["ollama", "claude", "deepseek"],
            findings=[
                {
                    "id": "finding-1",
                    "severity": "high",
                    "title": "Model inversion vulnerability detected",
                    "description": "Medical AI model susceptible to training data reconstruction"
                }
            ],
            confidence_score=0.92
        )
        
        await connector.submit_scan_results(scan_job_id, results)
        print("Results submitted successfully")


if __name__ == "__main__":
    asyncio.run(main())
