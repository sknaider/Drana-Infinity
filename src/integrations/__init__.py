"""
GTL Platform Integration Components
"""

from .gtl_platform_connector import (
    GTLPlatformConnector,
    GTLScanRequest,
    GTLScanResult,
    GTLComplianceData,
    GTLIntegrationError,
)

__all__ = [
    "GTLPlatformConnector",
    "GTLScanRequest",
    "GTLScanResult",
    "GTLComplianceData",
    "GTLIntegrationError",
]
