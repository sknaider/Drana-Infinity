"""
Drana-Infinity GTL Edition - Enterprise AI Security Platform

Author: GTL Consulting
Version: 1.0.0-gtl
License: Proprietary (Based on open-source Drana-Infinity)

An enhanced cybersecurity platform with 200%+ capability improvements:
- Multi-model AI orchestration (Ollama + Claude + DeepSeek)
- Automated compliance validation (HIPAA, ISO 27001, NIST CSF, SUNAT)
- Sector specialization (Logistics & Medical AI)
- RTX 5090 GPU optimization
- Enterprise integration capabilities
"""

__version__ = "1.0.0-gtl"
__author__ = "GTL Consulting"
__license__ = "Proprietary"

from typing import Dict, Any

# Package-level constants
SUPPORTED_COMPLIANCE_FRAMEWORKS = [
    "HIPAA",
    "ISO27001",
    "NIST_CSF",
    "SUNAT_PERU",
    "LEY_29733_PERU"
]

SUPPORTED_SECTORS = [
    "LOGISTICS",
    "MEDICAL_AI",
    "GENERAL"
]

AI_MODELS = {
    "OLLAMA": "drana-infinity-v1",
    "CLAUDE": "claude-sonnet-4-5-20250929",
    "DEEPSEEK": "deepseek-r1"
}

# Hardware specifications
GPU_SPECS = {
    "model": "RTX 5090",
    "vram_gb": 32,
    "tensor_cores": 680,
    "architecture": "Blackwell",
    "compute_capability": "sm_120"
}
