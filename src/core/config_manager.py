"""
Configuration Management System for Drana-Infinity GTL Edition

Handles environment variables, secrets, and dynamic configuration for:
- AI model endpoints and API keys
- Database connections
- GPU resource allocation
- Compliance framework settings
- Security parameters
"""

import os
import json
from typing import Dict, Any, Optional, List
from pathlib import Path
from dataclasses import dataclass, field
import logging
from enum import Enum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class Environment(Enum):
    """Deployment environment types."""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class ComplianceLevel(Enum):
    """Compliance enforcement levels."""
    AUDIT_ONLY = "audit_only"
    WARN = "warn"
    ENFORCE = "enforce"


@dataclass
class AIModelConfig:
    """Configuration for AI model endpoints."""
    model_name: str
    endpoint_url: str
    api_key: Optional[str] = None
    max_tokens: int = 4096
    temperature: float = 0.7
    timeout_seconds: int = 120
    enabled: bool = True
    priority: int = 1  # Lower = higher priority for orchestration


@dataclass
class GPUConfig:
    """RTX 5090 GPU configuration."""
    device_id: int = 0
    max_vram_allocation_gb: int = 24  # Leave 8GB for medical AI
    concurrent_workloads: int = 4
    enable_mixed_precision: bool = True
    enable_tensor_cores: bool = True
    compute_capability: str = "sm_120"
    monitoring_interval_seconds: int = 30


@dataclass
class DatabaseConfig:
    """Database connection configuration."""
    type: str = "postgresql"  # postgresql for production, sqlite for dev
    host: str = "localhost"
    port: int = 5432
    database: str = "drana_gtl"
    username: str = ""
    password: str = ""
    pool_size: int = 20
    max_overflow: int = 10
    ssl_mode: str = "require"  # For production


@dataclass
class SecurityConfig:
    """Security and authentication settings."""
    jwt_secret_key: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60
    jwt_refresh_expiry_days: int = 30
    enable_mfa: bool = True
    password_min_length: int = 12
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 30
    encryption_algorithm: str = "AES-256-GCM"
    tls_version: str = "1.3"
    enable_audit_logging: bool = True
    phi_detection_enabled: bool = True  # Prevent PHI in logs


@dataclass
class ComplianceConfig:
    """Compliance framework settings."""
    enabled_frameworks: List[str] = field(default_factory=lambda: ["HIPAA", "ISO27001", "NIST_CSF"])
    enforcement_level: ComplianceLevel = ComplianceLevel.WARN
    audit_retention_years: int = 6
    auto_remediation: bool = False
    compliance_scan_interval_hours: int = 24
    report_generation_enabled: bool = True


@dataclass
class ThreatIntelConfig:
    """Threat intelligence feed configuration."""
    enable_cisa_feed: bool = True
    enable_fda_feed: bool = True
    enable_nvd_feed: bool = True
    enable_mitre_attack: bool = True
    update_interval_hours: int = 6
    ioc_retention_days: int = 90
    threat_score_threshold: float = 0.7  # 0.0-1.0


class ConfigManager:
    """
    Central configuration management for Drana-Infinity GTL Edition.

    Loads configuration from environment variables with sensible defaults.
    Implements secure secret handling and validation.
    """

    def __init__(self, env_file: Optional[str] = None):
        """
        Initialize configuration manager.

        Args:
            env_file: Path to .env file (optional, defaults to .env in project root)
        """
        self.env_file = env_file or self._find_env_file()
        self.environment = self._load_environment()

        # Load all configuration sections
        self.ai_models = self._load_ai_models()
        self.gpu = self._load_gpu_config()
        self.database = self._load_database_config()
        self.security = self._load_security_config()
        self.compliance = self._load_compliance_config()
        self.threat_intel = self._load_threat_intel_config()

        # Validate critical configurations
        self._validate_config()

        logger.info(f"Configuration loaded for environment: {self.environment.value}")

    def _find_env_file(self) -> Optional[str]:
        """Find .env file in project root."""
        current_dir = Path(__file__).parent
        while current_dir != current_dir.parent:
            env_path = current_dir / ".env"
            if env_path.exists():
                return str(env_path)
            current_dir = current_dir.parent
        return None

    def _load_environment(self) -> Environment:
        """Load and validate deployment environment."""
        env_str = os.getenv("DRANA_ENV", "development").lower()
        try:
            return Environment(env_str)
        except ValueError:
            logger.warning(f"Invalid environment '{env_str}', defaulting to development")
            return Environment.DEVELOPMENT

    def _load_ai_models(self) -> Dict[str, AIModelConfig]:
        """Load AI model configurations."""
        return {
            "ollama": AIModelConfig(
                model_name=os.getenv("OLLAMA_MODEL", "IHA089/drana-infinity-v1"),
                endpoint_url=os.getenv("OLLAMA_ENDPOINT", "http://localhost:11434"),
                api_key=None,  # Ollama doesn't require API key
                max_tokens=int(os.getenv("OLLAMA_MAX_TOKENS", "4096")),
                temperature=float(os.getenv("OLLAMA_TEMPERATURE", "0.7")),
                timeout_seconds=int(os.getenv("OLLAMA_TIMEOUT", "120")),
                enabled=os.getenv("OLLAMA_ENABLED", "true").lower() == "true",
                priority=1
            ),
            "claude": AIModelConfig(
                model_name=os.getenv("CLAUDE_MODEL", "claude-sonnet-4-5-20250929"),
                endpoint_url=os.getenv("CLAUDE_ENDPOINT", "https://api.anthropic.com/v1"),
                api_key=os.getenv("ANTHROPIC_API_KEY"),
                max_tokens=int(os.getenv("CLAUDE_MAX_TOKENS", "8192")),
                temperature=float(os.getenv("CLAUDE_TEMPERATURE", "0.5")),
                timeout_seconds=int(os.getenv("CLAUDE_TIMEOUT", "180")),
                enabled=os.getenv("CLAUDE_ENABLED", "true").lower() == "true",
                priority=2
            ),
            "deepseek": AIModelConfig(
                model_name=os.getenv("DEEPSEEK_MODEL", "deepseek-r1"),
                endpoint_url=os.getenv("DEEPSEEK_ENDPOINT", "http://localhost:8000"),
                api_key=os.getenv("DEEPSEEK_API_KEY"),
                max_tokens=int(os.getenv("DEEPSEEK_MAX_TOKENS", "8192")),
                temperature=float(os.getenv("DEEPSEEK_TEMPERATURE", "0.6")),
                timeout_seconds=int(os.getenv("DEEPSEEK_TIMEOUT", "180")),
                enabled=os.getenv("DEEPSEEK_ENABLED", "false").lower() == "true",
                priority=3
            )
        }

    def _load_gpu_config(self) -> GPUConfig:
        """Load GPU configuration for RTX 5090."""
        return GPUConfig(
            device_id=int(os.getenv("GPU_DEVICE_ID", "0")),
            max_vram_allocation_gb=int(os.getenv("GPU_MAX_VRAM_GB", "24")),
            concurrent_workloads=int(os.getenv("GPU_CONCURRENT_WORKLOADS", "4")),
            enable_mixed_precision=os.getenv("GPU_MIXED_PRECISION", "true").lower() == "true",
            enable_tensor_cores=os.getenv("GPU_TENSOR_CORES", "true").lower() == "true",
            compute_capability=os.getenv("GPU_COMPUTE_CAPABILITY", "sm_120"),
            monitoring_interval_seconds=int(os.getenv("GPU_MONITOR_INTERVAL", "30"))
        )

    def _load_database_config(self) -> DatabaseConfig:
        """Load database configuration."""
        return DatabaseConfig(
            type=os.getenv("DB_TYPE", "postgresql" if self.environment == Environment.PRODUCTION else "sqlite"),
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            database=os.getenv("DB_NAME", "drana_gtl"),
            username=os.getenv("DB_USERNAME", ""),
            password=os.getenv("DB_PASSWORD", ""),
            pool_size=int(os.getenv("DB_POOL_SIZE", "20")),
            max_overflow=int(os.getenv("DB_MAX_OVERFLOW", "10")),
            ssl_mode=os.getenv("DB_SSL_MODE", "require" if self.environment == Environment.PRODUCTION else "disable")
        )

    def _load_security_config(self) -> SecurityConfig:
        """Load security configuration."""
        jwt_secret = os.getenv("JWT_SECRET_KEY")
        if not jwt_secret and self.environment == Environment.PRODUCTION:
            raise ValueError("JWT_SECRET_KEY must be set in production environment")

        return SecurityConfig(
            jwt_secret_key=jwt_secret or "dev-secret-key-change-in-production",
            jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
            jwt_expiry_minutes=int(os.getenv("JWT_EXPIRY_MINUTES", "60")),
            jwt_refresh_expiry_days=int(os.getenv("JWT_REFRESH_EXPIRY_DAYS", "30")),
            enable_mfa=os.getenv("ENABLE_MFA", "true" if self.environment == Environment.PRODUCTION else "false").lower() == "true",
            password_min_length=int(os.getenv("PASSWORD_MIN_LENGTH", "12")),
            max_login_attempts=int(os.getenv("MAX_LOGIN_ATTEMPTS", "5")),
            lockout_duration_minutes=int(os.getenv("LOCKOUT_DURATION_MINUTES", "30")),
            encryption_algorithm=os.getenv("ENCRYPTION_ALGORITHM", "AES-256-GCM"),
            tls_version=os.getenv("TLS_VERSION", "1.3"),
            enable_audit_logging=os.getenv("ENABLE_AUDIT_LOGGING", "true").lower() == "true",
            phi_detection_enabled=os.getenv("PHI_DETECTION_ENABLED", "true").lower() == "true"
        )

    def _load_compliance_config(self) -> ComplianceConfig:
        """Load compliance framework configuration."""
        frameworks_str = os.getenv("COMPLIANCE_FRAMEWORKS", "HIPAA,ISO27001,NIST_CSF")
        frameworks = [f.strip() for f in frameworks_str.split(",")]

        enforcement_str = os.getenv("COMPLIANCE_ENFORCEMENT", "warn").lower()
        try:
            enforcement = ComplianceLevel(enforcement_str)
        except ValueError:
            logger.warning(f"Invalid compliance enforcement level '{enforcement_str}', defaulting to WARN")
            enforcement = ComplianceLevel.WARN

        return ComplianceConfig(
            enabled_frameworks=frameworks,
            enforcement_level=enforcement,
            audit_retention_years=int(os.getenv("AUDIT_RETENTION_YEARS", "6")),
            auto_remediation=os.getenv("AUTO_REMEDIATION", "false").lower() == "true",
            compliance_scan_interval_hours=int(os.getenv("COMPLIANCE_SCAN_INTERVAL", "24")),
            report_generation_enabled=os.getenv("COMPLIANCE_REPORTS_ENABLED", "true").lower() == "true"
        )

    def _load_threat_intel_config(self) -> ThreatIntelConfig:
        """Load threat intelligence configuration."""
        return ThreatIntelConfig(
            enable_cisa_feed=os.getenv("ENABLE_CISA_FEED", "true").lower() == "true",
            enable_fda_feed=os.getenv("ENABLE_FDA_FEED", "true").lower() == "true",
            enable_nvd_feed=os.getenv("ENABLE_NVD_FEED", "true").lower() == "true",
            enable_mitre_attack=os.getenv("ENABLE_MITRE_ATTACK", "true").lower() == "true",
            update_interval_hours=int(os.getenv("THREAT_INTEL_UPDATE_INTERVAL", "6")),
            ioc_retention_days=int(os.getenv("IOC_RETENTION_DAYS", "90")),
            threat_score_threshold=float(os.getenv("THREAT_SCORE_THRESHOLD", "0.7"))
        )

    def _validate_config(self) -> None:
        """Validate critical configuration values."""
        errors = []

        # Validate at least one AI model is enabled
        if not any(model.enabled for model in self.ai_models.values()):
            errors.append("At least one AI model must be enabled")

        # Validate Claude API key if enabled
        if self.ai_models["claude"].enabled and not self.ai_models["claude"].api_key:
            errors.append("ANTHROPIC_API_KEY required when Claude is enabled")

        # Validate production security
        if self.environment == Environment.PRODUCTION:
            if self.security.jwt_secret_key == "dev-secret-key-change-in-production":
                errors.append("JWT_SECRET_KEY must be changed for production")
            if not self.security.enable_mfa:
                logger.warning("MFA is disabled in production - security risk")
            if self.database.ssl_mode != "require":
                errors.append("Database SSL must be required in production")

        # Validate GPU configuration
        if self.gpu.max_vram_allocation_gb > 24:
            logger.warning(f"GPU VRAM allocation ({self.gpu.max_vram_allocation_gb}GB) exceeds recommended 24GB - may impact medical AI performance")

        if errors:
            error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {err}" for err in errors)
            raise ValueError(error_msg)

    def get_connection_string(self) -> str:
        """
        Get database connection string.

        Returns:
            SQLAlchemy-compatible connection string
        """
        if self.database.type == "sqlite":
            return f"sqlite:///drana_gtl.db"
        elif self.database.type == "postgresql":
            return (
                f"postgresql://{self.database.username}:{self.database.password}"
                f"@{self.database.host}:{self.database.port}/{self.database.database}"
                f"?sslmode={self.database.ssl_mode}"
            )
        else:
            raise ValueError(f"Unsupported database type: {self.database.type}")

    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment == Environment.PRODUCTION

    def to_dict(self, include_secrets: bool = False) -> Dict[str, Any]:
        """
        Export configuration as dictionary.

        Args:
            include_secrets: If False, redacts sensitive values

        Returns:
            Configuration dictionary
        """
        config = {
            "environment": self.environment.value,
            "ai_models": {
                name: {
                    "model_name": model.model_name,
                    "endpoint_url": model.endpoint_url,
                    "api_key": model.api_key if include_secrets else ("***" if model.api_key else None),
                    "enabled": model.enabled,
                    "priority": model.priority
                }
                for name, model in self.ai_models.items()
            },
            "gpu": {
                "device_id": self.gpu.device_id,
                "max_vram_gb": self.gpu.max_vram_allocation_gb,
                "concurrent_workloads": self.gpu.concurrent_workloads
            },
            "database": {
                "type": self.database.type,
                "host": self.database.host,
                "database": self.database.database
            },
            "compliance": {
                "enabled_frameworks": self.compliance.enabled_frameworks,
                "enforcement_level": self.compliance.enforcement_level.value
            }
        }
        return config

    def __repr__(self) -> str:
        """String representation of configuration."""
        return f"<ConfigManager env={self.environment.value} models={len(self.ai_models)}>"


# Global configuration instance
_config_instance: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """
    Get global configuration instance (singleton pattern).

    Returns:
        ConfigManager instance
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigManager()
    return _config_instance


def reset_config() -> None:
    """Reset global configuration (useful for testing)."""
    global _config_instance
    _config_instance = None
