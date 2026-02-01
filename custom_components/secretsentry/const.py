"""Constants for the SecretSentry integration."""
from __future__ import annotations

from enum import StrEnum
from typing import Final

DOMAIN: Final = "secretsentry"

# Configuration
CONF_SCAN_INTERVAL: Final = "scan_interval"
DEFAULT_SCAN_INTERVAL: Final = 3600  # 1 hour in seconds

# Attributes
ATTR_FINDINGS: Final = "findings"
ATTR_LAST_SCAN: Final = "last_scan"
ATTR_SCAN_DURATION: Final = "scan_duration"

# Services
SERVICE_SCAN_NOW: Final = "scan_now"
SERVICE_EXPORT_REPORT: Final = "export_report"

# Report file
REPORT_FILENAME: Final = "secretsentry_report.json"


class Severity(StrEnum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RuleID(StrEnum):
    """Rule identifiers for scanner."""

    R001_INLINE_SECRETS = "R001"
    R002_JWT_DETECTED = "R002"
    R003_PEM_BLOCK = "R003"
    R004_MISSING_SECRET = "R004"
    R005_GITIGNORE_MISSING = "R005"
    R006_HTTP_SECURITY = "R006"
    R007_BROAD_TRUSTED_PROXIES = "R007"


# Rule definitions with metadata
RULE_DEFINITIONS: Final[dict[str, dict]] = {
    RuleID.R001_INLINE_SECRETS: {
        "title": "Inline Secret Detected",
        "severity": Severity.HIGH,
        "description": "A sensitive configuration key contains a hardcoded value instead of using !secret reference.",
        "recommendation": "Move the secret value to secrets.yaml and reference it using !secret.",
    },
    RuleID.R002_JWT_DETECTED: {
        "title": "JWT Token Detected",
        "severity": Severity.HIGH,
        "description": "A JSON Web Token (JWT) was found in configuration files.",
        "recommendation": "Store JWT tokens in secrets.yaml and use !secret references.",
    },
    RuleID.R003_PEM_BLOCK: {
        "title": "PEM Private Key Detected",
        "severity": Severity.CRITICAL,
        "description": "A PEM-encoded private key block was detected in configuration.",
        "recommendation": "Store private keys in separate files outside the config directory or use secrets.yaml.",
    },
    RuleID.R004_MISSING_SECRET: {
        "title": "Missing Secret Reference",
        "severity": Severity.MEDIUM,
        "description": "A !secret reference points to a key that does not exist in secrets.yaml.",
        "recommendation": "Add the missing key to secrets.yaml or correct the reference name.",
    },
    RuleID.R005_GITIGNORE_MISSING: {
        "title": "Gitignore Missing Recommended Entries",
        "severity": Severity.MEDIUM,
        "description": "The .gitignore file is missing recommended entries to protect sensitive files.",
        "recommendation": "Add the recommended entries to .gitignore to prevent accidental commits of sensitive data.",
    },
    RuleID.R006_HTTP_SECURITY: {
        "title": "HTTP Security Configuration Issue",
        "severity": Severity.MEDIUM,
        "description": "The HTTP integration has security settings that may allow brute force attacks.",
        "recommendation": "Enable ip_ban and set login_attempts_threshold to limit failed login attempts.",
    },
    RuleID.R007_BROAD_TRUSTED_PROXIES: {
        "title": "Overly Broad Trusted Proxies",
        "severity": Severity.HIGH,
        "description": "The trusted_proxies configuration allows all IP addresses, which is insecure.",
        "recommendation": "Restrict trusted_proxies to specific IP addresses or ranges of your actual proxy servers.",
    },
}

# Sensitive keys to check for inline secrets (R001)
SENSITIVE_KEYS: Final[tuple[str, ...]] = (
    "api_key",
    "apikey",
    "api_token",
    "token",
    "password",
    "passwd",
    "pwd",
    "client_secret",
    "secret",
    "private_key",
    "bearer",
    "webhook",
    "webhook_id",
    "access_token",
    "refresh_token",
    "auth_token",
    "authorization",
    "credential",
    "credentials",
    "secret_key",
    "app_secret",
    "consumer_secret",
)

# Recommended .gitignore entries (R005)
RECOMMENDED_GITIGNORE: Final[tuple[str, ...]] = (
    "secrets.yaml",
    ".storage/",
    "*.db",
    "backups/",
    "home-assistant_v2.db",
    "home-assistant_v2.db-shm",
    "home-assistant_v2.db-wal",
    ".cloud/",
)

# Broad proxy ranges to flag (R007)
BROAD_PROXY_RANGES: Final[tuple[str, ...]] = (
    "0.0.0.0/0",
    "::/0",
    "0.0.0.0",
    "::",
)

# File patterns to scan
YAML_PATTERNS: Final[tuple[str, ...]] = (
    "*.yaml",
    "*.yml",
)

# Files/directories to skip during scanning
SKIP_PATHS: Final[tuple[str, ...]] = (
    ".storage",
    "deps",
    "tts",
    "__pycache__",
    ".git",
    "backups",
    "custom_components",
    "www",
)

# Maximum file size to scan (5MB)
MAX_FILE_SIZE: Final = 5 * 1024 * 1024
