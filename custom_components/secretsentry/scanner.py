"""Scanner module for SecretSentry integration.

This module implements all scanning rules to detect potential security issues
in Home Assistant configuration files.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from .const import (
    BROAD_PROXY_RANGES,
    MAX_FILE_SIZE,
    RECOMMENDED_GITIGNORE,
    RULE_DEFINITIONS,
    SENSITIVE_KEYS,
    SKIP_PATHS,
    RuleID,
    Severity,
)

if TYPE_CHECKING:
    from collections.abc import Generator

_LOGGER = logging.getLogger(__name__)

# Regex patterns
JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
)
PEM_PATTERN = re.compile(
    r"-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|ENCRYPTED)\s+KEY-----"
)
SECRET_REF_PATTERN = re.compile(r"!secret\s+(\S+)")


@dataclass
class Finding:
    """Represents a security finding."""

    rule_id: str
    severity: Severity
    title: str
    description: str
    file_path: str
    line_number: int
    evidence_masked: str
    recommendation: str
    _raw_evidence: str = field(default="", repr=False)

    @property
    def unique_key(self) -> str:
        """Generate a unique key for this finding."""
        return f"{self.rule_id}:{self.file_path}:{self.line_number}"

    def to_dict(self) -> dict:
        """Convert finding to dictionary for JSON export."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "evidence_masked": self.evidence_masked,
            "recommendation": self.recommendation,
        }


def mask_secret(value: str, visible_chars: int = 4) -> str:
    """Mask a secret value, showing only first few characters.

    Args:
        value: The secret value to mask.
        visible_chars: Number of characters to show at the start.

    Returns:
        Masked string with asterisks.
    """
    if not value or len(value) <= visible_chars:
        return "****"
    return value[:visible_chars] + "*" * min(len(value) - visible_chars, 20)


def mask_line(line: str, secrets: list[str] | None = None) -> str:
    """Mask any potential secrets in a line.

    Args:
        line: The line of text to mask.
        secrets: Optional list of known secret values to mask.

    Returns:
        Line with secrets masked.
    """
    masked = line

    # Mask JWT tokens
    for match in JWT_PATTERN.finditer(line):
        token = match.group(0)
        masked = masked.replace(token, mask_secret(token, 10))

    # Mask quoted values that look like secrets
    quoted_pattern = re.compile(r'["\']([^"\']{8,})["\']')
    for match in quoted_pattern.finditer(line):
        value = match.group(1)
        # Check if this looks like a secret (long alphanumeric string)
        if re.match(r"^[A-Za-z0-9+/=_-]{16,}$", value):
            masked = masked.replace(value, mask_secret(value))

    # Mask specific known secrets
    if secrets:
        for secret in secrets:
            if secret and len(secret) > 4:
                masked = masked.replace(secret, mask_secret(secret))

    return masked


class SecretSentryScanner:
    """Scanner for detecting security issues in Home Assistant configuration."""

    def __init__(self, config_path: str) -> None:
        """Initialize the scanner.

        Args:
            config_path: Path to the Home Assistant configuration directory.
        """
        self.config_path = Path(config_path)
        self.findings: list[Finding] = []
        self._secrets_yaml: dict[str, str] = {}
        self._loaded_secrets = False

    def _load_secrets_yaml(self) -> dict[str, str]:
        """Load and parse secrets.yaml file.

        Returns:
            Dictionary of secret key-value pairs.
        """
        if self._loaded_secrets:
            return self._secrets_yaml

        secrets_path = self.config_path / "secrets.yaml"
        if secrets_path.exists():
            try:
                with open(secrets_path, encoding="utf-8") as f:
                    content = yaml.safe_load(f)
                    if isinstance(content, dict):
                        self._secrets_yaml = content
            except (yaml.YAMLError, OSError) as err:
                _LOGGER.warning("Failed to load secrets.yaml: %s", err)

        self._loaded_secrets = True
        return self._secrets_yaml

    def _should_skip_path(self, path: Path) -> bool:
        """Check if a path should be skipped during scanning.

        Args:
            path: Path to check.

        Returns:
            True if path should be skipped.
        """
        rel_path = path.relative_to(self.config_path)
        parts = rel_path.parts

        for skip in SKIP_PATHS:
            if skip in parts:
                return True

        return False

    def _get_yaml_files(self) -> Generator[Path, None, None]:
        """Get all YAML files in the config directory.

        Yields:
            Path objects for each YAML file to scan.
        """
        for pattern in ("*.yaml", "*.yml"):
            yield from self.config_path.rglob(pattern)

    def _create_finding(
        self,
        rule_id: RuleID,
        file_path: str,
        line_number: int,
        evidence: str,
    ) -> Finding:
        """Create a Finding object with rule metadata.

        Args:
            rule_id: The rule identifier.
            file_path: Path to the file containing the issue.
            line_number: Line number of the issue.
            evidence: Raw evidence string (will be masked).

        Returns:
            Finding object with all metadata populated.
        """
        rule_def = RULE_DEFINITIONS[rule_id]
        return Finding(
            rule_id=rule_id,
            severity=rule_def["severity"],
            title=rule_def["title"],
            description=rule_def["description"],
            file_path=file_path,
            line_number=line_number,
            evidence_masked=mask_line(evidence),
            recommendation=rule_def["recommendation"],
            _raw_evidence=evidence,
        )

    def scan_r001_inline_secrets(self, file_path: Path, content: str) -> None:
        """R001: Detect inline secrets in YAML configuration.

        Checks for sensitive keys that have hardcoded values instead of
        !secret references.

        Args:
            file_path: Path to the file being scanned.
            content: File content to scan.
        """
        rel_path = str(file_path.relative_to(self.config_path))

        # Skip secrets.yaml itself
        if file_path.name == "secrets.yaml":
            return

        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            # Skip comments and empty lines
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Check for sensitive keys with values
            lower_line = line.lower()
            for key in SENSITIVE_KEYS:
                # Match patterns like "api_key: value" or "api_key=value"
                pattern = rf"\b{re.escape(key)}\s*[:=]\s*(.+)"
                match = re.search(pattern, lower_line, re.IGNORECASE)
                if match:
                    value_part = match.group(1).strip()
                    # Skip if using !secret reference
                    if value_part.startswith("!secret"):
                        continue
                    # Skip if it's a placeholder or empty
                    if value_part in ('""', "''", "", "null", "~"):
                        continue
                    # Skip if it's a template
                    if "{{" in value_part or "{%" in value_part:
                        continue

                    self.findings.append(
                        self._create_finding(
                            RuleID.R001_INLINE_SECRETS,
                            rel_path,
                            line_num,
                            line.strip(),
                        )
                    )
                    break  # Only one finding per line

    def scan_r002_jwt_detection(self, file_path: Path, content: str) -> None:
        """R002: Detect JWT tokens in configuration files.

        Args:
            file_path: Path to the file being scanned.
            content: File content to scan.
        """
        rel_path = str(file_path.relative_to(self.config_path))

        # Skip secrets.yaml for JWT detection
        if file_path.name == "secrets.yaml":
            return

        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            if JWT_PATTERN.search(line):
                self.findings.append(
                    self._create_finding(
                        RuleID.R002_JWT_DETECTED,
                        rel_path,
                        line_num,
                        line.strip(),
                    )
                )

    def scan_r003_pem_detection(self, file_path: Path, content: str) -> None:
        """R003: Detect PEM private key blocks.

        Args:
            file_path: Path to the file being scanned.
            content: File content to scan.
        """
        rel_path = str(file_path.relative_to(self.config_path))

        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            if PEM_PATTERN.search(line):
                self.findings.append(
                    self._create_finding(
                        RuleID.R003_PEM_BLOCK,
                        rel_path,
                        line_num,
                        "-----BEGIN PRIVATE KEY----- [REDACTED]",
                    )
                )

    def scan_r004_missing_secrets(self, file_path: Path, content: str) -> None:
        """R004: Detect !secret references that are missing from secrets.yaml.

        Args:
            file_path: Path to the file being scanned.
            content: File content to scan.
        """
        rel_path = str(file_path.relative_to(self.config_path))

        # Load secrets if not already loaded
        secrets = self._load_secrets_yaml()

        lines = content.splitlines()
        for line_num, line in enumerate(lines, start=1):
            for match in SECRET_REF_PATTERN.finditer(line):
                secret_key = match.group(1)
                if secret_key not in secrets:
                    self.findings.append(
                        self._create_finding(
                            RuleID.R004_MISSING_SECRET,
                            rel_path,
                            line_num,
                            f"!secret {secret_key}",
                        )
                    )

    def scan_r005_gitignore(self) -> None:
        """R005: Check .gitignore for recommended entries."""
        gitignore_path = self.config_path / ".gitignore"

        if not gitignore_path.exists():
            # No .gitignore means all recommended entries are missing
            self.findings.append(
                self._create_finding(
                    RuleID.R005_GITIGNORE_MISSING,
                    ".gitignore",
                    0,
                    f"Missing .gitignore file. Recommended entries: {', '.join(RECOMMENDED_GITIGNORE)}",
                )
            )
            return

        try:
            with open(gitignore_path, encoding="utf-8") as f:
                gitignore_content = f.read()
        except OSError as err:
            _LOGGER.warning("Failed to read .gitignore: %s", err)
            return

        gitignore_lines = [
            line.strip() for line in gitignore_content.splitlines()
        ]

        missing = []
        for entry in RECOMMENDED_GITIGNORE:
            # Check if entry or a pattern that would match it exists
            entry_found = False
            for line in gitignore_lines:
                if line == entry or line == entry.rstrip("/"):
                    entry_found = True
                    break
                # Check for glob patterns that might cover the entry
                if line.endswith("*") and entry.startswith(line[:-1]):
                    entry_found = True
                    break
            if not entry_found:
                missing.append(entry)

        if missing:
            self.findings.append(
                self._create_finding(
                    RuleID.R005_GITIGNORE_MISSING,
                    ".gitignore",
                    0,
                    f"Missing recommended entries: {', '.join(missing)}",
                )
            )

    def scan_r006_http_security(self, content: str) -> None:
        """R006: Check HTTP integration security settings.

        Args:
            content: Content of configuration.yaml.
        """
        try:
            config = yaml.safe_load(content)
        except yaml.YAMLError:
            return

        if not isinstance(config, dict):
            return

        http_config = config.get("http")
        if not http_config:
            return

        if not isinstance(http_config, dict):
            return

        issues = []

        # Check ip_ban_enabled
        if http_config.get("ip_ban_enabled") is False:
            issues.append("ip_ban_enabled is set to false")

        # Check login_attempts_threshold
        threshold = http_config.get("login_attempts_threshold")
        if threshold is None:
            issues.append("login_attempts_threshold is not configured")
        elif isinstance(threshold, int) and threshold < 0:
            issues.append("login_attempts_threshold is disabled (< 0)")

        if issues:
            # Find line number for http: section
            lines = content.splitlines()
            line_num = 1
            for idx, line in enumerate(lines, start=1):
                if line.strip().startswith("http:"):
                    line_num = idx
                    break

            self.findings.append(
                self._create_finding(
                    RuleID.R006_HTTP_SECURITY,
                    "configuration.yaml",
                    line_num,
                    "; ".join(issues),
                )
            )

    def scan_r007_trusted_proxies(self, content: str) -> None:
        """R007: Check for overly broad trusted_proxies.

        Args:
            content: Content of configuration.yaml.
        """
        try:
            config = yaml.safe_load(content)
        except yaml.YAMLError:
            return

        if not isinstance(config, dict):
            return

        http_config = config.get("http")
        if not http_config or not isinstance(http_config, dict):
            return

        trusted_proxies = http_config.get("trusted_proxies", [])
        if not trusted_proxies:
            return

        if isinstance(trusted_proxies, str):
            trusted_proxies = [trusted_proxies]

        broad_found = []
        for proxy in trusted_proxies:
            proxy_str = str(proxy).strip()
            if proxy_str in BROAD_PROXY_RANGES:
                broad_found.append(proxy_str)

        if broad_found:
            # Find line number
            lines = content.splitlines()
            line_num = 1
            for idx, line in enumerate(lines, start=1):
                if "trusted_proxies" in line:
                    line_num = idx
                    break

            self.findings.append(
                self._create_finding(
                    RuleID.R007_BROAD_TRUSTED_PROXIES,
                    "configuration.yaml",
                    line_num,
                    f"Overly broad proxy ranges: {', '.join(broad_found)}",
                )
            )

    def scan_file(self, file_path: Path) -> None:
        """Scan a single file for security issues.

        Args:
            file_path: Path to the file to scan.
        """
        if self._should_skip_path(file_path):
            return

        # Check file size
        try:
            if file_path.stat().st_size > MAX_FILE_SIZE:
                _LOGGER.debug("Skipping large file: %s", file_path)
                return
        except OSError:
            return

        try:
            with open(file_path, encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except OSError as err:
            _LOGGER.debug("Failed to read file %s: %s", file_path, err)
            return

        # Run inline secret detection
        self.scan_r001_inline_secrets(file_path, content)

        # Run JWT detection
        self.scan_r002_jwt_detection(file_path, content)

        # Run PEM detection
        self.scan_r003_pem_detection(file_path, content)

        # Run missing secret reference check
        self.scan_r004_missing_secrets(file_path, content)

        # Run HTTP security checks on configuration.yaml
        if file_path.name == "configuration.yaml":
            self.scan_r006_http_security(content)
            self.scan_r007_trusted_proxies(content)

    def scan(self) -> list[Finding]:
        """Run all security scans on the configuration directory.

        Returns:
            List of Finding objects for all detected issues.
        """
        self.findings = []
        self._loaded_secrets = False
        self._secrets_yaml = {}

        _LOGGER.debug("Starting security scan of %s", self.config_path)

        # Pre-load secrets.yaml for reference checking
        self._load_secrets_yaml()

        # Scan all YAML files
        for yaml_file in self._get_yaml_files():
            self.scan_file(yaml_file)

        # Run gitignore check
        self.scan_r005_gitignore()

        _LOGGER.info(
            "Security scan complete. Found %d issues.", len(self.findings)
        )

        return self.findings

    def get_findings_by_severity(self, severity: Severity) -> list[Finding]:
        """Get findings filtered by severity.

        Args:
            severity: Severity level to filter by.

        Returns:
            List of findings with the specified severity.
        """
        return [f for f in self.findings if f.severity == severity]

    def get_high_severity_count(self) -> int:
        """Get count of high and critical severity findings.

        Returns:
            Number of high and critical findings.
        """
        return len(
            [
                f
                for f in self.findings
                if f.severity in (Severity.HIGH, Severity.CRITICAL)
            ]
        )
