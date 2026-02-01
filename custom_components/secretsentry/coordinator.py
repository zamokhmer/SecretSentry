"""DataUpdateCoordinator for SecretSentry integration."""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
import logging
from typing import TYPE_CHECKING, Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import DEFAULT_SCAN_INTERVAL, DOMAIN
from .scanner import Finding, SecretSentryScanner

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry

_LOGGER = logging.getLogger(__name__)


class SecretSentryData:
    """Data class to hold scan results."""

    def __init__(
        self,
        findings: list[Finding],
        last_scan: datetime,
        scan_duration: float,
    ) -> None:
        """Initialize the data class.

        Args:
            findings: List of security findings.
            last_scan: Timestamp of the last scan.
            scan_duration: Duration of the scan in seconds.
        """
        self.findings = findings
        self.last_scan = last_scan
        self.scan_duration = scan_duration

    @property
    def total_findings(self) -> int:
        """Get total number of findings."""
        return len(self.findings)

    @property
    def high_severity_count(self) -> int:
        """Get count of high and critical severity findings."""
        from .const import Severity

        return len(
            [
                f
                for f in self.findings
                if f.severity in (Severity.HIGH, Severity.CRITICAL)
            ]
        )

    @property
    def findings_by_severity(self) -> dict[str, int]:
        """Get findings count grouped by severity."""
        from .const import Severity

        counts: dict[str, int] = {s.value: 0 for s in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_findings": self.total_findings,
            "high_severity_count": self.high_severity_count,
            "findings_by_severity": self.findings_by_severity,
            "last_scan": self.last_scan.isoformat(),
            "scan_duration": self.scan_duration,
            "findings": [f.to_dict() for f in self.findings],
        }


class SecretSentryCoordinator(DataUpdateCoordinator[SecretSentryData]):
    """Coordinator for SecretSentry security scanning.

    This coordinator manages periodic security scans of the Home Assistant
    configuration directory and provides the results to sensors.
    """

    config_entry: ConfigEntry

    def __init__(
        self,
        hass: HomeAssistant,
        config_entry: ConfigEntry,
        scan_interval: int = DEFAULT_SCAN_INTERVAL,
    ) -> None:
        """Initialize the coordinator.

        Args:
            hass: Home Assistant instance.
            config_entry: Configuration entry for this integration.
            scan_interval: Interval between scans in seconds.
        """
        super().__init__(
            hass,
            _LOGGER,
            name=DOMAIN,
            update_interval=timedelta(seconds=scan_interval),
        )
        self.config_entry = config_entry
        self._config_path = hass.config.path()
        self._previous_findings: dict[str, Finding] = {}

    async def _async_update_data(self) -> SecretSentryData:
        """Fetch data from scanner.

        This method is called by the coordinator on the update interval.
        The actual scanning is run in the executor to avoid blocking.

        Returns:
            SecretSentryData containing scan results.

        Raises:
            UpdateFailed: If the scan fails.
        """
        start_time = datetime.now()

        # Run scanner in executor to avoid blocking the event loop
        findings = await self.hass.async_add_executor_job(self._run_scan)

        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()

        _LOGGER.debug(
            "Scan completed in %.2f seconds. Found %d issues.",
            scan_duration,
            len(findings),
        )

        # Store current findings for comparison
        current_findings = {f.unique_key: f for f in findings}

        # Update repairs
        await self._update_repairs(current_findings)

        self._previous_findings = current_findings

        return SecretSentryData(
            findings=findings,
            last_scan=end_time,
            scan_duration=scan_duration,
        )

    def _run_scan(self) -> list[Finding]:
        """Run the security scan synchronously.

        This method is executed in the executor pool.

        Returns:
            List of security findings.
        """
        scanner = SecretSentryScanner(self._config_path)
        return scanner.scan()

    async def _update_repairs(
        self, current_findings: dict[str, Finding]
    ) -> None:
        """Update repair issues based on scan results.

        Creates new repair issues for new findings and removes
        resolved issues.

        Args:
            current_findings: Dictionary of current findings keyed by unique_key.
        """
        from homeassistant.helpers import issue_registry as ir

        # Get keys for comparison
        current_keys = set(current_findings.keys())
        previous_keys = set(self._previous_findings.keys())

        # New findings - create repair issues
        new_keys = current_keys - previous_keys
        for key in new_keys:
            finding = current_findings[key]
            ir.async_create_issue(
                self.hass,
                DOMAIN,
                key,
                is_fixable=False,
                is_persistent=True,
                severity=self._map_severity_to_ir(finding.severity),
                translation_key=finding.rule_id.lower(),
                translation_placeholders={
                    "file_path": finding.file_path,
                    "line_number": str(finding.line_number),
                    "evidence": finding.evidence_masked,
                    "recommendation": finding.recommendation,
                },
            )

        # Resolved findings - delete repair issues
        resolved_keys = previous_keys - current_keys
        for key in resolved_keys:
            ir.async_delete_issue(self.hass, DOMAIN, key)

    @staticmethod
    def _map_severity_to_ir(severity: str) -> ir.IssueSeverity:
        """Map finding severity to issue registry severity.

        Args:
            severity: Finding severity string.

        Returns:
            IssueSeverity enum value.
        """
        from homeassistant.helpers import issue_registry as ir

        from .const import Severity

        mapping = {
            Severity.CRITICAL: ir.IssueSeverity.ERROR,
            Severity.HIGH: ir.IssueSeverity.ERROR,
            Severity.MEDIUM: ir.IssueSeverity.WARNING,
            Severity.LOW: ir.IssueSeverity.WARNING,
            Severity.INFO: ir.IssueSeverity.WARNING,
        }
        return mapping.get(severity, ir.IssueSeverity.WARNING)

    async def async_scan_now(self) -> SecretSentryData:
        """Trigger an immediate scan.

        Returns:
            SecretSentryData containing scan results.
        """
        await self.async_refresh()
        return self.data

    async def async_export_report(self) -> str:
        """Export findings to a JSON report file.

        Returns:
            Path to the exported report file.
        """
        import json
        from pathlib import Path

        from .const import REPORT_FILENAME

        if not self.data:
            await self.async_refresh()

        report_path = Path(self._config_path) / REPORT_FILENAME

        report_data = {
            "generated_at": datetime.now().isoformat(),
            "config_path": self._config_path,
            **self.data.to_dict(),
        }

        # Write report in executor
        def write_report() -> None:
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2)

        await self.hass.async_add_executor_job(write_report)

        _LOGGER.info("Security report exported to %s", report_path)
        return str(report_path)
