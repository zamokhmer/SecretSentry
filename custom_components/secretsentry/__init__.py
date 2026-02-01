"""SecretSentry - Local security scanner for Home Assistant.

This integration provides local static scanning for credential leak risks
and insecure exposure settings in your Home Assistant configuration.

IMPORTANT: This integration performs ONLY local scanning. It does not:
- Connect to the internet for any scanning purposes
- Enumerate other Home Assistant instances
- Use external services like Shodan or any registry lookups
- Send any data outside your local network

All scanning is performed locally against your /config directory.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from homeassistant.const import Platform
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers import config_validation as cv

from .const import (
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    SERVICE_EXPORT_REPORT,
    SERVICE_SCAN_NOW,
)
from .coordinator import SecretSentryCoordinator

if TYPE_CHECKING:
    from homeassistant.config_entries import ConfigEntry

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.SENSOR]

# Service schema - no parameters needed
SERVICE_SCHEMA = cv.make_entity_service_schema({})


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up SecretSentry from a config entry.

    Args:
        hass: Home Assistant instance.
        entry: Configuration entry for this integration.

    Returns:
        True if setup was successful.
    """
    scan_interval = entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)

    coordinator = SecretSentryCoordinator(
        hass,
        entry,
        scan_interval=scan_interval,
    )

    # Perform initial scan
    await coordinator.async_config_entry_first_refresh()

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = coordinator

    # Set up platforms
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    # Register services
    await _async_setup_services(hass, coordinator)

    # Listen for options updates
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    _LOGGER.info(
        "SecretSentry initialized. Found %d security findings.",
        coordinator.data.total_findings if coordinator.data else 0,
    )

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry.

    Args:
        hass: Home Assistant instance.
        entry: Configuration entry to unload.

    Returns:
        True if unload was successful.
    """
    # Unload platforms
    unload_ok = await hass.config_entries.async_unload_platforms(
        entry, PLATFORMS
    )

    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id)

        # Remove services if no more entries
        if not hass.data[DOMAIN]:
            hass.services.async_remove(DOMAIN, SERVICE_SCAN_NOW)
            hass.services.async_remove(DOMAIN, SERVICE_EXPORT_REPORT)

    return unload_ok


async def _async_update_listener(
    hass: HomeAssistant, entry: ConfigEntry
) -> None:
    """Handle options update.

    Args:
        hass: Home Assistant instance.
        entry: Updated configuration entry.
    """
    await hass.config_entries.async_reload(entry.entry_id)


async def _async_setup_services(
    hass: HomeAssistant, coordinator: SecretSentryCoordinator
) -> None:
    """Set up SecretSentry services.

    Args:
        hass: Home Assistant instance.
        coordinator: The data update coordinator.
    """

    async def handle_scan_now(call: ServiceCall) -> None:
        """Handle the scan_now service call.

        Args:
            call: Service call data.
        """
        _LOGGER.info("Manual security scan triggered")
        result = await coordinator.async_scan_now()
        _LOGGER.info(
            "Manual scan complete. Found %d findings.",
            result.total_findings,
        )

    async def handle_export_report(call: ServiceCall) -> None:
        """Handle the export_report service call.

        Args:
            call: Service call data.
        """
        _LOGGER.info("Exporting security report")
        report_path = await coordinator.async_export_report()
        _LOGGER.info("Security report exported to %s", report_path)

    # Register services only if not already registered
    if not hass.services.has_service(DOMAIN, SERVICE_SCAN_NOW):
        hass.services.async_register(
            DOMAIN,
            SERVICE_SCAN_NOW,
            handle_scan_now,
        )

    if not hass.services.has_service(DOMAIN, SERVICE_EXPORT_REPORT):
        hass.services.async_register(
            DOMAIN,
            SERVICE_EXPORT_REPORT,
            handle_export_report,
        )
