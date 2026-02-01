# SecretSentry

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)

**Local security scanner for Home Assistant configurations.**

SecretSentry scans your Home Assistant configuration directory for potential security issues, including exposed credentials, insecure settings, and missing security best practices.

## ⚠️ Important Safety Note

**SecretSentry performs ONLY local scanning.** It does NOT:

- Connect to the internet for any scanning purposes
- Enumerate other Home Assistant instances
- Use external services like Shodan or any registry lookups
- Send any data outside your local network
- Perform any network scanning or enumeration

All scanning is performed locally against your `/config` directory. Your secrets and configuration data never leave your system.

## Features

- **Local Static Analysis**: Scans YAML configuration files for security issues
- **7 Built-in Security Rules**: Comprehensive checks for common security mistakes
- **Repairs Integration**: Findings appear in Home Assistant's Repairs dashboard
- **Two Sensors**: Monitor total findings and high-severity findings
- **On-Demand Scanning**: Trigger scans manually via service calls
- **Export Reports**: Generate masked JSON reports for review
- **Evidence Masking**: All secrets are automatically masked in logs and reports

## Installation

### HACS Installation (Recommended)

1. Open HACS in Home Assistant
2. Click on "Integrations"
3. Click the three dots menu in the top right
4. Select "Custom repositories"
5. Add the repository URL and select "Integration" as the category
6. Click "Add"
7. Search for "SecretSentry" and install it
8. Restart Home Assistant
9. Go to Settings → Devices & Services → Add Integration → Search for "SecretSentry"

### Manual Installation

1. Download the `custom_components/secretsentry` folder from this repository
2. Copy it to your Home Assistant `config/custom_components/` directory
3. Restart Home Assistant
4. Go to Settings → Devices & Services → Add Integration → Search for "SecretSentry"

## Configuration

During setup, you can configure:

- **Scan Interval**: How often to scan for security issues (default: 1 hour, range: 5 minutes to 24 hours)

You can change these options later in the integration's configuration.

## Security Rules

### R001: Inline Secrets Detected
**Severity: High**

Detects sensitive configuration keys (api_key, token, password, client_secret, private_key, bearer, webhook, etc.) that contain hardcoded values instead of using `!secret` references.

**Example of flagged configuration:**
```yaml
# BAD - will be flagged
api_key: abc123secretkey

# GOOD - uses secret reference
api_key: !secret my_api_key
```

### R002: JWT Token Detected
**Severity: High**

Detects JSON Web Tokens (JWTs) in configuration files. JWTs should be stored in `secrets.yaml`.

### R003: PEM Private Key Detected
**Severity: Critical**

Detects PEM-encoded private key blocks in configuration files. Private keys should be stored in separate files outside the config directory.

### R004: Missing Secret Reference
**Severity: Medium**

Detects `!secret` references that point to keys not defined in `secrets.yaml`.

**Example:**
```yaml
# In configuration.yaml
api_key: !secret nonexistent_key  # Flagged if not in secrets.yaml
```

### R005: Gitignore Missing Recommended Entries
**Severity: Medium**

Checks if `.gitignore` is missing recommended entries:
- `secrets.yaml`
- `.storage/`
- `*.db`
- `backups/`
- `home-assistant_v2.db`
- `.cloud/`

### R006: HTTP Security Configuration Issue
**Severity: Medium**

Checks the HTTP integration for:
- `ip_ban_enabled` set to false
- Missing `login_attempts_threshold` configuration

### R007: Overly Broad Trusted Proxies
**Severity: High**

Detects overly permissive `trusted_proxies` configurations like `0.0.0.0/0` or `::/0` that trust all IP addresses.

## Sensors

### Total Security Findings
`sensor.secretsentry_total_findings`

Shows the total number of security findings across all severity levels.

**Attributes:**
- `findings_by_severity`: Count of findings per severity level
- `last_scan`: Timestamp of the last scan
- `scan_duration_seconds`: How long the scan took
- `findings`: List of findings (limited to first 20)

### High Severity Findings
`sensor.secretsentry_high_severity_findings`

Shows the count of high and critical severity findings.

**Attributes:**
- `critical_count`: Number of critical findings
- `high_count`: Number of high severity findings
- `findings`: List of high/critical findings (limited to first 10)

## Services

### `secretsentry.scan_now`

Triggers an immediate security scan, regardless of the configured interval.

```yaml
service: secretsentry.scan_now
```

### `secretsentry.export_report`

Exports a masked JSON report of all findings to `/config/secretsentry_report.json`.

```yaml
service: secretsentry.export_report
```

## Repairs Integration

All findings appear in Home Assistant's Repairs dashboard (Settings → System → Repairs). Each finding includes:

- Rule ID and severity
- File path and line number
- Masked evidence (secrets are never shown in plain text)
- Remediation recommendations

When you fix an issue and the next scan runs, the repair issue is automatically removed.

## Example Automations

### Notify on High Severity Findings

```yaml
automation:
  - alias: "Notify on security findings"
    trigger:
      - platform: numeric_state
        entity_id: sensor.secretsentry_high_severity_findings
        above: 0
    action:
      - service: notify.mobile_app
        data:
          title: "Security Alert"
          message: >
            SecretSentry found {{ states('sensor.secretsentry_high_severity_findings') }}
            high severity security issues. Check the Repairs dashboard.
```

### Weekly Security Scan

```yaml
automation:
  - alias: "Weekly security scan"
    trigger:
      - platform: time
        at: "03:00:00"
    condition:
      - condition: time
        weekday:
          - sun
    action:
      - service: secretsentry.scan_now
      - delay: "00:01:00"
      - service: secretsentry.export_report
```

## Limitations

- **YAML Files Only**: Only scans `.yaml` and `.yml` files
- **Static Analysis**: Cannot detect runtime secrets or environment variables
- **No Auto-Fix**: Findings require manual remediation
- **Local Only**: Does not check for exposed ports or network-level issues
- **File Size Limit**: Files larger than 5MB are skipped

## Privacy & Security

- All scanning is performed locally
- No data is sent to external services
- Secrets are automatically masked in all outputs
- Reports contain only masked evidence
- No network connections are made by this integration

## Troubleshooting

### Findings Not Appearing

1. Check if the scan has completed (look at `last_scan` attribute)
2. Verify file permissions allow Home Assistant to read config files
3. Check Home Assistant logs for any scanner errors

### False Positives

Some findings may be intentional (e.g., test configurations). You can:
1. Acknowledge them in the Repairs dashboard
2. Move the values to `secrets.yaml` even if not strictly necessary

### Scan Taking Too Long

- Large configuration directories may take longer
- Files in `.storage`, `deps`, and other excluded directories are automatically skipped
- Consider increasing the scan interval if scans are too frequent

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

SecretSentry is a security scanning tool that helps identify potential issues but does not guarantee complete security. Always follow security best practices and regularly review your Home Assistant configuration.
