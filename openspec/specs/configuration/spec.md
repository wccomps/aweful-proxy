# Configuration Specification

## Requirements

### Requirement: Configuration Loading and Validation
The system SHALL load its configuration from a JSON file specified via the `-config` CLI flag (default `/etc/aweful-proxy/config.json`), with support for environment variable overrides.

The configuration schema SHALL require:
- `number_of_teams` (integer, `1..99`)
- `internal_mask` (string prefix with 3 octets and trailing dot, e.g., `"192.168.220."`)
- `external_mask` (string prefix containing `"xx"` placeholder for the two-digit team number, e.g., `"10.100.1xx."`)
- `team_dns_server_last_octet` (string or integer `1..254`, e.g., `"132"`)
- `team_domain_name` (string, e.g., `"example.com"`)

The configuration schema SHALL accept optional fields with defaults:
- `base_socks_port` (integer, default `1080`)
- `http_listen_addr` (string, default `":8080"`)
- `proxy_advertise_host` (string, default `""` — falls back to HTTP `Host` header host)
- `dns_timeout_ms` (integer, default `2000`)
- `dial_timeout_ms` (integer, default `5000`)
- `idle_timeout_sec` (integer, default `300`)

#### Scenario: Valid configuration file loaded at startup
- **GIVEN** a JSON configuration file with `number_of_teams: 20`, `internal_mask: "192.168.220."`, `external_mask: "10.100.1xx."`, `team_dns_server_last_octet: "132"`, and `team_domain_name: "example.com"`
- **WHEN** `aweful-proxy` starts with `-config config.json`
- **THEN** the configuration is parsed without error and team external prefixes are computed as `"10.100.101."` through `"10.100.120."`

#### Scenario: Invalid configuration rejected at startup
- **GIVEN** a configuration file where `external_mask` does not contain `"xx"` or `number_of_teams` is `0`
- **WHEN** `aweful-proxy` starts
- **THEN** it logs a descriptive validation error and exits with a non-zero status code
