# HTTP Management Specification

## Requirements

### Requirement: Status Page, Configuration API, Health Check, and FoxyProxy Configuration Export
The system SHALL serve an HTTP endpoint on `http_listen_addr` (default `:8080`) providing:
- `GET /`: Returns HTTP `200` with `Content-Type: text/html; charset=utf-8` displaying the active proxy configuration, per-team SOCKS5 ports (`base_socks_port` through `base_socks_port + number_of_teams`), FoxyProxy download link, and CLI examples.
- `GET /healthz`: Returns HTTP `200` with JSON `{"status": "ok", "teams": <number_of_teams>, "domain": "<team_domain_name>"}`.
- `GET /config` and `POST /config`: Returns or updates the active `Config` (reconciling SOCKS5 listeners and persisting the updated config to disk).
- `GET /foxyproxy.json`: Returns HTTP `200` with `Content-Type: application/json` and `Content-Disposition: attachment; filename="foxyproxy-teams.json"` containing a valid FoxyProxy v8 JSON configuration with one `socks5` proxy entry per team (`proxyDNS: true`, port `base_socks_port + N`, title `"Team 00"` .. `"Team <N>"`).

#### Scenario: Client downloads FoxyProxy config
- **GIVEN** `aweful-proxy` is configured with `number_of_teams: 20` and `base_socks_port: 8000`
- **WHEN** a user requests `GET http://192.0.2.10:8080/foxyproxy.json`
- **THEN** the response is a FoxyProxy v8 JSON document containing 21 `socks5` proxy definitions for host `192.0.2.10` on ports `8000` through `8020` with `proxyDNS: true`
