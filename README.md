# aweful-proxy

A multi-environment SOCKS5 proxy that resolves DNS against per-team upstream DNS servers and translates internal RFC1918 addresses to external 1-to-1 NAT prefixes.

## Overview

When multiple identical environments share the same internal IP range and domain name behind 1-to-1 NAT, `aweful-proxy` exposes a SOCKS5 listener per environment so clients can connect using canonical domain names without modifying local `/etc/hosts` files or rewriting HTTP `Host` headers.

- **Per-team SOCKS5 ports:** Listens on `base_socks_port + 1` through `base_socks_port + number_of_teams` ( plus `base_socks_port` with RFC 1929 username routing, e.g. `team1`).
- **DNS + NAT translation:** Queries the target environment's DNS server, rewrites `internal_mask` to the environment's `external_mask`, and forwards raw TCP traffic.
- **FoxyProxy export:** Serves `GET /foxyproxy.json` and `GET /healthz` on `http_listen_addr` (default `:8080`).

## Example Configuration (`config.json`)

```json
{
  "number_of_teams": 20,
  "internal_mask": "192.168.220.",
  "external_mask": "10.100.1xx.",
  "team_dns_server_last_octet": "132",
  "team_domain_name": "example.com"
}
```

## Usage

```bash
./aweful-proxy -config config.json
```
