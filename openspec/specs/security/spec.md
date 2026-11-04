# Security Specification

## Requirements

### Requirement: Strict Team Subnet Destination Allowlist
Before dialing any outbound TCP connection for Team `N`, the system MUST verify that the translated destination IPv4 address starts with Team `N`'s `external_mask` prefix (e.g., `10.100.106.`) and has a host octet in `1..254`. Any destination IP outside Team `N`'s external subnet MUST be rejected without dialing.

#### Scenario: Attempt to reach localhost or Kubernetes cluster network via proxy
- **GIVEN** a client connected to Team 1's proxy (`1081`)
- **WHEN** the client requests `CONNECT 127.0.0.1:8080`, `CONNECT 192.0.2.6:22`, or a hostname that resolves to `10.0.0.1`
- **THEN** the proxy rejects the request with SOCKS5 `REP = 0x02` (`Connection not allowed by ruleset`) and does not dial the target

#### Scenario: Cross-team pivot attempt via literal IP or poisoned DNS
- **GIVEN** a client connected to Team 1's proxy (`1081`, allowed prefix `10.100.101.`)
- **WHEN** the client requests `CONNECT 10.100.102.25:80` or Team 1's DNS server returns `A 10.100.102.25`
- **THEN** the proxy rejects the request with SOCKS5 `REP = 0x02` (`Connection not allowed by ruleset`)
