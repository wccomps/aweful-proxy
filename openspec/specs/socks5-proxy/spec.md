# SOCKS5 Proxy Specification

## Requirements

### Requirement: Per-Team SOCKS5 Listener Binding
The system SHALL bind a dedicated TCP listener on `base_socks_port + N` for every team `N` from `1` through `number_of_teams`. Every connection accepted on port `base_socks_port + N` SHALL be permanently scoped to Team `N`.

#### Scenario: Team port mapping
- **GIVEN** `base_socks_port` is `1080` and `number_of_teams` is `20`
- **WHEN** `aweful-proxy` starts
- **THEN** TCP ports `1081` through `1100` are bound and listening, where port `1086` routes exclusively to Team 6

### Requirement: Multiplexed SOCKS5 Username Selection on Base Port
The system SHALL also bind `base_socks_port` (e.g., `1080`) and support RFC 1929 Username/Password authentication where the username identifies the team (`team<N>`, `team<0N>`, or `<N>`, case-insensitive). Any password value SHALL be accepted.

#### Scenario: CLI client selects team via SOCKS5 username
- **GIVEN** `base_socks_port` is `1080` and `number_of_teams` is `20`
- **WHEN** a client connects to port `1080` using RFC 1929 authentication with username `"team6"` (or `"team06"` or `"6"`)
- **THEN** authentication succeeds (`0x01 0x00`) and the connection is scoped to Team 6

#### Scenario: Invalid team username or missing auth on base port
- **GIVEN** `base_socks_port` is `1080` and `number_of_teams` is `20`
- **WHEN** a client connects to port `1080` without offering RFC 1929 authentication, or authenticates with username `"team99"`
- **THEN** method negotiation replies `0x05 0xFF` (when RFC 1929 is not offered) or authentication replies `0x01 0x01` (when username is out of range) and the connection is closed

### Requirement: SOCKS5 CONNECT Command and Address Types
On a team-scoped connection, the system SHALL accept RFC 1928 `CONNECT` (`CMD = 0x01`) requests with `ATYP = 0x03` (`DOMAINNAME`) or `ATYP = 0x01` (`IPv4`). All other commands (`BIND`, `UDP ASSOCIATE`) and address types (`IPv6`) SHALL be rejected with standard SOCKS5 reply codes.

#### Scenario: Unsupported SOCKS5 command rejected
- **GIVEN** a client connected to Team 1's SOCKS5 port (`1081`)
- **WHEN** the client sends a `UDP ASSOCIATE` (`0x03`) request
- **THEN** the proxy replies with `REP = 0x07` (`Command not supported`) and closes the connection

#### Scenario: Transparent Layer-4 bidirectional piping
- **GIVEN** a client connected to Team 6's SOCKS5 port (`1086`) requesting `CONNECT app.example.com:443`
- **WHEN** `app.example.com` resolves and translates to `10.100.106.25` and the TCP connection to `10.100.106.25:443` succeeds
- **THEN** the proxy replies with `REP = 0x00` (`Succeeded`) and copies raw bytes bidirectionally without inspecting or modifying TLS or HTTP payloads
