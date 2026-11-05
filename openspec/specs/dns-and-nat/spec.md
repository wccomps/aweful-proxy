# DNS and NAT Translation Specification

## Requirements

### Requirement: Per-Team DNS Resolution with Internal-to-External Translation
When handling a `DOMAINNAME` (`ATYP = 0x03`) request on Team `N`'s proxy, the system SHALL query Team `N`'s DNS server at `<team_N_external_prefix><team_dns_server_last_octet>:53` for an `A` record. If the returned IPv4 address begins with `internal_mask`, the system SHALL replace `internal_mask` with Team `N`'s `external_mask` prefix.

#### Scenario: Team DNS returns internal IP
- **GIVEN** Team 6 has external prefix `"10.100.106."`, `internal_mask` is `"192.168.220."`, and `team_dns_server_last_octet` is `"132"`
- **WHEN** a client on port `1086` requests `CONNECT app.example.com:80` and `10.100.106.132:53` returns `A 192.168.220.25`
- **THEN** the proxy translates the target address to `10.100.106.25:80` and dials `10.100.106.25:80`

### Requirement: Strict Per-Team DNS Failure Behavior
If Team `N`'s DNS server times out, returns an error (`SERVFAIL`, `REFUSED`, `NXDOMAIN`, network unreachable), or returns no valid `A` record, the system SHALL fail the request with `ErrHostNotFound` (`REP = 0x04 Host unreachable`) and SHALL NOT fall back to another team's DNS server or to cached DNS records.

#### Scenario: Team DNS server is down
- **GIVEN** Team 3's DNS server at `10.100.103.132:53` is unreachable
- **WHEN** a client on port `1083` requests `CONNECT app.example.com:443`
- **THEN** the proxy rejects the connection with `REP = 0x04 (Host unreachable)` without querying any other team's DNS server

### Requirement: Literal IPv4 Destination Translation
When a client sends an `IPv4` (`ATYP = 0x01`) `CONNECT` request on Team `N`'s proxy whose destination IP begins with `internal_mask`, the system SHALL rewrite the prefix to Team `N`'s `external_mask` prefix before dialing.

#### Scenario: Web application redirects browser to literal internal IP
- **GIVEN** Team 6 has external prefix `"10.100.106."` and `internal_mask` is `"192.168.220."`
- **WHEN** a client on port `1086` requests `CONNECT 192.168.220.25:8080`
- **THEN** the proxy translates the destination to `10.100.106.25:8080` and dials `10.100.106.25:8080`
