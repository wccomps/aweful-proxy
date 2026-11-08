# Threat model

What `aweful-proxy` defends, against whom, and the rules a change must keep. Every mitigation cites the Go file, line,
and function or type that enforces it; a change that moves a trust boundary updates this file in the same pull request.

## Attackers and their goals

| Attacker | Starts with | Wants |
|---|---|---|
| Blue team competitor | A shared team Authentik account (`WCComps_BlueTeam`), a team VM in `10.100.1XX.0/24` | To reach another team's subnet (`10.100.1YY.0/24`) through the proxy, or to read or overwrite proxy configuration |
| Unauthenticated network peer | Reachability to the proxy host on `:8080` or `8000..8000+N` without a staff Authentik login | To pivot into Blue Team networks or internal infrastructure (`10.0.0.0/16`, `10.2.0.0/24`, `172.16.0.0/12`), or to push a malicious `POST /config` |
| Hostile Blue Team DNS server | Control of `10.100.1XX.<dns_octet>:53` for their own team | To return a DNS `A` record pointing to `127.0.0.1`, management infrastructure (`10.0.0.x`), or another team (`10.100.1YY.x`) so a grading staff browser hits the wrong target |
| Rogue browser tab | A staff member's browser visiting an untrusted page while signed in | Cross-site request forgery against `POST /config` or `POST /auth/logout`, or script injection through rendered configuration fields |

## Assets ranked by impact

1. **Proxy host and internal management/container networks**: the proxy host's own loopback (`127.0.0.0/8`), management
   interfaces (`10.0.0.0/16`, `10.2.0.0/24`), and local container bridges (`172.16.0.0/12`) must never be reachable as
   SOCKS5 destinations (`resolver.go:139` `Resolver.TranslateAndValidateIPv4`; `auth.go:595` `overlapsLocalInterfaceSubnet`;
   `http_server.go:414` `hasLoopbackPrefix`).
2. **Cross-team network isolation**: a connection on port `base_socks_port + N` (`8000 + N`) must only ever dial a
   destination inside Team `N`'s external `/24` (`10.100.1NN.1..254`), never another team's subnet (`resolver.go:90`
   `Resolver.Resolve`, `resolver.go:139` `Resolver.TranslateAndValidateIPv4`; `socks5.go:244` `Socks5Server.handleConnection`).
3. **Staff-only access (Authentik SSO) and signing secrets**:
   - **Service credentials**: `AWEFUL_PROXY_CONFIG_TOKEN` (`config.go:54` `Config.ConfigToken`, `json:"-"`) authenticates
     `POST /config` from `wccomps-portal`; `AWEFUL_PROXY_OIDC_CLIENT_SECRET` (`config.go:58` `Config.OIDCClientSecret`, `json:"-"`)
     authenticates OAuth code exchange with Authentik; `AWEFUL_PROXY_SESSION_SECRET` (`config.go:59` `Config.SessionSecret`, `json:"-"`)
     derives the 32-byte SHA-256 HMAC key (`auth.go:74` `NewAuthenticator`).
   - **Cryptographic sealing and domain separation**: `Authenticator.signJSON` (`auth.go:166`) signs base64url JSON payloads
     for `aweful_session` and `aweful_oauth_state` cookies, while `Authenticator.IssueSocksToken` (`auth.go:139`) signs a
     distinct domain-prefixed string `"socks:<username>:<exp>"` so a session cookie and a SOCKS5 token are not interchangeable.
   - **Delegated user credentials**: only authenticated staff holding an allowed Authentik group (`auth.go:32`
     `defaultStaffGroups`, `auth.go:500` `hasAllowedGroup`, `auth.go:196` `Authenticator.AuthenticateRequest`, `auth.go:615`
     `CheckSocksAuth`) receive a session cookie, a client-IP lease (`auth.go:96` `Authenticator.AuthorizeIP`), or a SOCKS5
     HMAC token (`auth.go:139` `Authenticator.IssueSocksToken`).
4. **Configuration integrity (`POST /config`)**: only `wccomps-portal` presenting the shared `AWEFUL_PROXY_CONFIG_TOKEN`
   bearer secret (`http_server.go:286` `NewHTTPHandler`) may update the active competition network configuration.
5. **Availability during an event**: a single client IP or a listener reconfiguration must not starve or drop active
   staff grading sessions (`socks5.go:40` `maxConcurrentConns`, `socks5.go:41` `maxConnsPerClient`, `socks5.go:96`
   `Socks5Server.Reconcile`).

## Entry points

| Surface | Entry point | Authentication & authorization gate | Handler |
|---|---|---|---|
| HTTP `:8080` | `GET /` | `IsClientAllowed` (`auth.go:540`) + `requireStaffAuth` (`http_server.go:168`) | `http_server.go:199` |
| HTTP `:8080` | `GET /foxyproxy.json` | `IsClientAllowed` (`auth.go:540`) + `requireStaffAuth` (`http_server.go:168`) | `http_server.go:381` |
| HTTP `:8080` | `GET /config` | `IsClientAllowed` (`auth.go:540`) + `requireStaffAuth` (`http_server.go:168`) | `http_server.go:276` |
| HTTP `:8080` | `POST /config` | `IsClientAllowed` (`auth.go:540`) + fail-closed `Bearer <ConfigToken>` (`http_server.go:292`) + same-origin check (`http_server.go:313`) | `http_server.go:285` |
| HTTP `:8080` | `GET /healthz` | `IsClientAllowed` (`auth.go:540`), returns read-only status summary | `http_server.go:261` |
| HTTP `:8080` | `GET /auth/login` | `IsClientAllowed` (`auth.go:540`), initiates OIDC PKCE `S256` flow | `http_server.go:189`, `auth.go:231` |
| HTTP `:8080` | `GET /auth/callback` | `IsClientAllowed` (`auth.go:540`), verifies HMAC state + nonce cookie + `hasAllowedGroup` | `http_server.go:192`, `auth.go:286` |
| HTTP `:8080` | `POST /auth/logout` | `IsClientAllowed` (`auth.go:540`) + `Sec-Fetch-Site` check + `AuthenticateRequest` before `RevokeIP` | `http_server.go:195`, `auth.go:430` |
| SOCKS5 `8000..8000+N` | TCP `CONNECT` | `IsClientAllowed` (`auth.go:540`) + `CheckSocksAuth` (`auth.go:615`) + `Resolver.Resolve` (`resolver.go:90`) | `socks5.go:244` |

## Trust boundaries and data flows

```mermaid
flowchart LR
    subgraph Staff
        B[Staff Browser / FoxyProxy / CLI]
    end
    subgraph Edge
        T[Traefik ForwardAuth / OIDC]
        A[Authentik SSO]
    end
    subgraph ControlPlane
        P[wccomps-portal Quotient Sync]
    end
    subgraph ProxyHost
        H[aweful-proxy HTTP :8080]
        S[aweful-proxy SOCKS5 8000..8000+N]
    end
    subgraph TeamNetwork
        D[Team N DNS Server 10.100.1NN.dns:53]
        V[Team N VMs 10.100.1NN.1..254]
    end
    B -- "1 HTTPS / OIDC or ForwardAuth" --> T
    T -- "1 verify session & groups" --> A
    T -- "2 authenticated HTTP" --> H
    B -- "3 SOCKS5 CONNECT (SSO IP lease or HMAC token)" --> S
    P -- "4 POST /config (Bearer AWEFUL_PROXY_CONFIG_TOKEN)" --> H
    S -- "5 UDP/TCP DNS A query" --> D
    S -- "6 TCP dial to 10.100.1NN.1..254 only" --> V
```

## Threats per boundary (STRIDE) and their mitigations

| # | Boundary | Threat | Mitigation |
|---|---|---|---|
| 1, 2 | Browser to HTTP (`:8080`) | S, E: an unauthenticated user or a Blue Team competitor (`WCComps_BlueTeam`) accesses `/`, `/foxyproxy.json`, or `/config` | When SSO is enabled (`RequireSSO`, `OIDCClientID`, or `TrustForwardAuth`), `Authenticator.AuthenticateRequest` (`auth.go:196`) verifies either the HMAC-signed `aweful_session` OIDC cookie (`auth.go:212`) or `X-authentik-*` headers from `isTrustedProxyPeer` (`auth.go:197`, `auth.go:528`), and `hasAllowedGroup` (`auth.go:500`) requires a staff group in `AllowedGroups`, returning `errForbiddenGroup` (`auth.go:30`, `http_server.go:175`) |
| 1, 2 | Browser to HTTP (`:8080`) | S: forged `X-Forwarded-For` header spoofs client IP to bypass ACLs or hijack an IP lease | `isTrustedProxyPeer` (`auth.go:528`) trusts `X-Forwarded-For` only from `TrustedProxyCIDRs` (defaulting to loopback `127.0.0.1/32`, `::1/128` at `auth.go:44`), and `ClientIPFromRequest` (`auth.go:513`) reads the rightmost `X-Forwarded-For` entry appended by the trusted proxy |
| 1, 2 | Browser to HTTP (`:8080`) | S: OAuth login CSRF or open redirect | `Authenticator.HandleLogin` (`auth.go:231`) binds an `HttpOnly`, `SameSite=Lax` nonce cookie (`aweful_oauth_state`) and PKCE `S256` verifier to an HMAC-signed `state` with a 300 s lifetime, verified in constant time in `Authenticator.HandleCallback` (`auth.go:286`), and restricts `next` to a relative path starting with a single `/` (`auth.go:244`, `auth.go:424`) |
| 2 | Browser to HTTP (`:8080`) | T, D: cross-site or unauthenticated logout revokes another staff member's SOCKS5 IP lease | Logout is restricted to `POST /auth/logout` (`http_server.go:195`), rejects cross-origin `Sec-Fetch-Site` headers (`auth.go:431`), and calls `Authenticator.RevokeIP` only when `AuthenticateRequest` succeeds (`auth.go:436`) |
| 2 | Browser to HTTP (`:8080`) | T, E: script injection or proxy host hijacking through status page or FoxyProxy export | `GET /` renders through `html/template` (`http_server.go:83` `statusPageTmpl`), `resolveAdvertiseHost` (`http_server.go:426`) uses only `ProxyAdvertiseHost` or the validated `Host` header, and `TeamDomainName` and `ProxyAdvertiseHost` are validated by `isValidHostOrIP` (`config.go:295`, `http_server.go:442`) |
| 2, 3 | Blue Team VM to HTTP or SOCKS5 | E: a Blue Team VM in `10.100.1XX.0/24` connects to the proxy to pivot into another team | `IsClientAllowed` (`auth.go:540`) rejects any HTTP request (`http_server.go:404`) or SOCKS5 connection (`socks5.go:248`) whose client IP falls within `TeamExternalPrefix(1..NumberOfTeams)` or outside `AllowedClientCIDRs` |
| 3 | Client to SOCKS5 (`8000..8000+N`) | S, E: an unauthenticated host connects to a SOCKS5 port | When SSO is enabled, `Socks5Server.negotiateAuth` (`socks5.go:336`) and `Socks5Server.readUserPassAuth` (`socks5.go:370`) call `CheckSocksAuth` (`auth.go:615`), which requires either an active Authentik SSO IP lease (`auth.go:125` `Authenticator.LookupIPLease`) or a valid HMAC-signed staff token (`auth.go:147` `Authenticator.VerifySocksToken`) |
| 3 | Client to SOCKS5 (`8000..8000+N`) | T, E: a client on Team `N`'s port requests a host or IP belonging to another team or non-team domain | Each listener `base_socks_port + N` passes a fixed `team = N` to `handleConnection` (`socks5.go:138`, `socks5.go:244`); `parseTeamAndUser` (`socks5.go:411`) rejects mismatched team usernames, `Resolver.Resolve` (`resolver.go:90`) rejects IPv6 and domains outside `TeamDomainName`, and `Resolver.TranslateAndValidateIPv4` (`resolver.go:139`) rejects any resulting IP outside `TeamExternalPrefix(team)` |
| 3 | Client to SOCKS5 (`8000..8000+N`) | D: a single client opens thousands of idle connections and exhausts the proxy | `Socks5Server` caps total concurrent connections at `maxConcurrentConns` (`1024`, `socks5.go:40`), caps concurrent connections per client IP at `maxConnsPerClient` (`128`, `socks5.go:41`, `socks5.go:180` `Socks5Server.acquireClientConn`), checks `s.closed` before tracking connections (`socks5.go:166`, `socks5.go:180`), and enforces handshake and idle deadlines (`socks5.go:252`, `socks5.go:514` `pipeConnections`) |
| 4 | Portal to `POST /config` | S, T, E: an unauthorized client or cross-origin browser tab overwrites proxy configuration | `POST /config` fails closed with `503` when `ConfigToken` is empty (`http_server.go:292`), compares `Authorization: Bearer <token>` in constant time (`http_server.go:302`), rejects requests with an `Origin` header or cross-site `Sec-Fetch-Site` (`http_server.go:313`) or non-`application/json` `Content-Type` (`http_server.go:321`), and decodes only `ConfigUpdate` with `DisallowUnknownFields` (`config.go:67`, `http_server.go:332`) |
| 4 | Portal to `POST /config` | T: a config update sets `external_mask` to loopback or a proxy-host interface subnet | `Config.Validate` (`config.go:258`), `isValidThreeOctetPrefix` (`config.go:313`), `overlapsLocalInterfaceSubnet` (`auth.go:595`), and `hasLoopbackPrefix` (`http_server.go:414`) reject loopback, link-local, multicast, unspecified, and local host interface subnets across all teams `0..NumberOfTeams`, and `Socks5Server.Reconcile` (`socks5.go:96`) binds all new ports before closing superseded listeners |
| 5, 6 | Proxy to Team DNS & Team VMs | T, E: a hostile Blue Team DNS server returns `127.0.0.1`, `10.0.0.x`, or another team's IP | `Resolver.Resolve` (`resolver.go:90`) passes every DNS `A` record through `Resolver.TranslateAndValidateIPv4` (`resolver.go:139`), which translates `InternalMask` to `TeamExternalPrefix(team)` and rejects any IP not in that team's `/24` (`1..254`) or overlapping a local host interface (`auth.go:595` `overlapsLocalInterfaceSubnet`) |

## Accepted risks and non-goals

- **Shared NAT client IPs and SOCKS5 IP leases.** Chrome and Chromium extensions using the `chrome.proxy` API do not
  support SOCKS5 RFC 1929 username/password authentication. To keep Chrome and Firefox working without manual per-request
  prompts, `Authenticator.AuthorizeIP` (`auth.go:96`) grants a session-scoped SOCKS5 lease to the authenticated staff
  member's client IP. If multiple users share a single NAT source IP, authenticating from that IP authorizes SOCKS5
  connections from that NAT IP until the lease expires or the user signs out. Deployments requiring per-connection
  cryptographic authentication across shared NATs should connect via CLI or Firefox using the RFC 1929 token
  (`auth.go:139` `IssueSocksToken`).
- **Layer-4 transparent forwarding.** `aweful-proxy` is a Layer-4 TCP proxy (`socks5.go:514` `pipeConnections`). It does
  not terminate TLS or isolate browser cookies between teams; staff must use separate browser containers or private
  windows when switching teams (`http_server.go:123`).
- **Blue Team DNS availability.** Each team's DNS server (`10.100.1XX.<dns_octet>:53`) is authoritative for that team's
  domain; if a team's DNS server is down, hostname resolution for that team fails fast after `DNSTimeoutMs` (`2000 ms`,
  `resolver.go:52` `Resolver.queryDNS`) while literal IPv4 access (`192.168.220.Y` or `10.100.1XX.Y`) continues to work.

## Build and deploy path

1. Changes land on `main` through a pull request verified by `.github/workflows/ci.yml` (`.github/workflows/ci.yml:1-64`),
   which runs `go vet ./...` and `go test -race ./...` (`aweful_proxy_test.go`) on pull requests and pushes to `main`,
   and publishes `ghcr.io/wccomps/aweful-proxy` (`sha-<short>` and `main`) to GHCR on pushes to `main` using
   `GITHUB_TOKEN` (`packages: write`, `.github/workflows/ci.yml:30-32`).
2. `Dockerfile` (`Dockerfile:1-14`) builds a static Go binary (`CGO_ENABLED=0`) and packages it on
   `gcr.io/distroless/static-debian12:nonroot` running as an unprivileged user on ports `8080` and `8000-8050`, seeding
   initial defaults from `/etc/aweful-proxy/config.json` via `AWEFUL_PROXY_SEED_CONFIG` (`Dockerfile:10-11`,
   `config.go:111-115` `LoadConfig`) while writing runtime `POST /config` updates to `/tmp/config.json` (`Dockerfile:14`,
   `config.go:134` `SaveConfig`).
3. Secrets (`AWEFUL_PROXY_CONFIG_TOKEN`, `AWEFUL_PROXY_OIDC_CLIENT_SECRET`, `AWEFUL_PROXY_SESSION_SECRET`) are injected
   via environment variables (`config.go:154` `applyEnvOverrides`) and marked `json:"-"` (`config.go:54-59`) so they are
   never written to disk by `SaveConfig` (`config.go:134`) or returned by `GET /config`.

## Owner and review triggers

The repository maintainers own this file. Update it in the same pull request when a change:

- adds or modifies an HTTP route in `http_server.go` or a SOCKS5 command/auth mode in `socks5.go`;
- changes `ConfigUpdate` fields or `POST /config` validation in `config.go` or `http_server.go`;
- changes Authentik OIDC, ForwardAuth, group checks, or client-IP lease/ACL logic in `auth.go`;
- changes DNS resolution or IP translation rules in `resolver.go`.
