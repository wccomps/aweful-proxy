# aweful-proxy

Multi-team Layer-4 SOCKS5 proxy and per-team DNS/NAT translator for WRCCDC / WCComps competitions.

`aweful-proxy` replaces `aweful-dns` so Orange Team evaluators and Black/White Team operators can access identically cloned team environments using unmodified canonical domain names (e.g., `https://chat.acme.com`, `https://sso.acme.com`) without editing `/etc/hosts` or rewriting HTTP `Host` headers.

## How It Works

1. **Per-Team SOCKS5 Ports (`base_socks_port + N`):**
   - Binds one TCP port per team (`1081` = Team 1 .. `1100` = Team 20 when `base_socks_port` is `1080`).
   - Also binds a multiplexed base port (`1080`) supporting RFC 1929 SOCKS5 usernames (`team1`..`team20`).
2. **Per-Team DNS & NAT Translation (`proxyDNS: true`):**
   - When a browser or CLI tool connects to Team $N$'s SOCKS5 port and requests `chat.acme.com:443`, `aweful-proxy` queries Team $N$'s DNS server (`10.100.1<NN>.132:53`).
   - Translates the returned internal IP (`192.168.220.25`) to Team $N$'s external NAT IP (`10.100.1<NN>.25`).
   - Also translates literal internal IPv4 addresses (`192.168.220.25` -> `10.100.1<NN>.25`).
   - Enforces a strict subnet allowlist (`10.100.1<NN>.1..254`) before dialing and pipes raw TCP bytes transparently.
3. **One-Click FoxyProxy Export (`/foxyproxy.json`):**
   - Exposes `GET /foxyproxy.json` on `:8080`, generating a ready-to-import FoxyProxy v8 JSON configuration containing all teams (`Team 01` .. `Team 20`) with `proxyDNS: true`.
   - Exposes `GET /healthz` on `:8080` for readiness/liveness probes.

## Configuration (`config.json`)

```json
{
  "number_of_teams": 20,
  "internal_mask": "192.168.220.",
  "external_mask": "10.100.1xx.",
  "team_dns_server_last_octet": "132",
  "team_domain_name": "acme.com",
  "base_socks_port": 1080,
  "http_listen_addr": ":8080",
  "dns_timeout_ms": 2000,
  "dial_timeout_ms": 5000,
  "idle_timeout_sec": 300,
  "static_hosts_mode": "fallback",
  "static_hosts": {
    "chat.acme.com": 25
  }
}
```

## CLI Usage

```bash
# Run server
./aweful-proxy -config /etc/aweful-proxy/config.json

# Test Team 6 via dedicated port (socks5h sends DNS through the proxy)
curl --proxy socks5h://10.0.4.15:1086 https://chat.acme.com

# Test Team 6 via multiplexed port 1080 using SOCKS5 username
curl --proxy socks5h://team6:x@10.0.4.15:1080 https://chat.acme.com
```
