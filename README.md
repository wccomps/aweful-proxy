# aweful-proxy

A multi-environment SOCKS5 proxy that resolves DNS against per-team upstream DNS servers and translates internal RFC1918 addresses to external 1-to-1 NAT prefixes.

## Overview

When multiple identical environments share the same internal IP range and domain name behind 1-to-1 NAT, `aweful-proxy` exposes a SOCKS5 listener per environment so clients can connect using canonical domain names without modifying local `/etc/hosts` files or rewriting HTTP `Host` headers.

- **Per-team SOCKS5 ports:** Listens on `base_socks_port` (`Team 0`, plus RFC 1929 username routing such as `team1`) through `base_socks_port + number_of_teams` (default base port `8000`).
- **DNS + NAT translation:** Queries the target environment's DNS server, rewrites `internal_mask` to the environment's `external_mask`, and forwards raw TCP traffic.
- **HTTP status, config push, and FoxyProxy export:** Serves `GET /`, `GET /config`, `POST /config`, `GET /foxyproxy.json`, and `GET /healthz` on `http_listen_addr` (default `:8080`).

## Volunteer access (SSO mode)

1. Connect to the event VPN and sign in to the proxy status page. If shown, select **Start local SOCKS session**.
   Select **Generate SOCKS5 credentials**.
2. In a dedicated Firefox profile, allow FoxyProxy Standard to **Run in Private Windows**. Import the credential-free
   preset using **Options → Import**. Under **Proxies → Bulk Edit**, enter the username in the last text box and
   choose **Set → Username**. Repeat with the password and **Set → Password**, then **Save**. This edits every
   preset in the profile. Keep **Proxy DNS** enabled. To use Team 00, expand that preset and prefix its username
   with `team00+` after the bulk username edit.
3. Leave global proxying disabled. Choose **More → Tab Proxy → Team NN** in the check tab and open or reload the
   service. The preset, not the hostname, picks the team. Use separate containers or profiles to isolate service cookies.
4. To renew, generate a replacement, bulk-set only **Password**, and **Save**. Clear and reselect the team in every
   open check tab: an existing tab selection keeps the old password. Close the check tab to turn off its proxy.

SSO mode requires RFC 1929 credentials on every new SOCKS connection. The password expires after 15 minutes or at the
end of the issuing browser session, whichever comes first. A replacement or explicit revocation invalidates the
password for new connections. Signing out invalidates that browser session and revokes the password if that session
issued it. A restart clears all sessions and grants. Expiry and revocation do not close open tunnels.

Under ForwardAuth, ending the local session does not sign out of Authentik. Starting another local session requires
an explicit action and a currently allowed forwarded identity. Built-in OIDC uses a group snapshot from sign-in.
To block a subject from minting after an operator-controlled restart, persist `AWEFUL_PROXY_BLOCKED_SOCKS_SUBJECTS`
as a comma-separated list of `oidc:<sub>` or `forward:<uid>` values in startup configuration. Include both for
accounts that can use both modes. To restore issuance, remove the entries and restart. The block does not change
Authentik access or hide the status page.
Remove expired passwords from FoxyProxy and do not sync, back up, or export profiles that contain them. Chrome does not
support SOCKS5 username/password through FoxyProxy. RFC 1929 sends passwords in cleartext: keep the SOCKS ports on the
trusted private network and do not expose them through public ingress.

Non-SSO mode retains unauthenticated SOCKS and username-based team selection on the base port for isolated consumers.
Do not enable it as a fallback on a volunteer deployment. A volunteer rollout must keep the scorer image, deployment
and configuration pinned, and preserve the active team DNS, masks and ports through the proxy pod replacement.

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

### Debug logging

Debug logging surfaces per-request DNS and dial diagnostics (which team DNS server was queried, the resolved and translated IPs, and the SOCKS reply code on resolution/dial failures). Enable it with either the flag or the environment variable:

```bash
./aweful-proxy -config config.json -debug
# or, without changing the command/args (e.g. in Kubernetes):
AWEFUL_PROXY_DEBUG=true ./aweful-proxy -config config.json
```

`AWEFUL_PROXY_DEBUG` accepts `true`/`false` and `1`/`0`. The `-debug` flag and the env var are OR'd: either one enabling turns on debug logging.
