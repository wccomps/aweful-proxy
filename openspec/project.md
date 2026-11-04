# Project Context

## Purpose
`aweful-proxy` is a multi-team Layer-4 SOCKS5 proxy and per-team DNS/NAT translator. It enables clients to access identically cloned environments using unmodified domain names (e.g., `https://app.example.com`) without modifying `/etc/hosts` or rewriting Layer-7 HTTP/TLS traffic.

## Tech Stack
- **Language:** Go 1.22+
- **DNS Client Library:** `github.com/miekg/dns`
- **Packaging:** Multi-stage `Dockerfile` (static binary on `gcr.io/distroless/static-debian12:nonroot`)
