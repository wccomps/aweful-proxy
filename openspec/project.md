# Project Context

## Purpose
`aweful-proxy` is a multi-team Layer-4 SOCKS5 proxy and per-team DNS/NAT translator for WCComps cybersecurity competitions. It enables evaluators (Orange Team) and operations staff (Black/White Team) to access identically cloned team environments using unmodified canonical domain names (e.g., `https://chat.acme.com`) without modifying `/etc/hosts` or rewriting Layer-7 HTTP/TLS traffic.

## Tech Stack
- **Language:** Go 1.22+
- **DNS Client Library:** `github.com/miekg/dns`
- **Packaging:** Multi-stage `Dockerfile` (static binary on `gcr.io/distroless/static-debian12:nonroot`)
- **Deployment:** Kubernetes (`wccomps/wccomps-argocd`) or standalone Linux service
