package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/miekg/dns"
)

const maxLKGCacheEntries = 2048

var (
	ErrDestinationNotAllowed = errors.New("destination IP is outside team external subnet")
	ErrHostNotFound          = errors.New("unable to resolve host")
)

type cacheKey struct {
	team int
	host string
}

type Resolver struct {
	cfg      Config
	cacheMu  sync.RWMutex
	lkgCache map[cacheKey]string
}

func NewResolver(cfg Config) *Resolver {
	cfg.normalize()
	return &Resolver{
		cfg:      cfg,
		lkgCache: make(map[cacheKey]string),
	}
}

func (r *Resolver) queryDNS(ctx context.Context, serverAddr string, fqdn string) ([]net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	msg.RecursionDesired = true

	client := &dns.Client{
		Net:     "udp",
		Timeout: r.cfg.DNSTimeout(),
	}
	resp, _, err := client.ExchangeContext(ctx, msg, serverAddr)
	if err == nil && resp != nil && resp.Truncated {
		tcpClient := &dns.Client{
			Net:     "tcp",
			Timeout: r.cfg.DNSTimeout(),
		}
		resp, _, err = tcpClient.ExchangeContext(ctx, msg, serverAddr)
	}
	if err != nil {
		return nil, err
	}
	if resp == nil {
		return nil, errors.New("empty DNS response")
	}
	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS rcode %s", dns.RcodeToString[resp.Rcode])
	}

	var ips []net.IP
	for _, ans := range resp.Answer {
		if aRec, ok := ans.(*dns.A); ok && aRec.A != nil {
			if ip4 := aRec.A.To4(); ip4 != nil {
				ips = append(ips, ip4)
			}
		}
	}
	return ips, nil
}

func (r *Resolver) Resolve(ctx context.Context, team int, host string) (string, error) {
	if team < 1 || team > r.cfg.NumberOfTeams {
		return "", ErrDestinationNotAllowed
	}
	normalized := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if normalized == "" {
		return "", ErrHostNotFound
	}

	if ip := net.ParseIP(normalized); ip != nil {
		if ip.To4() == nil {
			return "", ErrDestinationNotAllowed
		}
		return r.TranslateAndValidateIPv4(team, ip.To4().String())
	}

	if r.cfg.StaticHostsMode == "override" {
		if ip, ok := r.lookupStaticHost(team, normalized); ok {
			return ip, nil
		}
	}

	serverAddr := r.cfg.TeamDNSServerAddr(team)
	ips, dnsErr := r.queryDNS(ctx, serverAddr, normalized)
	if dnsErr == nil && len(ips) > 0 {
		var sawDisallowed bool
		for _, ip := range ips {
			translated, err := r.TranslateAndValidateIPv4(team, ip.String())
			if err == nil {
				r.cacheMu.Lock()
				if len(r.lkgCache) >= maxLKGCacheEntries {
					clear(r.lkgCache)
				}
				r.lkgCache[cacheKey{team: team, host: normalized}] = translated
				r.cacheMu.Unlock()
				return translated, nil
			}
			if errors.Is(err, ErrDestinationNotAllowed) {
				sawDisallowed = true
			}
		}
		if sawDisallowed {
			slog.Warn("DNS returned IP outside team subnet",
				"team", team,
				"host", normalized,
				"dns_server", serverAddr,
				"ips", ips,
			)
			return "", ErrDestinationNotAllowed
		}
	}

	if r.cfg.StaticHostsMode == "fallback" {
		if ip, ok := r.lookupStaticHost(team, normalized); ok {
			slog.Info("Using static_hosts fallback for host",
				"team", team,
				"host", normalized,
				"ip", ip,
				"dns_error", dnsErr,
			)
			return ip, nil
		}
	}

	r.cacheMu.RLock()
	cachedIP, ok := r.lkgCache[cacheKey{team: team, host: normalized}]
	r.cacheMu.RUnlock()
	if ok {
		slog.Info("Using last-known-good cached DNS record",
			"team", team,
			"host", normalized,
			"ip", cachedIP,
			"dns_error", dnsErr,
		)
		return cachedIP, nil
	}

	if dnsErr != nil {
		return "", fmt.Errorf("%w: %v", ErrHostNotFound, dnsErr)
	}
	return "", ErrHostNotFound
}

func (r *Resolver) TranslateAndValidateIPv4(team int, rawIP string) (string, error) {
	if team < 1 || team > r.cfg.NumberOfTeams {
		return "", ErrDestinationNotAllowed
	}
	parsed := net.ParseIP(strings.TrimSpace(rawIP))
	if parsed == nil || parsed.To4() == nil {
		return "", ErrDestinationNotAllowed
	}
	ipStr := parsed.To4().String()

	teamPrefix := r.cfg.TeamExternalPrefix(team)
	if strings.HasPrefix(ipStr, r.cfg.InternalMask) {
		lastOctet := strings.TrimPrefix(ipStr, r.cfg.InternalMask)
		ipStr = teamPrefix + lastOctet
	}

	if !strings.HasPrefix(ipStr, teamPrefix) {
		return "", ErrDestinationNotAllowed
	}
	lastOctetStr := strings.TrimPrefix(ipStr, teamPrefix)
	octet, err := strconv.Atoi(lastOctetStr)
	if err != nil || octet < 1 || octet > 254 {
		return "", ErrDestinationNotAllowed
	}
	return ipStr, nil
}

func (r *Resolver) lookupStaticHost(team int, normalizedHost string) (string, bool) {
	if len(r.cfg.StaticHosts) == 0 {
		return "", false
	}
	octet, ok := r.cfg.StaticHosts[normalizedHost]
	if !ok && r.cfg.TeamDomainName != "" {
		suffix := "." + r.cfg.TeamDomainName
		if strings.HasSuffix(normalizedHost, suffix) {
			short := strings.TrimSuffix(normalizedHost, suffix)
			octet, ok = r.cfg.StaticHosts[short]
		}
	}
	if !ok || octet < 1 || octet > 254 {
		return "", false
	}
	return fmt.Sprintf("%s%d", r.cfg.TeamExternalPrefix(team), octet), true
}
