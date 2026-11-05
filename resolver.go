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
	"time"

	"github.com/miekg/dns"
)

const (
	maxLKGCacheEntries   = 2048
	dnsUnhealthyCooldown = 15 * time.Second
)

var (
	ErrDestinationNotAllowed = errors.New("destination IP is outside team external subnet")
	ErrHostNotFound          = errors.New("unable to resolve host")
)

type cacheKey struct {
	team int
	host string
}

type Resolver struct {
	mu             sync.RWMutex
	cfg            Config
	cacheMu        sync.RWMutex
	lkgCache       map[cacheKey]string
	unhealthyDNS   map[int]time.Time
}

func NewResolver(cfg Config) *Resolver {
	cfg.normalize()
	return &Resolver{
		cfg:          cfg,
		lkgCache:     make(map[cacheKey]string),
		unhealthyDNS: make(map[int]time.Time),
	}
}

func (r *Resolver) ConfigSnapshot() Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.cfg
}

func (r *Resolver) UpdateDiscovery(dnsOctet int, domain string) {
	r.mu.Lock()
	if dnsOctet >= 1 && dnsOctet <= 254 {
		r.cfg.TeamDNSServerLastOctet = FlexibleOctet(dnsOctet)
	}
	if domain != "" && domain != "auto" {
		r.cfg.TeamDomainName = strings.ToLower(strings.Trim(domain, "."))
	}
	r.mu.Unlock()
}

func (r *Resolver) queryDNS(ctx context.Context, serverAddr string, fqdn string, timeoutCfg Config) ([]net.IP, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(fqdn), dns.TypeA)
	msg.RecursionDesired = true

	client := &dns.Client{
		Net:     "udp",
		Timeout: timeoutCfg.DNSTimeout(),
	}
	resp, _, err := client.ExchangeContext(ctx, msg, serverAddr)
	if err == nil && resp != nil && resp.Truncated {
		tcpClient := &dns.Client{
			Net:     "tcp",
			Timeout: timeoutCfg.DNSTimeout(),
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
	cfg := r.ConfigSnapshot()
	if team < 0 || team > cfg.NumberOfTeams {
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

	if cfg.StaticHostsMode == "override" {
		if ip, ok := r.lookupStaticHost(cfg, team, normalized); ok {
			return ip, nil
		}
	}

	if cfg.TeamDomainName != "" && cfg.TeamDomainName != "auto" {
		if !isHostInTeamDomain(normalized, cfg.TeamDomainName) {
			if _, ok := r.lookupStaticHost(cfg, team, normalized); !ok {
				return "", ErrDestinationNotAllowed
			}
		}
	}

	var (
		ips    []net.IP
		dnsErr error
	)
	if int(cfg.TeamDNSServerLastOctet) >= 1 {
		skipPrimary := false
		if team > 0 {
			r.cacheMu.RLock()
			until, exists := r.unhealthyDNS[team]
			r.cacheMu.RUnlock()
			if exists && time.Now().Before(until) {
				skipPrimary = true
			}
		}
		if !skipPrimary {
			serverAddr := cfg.TeamDNSServerAddr(team)
			ips, dnsErr = r.queryDNS(ctx, serverAddr, normalized, cfg)
		}
		// If Team N's DNS server is unreachable/refused and Team 0 (golden master pod) exists,
		// fall back to querying Team 0's DNS server since all team zones are cloned identically.
		if (skipPrimary || dnsErr != nil || len(ips) == 0) && team > 0 {
			masterAddr := cfg.TeamDNSServerAddr(0)
			if masterIPs, masterErr := r.queryDNS(ctx, masterAddr, normalized, cfg); masterErr == nil && len(masterIPs) > 0 {
				if !skipPrimary && dnsErr != nil {
					r.cacheMu.Lock()
					r.unhealthyDNS[team] = time.Now().Add(dnsUnhealthyCooldown)
					r.cacheMu.Unlock()
				}
				ips = masterIPs
				dnsErr = nil
			}
		}
	} else {
		dnsErr = errors.New("DNS server octet not yet discovered")
	}

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
				"ips", ips,
			)
			return "", ErrDestinationNotAllowed
		}
	}

	if cfg.StaticHostsMode == "fallback" {
		if ip, ok := r.lookupStaticHost(cfg, team, normalized); ok {
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
	cfg := r.ConfigSnapshot()
	if team < 0 || team > cfg.NumberOfTeams {
		return "", ErrDestinationNotAllowed
	}
	parsed := net.ParseIP(strings.TrimSpace(rawIP))
	if parsed == nil || parsed.To4() == nil {
		return "", ErrDestinationNotAllowed
	}
	ipStr := parsed.To4().String()

	teamPrefix := cfg.TeamExternalPrefix(team)
	if strings.HasPrefix(ipStr, cfg.InternalMask) {
		lastOctet := strings.TrimPrefix(ipStr, cfg.InternalMask)
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

func (r *Resolver) lookupStaticHost(cfg Config, team int, normalizedHost string) (string, bool) {
	if len(cfg.StaticHosts) == 0 {
		return "", false
	}
	octet, ok := cfg.StaticHosts[normalizedHost]
	if !ok && cfg.TeamDomainName != "" {
		suffix := "." + cfg.TeamDomainName
		if strings.HasSuffix(normalizedHost, suffix) {
			short := strings.TrimSuffix(normalizedHost, suffix)
			octet, ok = cfg.StaticHosts[short]
		}
	}
	if !ok || octet < 1 || octet > 254 {
		return "", false
	}
	return fmt.Sprintf("%s%d", cfg.TeamExternalPrefix(team), octet), true
}

func isHostInTeamDomain(normalizedHost, teamDomain string) bool {
	domain := strings.ToLower(strings.Trim(teamDomain, "."))
	if domain == "" {
		return true
	}
	return normalizedHost == domain || strings.HasSuffix(normalizedHost, "."+domain)
}
