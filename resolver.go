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

var (
	ErrDestinationNotAllowed = errors.New("destination IP is outside team external subnet")
	ErrHostNotFound          = errors.New("unable to resolve host")
)

type Resolver struct {
	mu  sync.RWMutex
	cfg Config
}

func NewResolver(cfg Config) *Resolver {
	cfg.normalize()
	return &Resolver{
		cfg: cfg,
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
	if team < 1 || team > cfg.NumberOfTeams {
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

	if cfg.TeamDomainName != "" && cfg.TeamDomainName != "auto" {
		if !isHostInTeamDomain(normalized, cfg.TeamDomainName) {
			return "", ErrDestinationNotAllowed
		}
	}

	if int(cfg.TeamDNSServerLastOctet) < 1 {
		return "", fmt.Errorf("%w: DNS server octet not yet discovered", ErrHostNotFound)
	}

	serverAddr := cfg.TeamDNSServerAddr(team)
	ips, dnsErr := r.queryDNS(ctx, serverAddr, normalized, cfg)
	if dnsErr != nil {
		return "", fmt.Errorf("%w: %v", ErrHostNotFound, dnsErr)
	}
	if len(ips) == 0 {
		return "", ErrHostNotFound
	}

	for _, ip := range ips {
		if translated, err := r.TranslateAndValidateIPv4(team, ip.String()); err == nil {
			return translated, nil
		}
	}
	slog.Warn("DNS returned IP outside team subnet",
		"team", team,
		"host", normalized,
		"ips", ips,
	)
	return "", ErrDestinationNotAllowed
}

func (r *Resolver) TranslateAndValidateIPv4(team int, rawIP string) (string, error) {
	cfg := r.ConfigSnapshot()
	if team < 1 || team > cfg.NumberOfTeams {
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

func isHostInTeamDomain(normalizedHost, teamDomain string) bool {
	domain := strings.ToLower(strings.Trim(teamDomain, "."))
	if domain == "" {
		return true
	}
	return normalizedHost == domain || strings.HasSuffix(normalizedHost, "."+domain)
}
