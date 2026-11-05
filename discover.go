package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type DiscoveryResult struct {
	DNSServerLastOctet int    `json:"team_dns_server_last_octet"`
	TeamDomainName     string `json:"team_domain_name"`
	SampleHost         string `json:"sample_host,omitempty"`
	DiscoveredFromIP   string `json:"discovered_from_ip,omitempty"`
}

func DiscoverEnvironment(ctx context.Context, cfg Config) (DiscoveryResult, error) {
	maxProbeTeam := cfg.NumberOfTeams
	if maxProbeTeam > 3 {
		maxProbeTeam = 3
	}

	type candidate struct {
		team  int
		octet int
		ip    string
	}

	var (
		mu         sync.Mutex
		candidates []candidate
		wg         sync.WaitGroup
		sem        = make(chan struct{}, 64)
	)

	for team := 0; team <= maxProbeTeam; team++ {
		prefix := cfg.TeamExternalPrefix(team)
		for octet := 1; octet <= 254; octet++ {
			t, o := team, octet
			ip := fmt.Sprintf("%s%d", prefix, o)
			wg.Add(1)
			go func() {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
				case <-ctx.Done():
					return
				}
				conn, err := net.DialTimeout("tcp", ip+":53", 300*time.Millisecond)
				if err == nil {
					_ = conn.Close()
					mu.Lock()
					candidates = append(candidates, candidate{team: t, octet: o, ip: ip})
					mu.Unlock()
				}
			}()
		}
	}
	wg.Wait()

	if len(candidates) == 0 {
		return DiscoveryResult{}, errors.New("no DNS servers found on port 53 across team subnets")
	}

	// Probe PTR for each candidate's own internal IP in parallel to discover candidate domains.
	type ptrHit struct {
		cand       candidate
		domain     string
		sampleFQDN string
	}
	var (
		hitsMu sync.Mutex
		hits   []ptrHit
	)
	for _, cand := range candidates {
		c := cand
		wg.Add(1)
		go func() {
			defer wg.Done()
			internalIP := fmt.Sprintf("%s%d", cfg.InternalMask, c.octet)
			for _, ptrHost := range queryPTR(ctx, c.ip+":53", internalIP, 500*time.Millisecond) {
				if domain, ok := extractDomainFromFQDN(ptrHost); ok {
					hitsMu.Lock()
					hits = append(hits, ptrHit{cand: c, domain: domain, sampleFQDN: ptrHost})
					hitsMu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	// First check which candidate is authoritative (returns SOA in Answer) for a discovered domain.
	for _, cand := range candidates {
		for _, h := range hits {
			if hasAuthoritativeSOA(ctx, cand.ip+":53", h.domain) {
				return DiscoveryResult{
					DNSServerLastOctet: cand.octet,
					TeamDomainName:     h.domain,
					SampleHost:         strings.TrimSuffix(h.sampleFQDN, "."),
					DiscoveredFromIP:   cand.ip,
				}, nil
			}
		}
	}

	// Fallback: check which candidate resolves the PTR hostname to an internal_mask A record.
	for _, h := range hits {
		if resolvesInternalA(ctx, h.cand.ip+":53", h.sampleFQDN, cfg.InternalMask) {
			return DiscoveryResult{
				DNSServerLastOctet: h.cand.octet,
				TeamDomainName:     h.domain,
				SampleHost:         strings.TrimSuffix(h.sampleFQDN, "."),
				DiscoveredFromIP:   h.cand.ip,
			}, nil
		}
	}

	return DiscoveryResult{}, errors.New("could not determine authoritative DNS server and domain name")
}

func queryPTR(ctx context.Context, serverAddr, ipStr string, timeout time.Duration) []string {
	arpa, err := dns.ReverseAddr(ipStr)
	if err != nil {
		return nil
	}
	msg := new(dns.Msg)
	msg.SetQuestion(arpa, dns.TypePTR)
	msg.RecursionDesired = true

	client := &dns.Client{Net: "udp", Timeout: timeout}
	resp, _, err := client.ExchangeContext(ctx, msg, serverAddr)
	if err != nil || resp == nil || resp.Rcode != dns.RcodeSuccess {
		return nil
	}
	var out []string
	for _, ans := range resp.Answer {
		if ptr, ok := ans.(*dns.PTR); ok && ptr.Ptr != "" {
			out = append(out, strings.ToLower(ptr.Ptr))
		}
	}
	return out
}

func extractDomainFromFQDN(fqdn string) (string, bool) {
	trimmed := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	parts := strings.Split(trimmed, ".")
	if len(parts) < 3 {
		return "", false
	}
	domain := strings.Join(parts[1:], ".")
	if strings.HasSuffix(domain, ".in-addr.arpa") || domain == "local" || domain == "localhost" {
		return "", false
	}
	return domain, true
}

func hasAuthoritativeSOA(ctx context.Context, serverAddr, domain string) bool {
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}
	msgSOA := new(dns.Msg)
	msgSOA.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	msgSOA.RecursionDesired = true
	if resp, _, err := client.ExchangeContext(ctx, msgSOA, serverAddr); err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
		for _, ans := range resp.Answer {
			if soa, ok := ans.(*dns.SOA); ok && strings.HasSuffix(strings.ToLower(soa.Hdr.Name), strings.ToLower(domain)+".") {
				return true
			}
		}
	}
	return false
}

func resolvesInternalA(ctx context.Context, serverAddr, sampleFQDN, internalMask string) bool {
	if sampleFQDN == "" {
		return false
	}
	client := &dns.Client{Net: "udp", Timeout: 500 * time.Millisecond}
	msgA := new(dns.Msg)
	msgA.SetQuestion(dns.Fqdn(sampleFQDN), dns.TypeA)
	msgA.RecursionDesired = true
	if resp, _, err := client.ExchangeContext(ctx, msgA, serverAddr); err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
		for _, ans := range resp.Answer {
			if aRec, ok := ans.(*dns.A); ok && aRec.A != nil && aRec.A.To4() != nil {
				if strings.HasPrefix(aRec.A.To4().String(), internalMask) {
					return true
				}
			}
		}
	}
	return false
}
