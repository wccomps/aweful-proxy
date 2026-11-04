package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestLoadAndValidateConfig(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")
	content := `{
		"number_of_teams": 20,
		"internal_mask": "192.168.220.",
		"external_mask": "10.100.1xx.",
		"team_dns_server_last_octet": "132",
		"team_domain_name": "acme.com",
		"static_hosts": {
			"chat.acme.com": 25
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(content), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}
	if cfg.NumberOfTeams != 20 {
		t.Fatalf("expected 20 teams, got %d", cfg.NumberOfTeams)
	}
	if got := cfg.TeamExternalPrefix(1); got != "10.100.101." {
		t.Fatalf("expected team 1 prefix 10.100.101., got %q", got)
	}
	if got := cfg.TeamExternalPrefix(20); got != "10.100.120." {
		t.Fatalf("expected team 20 prefix 10.100.120., got %q", got)
	}
	if got := cfg.TeamDNSServerAddr(6); got != "10.100.106.132:53" {
		t.Fatalf("expected team 6 DNS server 10.100.106.132:53, got %q", got)
	}
}

func TestInvalidConfigsRejected(t *testing.T) {
	base := DefaultConfig()
	base.NumberOfTeams = 20
	base.InternalMask = "192.168.220."
	base.ExternalMask = "10.100.1xx."
	base.TeamDNSServerLastOctet = 132
	base.TeamDomainName = "acme.com"

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"zero teams", func(c *Config) { c.NumberOfTeams = 0 }},
		{"too many teams", func(c *Config) { c.NumberOfTeams = 100 }},
		{"missing xx in external_mask", func(c *Config) { c.ExternalMask = "10.100.100." }},
		{"bad internal_mask", func(c *Config) { c.InternalMask = "192.168.220" }},
		{"bad dns octet", func(c *Config) { c.TeamDNSServerLastOctet = 0 }},
		{"empty domain", func(c *Config) { c.TeamDomainName = "" }},
		{"bad static_hosts_mode", func(c *Config) { c.StaticHostsMode = "invalid" }},
		{"bad static_hosts octet", func(c *Config) { c.StaticHosts = map[string]int{"chat.acme.com": 255} }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error for %s, got nil", tc.name)
			}
		})
	}
}

func TestResolverDNSAndFallbackAndSecurity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NumberOfTeams = 6
	cfg.InternalMask = "192.168.220."
	cfg.ExternalMask = "10.100.1xx."
	cfg.TeamDNSServerLastOctet = 132
	cfg.TeamDomainName = "acme.com"
	cfg.StaticHosts = map[string]int{
		"mail.acme.com": 50,
	}
	cfg.normalize()

	resolver := NewResolver(cfg)

	// Start a local UDP DNS server simulating Team 6's DNS server.
	var (
		dnsMu      sync.Mutex
		failDNS    bool
		poisonedIP string
	)
	dnsHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		dnsMu.Lock()
		shouldFail := failDNS
		badIP := poisonedIP
		dnsMu.Unlock()

		m := new(dns.Msg)
		m.SetReply(r)
		if shouldFail {
			m.Rcode = dns.RcodeServerFailure
			_ = w.WriteMsg(m)
			return
		}
		for _, q := range r.Question {
			switch q.Name {
			case "chat.acme.com.":
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.168.220.25"),
				})
			case "poison.acme.com.":
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(badIP),
				})
			}
		}
		_ = w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind UDP listener: %v", err)
	}
	dnsSrv := &dns.Server{PacketConn: pc, Handler: dnsHandler}
	go func() {
		_ = dnsSrv.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = dnsSrv.Shutdown()
	})

	resolver.SetTeamDNSServerAddr(6, pc.LocalAddr().String())

	ctx := context.Background()

	// 1. Live DNS resolution + internal-to-external translation.
	gotIP, err := resolver.Resolve(ctx, 6, "chat.acme.com")
	if err != nil {
		t.Fatalf("Resolve chat.acme.com failed: %v", err)
	}
	if gotIP != "10.100.106.25" {
		t.Fatalf("expected 10.100.106.25, got %s", gotIP)
	}

	// 2. Simulate Team 6 DNS server going down -> should return LKG cached IP for chat.acme.com.
	dnsMu.Lock()
	failDNS = true
	dnsMu.Unlock()
	gotCached, err := resolver.Resolve(ctx, 6, "chat.acme.com")
	if err != nil {
		t.Fatalf("Resolve chat.acme.com from LKG cache failed: %v", err)
	}
	if gotCached != "10.100.106.25" {
		t.Fatalf("expected cached 10.100.106.25, got %s", gotCached)
	}

	// 3. With DNS still failing, resolve mail.acme.com via static_hosts fallback.
	gotStatic, err := resolver.Resolve(ctx, 6, "mail.acme.com")
	if err != nil {
		t.Fatalf("Resolve mail.acme.com from static_hosts failed: %v", err)
	}
	if gotStatic != "10.100.106.50" {
		t.Fatalf("expected static 10.100.106.50, got %s", gotStatic)
	}

	// 4. Security check: poisoned DNS record returning another team's IP (10.100.101.25) or localhost (127.0.0.1).
	for _, bad := range []string{"10.100.101.25", "127.0.0.1", "10.0.4.6"} {
		dnsMu.Lock()
		failDNS = false
		poisonedIP = bad
		dnsMu.Unlock()
		_, err := resolver.Resolve(ctx, 6, "poison.acme.com")
		if !errors.Is(err, ErrDestinationNotAllowed) {
			t.Fatalf("expected ErrDestinationNotAllowed for poisoned IP %s, got %v", bad, err)
		}
	}

	// 5. Literal IPv4 translation and security enforcement.
	translatedLiteral, err := resolver.TranslateAndValidateIPv4(6, "192.168.220.42")
	if err != nil || translatedLiteral != "10.100.106.42" {
		t.Fatalf("expected literal 192.168.220.42 -> 10.100.106.42, got %q (err=%v)", translatedLiteral, err)
	}
	if _, err := resolver.TranslateAndValidateIPv4(6, "10.100.105.42"); !errors.Is(err, ErrDestinationNotAllowed) {
		t.Fatalf("expected cross-team literal IP to be rejected with ErrDestinationNotAllowed, got %v", err)
	}
	if _, err := resolver.TranslateAndValidateIPv4(6, "127.0.0.1"); !errors.Is(err, ErrDestinationNotAllowed) {
		t.Fatalf("expected 127.0.0.1 to be rejected with ErrDestinationNotAllowed, got %v", err)
	}
}

func TestSocks5EndToEndPerTeamAndMultiplexed(t *testing.T) {
	// Start a mock upstream TCP server on 127.0.0.1 (which represents Team 1's external subnet "127.0.0." when xx -> 01 is mapped via 127.0.xx. or we test with 127.0.0.1 for team 1).
	// Wait: with external_mask = "127.0.xx.", Team 1 is "127.0.01." -> net.ParseIP("127.0.01.1") or let's use "127.1xx.0." so Team 1 is "127.101.0.1" (valid loopback on Linux!).
	upstreamLn, err := net.Listen("tcp", "127.101.0.25:0")
	if err != nil {
		t.Fatalf("failed to listen on 127.101.0.25: %v", err)
	}
	defer upstreamLn.Close()
	upstreamPort := upstreamLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			c, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(conn, buf); err == nil && string(buf) == "PING" {
					_, _ = conn.Write([]byte("PONG-TEAM1"))
				}
			}(c)
		}
	}()

	// Reserve a free port range for base_socks_port + 0..2.
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to probe free port: %v", err)
	}
	basePort := probeLn.Addr().(*net.TCPAddr).Port
	_ = probeLn.Close()

	cfg := DefaultConfig()
	cfg.NumberOfTeams = 2
	cfg.InternalMask = "192.168.220."
	cfg.ExternalMask = "127.1xx.0."
	cfg.TeamDNSServerLastOctet = 132
	cfg.TeamDomainName = "acme.com"
	cfg.BaseSocksPort = basePort
	cfg.SocksListenHost = "127.0.0.1"
	cfg.StaticHostsMode = "override"
	cfg.StaticHosts = map[string]int{
		"chat.acme.com": 25,
	}
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config validation failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver := NewResolver(cfg)
	srv := NewSocks5Server(cfg, resolver)
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("failed to start SOCKS5 server: %v", err)
	}
	defer srv.Close()

	// 1. Connect to Team 1 dedicated port (basePort + 1) using DOMAINNAME ("chat.acme.com").
	t.Run("dedicated team port with domainname", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", basePort+1), 2*time.Second)
		if err != nil {
			t.Fatalf("dial team 1 socks port: %v", err)
		}
		defer conn.Close()

		// Greeting: VER=5, NMETHODS=1, METHOD=0x00 (NoAuth)
		if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
			t.Fatal(err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			t.Fatal(err)
		}
		if authResp[0] != 0x05 || authResp[1] != 0x00 {
			t.Fatalf("unexpected auth response: %v", authResp)
		}

		// Request: CONNECT chat.acme.com:<upstreamPort>
		host := "chat.acme.com"
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(upstreamPort))
		req = append(req, portBytes...)
		if _, err := conn.Write(req); err != nil {
			t.Fatal(err)
		}

		rep := make([]byte, 10)
		if _, err := io.ReadFull(conn, rep); err != nil {
			t.Fatal(err)
		}
		if rep[1] != repSucceeded {
			t.Fatalf("expected REP 0x00, got 0x%02x", rep[1])
		}

		if _, err := conn.Write([]byte("PING")); err != nil {
			t.Fatal(err)
		}
		pong := make([]byte, 10)
		if _, err := io.ReadFull(conn, pong); err != nil {
			t.Fatal(err)
		}
		if string(pong) != "PONG-TEAM1" {
			t.Fatalf("expected PONG-TEAM1, got %q", string(pong))
		}
	})

	// 2. Connect to Team 1 dedicated port using literal internal IPv4 (192.168.220.25).
	t.Run("dedicated team port with literal internal IPv4", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", basePort+1), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
		authResp := make([]byte, 2)
		_, _ = io.ReadFull(conn, authResp)

		req := []byte{0x05, 0x01, 0x00, 0x01, 192, 168, 220, 25}
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(upstreamPort))
		req = append(req, portBytes...)
		_, _ = conn.Write(req)

		rep := make([]byte, 10)
		if _, err := io.ReadFull(conn, rep); err != nil {
			t.Fatal(err)
		}
		if rep[1] != repSucceeded {
			t.Fatalf("expected REP 0x00 for literal internal IP, got 0x%02x", rep[1])
		}
	})

	// 3. Connect to multiplexed basePort with username "team1" (RFC 1929).
	t.Run("multiplexed base port with RFC 1929 username team1", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", basePort), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		_, _ = conn.Write([]byte{0x05, 0x01, 0x02})
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			t.Fatal(err)
		}
		if authResp[1] != 0x02 {
			t.Fatalf("expected method 0x02 on base port, got 0x%02x", authResp[1])
		}

		// RFC 1929 auth: VER=1, ULEN=5, UNAME="team1", PLEN=1, PASS="x"
		_, _ = conn.Write([]byte{0x01, 0x05, 't', 'e', 'a', 'm', '1', 0x01, 'x'})
		subResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, subResp); err != nil {
			t.Fatal(err)
		}
		if subResp[1] != 0x00 {
			t.Fatalf("expected RFC 1929 auth success 0x00, got 0x%02x", subResp[1])
		}

		host := "chat.acme.com"
		req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
		req = append(req, []byte(host)...)
		portBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(portBytes, uint16(upstreamPort))
		req = append(req, portBytes...)
		_, _ = conn.Write(req)

		rep := make([]byte, 10)
		if _, err := io.ReadFull(conn, rep); err != nil {
			t.Fatal(err)
		}
		if rep[1] != repSucceeded {
			t.Fatalf("expected REP 0x00, got 0x%02x", rep[1])
		}
	})

	// 4. Reject disallowed IP (10.0.4.6) on Team 1 port with REP = 0x02.
	t.Run("reject disallowed IP with REP 0x02", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", basePort+1), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
		authResp := make([]byte, 2)
		_, _ = io.ReadFull(conn, authResp)

		req := []byte{0x05, 0x01, 0x00, 0x01, 10, 0, 4, 6, 0x00, 0x50}
		_, _ = conn.Write(req)

		rep := make([]byte, 10)
		if _, err := io.ReadFull(conn, rep); err != nil {
			t.Fatal(err)
		}
		if rep[1] != repNotAllowedByRuleset {
			t.Fatalf("expected REP 0x02 (NotAllowedByRuleset), got 0x%02x", rep[1])
		}
	})

	// 5. Reject UDP ASSOCIATE (0x03) with REP = 0x07.
	t.Run("reject UDP ASSOCIATE with REP 0x07", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", basePort+1), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
		authResp := make([]byte, 2)
		_, _ = io.ReadFull(conn, authResp)

		req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		_, _ = conn.Write(req)

		rep := make([]byte, 10)
		if _, err := io.ReadFull(conn, rep); err != nil {
			t.Fatal(err)
		}
		if rep[1] != repCommandNotSupported {
			t.Fatalf("expected REP 0x07 (CommandNotSupported), got 0x%02x", rep[1])
		}
	})
}

func TestHTTPManagementEndpoints(t *testing.T) {
	cfg := DefaultConfig()
	cfg.NumberOfTeams = 20
	cfg.InternalMask = "192.168.220."
	cfg.ExternalMask = "10.100.1xx."
	cfg.TeamDNSServerLastOctet = 132
	cfg.TeamDomainName = "acme.com"
	cfg.BaseSocksPort = 1080
	cfg.normalize()

	handler := NewHTTPHandler(cfg)

	// 1. GET /healthz
	reqHealth := httptest.NewRequest(http.MethodGet, "http://10.0.4.15:8080/healthz", nil)
	recHealth := httptest.NewRecorder()
	handler.ServeHTTP(recHealth, reqHealth)
	if recHealth.Code != http.StatusOK {
		t.Fatalf("expected 200 from /healthz, got %d", recHealth.Code)
	}
	var health map[string]interface{}
	if err := json.Unmarshal(recHealth.Body.Bytes(), &health); err != nil {
		t.Fatalf("invalid healthz JSON: %v", err)
	}
	if health["status"] != "ok" || int(health["teams"].(float64)) != 20 {
		t.Fatalf("unexpected healthz body: %v", health)
	}

	// 2. GET /foxyproxy.json
	reqFoxy := httptest.NewRequest(http.MethodGet, "http://10.0.4.15:8080/foxyproxy.json", nil)
	recFoxy := httptest.NewRecorder()
	handler.ServeHTTP(recFoxy, reqFoxy)
	if recFoxy.Code != http.StatusOK {
		t.Fatalf("expected 200 from /foxyproxy.json, got %d", recFoxy.Code)
	}
	var export FoxyProxyExport
	if err := json.Unmarshal(recFoxy.Body.Bytes(), &export); err != nil {
		t.Fatalf("invalid foxyproxy JSON: %v", err)
	}
	if len(export.Data) != 20 {
		t.Fatalf("expected 20 FoxyProxy entries, got %d", len(export.Data))
	}
	first := export.Data[0]
	if first.Title != "Team 01" || first.Type != "socks5" || first.Hostname != "10.0.4.15" || first.Port != "1081" || !first.ProxyDNS {
		t.Fatalf("unexpected Team 01 entry: %+v", first)
	}
	last := export.Data[19]
	if last.Title != "Team 20" || last.Port != "1100" {
		t.Fatalf("unexpected Team 20 entry: %+v", last)
	}
}
