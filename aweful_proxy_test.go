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
	"strings"
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
		"team_domain_name": "example.com"
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
	base.TeamDomainName = "example.com"

	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"zero teams", func(c *Config) { c.NumberOfTeams = 0 }},
		{"too many teams", func(c *Config) { c.NumberOfTeams = 100 }},
		{"missing xx in external_mask", func(c *Config) { c.ExternalMask = "10.100.100." }},
		{"bad internal_mask", func(c *Config) { c.InternalMask = "192.168.220" }},
		{"bad dns octet", func(c *Config) { c.TeamDNSServerLastOctet = -1 }},
		{"http port collides with socks range", func(c *Config) { c.NumberOfTeams = 80 }},
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

func TestParseTeamUsername(t *testing.T) {
	valid := map[string]int{
		"team0":   0,
		"team00":  0,
		"0":       0,
		"team1":   1,
		"team01":  1,
		"TEAM20":  20,
		"team-6":  6,
		"team_06": 6,
		"6":       6,
		"06":      6,
	}
	for input, want := range valid {
		got, err := ParseTeamUsername(input, 20)
		if err != nil || got != want {
			t.Fatalf("ParseTeamUsername(%q) = (%d, %v), want (%d, nil)", input, got, err, want)
		}
	}

	invalid := []string{"", "team", "team21", "-1", "_1", "team-_1", "+1", "admin"}
	for _, input := range invalid {
		if got, err := ParseTeamUsername(input, 20); err == nil {
			t.Fatalf("ParseTeamUsername(%q) = %d, expected error", input, got)
		}
	}
}

func TestResolverPerTeamDNSAndSecurity(t *testing.T) {
	var (
		dnsMu            sync.Mutex
		failDNS          bool
		poisonedIP       string
		crossTeamQueries int
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
			case "app.example.com.":
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP("192.168.220.25"),
				})
			case "poison.example.com.":
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.ParseIP(badIP),
				})
			}
		}
		_ = w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.106.0.132:0")
	if err != nil {
		t.Fatalf("failed to bind UDP listener: %v", err)
	}
	dnsPort := pc.LocalAddr().(*net.UDPAddr).Port
	dnsSrv := &dns.Server{PacketConn: pc, Handler: dnsHandler}
	go func() {
		_ = dnsSrv.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = dnsSrv.Shutdown()
	})

	for _, crossIP := range []string{"127.100.0.132", "127.101.0.132"} {
		crossPC, err := net.ListenPacket("udp", fmt.Sprintf("%s:%d", crossIP, dnsPort))
		if err != nil {
			continue
		}
		crossSrv := &dns.Server{
			PacketConn: crossPC,
			Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
				dnsMu.Lock()
				crossTeamQueries++
				dnsMu.Unlock()
				m := new(dns.Msg)
				m.SetReply(r)
				for _, q := range r.Question {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("192.168.220.25"),
					})
				}
				_ = w.WriteMsg(m)
			}),
		}
		go func() {
			_ = crossSrv.ActivateAndServe()
		}()
		t.Cleanup(func() {
			_ = crossSrv.Shutdown()
		})
	}

	cfg := DefaultConfig()
	cfg.NumberOfTeams = 6
	cfg.InternalMask = "192.168.220."
	cfg.ExternalMask = "127.1xx.0."
	cfg.TeamDNSServerLastOctet = 132
	cfg.TeamDNSServerPort = dnsPort
	cfg.TeamDomainName = "example.com"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	resolver := NewResolver(cfg)
	ctx := context.Background()

	gotIP, err := resolver.Resolve(ctx, 6, "app.example.com")
	if err != nil {
		t.Fatalf("Resolve app.example.com failed: %v", err)
	}
	if gotIP != "127.106.0.25" {
		t.Fatalf("expected 127.106.0.25, got %s", gotIP)
	}

	dnsMu.Lock()
	failDNS = true
	dnsMu.Unlock()
	if _, err := resolver.Resolve(ctx, 6, "app.example.com"); !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("expected ErrHostNotFound when team DNS fails (no fallback), got %v", err)
	}
	dnsMu.Lock()
	gotCrossQueries := crossTeamQueries
	dnsMu.Unlock()
	if gotCrossQueries != 0 {
		t.Fatalf("expected 0 cross-team DNS queries when team 6 DNS fails, got %d", gotCrossQueries)
	}

	for _, bad := range []string{"127.101.0.25", "127.0.0.1", "192.0.2.6"} {
		dnsMu.Lock()
		failDNS = false
		poisonedIP = bad
		dnsMu.Unlock()
		_, err := resolver.Resolve(ctx, 6, "poison.example.com")
		if !errors.Is(err, ErrDestinationNotAllowed) {
			t.Fatalf("expected ErrDestinationNotAllowed for poisoned IP %s, got %v", bad, err)
		}
	}

	if _, err := resolver.Resolve(ctx, 7, "app.example.com"); !errors.Is(err, ErrDestinationNotAllowed) {
		t.Fatalf("expected ErrDestinationNotAllowed for out-of-range team 7, got %v", err)
	}
	if _, err := resolver.Resolve(ctx, -1, "app.example.com"); !errors.Is(err, ErrDestinationNotAllowed) {
		t.Fatalf("expected ErrDestinationNotAllowed for out-of-range team -1, got %v", err)
	}

	translatedLiteral, err := resolver.TranslateAndValidateIPv4(6, "192.168.220.42")
	if err != nil || translatedLiteral != "127.106.0.42" {
		t.Fatalf("expected literal 192.168.220.42 -> 127.106.0.42, got %q (err=%v)", translatedLiteral, err)
	}
	if _, err := resolver.TranslateAndValidateIPv4(6, "127.105.0.42"); !errors.Is(err, ErrDestinationNotAllowed) {
		t.Fatalf("expected cross-team literal IP to be rejected with ErrDestinationNotAllowed, got %v", err)
	}
	if _, err := resolver.TranslateAndValidateIPv4(6, "127.0.0.1"); !errors.Is(err, ErrDestinationNotAllowed) {
		t.Fatalf("expected 127.0.0.1 to be rejected with ErrDestinationNotAllowed, got %v", err)
	}
}

func startTestSocks5Server(t *testing.T, ctx context.Context, cfg Config) (*Resolver, *Socks5Server, int) {
	t.Helper()
	for attempt := 0; attempt < 10; attempt++ {
		probeLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to probe free port: %v", err)
		}
		basePort := probeLn.Addr().(*net.TCPAddr).Port
		_ = probeLn.Close()

		cfg.BaseSocksPort = basePort
		if err := cfg.Validate(); err != nil {
			continue
		}
		resolver := NewResolver(cfg)
		srv := NewSocks5Server(resolver)
		if err := srv.Start(ctx); err == nil {
			return resolver, srv, basePort
		}
	}
	t.Fatal("failed to start SOCKS5 server after retries")
	return nil, nil, 0
}

func TestSocks5EndToEndPerTeamAndMultiplexed(t *testing.T) {
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

	team1DNSPc, err := net.ListenPacket("udp", "127.101.0.132:0")
	if err != nil {
		t.Fatalf("failed to bind Team 1 UDP DNS listener: %v", err)
	}
	team1DNSPort := team1DNSPc.LocalAddr().(*net.UDPAddr).Port
	team1DNSSrv := &dns.Server{
		PacketConn: team1DNSPc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			for _, q := range r.Question {
				if q.Name == "app.example.com." {
					m.Answer = append(m.Answer, &dns.A{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
						A:   net.ParseIP("192.168.220.25"),
					})
				}
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() {
		_ = team1DNSSrv.ActivateAndServe()
	}()
	t.Cleanup(func() {
		_ = team1DNSSrv.Shutdown()
	})

	cfg := DefaultConfig()
	cfg.NumberOfTeams = 2
	cfg.InternalMask = "192.168.220."
	cfg.ExternalMask = "127.1xx.0."
	cfg.TeamDNSServerLastOctet = 132
	cfg.TeamDNSServerPort = team1DNSPort
	cfg.TeamDomainName = "example.com"
	cfg.SocksListenHost = "127.0.0.1"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, srv, basePort := startTestSocks5Server(t, ctx, cfg)
	defer srv.Close()

	t.Run("dedicated team port with domainname", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", basePort+1), 2*time.Second)
		if err != nil {
			t.Fatalf("dial team 1 socks port: %v", err)
		}
		defer conn.Close()

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

		host := "app.example.com"
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

		_, _ = conn.Write([]byte{0x01, 0x05, 't', 'e', 'a', 'm', '1', 0x01, 'x'})
		subResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, subResp); err != nil {
			t.Fatal(err)
		}
		if subResp[1] != 0x00 {
			t.Fatalf("expected RFC 1929 auth success 0x00, got 0x%02x", subResp[1])
		}

		host := "app.example.com"
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

	t.Run("reject disallowed IP with REP 0x02", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", basePort+1), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()

		_, _ = conn.Write([]byte{0x05, 0x01, 0x00})
		authResp := make([]byte, 2)
		_, _ = io.ReadFull(conn, authResp)

		req := []byte{0x05, 0x01, 0x00, 0x01, 192, 0, 2, 6, 0x00, 0x50}
		_, _ = conn.Write(req)

		rep := make([]byte, 10)
		if _, err := io.ReadFull(conn, rep); err != nil {
			t.Fatal(err)
		}
		if rep[1] != repNotAllowedByRuleset {
			t.Fatalf("expected REP 0x02 (NotAllowedByRuleset), got 0x%02x", rep[1])
		}
	})

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
	cfg.TeamDomainName = "example.com"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}

	handler := NewHTTPHandler(NewResolver(cfg), nil, "")

	reqHealth := httptest.NewRequest(http.MethodGet, "http://192.0.2.10:8080/healthz", nil)
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

	reqFoxy := httptest.NewRequest(http.MethodGet, "http://192.0.2.10:8080/foxyproxy.json", nil)
	recFoxy := httptest.NewRecorder()
	handler.ServeHTTP(recFoxy, reqFoxy)
	if recFoxy.Code != http.StatusOK {
		t.Fatalf("expected 200 from /foxyproxy.json, got %d", recFoxy.Code)
	}
	var export FoxyProxyExport
	if err := json.Unmarshal(recFoxy.Body.Bytes(), &export); err != nil {
		t.Fatalf("invalid foxyproxy JSON: %v", err)
	}
	if len(export.Data) != 21 {
		t.Fatalf("expected 21 FoxyProxy entries (Team 00..Team 20), got %d", len(export.Data))
	}
	wantPassthrough := "(?![^/]+.example.com|example.com|192.168.220.|10.100.1)*"
	if export.Passthrough != wantPassthrough {
		t.Fatalf("expected Passthrough %q, got %q", wantPassthrough, export.Passthrough)
	}
	team0 := export.Data[0]
	if team0.Title != "Team 00" || team0.Type != "socks5" || team0.Hostname != "192.0.2.10" || team0.Port != "8000" || !team0.ProxyDNS {
		t.Fatalf("unexpected Team 00 entry: %+v", team0)
	}
	first := export.Data[1]
	if first.Title != "Team 01" || first.Type != "socks5" || first.Hostname != "192.0.2.10" || first.Port != "8001" || !first.ProxyDNS {
		t.Fatalf("unexpected Team 01 entry: %+v", first)
	}
	last := export.Data[20]
	if last.Title != "Team 20" || last.Port != "8020" {
		t.Fatalf("unexpected Team 20 entry: %+v", last)
	}

	reqStatus := httptest.NewRequest(http.MethodGet, "http://192.0.2.10:8080/", nil)
	recStatus := httptest.NewRecorder()
	handler.ServeHTTP(recStatus, reqStatus)
	if recStatus.Code != http.StatusOK {
		t.Fatalf("expected 200 from GET /, got %d", recStatus.Code)
	}
	statusHTML := recStatus.Body.String()
	for _, wantSub := range []string{"example.com", "10.100.1xx.132:53", "192.0.2.10:8000", "192.0.2.10:8020", "/foxyproxy.json"} {
		if !strings.Contains(statusHTML, wantSub) {
			t.Fatalf("expected GET / HTML to contain %q", wantSub)
		}
	}

	reqNotFound := httptest.NewRequest(http.MethodGet, "http://192.0.2.10:8080/nonexistent", nil)
	recNotFound := httptest.NewRecorder()
	handler.ServeHTTP(recNotFound, reqNotFound)
	if recNotFound.Code != http.StatusNotFound {
		t.Fatalf("expected 404 from GET /nonexistent, got %d", recNotFound.Code)
	}
}

func TestPostConfigUpdatesResolverSocksAndFile(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "config.json")

	cfg := DefaultConfig()
	cfg.NumberOfTeams = 1
	cfg.InternalMask = "192.168.220."
	cfg.ExternalMask = "10.100.1xx."
	cfg.TeamDNSServerLastOctet = 10
	cfg.TeamDomainName = "initial.example"
	cfg.SocksListenHost = "127.0.0.1"

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	resolver, srv, basePort := startTestSocks5Server(t, ctx, cfg)
	defer srv.Close()

	handler := NewHTTPHandler(resolver, srv, cfgPath)

	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", basePort+2), 100*time.Millisecond); err == nil {
		_ = c.Close()
		t.Fatalf("expected port %d not to be listening before POST /config", basePort+2)
	}

	updateBody := `{
		"number_of_teams": 2,
		"external_mask": "10.100.1xx.",
		"internal_mask": "192.168.220.",
		"team_dns_server_last_octet": 53,
		"team_domain_name": "updated.example"
	}`
	reqPost := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/config", strings.NewReader(updateBody))
	reqPost.Header.Set("Content-Type", "application/json")
	recPost := httptest.NewRecorder()
	handler.ServeHTTP(recPost, reqPost)
	if recPost.Code != http.StatusOK {
		t.Fatalf("expected 200 from POST /config, got %d: %s", recPost.Code, recPost.Body.String())
	}

	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", basePort+2), 500*time.Millisecond)
	if err != nil {
		t.Fatalf("expected port %d to be listening after POST /config: %v", basePort+2, err)
	}
	_ = c.Close()

	savedCfg, err := LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig(cfgPath) failed: %v", err)
	}
	if savedCfg.NumberOfTeams != 2 || savedCfg.TeamDomainName != "updated.example" || int(savedCfg.TeamDNSServerLastOctet) != 53 {
		t.Fatalf("unexpected savedCfg: %+v", savedCfg)
	}

	reqBad := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/config", strings.NewReader(`{"number_of_teams": 0}`))
	reqBad.Header.Set("Content-Type", "application/json")
	recBad := httptest.NewRecorder()
	handler.ServeHTTP(recBad, reqBad)
	if recBad.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 from invalid POST /config, got %d", recBad.Code)
	}
	if resolver.ConfigSnapshot().NumberOfTeams != 2 {
		t.Fatalf("expected NumberOfTeams to remain 2 after rejected POST /config")
	}

	reqLoopback := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/config", strings.NewReader(`{"external_mask": "127.1xx.0."}`))
	reqLoopback.Header.Set("Content-Type", "application/json")
	recLoopback := httptest.NewRecorder()
	handler.ServeHTTP(recLoopback, reqLoopback)
	if recLoopback.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for loopback external_mask in POST /config, got %d", recLoopback.Code)
	}

	reqCrossOrigin := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/config", strings.NewReader(`{"number_of_teams": 1}`))
	reqCrossOrigin.Header.Set("Content-Type", "application/json")
	reqCrossOrigin.Header.Set("Origin", "https://evil.example")
	recCrossOrigin := httptest.NewRecorder()
	handler.ServeHTTP(recCrossOrigin, reqCrossOrigin)
	if recCrossOrigin.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-origin POST /config, got %d", recCrossOrigin.Code)
	}
}
