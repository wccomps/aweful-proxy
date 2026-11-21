package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var teamBadgeColors = []string{
	"#e53935", "#d81b60", "#8e24aa", "#5e35b1", "#3949ab",
	"#1e88e5", "#039be5", "#00acc1", "#00897b", "#43a047",
	"#7cb342", "#c0ca33", "#fdd835", "#ffb300", "#fb8c00",
	"#f4511e", "#6d4c41", "#757575", "#546e7a", "#26a69a",
}

type FoxyProxyExport struct {
	Mode        string                 `json:"mode"`
	Sync        bool                   `json:"sync"`
	AutoBackup  bool                   `json:"autoBackup"`
	Passthrough string                 `json:"passthrough"`
	Theme       string                 `json:"theme"`
	Container   map[string]interface{} `json:"container"`
	Commands    map[string]interface{} `json:"commands"`
	Data        []FoxyProxyEntry       `json:"data"`
}

type FoxyProxyEntry struct {
	Active   bool               `json:"active"`
	Title    string             `json:"title"`
	Type     string             `json:"type"`
	Hostname string             `json:"hostname"`
	Port     string             `json:"port"`
	Username string             `json:"username"`
	Password string             `json:"password"`
	CC       string             `json:"cc"`
	City     string             `json:"city"`
	Color    string             `json:"color"`
	PAC      string             `json:"pac"`
	PACURL   string             `json:"pacURL"`
	ProxyDNS bool               `json:"proxyDNS"`
	Include  []FoxyProxyPattern `json:"include"`
	Exclude  []FoxyProxyPattern `json:"exclude"`
}

type FoxyProxyPattern struct {
	Type    string `json:"type"`
	Title   string `json:"title"`
	Pattern string `json:"pattern"`
	Active  bool   `json:"active"`
}

type statusTeamRow struct {
	TeamLabel      string
	ProxyAddr      string
	ExternalSubnet string
	DNSServerAddr  string
}

type statusPageData struct {
	ProxyHost      string
	TeamDomain     string
	DNSServerLabel string
	ExternalMask   string
	InternalMask   string
	NumberOfTeams  int
	BasePort       int
	MaxPort        int
	ExamplePort    int
	ExampleHost    string
	AuthUser       string
	ForwardAuth    bool
	MintSession    bool
	Teams          []statusTeamRow
}

var statusPageTmpl = template.Must(template.New("status").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>aweful-proxy Status</title>
<style>
  body { font-family: system-ui, -apple-system, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; color: #111; }
  h1, h2 { margin-top: 1.5rem; margin-bottom: 0.5rem; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  th, td { border: 1px solid #ccc; padding: 0.45rem 0.65rem; text-align: left; font-size: 0.95rem; }
  th { background: #f4f4f4; }
  code, pre { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #f4f4f4; padding: 0.15rem 0.35rem; border-radius: 3px; }
  pre { padding: 0.75rem; overflow-x: auto; }
  .dl-link { display: inline-block; padding: 0.45rem 0.85rem; background: #1e88e5; color: #fff; text-decoration: none; border-radius: 4px; font-weight: 600; }
  .dl-link:hover { background: #1565c0; }
</style>
</head>
<body>
<h1>aweful-proxy</h1>
{{if .AuthUser}}
<p>Signed in via Authentik SSO as <code>{{.AuthUser}}</code>.</p>
{{if .MintSession}}
<form method="post" action="/auth/socks"><button type="submit">Generate SOCKS5 credentials</button></form>
<form method="post" action="/auth/socks/revoke"><button type="submit">Revoke SOCKS5 credentials</button></form>
<form method="post" action="/auth/logout"><button type="submit">{{if .ForwardAuth}}End local SOCKS session{{else}}Sign out{{end}}</button></form>
{{else}}
<form method="post" action="/auth/socks/session"><button type="submit">Start local SOCKS session</button></form>
{{end}}
{{end}}

<h2>Active Configuration</h2>
<table>
  <tbody>
    <tr><th>Team Domain</th><td><code>{{.TeamDomain}}</code></td></tr>
    <tr><th>Team DNS Server</th><td><code>{{.DNSServerLabel}}</code></td></tr>
    <tr><th>External Subnet Mask</th><td><code>{{.ExternalMask}}</code></td></tr>
    <tr><th>Internal Subnet Mask</th><td><code>{{.InternalMask}}</code></td></tr>
    <tr><th>Teams</th><td><code>Team 00</code> to <code>Team {{printf "%02d" .NumberOfTeams}}</code> ({{.NumberOfTeams}} active teams)</td></tr>
    <tr><th>SOCKS5 Port Range</th><td><code>{{.BasePort}}</code> to <code>{{.MaxPort}}</code> (<code>{{.BasePort}} + team_number</code>)</td></tr>
  </tbody>
</table>

<h2>Browser Setup (FoxyProxy)</h2>
<p><a class="dl-link" href="/foxyproxy.json">Download foxyproxy-teams.json</a></p>
<ol>
  <li>Use a dedicated Firefox profile with FoxyProxy Standard set to <strong>Run in Private Windows → Allow</strong>. Import <code>foxyproxy-teams.json</code> with <strong>Options → Import</strong> and save.</li>
  {{if .AuthUser}}
  <li>Generate credentials above. In FoxyProxy <strong>Proxies → Bulk Edit</strong>, enter the username in the last text box and choose <strong>Set → Username</strong>. Repeat with the password and <strong>Set → Password</strong>, then <strong>Save</strong>. This edits all presets in the profile. For Team 00, add <code>team00+</code> to that preset's username after bulk editing.</li>
  <li>To renew, bulk-set the new password and save, then clear and reselect the team in each open check tab.</li>
  {{end}}
  <li>Leave global proxying disabled. In the check tab, choose <strong>More → Tab Proxy</strong>, select the team, and open or reload the service. <strong>Proxy by Patterns</strong> does not select teams by hostname.</li>
  <li>Use separate Firefox containers or profiles if you sign into the same service on different teams; changing proxy ports does not isolate cookies.</li>
</ol>

<h2>CLI Usage</h2>
{{if .AuthUser}}
<pre>curl --proxy socks5h://{{.ProxyHost}}:{{.ExamplePort}} --proxy-user USERNAME:PASSWORD http://{{.ExampleHost}}/</pre>
{{else}}
<pre>curl -x socks5h://{{.ProxyHost}}:{{.ExamplePort}} http://{{.ExampleHost}}/
curl -x socks5h://{{.ProxyHost}}:{{.BasePort}} http://{{.ExampleHost}}/</pre>
{{end}}

<h2>Per-Team SOCKS5 Ports</h2>
<table>
  <thead>
    <tr>
      <th>Team</th>
      <th>SOCKS5 Proxy</th>
      <th>External Subnet</th>
      <th>Team DNS Server</th>
    </tr>
  </thead>
  <tbody>
  {{range .Teams}}
    <tr>
      <td><code>{{.TeamLabel}}</code></td>
      <td><code>{{.ProxyAddr}}</code></td>
      <td><code>{{.ExternalSubnet}}</code></td>
      <td><code>{{.DNSServerAddr}}</code></td>
    </tr>
  {{end}}
  </tbody>
</table>
</body>
</html>
`))

func NewHTTPHandler(resolver *Resolver, socksServer *Socks5Server, configPath string) http.Handler {
	var configMu sync.Mutex
	mux := http.NewServeMux()
	auth := resolver.Auth()

	requireStaffAuth := func(cfg Config, w http.ResponseWriter, r *http.Request) (*AuthIdentity, bool) {
		if !auth.Enabled(cfg) {
			return nil, true
		}
		id, err := auth.AuthenticateRequest(cfg, r)
		if err == nil {
			return id, true
		}
		if errors.Is(err, errForbiddenGroup) {
			http.Error(w, "Forbidden: your Authentik account is not in an authorized staff group", http.StatusForbidden)
			return nil, false
		}
		if cfg.OIDCClientID != "" && r.Method == http.MethodGet {
			http.Redirect(w, r, "/auth/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return nil, false
		}
		http.Error(w, "Unauthorized: Authentik SSO login required", http.StatusUnauthorized)
		return nil, false
	}

	mux.HandleFunc("GET /auth/login", func(w http.ResponseWriter, r *http.Request) {
		auth.HandleLogin(resolver.ConfigSnapshot(), w, r)
	})
	mux.HandleFunc("GET /auth/callback", func(w http.ResponseWriter, r *http.Request) {
		auth.HandleCallback(resolver.ConfigSnapshot(), w, r)
	})
	mux.HandleFunc("POST /auth/logout", func(w http.ResponseWriter, r *http.Request) {
		auth.HandleLogout(resolver.ConfigSnapshot(), w, r)
	})

	// All credential mutations require a staff identity and a same-origin form POST.
	socksCredentialPost := func(next func(Config, http.ResponseWriter, *http.Request, AuthIdentity)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			cfg := resolver.ConfigSnapshot()
			if !auth.Enabled(cfg) {
				http.NotFound(w, r)
				return
			}
			if !sameOriginPost(cfg, r) {
				http.Error(w, "Forbidden: cross-origin SOCKS credential request", http.StatusForbidden)
				return
			}
			if id, ok := requireStaffAuth(cfg, w, r); ok {
				next(cfg, w, r, *id)
			}
		}
	}
	mux.HandleFunc("POST /auth/socks/session", socksCredentialPost(func(cfg Config, w http.ResponseWriter, r *http.Request, id AuthIdentity) {
		if !strings.HasPrefix(id.Subject, "forward:") {
			http.NotFound(w, r)
			return
		}
		if id.SessionID == "" {
			if err := auth.startBrowserSession(cfg, w, r, id); err != nil {
				http.Error(w, "Failed to start local SOCKS session", http.StatusInternalServerError)
				return
			}
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}))
	mux.HandleFunc("POST /auth/socks", socksCredentialPost(func(cfg Config, w http.ResponseWriter, _ *http.Request, id AuthIdentity) {
		username, password, expires, err := auth.issueSocksCredential(cfg, id)
		switch {
		case errors.Is(err, errBlockedSocksSubject):
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		case errors.Is(err, errInactiveSession):
			http.Error(w, "Start a new local browser session before generating SOCKS5 credentials", http.StatusUnauthorized)
			return
		case err != nil:
			http.Error(w, "Failed to generate SOCKS5 credentials", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintf(w, "SOCKS5 username: %s\nSOCKS5 password: %s\nExpires: %s\n\nCopy into FoxyProxy, then return to the status page. Do not share these credentials.\n", username, password, expires.UTC().Format(time.RFC3339))
	}))
	mux.HandleFunc("POST /auth/socks/revoke", socksCredentialPost(func(_ Config, w http.ResponseWriter, r *http.Request, id AuthIdentity) {
		if !auth.revokeSocksCredential(id) {
			http.Error(w, errInactiveSession.Error(), http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}))

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		cfg := resolver.ConfigSnapshot()
		id, ok := requireStaffAuth(cfg, w, r)
		if !ok {
			return
		}
		proxyHost := resolveAdvertiseHost(cfg, r)
		domainLabel := cfg.TeamDomainName
		if domainLabel == "" {
			domainLabel = "(not configured)"
		}
		dnsLabel := "(not configured)"
		if int(cfg.TeamDNSServerLastOctet) >= 1 {
			dnsLabel = fmt.Sprintf("%s%d:%d", cfg.ExternalMask, int(cfg.TeamDNSServerLastOctet), cfg.TeamDNSServerPort)
		}
		exampleHost := "service." + cfg.TeamDomainName
		if cfg.TeamDomainName == "" {
			exampleHost = cfg.InternalMask + "10"
		}

		rows := make([]statusTeamRow, 0, cfg.NumberOfTeams+1)
		for team := 0; team <= cfg.NumberOfTeams; team++ {
			port := cfg.BaseSocksPort + team
			prefix := cfg.TeamExternalPrefix(team)
			teamDNS := "(not configured)"
			if int(cfg.TeamDNSServerLastOctet) >= 1 {
				teamDNS = cfg.TeamDNSServerAddr(team)
			}
			rows = append(rows, statusTeamRow{
				TeamLabel:      fmt.Sprintf("Team %02d", team),
				ProxyAddr:      net.JoinHostPort(proxyHost, strconv.Itoa(port)),
				ExternalSubnet: prefix + "0/24",
				DNSServerAddr:  teamDNS,
			})
		}

		data := statusPageData{
			ProxyHost:      proxyHost,
			TeamDomain:     domainLabel,
			DNSServerLabel: dnsLabel,
			ExternalMask:   cfg.ExternalMask,
			InternalMask:   cfg.InternalMask,
			NumberOfTeams:  cfg.NumberOfTeams,
			BasePort:       cfg.BaseSocksPort,
			MaxPort:        cfg.BaseSocksPort + cfg.NumberOfTeams,
			ExamplePort:    cfg.BaseSocksPort + 1,
			ExampleHost:    exampleHost,
			Teams:          rows,
		}
		if id != nil {
			data.AuthUser = id.Username
			data.ForwardAuth = strings.HasPrefix(id.Subject, "forward:")
			data.MintSession = id.SessionID != ""
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = statusPageTmpl.Execute(w, data)
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		cfg := resolver.ConfigSnapshot()
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"status":                     "ok",
			"teams":                      cfg.NumberOfTeams,
			"domain":                     cfg.TeamDomainName,
			"team_dns_server_last_octet": int(cfg.TeamDNSServerLastOctet),
			"base_socks_port":            cfg.BaseSocksPort,
			"external_mask":              cfg.ExternalMask,
			"internal_mask":              cfg.InternalMask,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("GET /config", func(w http.ResponseWriter, r *http.Request) {
		cfg := resolver.ConfigSnapshot()
		if _, ok := requireStaffAuth(cfg, w, r); !ok {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	})

	mux.HandleFunc("POST /config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		r.Body = http.MaxBytesReader(w, r.Body, 64*1024)

		configMu.Lock()
		defer configMu.Unlock()

		currentCfg := resolver.ConfigSnapshot()
		if currentCfg.ConfigToken == "" {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  "POST /config is disabled unless AWEFUL_PROXY_CONFIG_TOKEN is configured",
			})
			return
		}
		wantAuth := "Bearer " + currentCfg.ConfigToken
		gotAuth := strings.TrimSpace(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare([]byte(gotAuth), []byte(wantAuth)) != 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  "unauthorized",
			})
			return
		}

		secFetch := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
		if r.Header.Get("Origin") != "" || (secFetch != "" && secFetch != "same-origin" && secFetch != "none") {
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  "cross-origin requests are not allowed",
			})
			return
		}
		if ct := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Type"))); !strings.HasPrefix(ct, "application/json") {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  "Content-Type must be application/json",
			})
			return
		}

		var update ConfigUpdate
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&update); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  fmt.Sprintf("invalid JSON body: %v", err),
			})
			return
		}
		merged := currentCfg.ApplyUpdate(update)
		if err := merged.Validate(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  err.Error(),
			})
			return
		}
		if hasLoopbackPrefix(merged) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  "loopback prefixes are not allowed in POST /config",
			})
			return
		}
		if socksServer != nil {
			if err := socksServer.Reconcile(merged); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"status": "error",
					"error":  err.Error(),
				})
				return
			}
		} else {
			resolver.UpdateConfig(merged)
		}
		if configPath != "" {
			if err := SaveConfig(configPath, merged); err != nil {
				slog.Warn("Failed to persist updated config to disk", "path", configPath, "err", err)
			}
		}
		slog.Info("Updated configuration via HTTP",
			"teams", merged.NumberOfTeams,
			"domain", merged.TeamDomainName,
			"dns_octet", int(merged.TeamDNSServerLastOctet),
			"external_mask", merged.ExternalMask,
			"internal_mask", merged.InternalMask,
		)
		_ = json.NewEncoder(w).Encode(merged)
	})

	mux.HandleFunc("GET /foxyproxy.json", func(w http.ResponseWriter, r *http.Request) {
		cfg := resolver.ConfigSnapshot()
		if _, ok := requireStaffAuth(cfg, w, r); !ok {
			return
		}
		if qTeams := strings.TrimSpace(r.URL.Query().Get("teams")); qTeams != "" {
			if n, err := strconv.Atoi(qTeams); err == nil && n >= 1 && n <= cfg.NumberOfTeams {
				cfg.NumberOfTeams = n
			}
		}
		proxyHost := resolveAdvertiseHost(cfg, r)
		export := BuildFoxyProxyConfig(cfg, proxyHost)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="foxyproxy-teams.json"`)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(export)
	})

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := resolver.ConfigSnapshot()
		if !IsClientAllowed(cfg, ClientIPFromRequest(cfg, r)) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func hasLoopbackPrefix(cfg Config) bool {
	if intIP := net.ParseIP(cfg.InternalMask + "1"); intIP != nil && intIP.IsLoopback() {
		return true
	}
	for team := 0; team <= cfg.NumberOfTeams; team++ {
		if extIP := net.ParseIP(cfg.TeamExternalPrefix(team) + "1"); extIP != nil && extIP.IsLoopback() {
			return true
		}
	}
	return false
}

func resolveAdvertiseHost(cfg Config, r *http.Request) string {
	if cfg.ProxyAdvertiseHost != "" {
		return cfg.ProxyAdvertiseHost
	}
	if r.Host != "" {
		candidate := r.Host
		if h, _, err := net.SplitHostPort(r.Host); err == nil && h != "" {
			candidate = h
		}
		if isValidHostOrIP(candidate) {
			return candidate
		}
	}
	return "127.0.0.1"
}

func isValidHostOrIP(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	if ip := net.ParseIP(s); ip != nil {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlphaNum && c != '.' && c != '-' {
			return false
		}
	}
	return s[0] != '.' && s[0] != '-' && s[len(s)-1] != '-'
}

func BuildFoxyProxyConfig(cfg Config, proxyHost string) FoxyProxyExport {
	entries := make([]FoxyProxyEntry, 0, cfg.NumberOfTeams+1)
	for team := 0; team <= cfg.NumberOfTeams; team++ {
		port := cfg.BaseSocksPort + team
		color := teamBadgeColors[team%len(teamBadgeColors)]

		var includes []FoxyProxyPattern
		if cfg.TeamDomainName != "" {
			includes = append(includes, FoxyProxyPattern{
				Type:    "wildcard",
				Title:   cfg.TeamDomainName,
				Pattern: "*." + cfg.TeamDomainName,
				Active:  true,
			})
		}
		if cfg.InternalMask != "" {
			includes = append(includes, FoxyProxyPattern{
				Type:    "wildcard",
				Title:   "internal-subnet",
				Pattern: cfg.InternalMask + "*",
				Active:  true,
			})
		}

		entries = append(entries, FoxyProxyEntry{
			Active:   true,
			Title:    fmt.Sprintf("Team %02d", team),
			Type:     "socks5",
			Hostname: proxyHost,
			Port:     fmt.Sprintf("%d", port),
			Color:    color,
			ProxyDNS: true,
			Include:  includes,
			Exclude:  []FoxyProxyPattern{},
		})
	}

	return FoxyProxyExport{
		Mode:        "disable",
		Sync:        false,
		AutoBackup:  false,
		Passthrough: buildFoxyProxyPassthrough(cfg),
		Theme:       "",
		Container:   map[string]interface{}{},
		Commands:    map[string]interface{}{},
		Data:        entries,
	}
}

// buildFoxyProxyPassthrough returns a FoxyProxy v8 global passthrough pattern that bypasses the proxy for non-team hosts.
func buildFoxyProxyPassthrough(cfg Config) string {
	var allowed []string
	if cfg.TeamDomainName != "" {
		allowed = append(allowed, "[^/]+."+cfg.TeamDomainName, cfg.TeamDomainName)
	}
	if cfg.InternalMask != "" {
		allowed = append(allowed, cfg.InternalMask)
	}
	if extPrefix, _, ok := strings.Cut(cfg.ExternalMask, "xx."); ok && extPrefix != "" {
		allowed = append(allowed, extPrefix)
	}
	if len(allowed) == 0 {
		return ""
	}
	return "(?!" + strings.Join(allowed, "|") + ")*"
}
