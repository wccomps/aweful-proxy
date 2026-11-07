package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
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

func NewHTTPHandler(resolver *Resolver) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		cfg := resolver.ConfigSnapshot()
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"status":                     "ok",
			"teams":                      cfg.NumberOfTeams,
			"domain":                     cfg.TeamDomainName,
			"team_dns_server_last_octet": int(cfg.TeamDNSServerLastOctet),
			"base_socks_port":            cfg.BaseSocksPort,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("POST /discover", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		cfg := resolver.ConfigSnapshot()
		res, err := DiscoverEnvironment(ctx, cfg)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"status": "error",
				"error":  err.Error(),
			})
			return
		}
		resolver.UpdateDiscovery(res.DNSServerLastOctet, res.TeamDomainName)
		_ = json.NewEncoder(w).Encode(res)
	})

	mux.HandleFunc("GET /foxyproxy.json", func(w http.ResponseWriter, r *http.Request) {
		cfg := resolver.ConfigSnapshot()
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

	return mux
}

func resolveAdvertiseHost(cfg Config, r *http.Request) string {
	if cfg.ProxyAdvertiseHost != "" {
		return cfg.ProxyAdvertiseHost
	}
	if qHost := strings.TrimSpace(r.URL.Query().Get("host")); isValidHostOrIP(qHost) {
		return qHost
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
		if cfg.TeamDomainName != "" && cfg.TeamDomainName != "auto" {
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

// buildFoxyProxyPassthrough constructs a FoxyProxy v8 global passthrough rule that bypasses
// the proxy (sending traffic DIRECT) for any URL whose host does not match the team domain,
// internal subnet mask, or external subnet prefix. This allows users to select a specific
// "Team XX" proxy in the FoxyProxy toolbar without breaking general internet browsing.
func buildFoxyProxyPassthrough(cfg Config) string {
	var allowed []string
	if cfg.TeamDomainName != "" && cfg.TeamDomainName != "auto" {
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
