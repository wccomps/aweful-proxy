package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
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

func NewHTTPHandler(cfg Config) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"status":          "ok",
			"teams":           cfg.NumberOfTeams,
			"domain":          cfg.TeamDomainName,
			"base_socks_port": cfg.BaseSocksPort,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("GET /foxyproxy.json", func(w http.ResponseWriter, r *http.Request) {
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
	if qHost := strings.TrimSpace(r.URL.Query().Get("host")); qHost != "" {
		return qHost
	}
	if cfg.ProxyAdvertiseHost != "" {
		return cfg.ProxyAdvertiseHost
	}
	if r.Host != "" {
		if h, _, err := net.SplitHostPort(r.Host); err == nil && h != "" {
			return h
		}
		return r.Host
	}
	return "127.0.0.1"
}

func BuildFoxyProxyConfig(cfg Config, proxyHost string) FoxyProxyExport {
	entries := make([]FoxyProxyEntry, 0, cfg.NumberOfTeams)
	for team := 1; team <= cfg.NumberOfTeams; team++ {
		port := cfg.BaseSocksPort + team
		color := teamBadgeColors[(team-1)%len(teamBadgeColors)]

		var includes []FoxyProxyPattern
		if cfg.TeamDomainName != "" {
			includes = append(includes, FoxyProxyPattern{
				Type:    "wildcard",
				Title:   cfg.TeamDomainName,
				Pattern: "*." + cfg.TeamDomainName,
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
		Passthrough: "",
		Theme:       "",
		Container:   map[string]interface{}{},
		Commands:    map[string]interface{}{},
		Data:        entries,
	}
}
