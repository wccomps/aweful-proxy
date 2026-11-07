package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// FlexibleOctet unmarshals a JSON string ("132", for aweful-dns compatibility) or integer (132).
type FlexibleOctet int

func (fo *FlexibleOctet) UnmarshalJSON(b []byte) error {
	var intVal int
	if err := json.Unmarshal(b, &intVal); err == nil {
		*fo = FlexibleOctet(intVal)
		return nil
	}
	var strVal string
	if err := json.Unmarshal(b, &strVal); err != nil {
		return fmt.Errorf("octet must be a string or integer: %w", err)
	}
	trimmed := strings.ToLower(strings.TrimSpace(strVal))
	if trimmed == "" || trimmed == "auto" || trimmed == "0" {
		*fo = 0
		return nil
	}
	parsed, err := strconv.Atoi(trimmed)
	if err != nil {
		return fmt.Errorf("invalid octet %q: %w", strVal, err)
	}
	*fo = FlexibleOctet(parsed)
	return nil
}

type Config struct {
	NumberOfTeams          int           `json:"number_of_teams"`
	InternalMask           string        `json:"internal_mask"`
	ExternalMask           string        `json:"external_mask"`
	TeamDNSServerLastOctet FlexibleOctet `json:"team_dns_server_last_octet"`
	TeamDNSServerPort      int           `json:"team_dns_server_port"`
	TeamDomainName         string        `json:"team_domain_name"`
	BaseSocksPort          int           `json:"base_socks_port"`
	SocksListenHost        string        `json:"socks_listen_host"`
	HTTPListenAddr         string        `json:"http_listen_addr"`
	ProxyAdvertiseHost     string        `json:"proxy_advertise_host"`
	DNSTimeoutMs           int           `json:"dns_timeout_ms"`
	DialTimeoutMs          int           `json:"dial_timeout_ms"`
	IdleTimeoutSec         int           `json:"idle_timeout_sec"`
}

func DefaultConfig() Config {
	return Config{
		TeamDNSServerPort: 53,
		BaseSocksPort:     8000,
		SocksListenHost:   "0.0.0.0",
		HTTPListenAddr:    ":8080",
		DNSTimeoutMs:      2000,
		DialTimeoutMs:     5000,
		IdleTimeoutSec:    300,
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) || os.Getenv("AWEFUL_PROXY_NUMBER_OF_TEAMS") == "" {
				return cfg, fmt.Errorf("reading config file %s: %w", path, err)
			}
		} else if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parsing config file %s: %w", path, err)
		}
	}

	if err := applyEnvOverrides(&cfg); err != nil {
		return cfg, err
	}
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func SaveConfig(path string, cfg Config) error {
	if path == "" {
		return nil
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	data = append(data, '\n')
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("writing temp config file %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("replacing config file %s: %w", path, err)
	}
	return nil
}

func applyEnvOverrides(cfg *Config) error {
	strBindings := []struct {
		env    string
		target *string
	}{
		{"AWEFUL_PROXY_INTERNAL_MASK", &cfg.InternalMask},
		{"AWEFUL_PROXY_EXTERNAL_MASK", &cfg.ExternalMask},
		{"AWEFUL_PROXY_TEAM_DOMAIN_NAME", &cfg.TeamDomainName},
		{"AWEFUL_PROXY_SOCKS_LISTEN_HOST", &cfg.SocksListenHost},
		{"AWEFUL_PROXY_HTTP_LISTEN_ADDR", &cfg.HTTPListenAddr},
		{"AWEFUL_PROXY_ADVERTISE_HOST", &cfg.ProxyAdvertiseHost},
	}
	for _, b := range strBindings {
		if v := os.Getenv(b.env); v != "" {
			*b.target = v
		}
	}

	dnsOctet := int(cfg.TeamDNSServerLastOctet)
	intBindings := []struct {
		env    string
		target *int
	}{
		{"AWEFUL_PROXY_NUMBER_OF_TEAMS", &cfg.NumberOfTeams},
		{"AWEFUL_PROXY_TEAM_DNS_SERVER_LAST_OCTET", &dnsOctet},
		{"AWEFUL_PROXY_BASE_SOCKS_PORT", &cfg.BaseSocksPort},
		{"AWEFUL_PROXY_DNS_TIMEOUT_MS", &cfg.DNSTimeoutMs},
		{"AWEFUL_PROXY_DIAL_TIMEOUT_MS", &cfg.DialTimeoutMs},
		{"AWEFUL_PROXY_IDLE_TIMEOUT_SEC", &cfg.IdleTimeoutSec},
	}
	for _, b := range intBindings {
		if v := os.Getenv(b.env); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fmt.Errorf("invalid %s: %w", b.env, err)
			}
			*b.target = n
		}
	}
	cfg.TeamDNSServerLastOctet = FlexibleOctet(dnsOctet)
	return nil
}

func (c *Config) normalize() {
	c.InternalMask = strings.TrimSpace(c.InternalMask)
	c.ExternalMask = strings.TrimSpace(c.ExternalMask)
	c.TeamDomainName = strings.ToLower(strings.Trim(strings.TrimSpace(c.TeamDomainName), "."))
	if c.ExternalMask == "" {
		c.ExternalMask = "10.100.1xx."
	}
	if c.InternalMask == "" {
		c.InternalMask = "192.168.220."
	}
	if c.TeamDNSServerPort == 0 {
		c.TeamDNSServerPort = 53
	}
}

func (c *Config) Validate() error {
	c.normalize()
	if c.NumberOfTeams < 1 || c.NumberOfTeams > 99 {
		return fmt.Errorf("number_of_teams must be between 1 and 99 (got %d)", c.NumberOfTeams)
	}
	if !isValidThreeOctetPrefix(c.InternalMask) {
		return fmt.Errorf("internal_mask must be 3 IPv4 octets ending with a dot, e.g. \"192.168.220.\" (got %q)", c.InternalMask)
	}
	if !strings.Contains(c.ExternalMask, "xx") || !strings.HasSuffix(c.ExternalMask, ".") {
		return fmt.Errorf("external_mask must contain \"xx\" and end with a dot, e.g. \"10.100.1xx.\" (got %q)", c.ExternalMask)
	}
	for team := 0; team <= c.NumberOfTeams; team++ {
		prefix := c.TeamExternalPrefix(team)
		if !isValidThreeOctetPrefix(prefix) {
			return fmt.Errorf("external_mask %q produced invalid IPv4 prefix %q for team %d", c.ExternalMask, prefix, team)
		}
	}
	dnsOctet := int(c.TeamDNSServerLastOctet)
	if dnsOctet < 0 || dnsOctet > 254 {
		return fmt.Errorf("team_dns_server_last_octet must be between 0 (auto) and 254 (got %d)", dnsOctet)
	}
	if c.TeamDNSServerPort < 1 || c.TeamDNSServerPort > 65535 {
		return fmt.Errorf("team_dns_server_port must be between 1 and 65535 (got %d)", c.TeamDNSServerPort)
	}
	if c.BaseSocksPort < 1 || c.BaseSocksPort+c.NumberOfTeams > 65535 {
		return fmt.Errorf("base_socks_port (%d) + number_of_teams (%d) must be within valid TCP port range 1..65535", c.BaseSocksPort, c.NumberOfTeams)
	}
	if c.DNSTimeoutMs <= 0 {
		return fmt.Errorf("dns_timeout_ms must be positive (got %d)", c.DNSTimeoutMs)
	}
	if c.DialTimeoutMs <= 0 {
		return fmt.Errorf("dial_timeout_ms must be positive (got %d)", c.DialTimeoutMs)
	}
	if c.IdleTimeoutSec <= 0 {
		return fmt.Errorf("idle_timeout_sec must be positive (got %d)", c.IdleTimeoutSec)
	}
	return nil
}

func isValidThreeOctetPrefix(prefix string) bool {
	if !strings.HasSuffix(prefix, ".") {
		return false
	}
	ip := net.ParseIP(prefix + "1")
	return ip != nil && ip.To4() != nil && strings.Count(prefix, ".") == 3
}

func (c Config) TeamExternalPrefix(team int) string {
	return strings.Replace(c.ExternalMask, "xx", fmt.Sprintf("%02d", team), 1)
}

func (c Config) TeamDNSServerAddr(team int) string {
	port := c.TeamDNSServerPort
	if port == 0 {
		port = 53
	}
	return fmt.Sprintf("%s%d:%d", c.TeamExternalPrefix(team), int(c.TeamDNSServerLastOctet), port)
}

func (c Config) DNSTimeout() time.Duration {
	return time.Duration(c.DNSTimeoutMs) * time.Millisecond
}

func (c Config) DialTimeout() time.Duration {
	return time.Duration(c.DialTimeoutMs) * time.Millisecond
}

func (c Config) IdleTimeout() time.Duration {
	return time.Duration(c.IdleTimeoutSec) * time.Second
}
