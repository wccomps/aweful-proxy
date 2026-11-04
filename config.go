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

// FlexibleOctet allows JSON configuration to specify the last octet as either
// a string ("132") for compatibility with aweful-dns or an integer (132).
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
	parsed, err := strconv.Atoi(strings.TrimSpace(strVal))
	if err != nil {
		return fmt.Errorf("invalid octet %q: %w", strVal, err)
	}
	*fo = FlexibleOctet(parsed)
	return nil
}

func (fo FlexibleOctet) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.Itoa(int(fo)))
}

type Config struct {
	NumberOfTeams          int            `json:"number_of_teams"`
	InternalMask           string         `json:"internal_mask"`
	ExternalMask           string         `json:"external_mask"`
	TeamDNSServerLastOctet FlexibleOctet  `json:"team_dns_server_last_octet"`
	TeamDomainName         string         `json:"team_domain_name"`
	BaseSocksPort          int            `json:"base_socks_port"`
	SocksListenHost        string         `json:"socks_listen_host"`
	HTTPListenAddr         string         `json:"http_listen_addr"`
	ProxyAdvertiseHost     string         `json:"proxy_advertise_host"`
	DNSTimeoutMs           int            `json:"dns_timeout_ms"`
	DialTimeoutMs          int            `json:"dial_timeout_ms"`
	IdleTimeoutSec         int            `json:"idle_timeout_sec"`
	StaticHostsMode        string         `json:"static_hosts_mode"`
	StaticHosts            map[string]int `json:"static_hosts"`
}

func DefaultConfig() Config {
	return Config{
		BaseSocksPort:   1080,
		SocksListenHost: "0.0.0.0",
		HTTPListenAddr:  ":8080",
		DNSTimeoutMs:    2000,
		DialTimeoutMs:   5000,
		IdleTimeoutSec:  300,
		StaticHostsMode: "fallback",
		StaticHosts:     make(map[string]int),
	}
}

func LoadConfig(path string) (Config, error) {
	cfg := DefaultConfig()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) || !hasEnvConfig() {
				return cfg, fmt.Errorf("reading config file %s: %w", path, err)
			}
		} else if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parsing config file %s: %w", path, err)
		}
	}

	if err := applyEnvOverrides(&cfg); err != nil {
		return cfg, err
	}
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func hasEnvConfig() bool {
	return os.Getenv("AWEFUL_PROXY_NUMBER_OF_TEAMS") != ""
}

func applyEnvOverrides(cfg *Config) error {
	if v := os.Getenv("AWEFUL_PROXY_NUMBER_OF_TEAMS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid AWEFUL_PROXY_NUMBER_OF_TEAMS: %w", err)
		}
		cfg.NumberOfTeams = n
	}
	if v := os.Getenv("AWEFUL_PROXY_INTERNAL_MASK"); v != "" {
		cfg.InternalMask = v
	}
	if v := os.Getenv("AWEFUL_PROXY_EXTERNAL_MASK"); v != "" {
		cfg.ExternalMask = v
	}
	if v := os.Getenv("AWEFUL_PROXY_TEAM_DNS_SERVER_LAST_OCTET"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid AWEFUL_PROXY_TEAM_DNS_SERVER_LAST_OCTET: %w", err)
		}
		cfg.TeamDNSServerLastOctet = FlexibleOctet(n)
	}
	if v := os.Getenv("AWEFUL_PROXY_TEAM_DOMAIN_NAME"); v != "" {
		cfg.TeamDomainName = v
	}
	if v := os.Getenv("AWEFUL_PROXY_BASE_SOCKS_PORT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid AWEFUL_PROXY_BASE_SOCKS_PORT: %w", err)
		}
		cfg.BaseSocksPort = n
	}
	if v := os.Getenv("AWEFUL_PROXY_SOCKS_LISTEN_HOST"); v != "" {
		cfg.SocksListenHost = v
	}
	if v := os.Getenv("AWEFUL_PROXY_HTTP_LISTEN_ADDR"); v != "" {
		cfg.HTTPListenAddr = v
	}
	if v := os.Getenv("AWEFUL_PROXY_ADVERTISE_HOST"); v != "" {
		cfg.ProxyAdvertiseHost = v
	}
	if v := os.Getenv("AWEFUL_PROXY_DNS_TIMEOUT_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid AWEFUL_PROXY_DNS_TIMEOUT_MS: %w", err)
		}
		cfg.DNSTimeoutMs = n
	}
	if v := os.Getenv("AWEFUL_PROXY_DIAL_TIMEOUT_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid AWEFUL_PROXY_DIAL_TIMEOUT_MS: %w", err)
		}
		cfg.DialTimeoutMs = n
	}
	if v := os.Getenv("AWEFUL_PROXY_IDLE_TIMEOUT_SEC"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return fmt.Errorf("invalid AWEFUL_PROXY_IDLE_TIMEOUT_SEC: %w", err)
		}
		cfg.IdleTimeoutSec = n
	}
	if v := os.Getenv("AWEFUL_PROXY_STATIC_HOSTS_MODE"); v != "" {
		cfg.StaticHostsMode = v
	}
	return nil
}

func (c *Config) normalize() {
	c.InternalMask = strings.TrimSpace(c.InternalMask)
	c.ExternalMask = strings.TrimSpace(c.ExternalMask)
	c.TeamDomainName = strings.ToLower(strings.Trim(strings.TrimSpace(c.TeamDomainName), "."))
	c.StaticHostsMode = strings.ToLower(strings.TrimSpace(c.StaticHostsMode))
	if c.StaticHostsMode == "" {
		c.StaticHostsMode = "fallback"
	}
	normalizedHosts := make(map[string]int, len(c.StaticHosts))
	for k, v := range c.StaticHosts {
		host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(k), "."))
		if host != "" {
			normalizedHosts[host] = v
		}
	}
	c.StaticHosts = normalizedHosts
}

func (c Config) Validate() error {
	if c.NumberOfTeams < 1 || c.NumberOfTeams > 99 {
		return fmt.Errorf("number_of_teams must be between 1 and 99 (got %d)", c.NumberOfTeams)
	}
	if !isValidThreeOctetPrefix(c.InternalMask) {
		return fmt.Errorf("internal_mask must be 3 IPv4 octets ending with a dot, e.g. \"192.168.220.\" (got %q)", c.InternalMask)
	}
	if !strings.Contains(c.ExternalMask, "xx") || ! strings.HasSuffix(c.ExternalMask, ".") {
		return fmt.Errorf("external_mask must contain \"xx\" and end with a dot, e.g. \"10.100.1xx.\" (got %q)", c.ExternalMask)
	}
	for team := 1; team <= c.NumberOfTeams; team++ {
		prefix := c.TeamExternalPrefix(team)
		if !isValidThreeOctetPrefix(prefix) {
			return fmt.Errorf("external_mask %q produced invalid IPv4 prefix %q for team %d", c.ExternalMask, prefix, team)
		}
	}
	dnsOctet := int(c.TeamDNSServerLastOctet)
	if dnsOctet < 1 || dnsOctet > 254 {
		return fmt.Errorf("team_dns_server_last_octet must be between 1 and 254 (got %d)", dnsOctet)
	}
	if c.TeamDomainName == "" {
		return errors.New("team_domain_name is required")
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
	if c.StaticHostsMode != "fallback" && c.StaticHostsMode != "override" {
		return fmt.Errorf("static_hosts_mode must be \"fallback\" or \"override\" (got %q)", c.StaticHostsMode)
	}
	for host, octet := range c.StaticHosts {
		if octet < 1 || octet > 254 {
			return fmt.Errorf("static_hosts[%q] octet must be between 1 and 254 (got %d)", host, octet)
		}
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

// TeamExternalPrefix returns the 3-octet trailing-dot prefix for team N (1-based),
// e.g. "10.100.106." when ExternalMask is "10.100.1xx." and team is 6.
func (c Config) TeamExternalPrefix(team int) string {
	teamStr := fmt.Sprintf("%02d", team)
	return strings.Replace(c.ExternalMask, "xx", teamStr, 1)
}

// TeamDNSServerAddr returns the ip:port of Team N's DNS server, e.g. "10.100.106.132:53".
func (c Config) TeamDNSServerAddr(team int) string {
	return fmt.Sprintf("%s%d:53", c.TeamExternalPrefix(team), int(c.TeamDNSServerLastOctet))
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
