package control

import (
	"encoding/json"
	"os"
	"regexp"
)

// Config represents server config.json
type Config struct {
	Socks5 struct {
		Host string `json:"host"`
		Port int    `json:"port"`
	} `json:"socks5"`

	MTProto struct {
		Enabled  bool   `json:"enabled"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Secret   string `json:"secret"`
		Domain   string `json:"domain"`
		MaskHost string `json:"mask_host"`
		MaskPort int    `json:"mask_port"`
		Tag      string `json:"tag"`
	} `json:"mtproto"`

	Control struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		SecretToken string `json:"secret_token"`
	} `json:"control"`

	Admin struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"admin"`

	BalanceStrategy      string  `json:"balance_strategy"`
	FastFailoverSeconds  float64 `json:"fast_failover_seconds"`
	ConnectTimeout       float64 `json:"connect_timeout"`
	LogLevel             string  `json:"log_level"`
}

// DefaultConfig returns default configuration.
func DefaultConfig() *Config {
	c := &Config{}
	c.Socks5.Host = "0.0.0.0"
	c.Socks5.Port = 1080

	c.MTProto.Enabled = true
	c.MTProto.Host = "0.0.0.0"
	c.MTProto.Port = 8443
	c.MTProto.Secret = "d04843361111fc744f516582107f9fb6"
	c.MTProto.Domain = "google.com"
	c.MTProto.MaskHost = "google.com"
	c.MTProto.MaskPort = 443

	c.Control.Host = "0.0.0.0"
	c.Control.Port = 9000
	c.Control.SecretToken = "SecretProxyToken2026!"

	c.Admin.Host = "0.0.0.0"
	c.Admin.Port = 9001
	c.Admin.Username = "admin"
	c.Admin.Password = "changeme"

	c.BalanceStrategy = "rotation"
	c.FastFailoverSeconds = 2.0
	c.ConnectTimeout = 15.0
	c.LogLevel = "INFO"
	return c
}

// LoadConfig loads configuration from path with tolerant JSON fallback.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, nil // return defaults if missing
	}

	if err := json.Unmarshal(data, cfg); err == nil {
		return cfg, nil
	}

	// Auto-repair common syntax quirks: trailing comments, trailing commas
	reComment := regexp.MustCompile(`(?m)(//.*$|#.*$)`)
	repaired := reComment.ReplaceAll(data, nil)
	reComma := regexp.MustCompile(`,\s*([}\]])`)
	repaired = reComma.ReplaceAll(repaired, []byte("$1"))

	_ = json.Unmarshal(repaired, cfg)
	return cfg, nil
}
