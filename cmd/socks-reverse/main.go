package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"reverse-socks/pkg/agent"
)

type reverseConfig struct {
	ControlServer struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		SecretToken string `json:"secret_token"`
	} `json:"control_server"`

	FakeTLS struct {
		Enabled bool   `json:"enabled"`
		Domain  string `json:"domain"`
	} `json:"fake_tls"`

	HTTPProxy struct {
		Enabled     bool   `json:"enabled"`
		ProxyURL    string `json:"proxy_url"`
		ConnectHost string `json:"connect_host"`
	} `json:"http_proxy"`

	AgentID           string  `json:"agent_id"`
	ConnectTimeout    float64 `json:"connect_timeout"`
	KeepaliveInterval float64 `json:"keepalive_interval"`
	ReconnectDelay    float64 `json:"reconnect_delay"`
}

func loadReverseConfig(path string) *reverseConfig {
	cfg := &reverseConfig{}
	cfg.ControlServer.Host = "127.0.0.1"
	cfg.ControlServer.Port = 9000
	cfg.ControlServer.SecretToken = "SecretProxyToken2026!"
	cfg.FakeTLS.Domain = "google.com"
	cfg.ConnectTimeout = 15.0
	cfg.KeepaliveInterval = 25.0
	cfg.ReconnectDelay = 3.0

	data, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(data, cfg)
	}
	return cfg
}

func main() {
	configPath := flag.String("config", "config.json", "Path to config.json")
	host := flag.String("host", "", "Control server IP/hostname")
	port := flag.Int("port", 0, "Control server bridge port")
	token := flag.String("token", "", "Secret token for authentication")
	agentID := flag.String("agent-id", "", "Unique ID/Name for this reverse agent")
	fakeTLS := flag.Bool("fake-tls", false, "Enable Fake-TLS 1.3 tunnel with white SNI")
	fakeTLSDomain := flag.String("fake-tls-domain", "", "Whitelisted domain for TLS SNI (default: google.com)")
	httpProxy := flag.String("http-proxy", "", "HTTP proxy URL (e.g. http://proxy.server:3128)")
	connectHost := flag.String("connect-host", "", "Custom host to send in HTTP CONNECT request")
	flag.Parse()

	cfg := loadReverseConfig(*configPath)

	cHost := cfg.ControlServer.Host
	if *host != "" {
		cHost = *host
	}
	cPort := cfg.ControlServer.Port
	if *port > 0 {
		cPort = *port
	}
	cToken := cfg.ControlServer.SecretToken
	if *token != "" {
		cToken = *token
	}

	aID := cfg.AgentID
	if *agentID != "" {
		aID = *agentID
	}
	if aID == "" {
		aID = fmt.Sprintf("agent-%d", os.Getpid())
	}

	useTLS := cfg.FakeTLS.Enabled
	if *fakeTLS {
		useTLS = true
	}
	tlsDomain := cfg.FakeTLS.Domain
	if *fakeTLSDomain != "" {
		tlsDomain = *fakeTLSDomain
	}
	if tlsDomain == "" {
		tlsDomain = "google.com"
	}

	proxyURL := cfg.HTTPProxy.ProxyURL
	if *httpProxy != "" {
		proxyURL = *httpProxy
	}
	if proxyURL == "" {
		if envProxy := os.Getenv("https_proxy"); envProxy != "" {
			proxyURL = envProxy
		} else if envProxy := os.Getenv("http_proxy"); envProxy != "" {
			proxyURL = envProxy
		}
	}

	cHostHdr := cfg.HTTPProxy.ConnectHost
	if *connectHost != "" {
		cHostHdr = *connectHost
	}

	modeInfo := "Plain TCP"
	if useTLS {
		modeInfo = fmt.Sprintf("Fake-TLS (%s)", tlsDomain)
	}
	proxyInfo := ""
	if proxyURL != "" {
		proxyInfo = fmt.Sprintf(" via Proxy %s", proxyURL)
	}

	log.Println("============================================================")
	log.Println("   REVERSE SOCKS5 WORKER AGENT (GO HIGH-SPEED)")
	log.Printf("   Agent ID:          %s", aID)
	log.Printf("   Target Control:    %s:%d%s", cHost, cPort, proxyInfo)
	log.Printf("   Transport Mode:    %s", modeInfo)
	log.Println("============================================================")

	revAgent := agent.NewReverseAgent(
		cHost,
		cPort,
		cToken,
		aID,
		useTLS,
		tlsDomain,
		proxyURL,
		cHostHdr,
		time.Duration(cfg.ConnectTimeout*float64(time.Second)),
		time.Duration(cfg.KeepaliveInterval*float64(time.Second)),
		time.Duration(cfg.ReconnectDelay*float64(time.Second)),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutdown signal received, stopping agent...")
		revAgent.Stop()
		cancel()
	}()

	if err := revAgent.Start(ctx); err != nil && err != context.Canceled {
		log.Printf("Agent stopped with error: %v", err)
	}
	log.Println("Agent stopped.")
}
