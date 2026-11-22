package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"reverse-socks/pkg/tor"
)

type clusterConfig struct {
	ControlServer struct {
		Host        string `json:"host"`
		Port        int    `json:"port"`
		SecretToken string `json:"secret_token"`
	} `json:"control_server"`

	Cluster struct {
		NodeCount        int    `json:"node_count"`
		TorHost          string `json:"tor_host"`
		TorStartPort     int    `json:"tor_start_port"`
		Prefix           string `json:"prefix"`
		EnsureUniqueIPs  bool   `json:"ensure_unique_ips"`
	} `json:"cluster"`

	ConnectTimeout    float64 `json:"connect_timeout"`
	KeepaliveInterval float64 `json:"keepalive_interval"`
	ReconnectDelay    float64 `json:"reconnect_delay"`
}

func loadClusterConfig(path string) *clusterConfig {
	cfg := &clusterConfig{}
	cfg.ControlServer.Host = "127.0.0.1"
	cfg.ControlServer.Port = 9000
	cfg.ControlServer.SecretToken = "SecretProxyToken2026!"
	cfg.Cluster.NodeCount = 10
	cfg.Cluster.TorHost = "127.0.0.1"
	cfg.Cluster.TorStartPort = 9050
	cfg.Cluster.Prefix = "tor-node-"
	cfg.Cluster.EnsureUniqueIPs = true
	cfg.ConnectTimeout = 20.0
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
	count := flag.Int("count", 0, "Number of Tor agents to spawn")
	startTorPort := flag.Int("start-tor-port", 0, "First Tor SOCKS port")
	torHost := flag.String("tor-host", "", "Tor SOCKS host")
	prefix := flag.String("prefix", "", "Agent ID prefix")
	noVerifyUnique := flag.Bool("no-verify-unique", false, "Skip unique exit IP discovery on startup")
	flag.Parse()

	cfg := loadClusterConfig(*configPath)

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

	nodeCount := cfg.Cluster.NodeCount
	if *count > 0 {
		nodeCount = *count
	}
	tHost := cfg.Cluster.TorHost
	if *torHost != "" {
		tHost = *torHost
	}
	tPort := cfg.Cluster.TorStartPort
	if *startTorPort > 0 {
		tPort = *startTorPort
	}
	pfx := cfg.Cluster.Prefix
	if *prefix != "" {
		pfx = *prefix
	}
	verifyUnique := cfg.Cluster.EnsureUniqueIPs && !(*noVerifyUnique)

	fmt.Println("======================================================================")
	fmt.Printf("   MULTI-TOR REVERSE CLUSTER: %d NODES (GO HIGH-SPEED)\n", nodeCount)
	fmt.Printf("   Target Control Server: %s:%d\n", cHost, cPort)
	fmt.Printf("   Tor SOCKS Ports:       %s:%d .. %d\n", tHost, tPort, tPort+nodeCount-1)
	fmt.Println("======================================================================")

	firstTorOK := tor.CheckTorPort(tHost, tPort, 1500*time.Millisecond)
	lastPort := tPort + nodeCount - 1
	lastTorOK := tor.CheckTorPort(tHost, lastPort, 1500*time.Millisecond)

	if !firstTorOK {
		log.Printf("[!] Tor port %s:%d is not responding yet! Make sure Tor is running.", tHost, tPort)
	} else if !lastTorOK {
		log.Printf("[*] Tor port %s:%d is active (single port mode). IsolateSOCKSAuth will build %d independent circuits!", tHost, tPort, nodeCount)
	} else {
		log.Printf("[OK] Pre-flight check passed: Tor ports %d..%d are active and listening.", tPort, lastPort)
	}

	ipRegistry := tor.NewClusterIPRegistry()
	agents := make([]*tor.TorReverseAgent, nodeCount)

	for i := 0; i < nodeCount; i++ {
		portToUse := tPort
		if lastTorOK {
			portToUse = tPort + i
		}
		agentID := fmt.Sprintf("%s%02d", pfx, i+1)
		agents[i] = tor.NewTorReverseAgent(
			cHost,
			cPort,
			cToken,
			agentID,
			tHost,
			portToUse,
			time.Duration(cfg.ConnectTimeout*float64(time.Second)),
			time.Duration(cfg.KeepaliveInterval*float64(time.Second)),
			time.Duration(cfg.ReconnectDelay*float64(time.Second)),
		)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if verifyUnique && firstTorOK {
		fmt.Println("\n[*] Discovering and verifying UNIQUE exit IP for each node (via Tor IsolateSOCKSAuth)...")
		discCtx, discCancel := context.WithTimeout(ctx, 12*time.Second)
		var discWg sync.WaitGroup
		for _, a := range agents {
			discWg.Add(1)
			go func(ag *tor.TorReverseAgent) {
				defer discWg.Done()
				tor.DiscoverUniqueExitIP(discCtx, ag, ipRegistry, 3)
			}(a)
		}
		discWg.Wait()
		discCancel()

		summary := ipRegistry.GetSummary()
		uniqueCount := ipRegistry.UniqueCount()
		fmt.Println("\n" + strings.Repeat("=", 70))
		fmt.Printf("             VERIFIED UNIQUE TOR EXIT IPS (%d/%d):\n", uniqueCount, len(agents))
		fmt.Println(strings.Repeat("=", 70))
		for _, s := range summary {
			fmt.Printf("  * %-14s -> Exit IP: %s\n", s.AgentID, s.ExitIP)
		}
		fmt.Println(strings.Repeat("-", 70))
		fmt.Printf("Всего проверено уникальных IP: %d из %d\n", uniqueCount, len(agents))
		fmt.Println(strings.Repeat("=", 70) + "\n")
	}

	var wg sync.WaitGroup
	for _, a := range agents {
		wg.Add(1)
		go func(ag *tor.TorReverseAgent) {
			defer wg.Done()
			_ = ag.Run(ctx)
		}(a)
	}

	// Cluster monitor
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				connCount := 0
				for _, a := range agents {
					if a.IsConnected.Load() {
						connCount++
					}
				}
				log.Printf("[CLUSTER MONITOR] Active connected nodes: %d/%d online | Verified unique IPs: %d/%d",
					connCount, len(agents), ipRegistry.UniqueCount(), len(agents))
			case <-ctx.Done():
				return
			}
		}
	}()

	log.Printf("[+] All %d Tor Reverse Agents launched! Connecting to %s:%d...", nodeCount, cHost, cPort)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("[*] Shutting down all Tor Reverse Agents...")
	cancel()
	for _, a := range agents {
		a.Stop()
	}
	wg.Wait()
	log.Println("[OK] Multi-Tor cluster stopped cleanly.")
}
