package tor

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// ClusterIPRegistry guarantees 100% unique exit IP per Tor agent.
type ClusterIPRegistry struct {
	assigned map[string]string // IP -> AgentID
	mu       sync.Mutex
}

// NewClusterIPRegistry creates a new registry.
func NewClusterIPRegistry() *ClusterIPRegistry {
	return &ClusterIPRegistry{
		assigned: make(map[string]string),
	}
}

// Claim claims an IP for an agentID. Returns true if granted.
func (r *ClusterIPRegistry) Claim(ip, agentID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	if existing, ok := r.assigned[ip]; ok && existing != agentID {
		return false
	}
	r.assigned[ip] = agentID
	return true
}

// UniqueCount returns total unique IPs claimed.
func (r *ClusterIPRegistry) UniqueCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.assigned)
}

// SummaryEntry represents an agent-to-IP mapping.
type SummaryEntry struct {
	AgentID string
	ExitIP  string
}

// GetSummary returns sorted list of claimed IPs.
func (r *ClusterIPRegistry) GetSummary() []SummaryEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	var list []SummaryEntry
	for ip, aid := range r.assigned {
		list = append(list, SummaryEntry{AgentID: aid, ExitIP: ip})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].AgentID < list[j].AgentID
	})
	return list
}

// CheckTorPort checks if local Tor SOCKS port is accepting connections.
func CheckTorPort(host string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// DiscoverUniqueExitIP attempts to find a unique exit IP for an agent using Tor IsolateSOCKSAuth.
func DiscoverUniqueExitIP(ctx context.Context, agent *TorReverseAgent, registry *ClusterIPRegistry, maxAttempts int) {
	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return
		default:
		}

		ip, err := agent.FetchExitIP()
		if err == nil && ip != "" {
			if registry.Claim(ip, agent.AgentID) {
				agent.ExitIP = ip
				return
			}
		}
		// Request new circuit
		agent.NextCircuit()
		time.Sleep(500 * time.Millisecond)
	}
}
