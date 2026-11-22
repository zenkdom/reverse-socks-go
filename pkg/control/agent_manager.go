package control

import (
	"context"
	"fmt"
	"hash/fnv"
	"log"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"reverse-socks/pkg/protocol"
)

// UserRotationState tracks independent rotation and fallback state for a specific user/client.
type UserRotationState struct {
	UserKey                 string
	RRIndex                 int
	LastAssignedAgentID     string
	LastSuccessfulAgentID   string
	TotalRequests           int64
	FailoverCount           int64
	LastSeen                time.Time
}

// AgentStatus contains snapshot data for web admin and API.
type AgentStatus struct {
	AgentID           string `json:"agent_id"`
	RemoteIP          string `json:"remote_ip"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
	ActiveConnections int64  `json:"active_connections"`
	TotalHandled      int64  `json:"total_handled"`
	IsLastUsed        bool   `json:"is_last_used"`
	IsFakeTLS         bool   `json:"is_faketls"`
	SNIDomain         string `json:"sni_domain"`
	ExitIP            string `json:"exit_ip"`
}

// AgentManager manages active reverse agents, continuous per-user rotation, and 2-second failover.
type AgentManager struct {
	agents                 map[string]*AgentSession
	agentsMu               sync.RWMutex
	strategy               string // "rotation", "round_robin", "random", "sticky"
	fastTimeout            time.Duration
	streamCounter          atomic.Uint32
	userStates             map[string]*UserRotationState
	userStatesMu           sync.Mutex
	lastSuccessfulAgentID  string
	lastSuccessfulAgentMu  sync.RWMutex
	FailoverCount          atomic.Int64
	TotalRequests          atomic.Int64
}

// NewAgentManager creates a new AgentManager.
func NewAgentManager(strategy string, fastTimeout time.Duration) *AgentManager {
	if strategy == "" {
		strategy = "rotation"
	}
	if fastTimeout <= 0 {
		fastTimeout = 2 * time.Second
	}
	am := &AgentManager{
		agents:      make(map[string]*AgentSession),
		strategy:    strategy,
		fastTimeout: fastTimeout,
		userStates:  make(map[string]*UserRotationState),
	}
	am.streamCounter.Store(1)
	return am
}

// GetAgentCount returns the number of active agents.
func (am *AgentManager) GetAgentCount() int {
	am.agentsMu.RLock()
	defer am.agentsMu.RUnlock()
	return len(am.agents)
}

// Register registers an authenticated agent.
func (am *AgentManager) Register(agent *AgentSession) {
	am.agentsMu.Lock()
	am.agents[agent.AgentID] = agent
	total := len(am.agents)
	am.agentsMu.Unlock()

	log.Printf("[+] Agent registered: '%s' from %s (Total active agents: %d)", agent.AgentID, agent.RemoteIP, total)
}

// Unregister removes an agent.
func (am *AgentManager) Unregister(agentID string) {
	am.agentsMu.Lock()
	delete(am.agents, agentID)
	total := len(am.agents)
	am.agentsMu.Unlock()

	log.Printf("[-] Agent unregistered: '%s' (Total active agents: %d)", agentID, total)
}

// CloseAll disconnects all connected agents.
func (am *AgentManager) CloseAll() {
	am.agentsMu.Lock()
	agents := make([]*AgentSession, 0, len(am.agents))
	for _, a := range am.agents {
		agents = append(agents, a)
	}
	am.agents = make(map[string]*AgentSession)
	am.agentsMu.Unlock()

	for _, a := range agents {
		a.Close()
	}
}

// ReapStaleAgents disconnects and unregisters reverse agents that have sent no pings or frames for > maxInactive.
func (am *AgentManager) ReapStaleAgents(maxInactive time.Duration) {
	am.agentsMu.Lock()
	now := time.Now().Unix()
	var stale []*AgentSession
	for id, a := range am.agents {
		if now-a.LastSeen.Load() > int64(maxInactive.Seconds()) {
			stale = append(stale, a)
			delete(am.agents, id)
		}
	}
	am.agentsMu.Unlock()

	for _, a := range stale {
		log.Printf("[-] Watchdog reaped inactive agent '%s' (idle > %v)", a.AgentID, maxInactive)
		a.Close()
	}
}

// NextStreamID generates a unique uint32 stream ID.
func (am *AgentManager) NextStreamID() uint32 {
	for {
		v := am.streamCounter.Add(1) & 0x7FFFFFFF
		if v != 0 {
			return v
		}
	}
}

func (am *AgentManager) getUserState(userKey string) *UserRotationState {
	am.userStatesMu.Lock()
	defer am.userStatesMu.Unlock()

	// Prune stale states if cache grows too large
	if len(am.userStates) > 5000 {
		cutoff := time.Now().Add(-24 * time.Hour)
		for k, s := range am.userStates {
			if s.LastSeen.Before(cutoff) {
				delete(am.userStates, k)
			}
		}
	}

	state, ok := am.userStates[userKey]
	if !ok {
		state = &UserRotationState{
			UserKey:  userKey,
			LastSeen: time.Now(),
		}
		am.userStates[userKey] = state
	}
	state.LastSeen = time.Now()
	return state
}

func hashKey(s string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(s))
	return h.Sum32()
}

// GetCandidateAgents returns an ordered list of candidate agents to attempt for a request.
func (am *AgentManager) GetCandidateAgents(userKey, clientIP string) []*AgentSession {
	am.agentsMu.RLock()
	var active []*AgentSession
	for _, a := range am.agents {
		if !a.Closed.Load() {
			active = append(active, a)
		}
	}
	am.agentsMu.RUnlock()

	if len(active) == 0 {
		return nil
	}
	if len(active) == 1 {
		return active
	}

	effectiveUser := userKey
	if effectiveUser == "" {
		if clientIP != "" {
			parts := strings.Split(clientIP, ":")
			effectiveUser = parts[0]
		} else {
			effectiveUser = "global"
		}
	}

	state := am.getUserState(effectiveUser)

	switch am.strategy {
	case "rotation", "round_robin":
		// MTProto sessions maintain stickiness per client device to prevent Telegram DC connection resets
		if strings.HasPrefix(userKey, "mtproto:") {
			// If last successful agent is active and healthy, stick to it!
			if state.LastSuccessfulAgentID != "" {
				for _, a := range active {
					if a.AgentID == state.LastSuccessfulAgentID && a.IsHealthy(30*time.Second) {
						var fallbacks []*AgentSession
						for _, fb := range active {
							if fb.AgentID != a.AgentID {
								fallbacks = append(fallbacks, fb)
							}
						}
						return append([]*AgentSession{a}, fallbacks...)
					}
				}
			}

			var healthy []*AgentSession
			for _, a := range active {
				if a.IsHealthy(30 * time.Second) {
					healthy = append(healthy, a)
				}
			}
			pool := healthy
			if len(pool) == 0 {
				pool = active
			}

			idx := int(hashKey(userKey) % uint32(len(pool)))
			primary := pool[idx]
			var fallbacks []*AgentSession
			for _, a := range active {
				if a.AgentID != primary.AgentID {
					fallbacks = append(fallbacks, a)
				}
			}
			return append([]*AgentSession{primary}, fallbacks...)
		}

		// Rotate to next agent specifically for this user, prioritizing healthy nodes
		var healthy []*AgentSession
		for _, a := range active {
			if a.IsHealthy(30 * time.Second) {
				healthy = append(healthy, a)
			}
		}
		pool := healthy
		if len(pool) == 0 {
			pool = active
		}

		startIdx := state.RRIndex % len(pool)
		state.RRIndex++

		// Ensure candidate 0 is strictly different from the previous node FOR THIS USER
		lastID := state.LastAssignedAgentID
		if lastID == "" {
			lastID = state.LastSuccessfulAgentID
		}
		if pool[startIdx].AgentID == lastID && len(pool) > 1 {
			startIdx = (startIdx + 1) % len(pool)
		}

		var candidates []*AgentSession
		for i := 0; i < len(pool); i++ {
			candidates = append(candidates, pool[(startIdx+i)%len(pool)])
		}
		for _, a := range active {
			found := false
			for _, c := range candidates {
				if c.AgentID == a.AgentID {
					found = true
					break
				}
			}
			if !found {
				candidates = append(candidates, a)
			}
		}
		state.LastAssignedAgentID = candidates[0].AgentID
		return candidates

	case "sticky", "client_ip":
		k := userKey
		if k == "" {
			if clientIP != "" {
				k = strings.Split(clientIP, ":")[0]
			} else {
				k = "default"
			}
		}
		idx := int(hashKey(k) % uint32(len(active)))
		primary := active[idx]
		var fallbacks []*AgentSession
		for _, a := range active {
			if a.AgentID != primary.AgentID {
				fallbacks = append(fallbacks, a)
			}
		}
		return append([]*AgentSession{primary}, fallbacks...)

	default: // "random"
		shuffled := make([]*AgentSession, len(active))
		copy(shuffled, active)
		rand.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})
		lastID := state.LastAssignedAgentID
		if lastID == "" {
			lastID = state.LastSuccessfulAgentID
		}
		if shuffled[0].AgentID == lastID && len(shuffled) > 1 {
			shuffled[0], shuffled[1] = shuffled[1], shuffled[0]
		}
		state.LastAssignedAgentID = shuffled[0].AgentID
		return shuffled
	}
}

// EstablishStream attempts to connect to targetHost:targetPort via a candidate agent with fast 2.0s failover.
// Returns (agent, stream, statusCode).
func (am *AgentManager) EstablishStream(
	ctx context.Context,
	host string,
	port int,
	userKey string,
	clientIP string,
	fastTimeout time.Duration,
	totalTimeout time.Duration,
	proto string,
) (*AgentSession, *StreamContext, int) {
	am.TotalRequests.Add(1)
	effectiveUser := userKey
	if effectiveUser == "" {
		if clientIP != "" {
			effectiveUser = strings.Split(clientIP, ":")[0]
		} else {
			effectiveUser = "global"
		}
	}
	state := am.getUserState(effectiveUser)
	state.TotalRequests++

	fastTo := fastTimeout
	if fastTo <= 0 {
		fastTo = am.fastTimeout
	}
	if strings.HasPrefix(userKey, "mtproto:") {
		if fastTo < 4*time.Second {
			fastTo = 4 * time.Second
		}
		if totalTimeout < 20*time.Second {
			totalTimeout = 20 * time.Second
		}
	}

	candidates := am.GetCandidateAgents(userKey, clientIP)
	if len(candidates) == 0 {
		log.Printf("[%s] No active reverse agents available to connect to %s:%d", effectiveUser, host, port)
		return nil, nil, protocol.StatusHostUnreachable
	}

	startTime := time.Now()
	lastErrorStatus := protocol.StatusGeneralFailure
	numCandidates := len(candidates)

	for idx, candidate := range candidates {
		if candidate.Closed.Load() {
			continue
		}

		elapsed := time.Since(startTime)
		if elapsed >= totalTimeout {
			log.Printf("[%s] Total timeout reached (%v) trying to connect to %s:%d", effectiveUser, totalTimeout, host, port)
			break
		}
		remaining := totalTimeout - elapsed
		if remaining < 500*time.Millisecond {
			remaining = 500 * time.Millisecond
		}

		attemptTimeout := fastTo
		if idx == numCandidates-1 || attemptTimeout > remaining {
			attemptTimeout = remaining
		}

		streamID := am.NextStreamID()
		stream := NewStreamContext(streamID, host, port, candidate.AgentID, proto)
		candidate.RegisterStream(stream)

		isFallback := (idx > 0)
		role := "Rotated Primary"
		if isFallback {
			role = fmt.Sprintf("Fallback #%d (previous/other node)", idx)
		}
		log.Printf("[CONNECT ATTEMPT] [%s] -> Routing to %s:%d (%s) via [%s] (%s, timeout: %v, Stream #%d)",
			effectiveUser, host, port, strings.ToUpper(proto), candidate.AgentID, role, attemptTimeout, streamID)

		reqData := map[string]any{
			"host":  host,
			"port":  port,
			"proto": proto,
		}
		if err := candidate.SendJSON(protocol.CmdConnectReq, streamID, reqData); err != nil {
			candidate.RemoveStream(streamID, false)
			continue
		}

		select {
		case <-stream.ConnectDone:
			if stream.ConnectStatus == protocol.StatusSuccess {
				candidate.RecordSuccess()
				state.LastSuccessfulAgentID = candidate.AgentID
				am.lastSuccessfulAgentMu.Lock()
				am.lastSuccessfulAgentID = candidate.AgentID
				am.lastSuccessfulAgentMu.Unlock()

				if isFallback {
					am.FailoverCount.Add(1)
					state.FailoverCount++
					log.Printf("[FAILOVER SUCCESS] [%s] Target %s:%d successfully connected via fallback agent [%s]!",
						effectiveUser, host, port, candidate.AgentID)
				}
				return candidate, stream, protocol.StatusSuccess
			}
			candidate.RecordFailure()
			if state.LastSuccessfulAgentID == candidate.AgentID {
				state.LastSuccessfulAgentID = ""
			}
			lastErrorStatus = stream.ConnectStatus
			log.Printf("[%s] [%s] Failed connecting to %s:%d: status=%d, err='%s'",
				effectiveUser, candidate.AgentID, host, port, stream.ConnectStatus, stream.ConnectError)

		case <-time.After(attemptTimeout):
			candidate.RecordFailure()
			if state.LastSuccessfulAgentID == candidate.AgentID {
				state.LastSuccessfulAgentID = ""
			}
			lastErrorStatus = protocol.StatusTimeout
			if isFallback {
				am.FailoverCount.Add(1)
				state.FailoverCount++
			}
			nextAction := "All candidates exhausted."
			if idx < numCandidates-1 {
				nextAction = "Switching to fallback node..."
			}
			log.Printf("[%s] [%s] Did not connect within %v to %s:%d. %s",
				effectiveUser, candidate.AgentID, attemptTimeout, host, port, nextAction)

		case <-ctx.Done():
			candidate.RemoveStream(streamID, true)
			return nil, nil, protocol.StatusGeneralFailure
		}

		candidate.RemoveStream(streamID, true)
	}

	return nil, nil, lastErrorStatus
}

// GetAgentStatusList returns list of connected agents with stats.
func (am *AgentManager) GetAgentStatusList() []AgentStatus {
	am.agentsMu.RLock()
	defer am.agentsMu.RUnlock()

	am.lastSuccessfulAgentMu.RLock()
	lastUsed := am.lastSuccessfulAgentID
	am.lastSuccessfulAgentMu.RUnlock()

	now := time.Now()
	res := make([]AgentStatus, 0, len(am.agents))
	for _, a := range am.agents {
		res = append(res, AgentStatus{
			AgentID:           a.AgentID,
			RemoteIP:          a.RemoteIP,
			UptimeSeconds:     int64(now.Sub(a.ConnectedAt).Seconds()),
			ActiveConnections: a.ActiveConns.Load(),
			TotalHandled:      a.TotalHandled.Load(),
			IsLastUsed:        (a.AgentID == lastUsed),
			IsFakeTLS:         a.IsFakeTLS,
			SNIDomain:         a.SNIDomain,
			ExitIP:            a.ExitIP,
		})
	}
	return res
}
