package control

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"reverse-socks/pkg/protocol"
)

// ControlBridgeServer manages the control channel where socks-reverse agents connect.
type ControlBridgeServer struct {
	agentManager *AgentManager
	host         string
	port         int
	secretToken  string
	listener     net.Listener
	closed       atomic.Bool
	stopReaper   chan struct{}
	wg           sync.WaitGroup
}

// NewControlBridgeServer creates a new ControlBridgeServer.
func NewControlBridgeServer(am *AgentManager, host string, port int, secretToken string) *ControlBridgeServer {
	return &ControlBridgeServer{
		agentManager: am,
		host:         host,
		port:         port,
		secretToken:  secretToken,
		stopReaper:   make(chan struct{}),
	}
}

// Start starts listening for reverse agents and launches the heartbeat watchdog.
func (s *ControlBridgeServer) Start() error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind control bridge on %s: %w", addr, err)
	}
	s.listener = l
	log.Printf("[*] Control Bridge Server listening on %s (Agents connect here)", l.Addr())

	s.wg.Add(1)
	go s.acceptLoop()

	s.wg.Add(1)
	go s.reaperLoop()

	return nil
}

// Addr returns the listener address.
func (s *ControlBridgeServer) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Port returns the listening TCP port.
func (s *ControlBridgeServer) Port() int {
	if s.listener != nil {
		if tcp, ok := s.listener.Addr().(*net.TCPAddr); ok {
			return tcp.Port
		}
	}
	return s.port
}

// Stop gracefully stops the server and reaper.
func (s *ControlBridgeServer) Stop() {
	if s.closed.CompareAndSwap(false, true) {
		close(s.stopReaper)
		if s.listener != nil {
			_ = s.listener.Close()
		}
		s.agentManager.CloseAll()
		log.Println("Control Bridge Server stopped.")
	}
}

func (s *ControlBridgeServer) reaperLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			s.agentManager.ReapStaleAgents(60 * time.Second)
		case <-s.stopReaper:
			return
		}
	}
}

func (s *ControlBridgeServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			log.Printf("Control Bridge accept error: %v", err)
			continue
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleAgent(c)
		}(conn)
	}
}

func (s *ControlBridgeServer) handleAgent(conn net.Conn) {
	defer conn.Close()

	protocol.EnableSocketKeepalive(conn)
	remoteIP := conn.RemoteAddr().String()
	log.Printf("Incoming connection from potential reverse agent at %s", remoteIP)

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var prefix [4]byte
	if _, err := io.ReadFull(conn, prefix[:]); err != nil {
		log.Printf("[%s] Failed reading initial transport bytes: %v", remoteIP, err)
		return
	}

	var reader io.Reader = conn
	var writer io.Writer = conn
	isFakeTLS := false
	sniDomain := ""

	// Case A: HTTP CONNECT request (forwarded proxy tunnel)
	if bytes.HasPrefix(prefix[:], []byte("CONN")) {
		br := bufio.NewReader(io.MultiReader(bytes.NewReader(prefix[:]), conn))
		for {
			line, err := br.ReadString('\n')
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}
		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			return
		}
		log.Printf("[%s] Accepted HTTP CONNECT tunnel, awaiting transport handshake...", remoteIP)

		if _, err := io.ReadFull(conn, prefix[:]); err != nil {
			return
		}
		reader = conn
	}

	var firstFrame *protocol.Frame

	// Case B: Fake-TLS 1.3 Handshake (disguised as HTTPS with whitelisted SNI)
	if prefix[0] == 0x16 && prefix[1] == 0x03 {
		tlsR, tlsW, sni, err := protocol.PerformTLSServerHandshake(conn, prefix[:], 10*time.Second)
		if err != nil {
			log.Printf("[%s] Fake-TLS server handshake failed: %v", remoteIP, err)
			return
		}
		reader = tlsR
		writer = tlsW
		isFakeTLS = true
		sniDomain = sni
		log.Printf("[%s] Upgraded agent transport to Fake-TLS (SNI: '%s')", remoteIP, sniDomain)

		frame, err := protocol.ReadFrame(reader)
		if err != nil {
			log.Printf("[%s] Failed reading first frame over Fake-TLS: %v", remoteIP, err)
			return
		}
		firstFrame = frame

	} else if bytes.Equal(prefix[:], protocol.Magic) {
		// Case C: Plain RSX5 protocol frame
		var hdrRest [protocol.HeaderSize - 4]byte
		if _, err := io.ReadFull(conn, hdrRest[:]); err != nil {
			return
		}
		cmd := hdrRest[0]
		streamID := binary.BigEndian.Uint32(hdrRest[1:5])
		length := binary.BigEndian.Uint32(hdrRest[5:9])

		var payload []byte
		if length > 0 {
			payload = make([]byte, length)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
		}
		firstFrame = &protocol.Frame{
			Cmd:      cmd,
			StreamID: streamID,
			Payload:  payload,
		}
		log.Printf("[%s] Connected agent using Plain TCP transport", remoteIP)

	} else {
		log.Printf("[%s] Unknown protocol prefix: %x, closing connection", remoteIP, prefix)
		return
	}

	if firstFrame == nil || firstFrame.Cmd != protocol.CmdAuthReq {
		log.Printf("[%s] Expected AUTH_REQ, got cmd: %v", remoteIP, firstFrame)
		return
	}

	var authData struct {
		Token   string `json:"token"`
		AgentID string `json:"agent_id"`
		ExitIP  string `json:"exit_ip"`
	}
	if err := json.Unmarshal(firstFrame.Payload, &authData); err != nil {
		log.Printf("[%s] Failed parsing auth payload: %v", remoteIP, err)
		return
	}

	agentID := authData.AgentID
	if agentID == "" {
		agentID = fmt.Sprintf("agent-%s", remoteIP)
	}

	// Verify token with constant-time comparison to prevent timing attacks
	if s.secretToken != "" {
		if subtle.ConstantTimeCompare([]byte(authData.Token), []byte(s.secretToken)) != 1 {
			log.Printf("[%s] Authentication failed for agent '%s': Invalid token", remoteIP, agentID)
			resp, _ := protocol.PackJSON(protocol.CmdAuthResp, 0, map[string]string{
				"status":  "error",
				"message": "Invalid authentication token",
			})
			_, _ = writer.Write(resp)
			return
		}
	}

	// Check agent_id collisions
	s.agentManager.agentsMu.RLock()
	_, exists := s.agentManager.agents[agentID]
	s.agentManager.agentsMu.RUnlock()
	if exists {
		agentID = fmt.Sprintf("%s-%d", agentID, time.Now().UnixNano()%10000)
	}

	// Send auth success
	resp, _ := protocol.PackJSON(protocol.CmdAuthResp, 0, map[string]string{
		"status":  "ok",
		"message": "Authenticated",
	})
	if _, err := writer.Write(resp); err != nil {
		return
	}

	// Clear connection deadline for active session
	_ = conn.SetDeadline(time.Time{})

	session := NewAgentSession(
		agentID,
		conn,
		reader,
		writer,
		remoteIP,
		isFakeTLS,
		sniDomain,
		authData.ExitIP,
	)
	s.agentManager.Register(session)
	defer func() {
		s.agentManager.Unregister(session.AgentID)
		session.Close()
	}()

	// Read frame loop
	for !session.Closed.Load() && !s.closed.Load() {
		frame, err := protocol.ReadFrame(reader)
		if err != nil {
			break
		}
		session.HandleIncomingFrame(frame.Cmd, frame.StreamID, frame.Payload)
	}
}
