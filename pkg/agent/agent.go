package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"reverse-socks/pkg/protocol"
)

// ReverseAgent runs on executing nodes and establishes reverse tunnels to socks-control.
type ReverseAgent struct {
	ControlHost       string
	ControlPort       int
	SecretToken       string
	AgentID           string
	UseFakeTLS        bool
	FakeTLSDomain     string
	HTTPProxy         string
	ConnectHost       string
	ConnectTimeout    time.Duration
	KeepaliveInterval time.Duration
	ReconnectDelay    time.Duration
	ExitIP            string

	running       atomic.Bool
	stopChan      chan struct{}
	sendQueue     chan []byte
	tcpStreams    map[uint32]*TargetTCPStream
	udpStreams    map[uint32]*TargetUDPStream
	streamsMu     sync.RWMutex
	currentConn   net.Conn
	currentWriter io.Writer
	connMu        sync.Mutex
}

// NewReverseAgent creates a new ReverseAgent.
func NewReverseAgent(
	controlHost string,
	controlPort int,
	secretToken string,
	agentID string,
	useFakeTLS bool,
	fakeTLSDomain string,
	httpProxy string,
	connectHost string,
	connectTimeout time.Duration,
	keepaliveInterval time.Duration,
	reconnectDelay time.Duration,
) *ReverseAgent {
	if fakeTLSDomain == "" {
		fakeTLSDomain = "google.com"
	}
	if connectTimeout <= 0 {
		connectTimeout = 15 * time.Second
	}
	if keepaliveInterval <= 0 {
		keepaliveInterval = 25 * time.Second
	}
	if reconnectDelay <= 0 {
		reconnectDelay = 3 * time.Second
	}
	if agentID == "" {
		agentID = fmt.Sprintf("agent-%d", os.Getpid())
	}

	return &ReverseAgent{
		ControlHost:       controlHost,
		ControlPort:       controlPort,
		SecretToken:       secretToken,
		AgentID:           agentID,
		UseFakeTLS:        useFakeTLS,
		FakeTLSDomain:     fakeTLSDomain,
		HTTPProxy:         httpProxy,
		ConnectHost:       connectHost,
		ConnectTimeout:    connectTimeout,
		KeepaliveInterval: keepaliveInterval,
		ReconnectDelay:    reconnectDelay,
		stopChan:          make(chan struct{}),
		sendQueue:         make(chan []byte, 10000),
		tcpStreams:        make(map[uint32]*TargetTCPStream),
		udpStreams:        make(map[uint32]*TargetUDPStream),
	}
}

// Start runs the agent with automatic reconnection until Stop() is called.
func (a *ReverseAgent) Start(ctx context.Context) error {
	a.running.Store(true)

	for a.running.Load() {
		select {
		case <-ctx.Done():
			return nil
		case <-a.stopChan:
			return nil
		default:
		}

		err := a.runSession(ctx)
		if err != nil && a.running.Load() {
			log.Printf("[%s] Reverse session disconnected: %v. Reconnecting in %v...", a.AgentID, err, a.ReconnectDelay)
			select {
			case <-time.After(a.ReconnectDelay):
			case <-ctx.Done():
				return nil
			case <-a.stopChan:
				return nil
			}
		}
	}
	return nil
}

// Stop stops the agent gracefully.
func (a *ReverseAgent) Stop() {
	if a.running.CompareAndSwap(true, false) {
		close(a.stopChan)
		a.connMu.Lock()
		if a.currentConn != nil {
			_ = a.currentConn.Close()
		}
		a.connMu.Unlock()
	}
}

func (a *ReverseAgent) runSession(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", a.ControlHost, a.ControlPort)
	log.Printf("[%s] Connecting to control server at %s...", a.AgentID, addr)

	var conn net.Conn
	var err error

	if a.HTTPProxy != "" {
		conn, err = protocol.PerformHTTPConnectTunnel(a.HTTPProxy, a.ControlHost, a.ControlPort, a.ConnectHost, a.ConnectTimeout)
		if err != nil {
			return fmt.Errorf("HTTP proxy CONNECT tunnel failed: %w", err)
		}
	} else {
		dialer := net.Dialer{Timeout: a.ConnectTimeout}
		conn, err = dialer.DialContext(ctx, "tcp", addr)
		if err != nil {
			return fmt.Errorf("TCP dial failed: %w", err)
		}
	}
	defer conn.Close()

	protocol.EnableSocketKeepalive(conn)

	a.connMu.Lock()
	a.currentConn = conn
	a.connMu.Unlock()

	var reader io.Reader = conn
	var writer io.Writer = conn

	// Fake-TLS handshake if requested
	if a.UseFakeTLS {
		log.Printf("[%s] Performing Fake-TLS 1.3 handshake (SNI: '%s')...", a.AgentID, a.FakeTLSDomain)
		tlsR, tlsW, err := protocol.PerformTLSClientHandshake(conn, a.FakeTLSDomain, a.ConnectTimeout)
		if err != nil {
			return fmt.Errorf("Fake-TLS handshake error: %w", err)
		}
		reader = tlsR
		writer = tlsW
	}

	a.connMu.Lock()
	a.currentWriter = writer
	a.connMu.Unlock()

	// Send AUTH_REQ
	authData := map[string]string{
		"token":    a.SecretToken,
		"agent_id": a.AgentID,
		"exit_ip":  a.ExitIP,
	}
	authPkt, err := protocol.PackJSON(protocol.CmdAuthReq, 0, authData)
	if err != nil {
		return err
	}
	if _, err := writer.Write(authPkt); err != nil {
		return fmt.Errorf("failed sending AUTH_REQ: %w", err)
	}

	// Read AUTH_RESP
	respFrame, err := protocol.ReadFrame(reader)
	if err != nil {
		return fmt.Errorf("failed reading AUTH_RESP: %w", err)
	}
	if respFrame.Cmd != protocol.CmdAuthResp {
		return fmt.Errorf("expected AUTH_RESP, got cmd %d", respFrame.Cmd)
	}

	var authResp struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(respFrame.Payload, &authResp); err != nil {
		return fmt.Errorf("failed parsing AUTH_RESP: %w", err)
	}
	if authResp.Status != "ok" {
		return fmt.Errorf("control rejected authentication: %s", authResp.Message)
	}

	log.Printf("[+] [%s] Successfully authenticated with control server!", a.AgentID)

	sessionDone := make(chan struct{})
	defer close(sessionDone)

	// Writer loop
	go func() {
		for {
			select {
			case frame := <-a.sendQueue:
				if frame == nil {
					return
				}
				a.connMu.Lock()
				w := a.currentWriter
				a.connMu.Unlock()
				if w != nil {
					_, _ = w.Write(frame)
				}
			case <-sessionDone:
				return
			case <-a.stopChan:
				return
			}
		}
	}()

	// Keepalive ping loop
	go func() {
		ticker := time.NewTicker(a.KeepaliveInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				a.sendFrame(protocol.CmdPing, 0, nil)
			case <-sessionDone:
				return
			case <-a.stopChan:
				return
			}
		}
	}()

	// Reader loop
	for a.running.Load() {
		frame, err := protocol.ReadFrame(reader)
		if err != nil {
			return err
		}
		a.handleFrame(frame)
	}
	return nil
}

func (a *ReverseAgent) sendFrame(cmd byte, streamID uint32, payload []byte) {
	frame := protocol.PackFrame(cmd, streamID, payload)
	select {
	case a.sendQueue <- frame:
	case <-a.stopChan:
	}
}

func (a *ReverseAgent) handleFrame(frame *protocol.Frame) {
	switch frame.Cmd {
	case protocol.CmdConnectReq:
		var req struct {
			Host  string `json:"host"`
			Port  int    `json:"port"`
			Proto string `json:"proto"`
		}
		if err := json.Unmarshal(frame.Payload, &req); err != nil {
			a.sendConnectResp(frame.StreamID, protocol.StatusGeneralFailure, "invalid payload")
			return
		}
		go a.handleConnect(frame.StreamID, req.Host, req.Port, req.Proto)

	case protocol.CmdData:
		a.streamsMu.RLock()
		s, ok := a.tcpStreams[frame.StreamID]
		a.streamsMu.RUnlock()
		if ok {
			s.WriteData(frame.Payload)
		}

	case protocol.CmdUDPData:
		a.streamsMu.RLock()
		s, ok := a.udpStreams[frame.StreamID]
		a.streamsMu.RUnlock()
		if ok {
			s.SendDatagram(frame.Payload)
		}

	case protocol.CmdClose:
		a.closeStream(frame.StreamID, false)

	case protocol.CmdPing:
		a.sendFrame(protocol.CmdPong, 0, nil)

	case protocol.CmdPong:
		// Pong ok
	}
}

func (a *ReverseAgent) sendConnectResp(streamID uint32, status int, errMsg string) {
	resp := map[string]any{
		"status": status,
		"error":  errMsg,
	}
	data, _ := protocol.PackJSON(protocol.CmdConnectResp, streamID, resp)
	select {
	case a.sendQueue <- data:
	case <-a.stopChan:
	}
}

func (a *ReverseAgent) handleConnect(streamID uint32, host string, port int, protoName string) {
	if protoName == "udp" {
		udpStream, err := NewTargetUDPStream(streamID, a.sendFrame)
		if err != nil {
			a.sendConnectResp(streamID, protocol.StatusGeneralFailure, err.Error())
			return
		}
		a.streamsMu.Lock()
		a.udpStreams[streamID] = udpStream
		a.streamsMu.Unlock()
		a.sendConnectResp(streamID, protocol.StatusSuccess, "")
		return
	}

	// Default TCP dial
	targetAddr := fmt.Sprintf("%s:%d", host, port)
	dialer := net.Dialer{Timeout: a.ConnectTimeout}
	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		status := protocol.StatusGeneralFailure
		if errors.Is(err, context.DeadlineExceeded) {
			status = protocol.StatusTimeout
		} else if opErr, ok := err.(*net.OpError); ok {
			if opErr.Timeout() {
				status = protocol.StatusTimeout
			}
		}
		a.sendConnectResp(streamID, status, err.Error())
		return
	}

	protocol.EnableSocketKeepalive(conn)

	tcpStream := NewTargetTCPStream(streamID, host, port, conn, a.sendFrame)
	a.streamsMu.Lock()
	a.tcpStreams[streamID] = tcpStream
	a.streamsMu.Unlock()

	a.sendConnectResp(streamID, protocol.StatusSuccess, "")
}

func (a *ReverseAgent) closeStream(streamID uint32, notifyControl bool) {
	a.streamsMu.Lock()
	tcpStream, hasTCP := a.tcpStreams[streamID]
	if hasTCP {
		delete(a.tcpStreams, streamID)
	}
	udpStream, hasUDP := a.udpStreams[streamID]
	if hasUDP {
		delete(a.udpStreams, streamID)
	}
	a.streamsMu.Unlock()

	if hasTCP && tcpStream != nil {
		tcpStream.Close(notifyControl)
	}
	if hasUDP && udpStream != nil {
		udpStream.Close(notifyControl)
	}
}
