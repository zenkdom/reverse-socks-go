package tor

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"reverse-socks/pkg/agent"
	"reverse-socks/pkg/protocol"
)

// TorReverseAgent connects to socks-control and routes outbound target connections via Tor SOCKS5.
type TorReverseAgent struct {
	ControlHost       string
	ControlPort       int
	SecretToken       string
	AgentID           string
	TorHost           string
	TorPort           int
	ConnectTimeout    time.Duration
	KeepaliveInterval time.Duration
	ReconnectDelay    time.Duration

	circuitID   int
	circuitSeed int
	torUsername string
	ExitIP      string
	IsConnected atomic.Bool

	running       atomic.Bool
	stopChan      chan struct{}
	sendQueue     chan []byte
	tcpStreams    map[uint32]*agent.TargetTCPStream
	streamsMu     sync.RWMutex
	currentConn   net.Conn
	currentWriter io.Writer
	connMu        sync.Mutex
}

// NewTorReverseAgent creates a new TorReverseAgent.
func NewTorReverseAgent(
	controlHost string,
	controlPort int,
	secretToken string,
	agentID string,
	torHost string,
	torPort int,
	connectTimeout time.Duration,
	keepaliveInterval time.Duration,
	reconnectDelay time.Duration,
) *TorReverseAgent {
	if torHost == "" {
		torHost = "127.0.0.1"
	}
	if torPort <= 0 {
		torPort = 9050
	}
	if connectTimeout <= 0 {
		connectTimeout = 20 * time.Second
	}
	if keepaliveInterval <= 0 {
		keepaliveInterval = 25 * time.Second
	}
	if reconnectDelay <= 0 {
		reconnectDelay = 3 * time.Second
	}

	seed := 1000 + rand.Intn(9000)
	torUser := fmt.Sprintf("%s_%d_1", agentID, seed)

	return &TorReverseAgent{
		ControlHost:       controlHost,
		ControlPort:       controlPort,
		SecretToken:       secretToken,
		AgentID:           agentID,
		TorHost:           torHost,
		TorPort:           torPort,
		ConnectTimeout:    connectTimeout,
		KeepaliveInterval: keepaliveInterval,
		ReconnectDelay:    reconnectDelay,
		circuitID:         1,
		circuitSeed:       seed,
		torUsername:       torUser,
		stopChan:          make(chan struct{}),
		sendQueue:         make(chan []byte, 10000),
		tcpStreams:        make(map[uint32]*agent.TargetTCPStream),
	}
}

// NextCircuit increments isolation credentials for Tor IsolateSOCKSAuth.
func (a *TorReverseAgent) NextCircuit() {
	a.circuitID++
	a.torUsername = fmt.Sprintf("%s_%d_%d", a.AgentID, a.circuitSeed, a.circuitID)
}

// DialViaTor dials targetHost:targetPort via Tor SOCKS5 using IsolateSOCKSAuth.
func (a *TorReverseAgent) DialViaTor(targetHost string, targetPort int) (net.Conn, error) {
	torAddr := fmt.Sprintf("%s:%d", a.TorHost, a.TorPort)
	dialer := net.Dialer{Timeout: a.ConnectTimeout}
	conn, err := dialer.Dial("tcp", torAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial Tor SOCKS5 %s: %w", torAddr, err)
	}

	_ = conn.SetDeadline(time.Now().Add(a.ConnectTimeout))

	// 1. Greeting: RFC 1928, offer Username/Password (0x02)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		conn.Close()
		return nil, err
	}
	var greetingResp [2]byte
	if _, err := io.ReadFull(conn, greetingResp[:]); err != nil || greetingResp[0] != 0x05 || greetingResp[1] != 0x02 {
		conn.Close()
		return nil, errors.New("Tor SOCKS5 auth negotiation failed")
	}

	// 2. Auth: RFC 1929 with IsolateSOCKSAuth username
	uBytes := []byte(a.torUsername)
	pBytes := []byte("torpass")
	authPkt := []byte{0x01, byte(len(uBytes))}
	authPkt = append(authPkt, uBytes...)
	authPkt = append(authPkt, byte(len(pBytes)))
	authPkt = append(authPkt, pBytes...)

	if _, err := conn.Write(authPkt); err != nil {
		conn.Close()
		return nil, err
	}
	var authResp [2]byte
	if _, err := io.ReadFull(conn, authResp[:]); err != nil || authResp[1] != 0x00 {
		conn.Close()
		return nil, errors.New("Tor SOCKS5 authentication rejected")
	}

	// 3. Connect request: ATYP Domain (0x03)
	dBytes := []byte(targetHost)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(dBytes))}
	req = append(req, dBytes...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], uint16(targetPort))
	req = append(req, portBuf[:]...)

	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, err
	}

	// Read reply
	var repHdr [4]byte
	if _, err := io.ReadFull(conn, repHdr[:]); err != nil || repHdr[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("Tor SOCKS5 CONNECT failed with rep code %d", repHdr[1])
	}
	// Consume bound address
	switch repHdr[3] {
	case 0x01: // IPv4
		var b [6]byte
		_, _ = io.ReadFull(conn, b[:])
	case 0x03: // Domain
		var l [1]byte
		_, _ = io.ReadFull(conn, l[:])
		b := make([]byte, int(l[0])+2)
		_, _ = io.ReadFull(conn, b)
	case 0x04: // IPv6
		var b [18]byte
		_, _ = io.ReadFull(conn, b[:])
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// FetchExitIP queries IP discovery service through Tor to check exit IP.
func (a *TorReverseAgent) FetchExitIP() (string, error) {
	conn, err := a.DialViaTor("api.ipify.org", 80)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: curl/7.88.1\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return "", err
	}

	br := bufio.NewReader(conn)
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	body, err := io.ReadAll(br)
	if err != nil {
		return "", err
	}
	ip := strings.TrimSpace(string(body))
	if net.ParseIP(ip) == nil {
		return "", fmt.Errorf("invalid IP returned: %s", ip)
	}
	return ip, nil
}

// Run runs the Tor reverse agent.
func (a *TorReverseAgent) Run(ctx context.Context) error {
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
			a.IsConnected.Store(false)
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

func (a *TorReverseAgent) runSession(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", a.ControlHost, a.ControlPort)
	dialer := net.Dialer{Timeout: a.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	protocol.EnableSocketKeepalive(conn)

	a.connMu.Lock()
	a.currentConn = conn
	a.currentWriter = conn
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
	if _, err := conn.Write(authPkt); err != nil {
		return err
	}

	respFrame, err := protocol.ReadFrame(conn)
	if err != nil {
		return err
	}
	if respFrame.Cmd != protocol.CmdAuthResp {
		return fmt.Errorf("expected AUTH_RESP, got cmd %d", respFrame.Cmd)
	}

	a.IsConnected.Store(true)
	log.Printf("[+] [%s] Tor Reverse Agent connected to %s (Exit IP: %s)", a.AgentID, addr, a.ExitIP)

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

	// Keepalive loop
	go func() {
		ticker := time.NewTicker(a.KeepaliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				frame := protocol.PackFrame(protocol.CmdPing, 0, nil)
				select {
				case a.sendQueue <- frame:
				default:
				}
			case <-sessionDone:
				return
			case <-a.stopChan:
				return
			}
		}
	}()

	// Reader loop
	for a.running.Load() {
		frame, err := protocol.ReadFrame(conn)
		if err != nil {
			return err
		}
		a.handleFrame(frame)
	}
	return nil
}

func (a *TorReverseAgent) handleFrame(frame *protocol.Frame) {
	switch frame.Cmd {
	case protocol.CmdConnectReq:
		var req struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if err := json.Unmarshal(frame.Payload, &req); err != nil {
			a.sendConnectResp(frame.StreamID, protocol.StatusGeneralFailure, "invalid payload")
			return
		}
		go a.handleConnect(frame.StreamID, req.Host, req.Port)

	case protocol.CmdData:
		a.streamsMu.RLock()
		s, ok := a.tcpStreams[frame.StreamID]
		a.streamsMu.RUnlock()
		if ok {
			s.WriteData(frame.Payload)
		}

	case protocol.CmdClose:
		a.streamsMu.Lock()
		s, ok := a.tcpStreams[frame.StreamID]
		if ok {
			delete(a.tcpStreams, frame.StreamID)
		}
		a.streamsMu.Unlock()
		if ok && s != nil {
			s.Close(false)
		}

	case protocol.CmdPing:
		frame := protocol.PackFrame(protocol.CmdPong, 0, nil)
		select {
		case a.sendQueue <- frame:
		default:
		}
	}
}

func (a *TorReverseAgent) sendConnectResp(streamID uint32, status int, errMsg string) {
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

func (a *TorReverseAgent) handleConnect(streamID uint32, host string, port int) {
	conn, err := a.DialViaTor(host, port)
	if err != nil {
		a.sendConnectResp(streamID, protocol.StatusHostUnreachable, err.Error())
		return
	}

	sendFunc := func(cmd byte, sID uint32, payload []byte) {
		frame := protocol.PackFrame(cmd, sID, payload)
		select {
		case a.sendQueue <- frame:
		case <-a.stopChan:
		}
	}

	tcpStream := agent.NewTargetTCPStream(streamID, host, port, conn, sendFunc)
	a.streamsMu.Lock()
	a.tcpStreams[streamID] = tcpStream
	a.streamsMu.Unlock()

	a.sendConnectResp(streamID, protocol.StatusSuccess, "")
}

// Stop stops the agent.
func (a *TorReverseAgent) Stop() {
	if a.running.CompareAndSwap(true, false) {
		close(a.stopChan)
		a.connMu.Lock()
		if a.currentConn != nil {
			_ = a.currentConn.Close()
		}
		a.connMu.Unlock()
	}
}
