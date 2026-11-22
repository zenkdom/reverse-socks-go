package proxy

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"reverse-socks/pkg/control"
	"reverse-socks/pkg/protocol"
	"reverse-socks/pkg/users"
)

// UniversalProxyServer serves SOCKS5, SOCKS4/4a, and HTTP/HTTPS CONNECT on a single port.
type UniversalProxyServer struct {
	agentManager   *control.AgentManager
	userManager    *users.UserManager
	host           string
	port           int
	fastTimeout    time.Duration
	connectTimeout time.Duration
	listener       net.Listener
	closed         atomic.Bool
	wg             sync.WaitGroup
}

// NewUniversalProxyServer creates a new UniversalProxyServer.
func NewUniversalProxyServer(
	am *control.AgentManager,
	um *users.UserManager,
	host string,
	port int,
	fastTimeout time.Duration,
	connectTimeout time.Duration,
) *UniversalProxyServer {
	if fastTimeout <= 0 {
		fastTimeout = 2 * time.Second
	}
	if connectTimeout <= 0 {
		connectTimeout = 15 * time.Second
	}
	return &UniversalProxyServer{
		agentManager:   am,
		userManager:    um,
		host:           host,
		port:           port,
		fastTimeout:    fastTimeout,
		connectTimeout: connectTimeout,
	}
}

// Start begins listening on proxy port.
func (s *UniversalProxyServer) Start() error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind universal proxy on %s: %w", addr, err)
	}
	s.listener = l
	log.Printf("[*] Universal Proxy Server listening on %s (SOCKS5 [TCP, UDP, BIND], SOCKS4/4a, HTTP/HTTPS CONNECT)", l.Addr())

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Addr returns the listener address.
func (s *UniversalProxyServer) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Port returns the listening TCP port.
func (s *UniversalProxyServer) Port() int {
	if s.listener != nil {
		if tcp, ok := s.listener.Addr().(*net.TCPAddr); ok {
			return tcp.Port
		}
	}
	return s.port
}

// Stop gracefully shuts down the proxy server.
func (s *UniversalProxyServer) Stop() {
	if s.closed.CompareAndSwap(false, true) {
		if s.listener != nil {
			_ = s.listener.Close()
		}
		log.Println("Universal Proxy Server stopped.")
	}
}

func (s *UniversalProxyServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			log.Printf("Universal Proxy accept error: %v", err)
			continue
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleClient(c)
		}(conn)
	}
}

func (s *UniversalProxyServer) handleClient(conn net.Conn) {
	defer conn.Close()
	protocol.EnableSocketKeepalive(conn)

	clientIP := conn.RemoteAddr().String()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	var firstByte [1]byte
	if _, err := io.ReadFull(conn, firstByte[:]); err != nil {
		return
	}

	switch firstByte[0] {
	case 0x05:
		// SOCKS5 (RFC 1928)
		s.handleSocks5(conn, clientIP)

	case 0x04:
		// SOCKS4 / SOCKS4a
		s.handleSocks4(conn, clientIP)

	case 'C', 'G', 'P', 'H', 'D', 'O', 'T':
		// HTTP / HTTPS CONNECT Proxy
		s.handleHTTPProxy(conn, clientIP, firstByte[0])

	default:
		log.Printf("[%s] Unsupported protocol prefix: 0x%02x", clientIP, firstByte[0])
	}
}
