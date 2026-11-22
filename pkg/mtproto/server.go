package mtproto

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"reverse-socks/pkg/control"
	"reverse-socks/pkg/protocol"
	"reverse-socks/pkg/users"
)

// MtprotoProxyServer runs MTProto Proxy on port 8443 (Dual-mode: Fake-TLS + Hex32).
type MtprotoProxyServer struct {
	agentManager   *control.AgentManager
	userManager    *users.MtprotoUserManager
	host           string
	port           int
	rawSecret      []byte
	domain         string
	fakeTLSSecret  string
	tag            *string
	maskHost       string
	maskPort       int
	fastTimeout    time.Duration
	connectTimeout time.Duration
	listener       net.Listener
	closed         atomic.Bool
	wg             sync.WaitGroup
}

// NewMtprotoProxyServer creates a new MtprotoProxyServer.
func NewMtprotoProxyServer(
	am *control.AgentManager,
	um *users.MtprotoUserManager,
	host string,
	port int,
	secret string,
	domain string,
	tag string,
	maskHost string,
	maskPort int,
	fastTimeout time.Duration,
	connectTimeout time.Duration,
) *MtprotoProxyServer {
	if domain == "" {
		domain = "google.com"
	}
	if maskHost == "" {
		maskHost = "google.com"
	}
	if maskPort <= 0 {
		maskPort = 443
	}
	if fastTimeout < 4*time.Second {
		fastTimeout = 4 * time.Second
	}
	if connectTimeout < 20*time.Second {
		connectTimeout = 20 * time.Second
	}

	rawHex, dom, fakeTLS := users.NormalizeHexSecret(secret, domain)
	rawBytes, _ := hex.DecodeString(rawHex)

	return &MtprotoProxyServer{
		agentManager:   am,
		userManager:    um,
		host:           host,
		port:           port,
		rawSecret:      rawBytes,
		domain:         dom,
		fakeTLSSecret:  fakeTLS,
		tag:            users.NormalizeTag(tag),
		maskHost:       maskHost,
		maskPort:       maskPort,
		fastTimeout:    fastTimeout,
		connectTimeout: connectTimeout,
	}
}

// FakeTLSSecret returns the generated Fake-TLS secret.
func (s *MtprotoProxyServer) FakeTLSSecret() string {
	return s.fakeTLSSecret
}

// Start starts the MTProto server.
func (s *MtprotoProxyServer) Start() error {
	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind MTProto proxy on %s: %w", addr, err)
	}
	s.listener = l
	log.Printf("[*] MTProto Proxy Server listening on %s (Dual-mode: Fake-TLS + Plain Hex32)", l.Addr())
	log.Printf("[*] Default MTProto Fake-TLS Secret: %s", s.fakeTLSSecret)
	log.Printf("[*] Default MTProto Raw Hex32 Secret: %s", hex.EncodeToString(s.rawSecret))

	s.wg.Add(1)
	go s.acceptLoop()
	return nil
}

// Addr returns the listener address.
func (s *MtprotoProxyServer) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// Port returns the listening TCP port.
func (s *MtprotoProxyServer) Port() int {
	if s.listener != nil {
		if tcp, ok := s.listener.Addr().(*net.TCPAddr); ok {
			return tcp.Port
		}
	}
	return s.port
}

// Stop gracefully shuts down the server.
func (s *MtprotoProxyServer) Stop() {
	if s.closed.CompareAndSwap(false, true) {
		if s.listener != nil {
			_ = s.listener.Close()
		}
		log.Println("MTProto Proxy Server stopped.")
	}
}

func (s *MtprotoProxyServer) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if s.closed.Load() {
				return
			}
			log.Printf("MTProto accept error: %v", err)
			continue
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleClient(c)
		}(conn)
	}
}

func (s *MtprotoProxyServer) handleClient(clientConn net.Conn) {
	defer clientConn.Close()
	protocol.EnableSocketKeepalive(clientConn)

	clientAddr := clientConn.RemoteAddr().String()
	ipOnly := clientAddr
	if idx := strings.LastIndex(clientAddr, ":"); idx != -1 {
		ipOnly = clientAddr[:idx]
	}

	log.Printf("[MTProto] Incoming connection from %s", clientAddr)

	secretsToCheck := make(map[string][]byte)
	if s.userManager != nil {
		secretsToCheck = s.userManager.GetSecretsMap()
	}
	if len(secretsToCheck) == 0 && len(s.rawSecret) > 0 {
		secretsToCheck["default"] = s.rawSecret
	}

	_ = clientConn.SetDeadline(time.Now().Add(10 * time.Second))
	var prefix [3]byte
	if _, err := io.ReadFull(clientConn, prefix[:]); err != nil {
		log.Printf("[%s] MTProto failed reading first 3 bytes: %v", clientAddr, err)
		return
	}

	isFakeTLS := false
	matchedUser := ""
	var matchedSecret []byte
	var protoTag []byte
	var dcNum int
	var clientDecryptor cipher.Stream
	var clientEncryptor cipher.Stream
	var streamReader io.Reader = clientConn
	var streamWriter io.Writer = clientConn

	// Case A: Fake-TLS 1.3 ClientHello (starts with 0x16 0x03 0x01)
	if prefix[0] == 0x16 && prefix[1] == 0x03 && prefix[2] == 0x01 {
		var lenBytes [2]byte
		if _, err := io.ReadFull(clientConn, lenBytes[:]); err != nil {
			log.Printf("[%s] Fake-TLS failed reading length: %v", clientAddr, err)
			HandleBadClient(clientConn, prefix[:], s.maskHost, s.maskPort, clientAddr)
			return
		}
		recLen := binary.BigEndian.Uint16(lenBytes[:])
		if recLen < 40 || recLen > 16384 {
			log.Printf("[%s] Fake-TLS invalid record length: %d", clientAddr, recLen)
			HandleBadClient(clientConn, append(prefix[:], lenBytes[:]...), s.maskHost, s.maskPort, clientAddr)
			return
		}

		body := make([]byte, recLen)
		if _, err := io.ReadFull(clientConn, body); err != nil {
			log.Printf("[%s] Fake-TLS failed reading body (%d bytes): %v", clientAddr, recLen, err)
			HandleBadClient(clientConn, append(append(prefix[:], lenBytes[:]...), body...), s.maskHost, s.maskPort, clientAddr)
			return
		}

		clientHello := append(append(prefix[:], lenBytes[:]...), body...)
		if len(clientHello) < 44 {
			log.Printf("[%s] Fake-TLS clientHello too short: %d", clientAddr, len(clientHello))
			HandleBadClient(clientConn, clientHello, s.maskHost, s.maskPort, clientAddr)
			return
		}

		digest := clientHello[11:43]
		msg := make([]byte, len(clientHello))
		copy(msg, clientHello)
		copy(msg[11:43], make([]byte, 32)) // zero out digest for verification

		for uname, secBytes := range secretsToCheck {
			mac := hmac.New(sha256.New, secBytes)
			mac.Write(msg)
			compDigest := mac.Sum(nil)

			xored := make([]byte, 32)
			for i := 0; i < 32; i++ {
				xored[i] = digest[i] ^ compDigest[i]
			}

			// First 28 bytes must be zeros, last 4 bytes timestamp (little-endian)
			if bytes.Equal(xored[:28], make([]byte, 28)) {
				matchedUser = uname
				matchedSecret = secBytes
				isFakeTLS = true
				break
			}
		}

		if !isFakeTLS {
			log.Printf("[%s] Invalid Fake-TLS secret HMAC. Digest: %x. Forwarding to mask host %s...", clientAddr, digest, s.maskHost)
			HandleBadClient(clientConn, clientHello, s.maskHost, s.maskPort, clientAddr)
			return
		}

		// Send Fake-TLS ServerHello response
		srvHelloPkt := BuildTLSServerHelloPacket(clientHello, digest, matchedSecret)
		if _, err := clientConn.Write(srvHelloPkt); err != nil {
			return
		}

		// Wrap in FakeTLS layers
		tlsR := protocol.NewFakeTLSReader(clientConn)
		tlsW := protocol.NewFakeTLSWriter(clientConn)
		streamReader = tlsR
		streamWriter = tlsW

		// Read Obfuscated2 64-byte handshake inside Fake-TLS
		var innerHandshake [HandshakeLen]byte
		if _, err := io.ReadFull(tlsR, innerHandshake[:]); err != nil {
			log.Printf("[%s] Invalid inner MTProto handshake read: %v", clientAddr, err)
			return
		}

		tag, dc, dec, enc, ok := DecryptObfuscated2(innerHandshake[:], matchedSecret)
		if !ok {
			log.Printf("[%s] Invalid inner MTProto handshake decrypt", clientAddr)
			return
		}
		protoTag = tag
		dcNum = dc
		clientDecryptor = dec
		clientEncryptor = enc

	} else {
		// Case B: Plain MTProto Obfuscated2 (connecting with 32-hex secret directly)
		var rest [HandshakeLen - 3]byte
		if _, err := io.ReadFull(clientConn, rest[:]); err != nil {
			log.Printf("[%s] Plain MTProto failed reading rest of handshake (%d bytes): %v", clientAddr, len(rest), err)
			HandleBadClient(clientConn, prefix[:], s.maskHost, s.maskPort, clientAddr)
			return
		}
		handshake := append(prefix[:], rest[:]...)

		for uname, secBytes := range secretsToCheck {
			tag, dc, dec, enc, ok := DecryptObfuscated2(handshake, secBytes)
			if ok {
				matchedUser = uname
				matchedSecret = secBytes
				protoTag = tag
				dcNum = dc
				clientDecryptor = dec
				clientEncryptor = enc
				isFakeTLS = false
				break
			}
		}

		if matchedSecret == nil {
			log.Printf("[%s] Invalid MTProto handshake / secret. Forwarding probe to mask host %s...", clientAddr, s.maskHost)
			HandleBadClient(clientConn, handshake, s.maskHost, s.maskPort, clientAddr)
			return
		}
	}

	authMode := "Plain Hex32 (Obfuscated2)"
	if isFakeTLS {
		authMode = "Fake-TLS"
	}

	targetDC := TGDatacentersV4[dcNum]
	if targetDC == "" {
		targetDC = TGDatacentersV4[DefaultDC]
	}
	targetPort := TGDatacenterPort

	clientTag := ""
	if s.userManager != nil {
		if t := s.userManager.GetTagForUser(matchedUser); t != nil {
			clientTag = *t
		}
	}
	if clientTag == "" && s.tag != nil {
		clientTag = *s.tag
	}

	tagInfo := "No Promo TAG"
	if clientTag != "" {
		tagInfo = fmt.Sprintf("Promo TAG: %s", clientTag)
	}

	log.Printf("[MTProto] Client %s authenticated as '%s' via %s [%s]! Target: Telegram DC %d (%s:%d)",
		clientAddr, matchedUser, authMode, tagInfo, dcNum, targetDC, targetPort)

	// Route to Telegram DC via reverse agent pool
	userKey := fmt.Sprintf("mtproto:%s:%s", matchedUser, ipOnly)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agent, stream, status := s.agentManager.EstablishStream(
		ctx,
		targetDC,
		targetPort,
		userKey,
		ipOnly,
		s.fastTimeout,
		s.connectTimeout,
		"tcp",
	)

	if agent == nil || stream == nil {
		log.Printf("[%s] [%s] No active socks-reverse agents to route Telegram DC connection (status=%d)!", clientAddr, userKey, status)
		return
	}

	streamID := stream.StreamID
	log.Printf("[MTProto ROUTE] [%s] [%s] -> Routing MTProto stream #%d (%s) to DC %s:%d via Reverse Agent [%s]",
		clientAddr, userKey, streamID, authMode, targetDC, targetPort, agent.AgentID)

	// Generate standard Obfuscated2 greeting for Telegram DC (NO secret)
	dcHandshake, dcDecryptor, dcEncryptor := GenerateDCHandshake(protoTag)
	agent.SendFrame(protocol.CmdData, streamID, dcHandshake)

	_ = clientConn.SetDeadline(time.Time{})

	// Bi-directional encrypted data tunneling
	s.tunnelTraffic(
		clientConn,
		streamReader,
		streamWriter,
		agent,
		stream,
		clientDecryptor,
		clientEncryptor,
		dcDecryptor,
		dcEncryptor,
		clientAddr,
	)
}

const idleMTProtoTimeout = 300 * time.Second

func (s *MtprotoProxyServer) tunnelTraffic(
	clientConn net.Conn,
	clientReader io.Reader,
	clientWriter io.Writer,
	agent *control.AgentSession,
	stream *control.StreamContext,
	clientDecryptor cipher.Stream,
	clientEncryptor cipher.Stream,
	dcDecryptor cipher.Stream,
	dcEncryptor cipher.Stream,
	clientIP string,
) {
	streamID := stream.StreamID
	var bytesUp, bytesDown int64
	var wg sync.WaitGroup
	wg.Add(2)

	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			stream.Close()
			_ = clientConn.Close()
		})
	}

	// Client -> Decrypt -> DC Encrypt -> Agent
	go func() {
		defer func() {
			closeBoth()
			wg.Done()
		}()
		buf := protocol.GetBuffer()
		defer protocol.PutBuffer(buf)

		plainBuf := protocol.GetBuffer()
		defer protocol.PutBuffer(plainBuf)

		for !agent.Closed.Load() && !stream.Closed.Load() {
			_ = clientConn.SetReadDeadline(time.Now().Add(idleMTProtoTimeout))
			n, err := clientReader.Read(*buf)
			if n > 0 {
				bytesUp += int64(n)
				clientDecryptor.XORKeyStream((*plainBuf)[:n], (*buf)[:n])
				toDC := make([]byte, n)
				dcEncryptor.XORKeyStream(toDC, (*plainBuf)[:n])
				agent.SendFrame(protocol.CmdData, streamID, toDC)
			}
			if err != nil {
				break
			}
		}
		agent.SendFrameNoWait(protocol.CmdClose, streamID, nil)
	}()

	// Agent -> DC Decrypt -> Client Encrypt -> Client
	go func() {
		defer func() {
			closeBoth()
			wg.Done()
		}()
		for {
			chunk, ok := <-stream.DataQueue
			if !ok || chunk == nil {
				break
			}
			n := len(chunk)
			bytesDown += int64(n)

			plain := make([]byte, n)
			dcDecryptor.XORKeyStream(plain, chunk)

			toClient := make([]byte, n)
			clientEncryptor.XORKeyStream(toClient, plain)

			_ = clientConn.SetWriteDeadline(time.Now().Add(idleMTProtoTimeout))
			if _, err := clientWriter.Write(toClient); err != nil {
				break
			}
		}
	}()

	log.Printf("[MTProto TUNNEL OPEN] Stream #%d active: %s <-> DC %s:%d", streamID, clientIP, stream.Host, stream.Port)
	wg.Wait()
	agent.RemoveStream(streamID, true)
	closeBoth()
	log.Printf("[MTProto TUNNEL CLOSED] Stream #%d finished. Client sent: %d bytes, Telegram DC returned: %d bytes",
		streamID, bytesUp, bytesDown)
}
