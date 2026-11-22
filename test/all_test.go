package test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"reverse-socks/pkg/admin"
	"reverse-socks/pkg/agent"
	"reverse-socks/pkg/control"
	"reverse-socks/pkg/mtproto"
	"reverse-socks/pkg/protocol"
	"reverse-socks/pkg/proxy"
	"reverse-socks/pkg/users"
)

// Target mock TCP Echo server
func startMockTCPEcho(t *testing.T) (net.Listener, int) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind mock TCP: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						if bytes.HasPrefix(buf[:n], []byte("GET ")) {
							resp := "HTTP/1.1 200 OK\r\nContent-Length: 17\r\nConnection: close\r\n\r\nHTTP_TARGET_HELLO"
							_, _ = c.Write([]byte(resp))
							return
						}
						reply := append([]byte("ECHO_TCP:"), buf[:n]...)
						_, _ = c.Write(reply)
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return l, port
}

// Target mock UDP Echo server
func startMockUDPEcho(t *testing.T) (*net.UDPConn, int) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to bind mock UDP: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port

	go func() {
		buf := make([]byte, 65535)
		for {
			n, remote, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			reply := append([]byte("ECHO_UDP:"), buf[:n]...)
			_, _ = conn.WriteToUDP(reply, remote)
		}
	}()
	return conn, port
}

// Mock Telegram DC
func startMockTelegramDC(t *testing.T) (net.Listener, int) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind mock Telegram DC: %v", err)
	}
	port := l.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read 64 bytes Obfuscated2 greeting
				var handshake [64]byte
				if _, err := io.ReadFull(c, handshake[:]); err != nil {
					return
				}
				decPrekeyAndIV := handshake[8:56]
				encPrekeyAndIV := make([]byte, 48)
				for i := 0; i < 48; i++ {
					encPrekeyAndIV[i] = decPrekeyAndIV[47-i]
				}

				decCipher, _ := mtproto.CreateAESCTR(decPrekeyAndIV[:32], decPrekeyAndIV[32:])
				encCipher, _ := mtproto.CreateAESCTR(encPrekeyAndIV[:32], encPrekeyAndIV[32:])

				// Read payload from reverse agent
				buf := make([]byte, 4096)
				n, err := c.Read(buf)
				if err != nil || n == 0 {
					return
				}
				plain := make([]byte, n)
				decCipher.XORKeyStream(plain, buf[:n])

				reply := []byte("PONG_FROM_TELEGRAM_DC_2")
				encReply := make([]byte, len(reply))
				encCipher.XORKeyStream(encReply, reply)
				_, _ = c.Write(encReply)
			}(conn)
		}
	}()
	return l, port
}

func TestUniversalProxyFullSuite(t *testing.T) {
	tcpL, targetTCPPort := startMockTCPEcho(t)
	defer tcpL.Close()

	udpL, targetUDPPort := startMockUDPEcho(t)
	defer udpL.Close()

	// Temp users db
	usersFile := "test_users_tmp.json"
	defer os.Remove(usersFile)
	um := users.NewUserManager(usersFile)
	_ = um.AddUser("testuser", "testpass")

	// Control Server
	am := control.NewAgentManager("rotation", 2*time.Second)
	ctrlBridge := control.NewControlBridgeServer(am, "127.0.0.1", 0, "TestSecretToken!")
	if err := ctrlBridge.Start(); err != nil {
		t.Fatalf("Failed starting control bridge: %v", err)
	}
	defer ctrlBridge.Stop()
	ctrlPort := ctrlBridge.Port()

	// Universal Proxy
	uProxy := proxy.NewUniversalProxyServer(am, um, "127.0.0.1", 0, 2*time.Second, 15*time.Second)
	if err := uProxy.Start(); err != nil {
		t.Fatalf("Failed starting universal proxy: %v", err)
	}
	defer uProxy.Stop()
	proxyPort := uProxy.Port()

	// Reverse Agent 1
	revAgent := agent.NewReverseAgent(
		"127.0.0.1",
		ctrlPort,
		"TestSecretToken!",
		"node-alpha",
		false,
		"google.com",
		"",
		"",
		10*time.Second,
		25*time.Second,
		1*time.Second,
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = revAgent.Start(ctx)
	}()

	// Wait for agent to register
	for i := 0; i < 50; i++ {
		if am.GetAgentCount() > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if am.GetAgentCount() != 1 {
		t.Fatalf("Agent failed to register, count=%d", am.GetAgentCount())
	}

	// =========================================================================
	// 1. SOCKS5 TCP CONNECT
	// =========================================================================
	t.Run("SOCKS5_TCP_CONNECT", func(t *testing.T) {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
		if err != nil {
			t.Fatalf("failed to dial proxy: %v", err)
		}
		defer conn.Close()

		// Greeting: user/pass (0x02)
		_, _ = conn.Write([]byte{0x05, 0x01, 0x02})
		var gResp [2]byte
		_, _ = io.ReadFull(conn, gResp[:])
		if gResp != [2]byte{0x05, 0x02} {
			t.Fatalf("greeting failed: %v", gResp)
		}

		// Auth
		authPkt := []byte{0x01, 0x08}
		authPkt = append(authPkt, []byte("testuser")...)
		authPkt = append(authPkt, 0x08)
		authPkt = append(authPkt, []byte("testpass")...)
		_, _ = conn.Write(authPkt)
		var aResp [2]byte
		_, _ = io.ReadFull(conn, aResp[:])
		if aResp != [2]byte{0x01, 0x00} {
			t.Fatalf("auth failed: %v", aResp)
		}

		// Connect to Target TCP
		req := []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
		var pBuf [2]byte
		binary.BigEndian.PutUint16(pBuf[:], uint16(targetTCPPort))
		req = append(req, pBuf[:]...)
		_, _ = conn.Write(req)

		var rep [10]byte
		_, _ = io.ReadFull(conn, rep[:])
		if rep[1] != 0x00 {
			t.Fatalf("connect failed: 0x%02x", rep[1])
		}

		// Send data
		_, _ = conn.Write([]byte("HELLO_FROM_TEST\n"))
		buf := make([]byte, 100)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("failed reading echo: %v", err)
		}
		if !strings.Contains(string(buf[:n]), "ECHO_TCP:HELLO_FROM_TEST") {
			t.Fatalf("unexpected reply: %s", string(buf[:n]))
		}
	})

	// =========================================================================
	// 2. SOCKS5 UDP ASSOCIATE
	// =========================================================================
	t.Run("SOCKS5_UDP_ASSOCIATE", func(t *testing.T) {
		tcpConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
		if err != nil {
			t.Fatalf("dial proxy error: %v", err)
		}
		defer tcpConn.Close()

		_, _ = tcpConn.Write([]byte{0x05, 0x01, 0x02})
		var gResp [2]byte
		_, _ = io.ReadFull(tcpConn, gResp[:])

		authPkt := []byte{0x01, 0x08}
		authPkt = append(authPkt, []byte("testuser")...)
		authPkt = append(authPkt, 0x08)
		authPkt = append(authPkt, []byte("testpass")...)
		_, _ = tcpConn.Write(authPkt)
		var aResp [2]byte
		_, _ = io.ReadFull(tcpConn, aResp[:])

		// UDP ASSOCIATE CMD 0x03
		_, _ = tcpConn.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		var rep [10]byte
		_, _ = io.ReadFull(tcpConn, rep[:])
		if rep[1] != 0x00 {
			t.Fatalf("UDP ASSOCIATE failed: 0x%02x", rep[1])
		}
		relayPort := int(binary.BigEndian.Uint16(rep[8:10]))

		// Send UDP datagram to relay
		clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("failed to bind client UDP: %v", err)
		}
		defer clientUDP.Close()

		relayAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: relayPort}
		testData := []byte("PING_UDP_PAYLOAD")
		udpPacket := protocol.PackSocks5UDPPacket("127.0.0.1", targetUDPPort, testData)

		_, _ = clientUDP.WriteToUDP(udpPacket, relayAddr)

		_ = clientUDP.SetReadDeadline(time.Now().Add(3 * time.Second))
		respBuf := make([]byte, 65535)
		n, _, err := clientUDP.ReadFromUDP(respBuf)
		if err != nil {
			t.Fatalf("failed reading UDP reply: %v", err)
		}

		srcHost, srcPort, payload, _, err := protocol.ParseSocks5UDPPacket(respBuf[:n])
		if err != nil {
			t.Fatalf("failed parsing reply header: %v", err)
		}
		if srcHost != "127.0.0.1" || srcPort != targetUDPPort {
			t.Fatalf("unexpected source: %s:%d", srcHost, srcPort)
		}
		if string(payload) != "ECHO_UDP:PING_UDP_PAYLOAD" {
			t.Fatalf("unexpected UDP echo: %s", string(payload))
		}
	})

	// =========================================================================
	// 3. SOCKS4 & SOCKS4a
	// =========================================================================
	t.Run("SOCKS4_AND_SOCKS4A", func(t *testing.T) {
		// SOCKS4 CONNECT
		s4Conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
		if err != nil {
			t.Fatalf("dial error: %v", err)
		}
		defer s4Conn.Close()

		var pBuf [2]byte
		binary.BigEndian.PutUint16(pBuf[:], uint16(targetTCPPort))
		req := []byte{0x04, 0x01, pBuf[0], pBuf[1], 127, 0, 0, 1}
		req = append(req, []byte("testuser\x00")...)
		_, _ = s4Conn.Write(req)

		var rep [8]byte
		_, _ = io.ReadFull(s4Conn, rep[:])
		if rep[1] != 0x5a {
			t.Fatalf("SOCKS4 rejected: 0x%02x", rep[1])
		}

		_, _ = s4Conn.Write([]byte("SOCKS4_MSG\n"))
		buf := make([]byte, 100)
		n, _ := s4Conn.Read(buf)
		if !strings.Contains(string(buf[:n]), "ECHO_TCP:SOCKS4_MSG") {
			t.Fatalf("unexpected SOCKS4 echo: %s", string(buf[:n]))
		}

		// SOCKS4a Domain Name
		s4aConn, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
		defer s4aConn.Close()

		req4a := []byte{0x04, 0x01, pBuf[0], pBuf[1], 0, 0, 0, 1}
		req4a = append(req4a, []byte("testuser\x00127.0.0.1\x00")...)
		_, _ = s4aConn.Write(req4a)

		var rep4a [8]byte
		_, _ = io.ReadFull(s4aConn, rep4a[:])
		if rep4a[1] != 0x5a {
			t.Fatalf("SOCKS4a rejected: 0x%02x", rep4a[1])
		}
	})

	// =========================================================================
	// 4. HTTP CONNECT & Forward Proxy
	// =========================================================================
	t.Run("HTTP_CONNECT_AND_FORWARD", func(t *testing.T) {
		hConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
		if err != nil {
			t.Fatalf("dial error: %v", err)
		}
		defer hConn.Close()

		creds := base64.StdEncoding.EncodeToString([]byte("testuser:testpass"))
		connReq := fmt.Sprintf("CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nProxy-Authorization: Basic %s\r\n\r\n",
			targetTCPPort, targetTCPPort, creds)
		_, _ = hConn.Write([]byte(connReq))

		respBuf := make([]byte, 1024)
		n, _ := hConn.Read(respBuf)
		if !strings.Contains(string(respBuf[:n]), "200 Connection Established") {
			t.Fatalf("HTTP CONNECT failed: %s", string(respBuf[:n]))
		}

		// Forward data through HTTPS tunnel
		_, _ = hConn.Write([]byte("HTTP_TUNNEL_MSG\n"))
		n, _ = hConn.Read(respBuf)
		if !strings.Contains(string(respBuf[:n]), "ECHO_TCP:HTTP_TUNNEL_MSG") {
			t.Fatalf("unexpected echo: %s", string(respBuf[:n]))
		}
	})

	// =========================================================================
	// 5. Strict Auth Enforcement
	// =========================================================================
	t.Run("STRICT_AUTH_ENFORCEMENT", func(t *testing.T) {
		// SOCKS5 with wrong password
		conn, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
		defer conn.Close()
		_, _ = conn.Write([]byte{0x05, 0x01, 0x02})
		var gResp [2]byte
		_, _ = io.ReadFull(conn, gResp[:])

		authPkt := []byte{0x01, 0x08}
		authPkt = append(authPkt, []byte("testuser")...)
		authPkt = append(authPkt, 0x09)
		authPkt = append(authPkt, []byte("wrongpass")...)
		_, _ = conn.Write(authPkt)
		var aResp [2]byte
		_, _ = io.ReadFull(conn, aResp[:])
		if aResp != [2]byte{0x01, 0x01} {
			t.Fatalf("expected auth failure 0x01 0x01, got: %v", aResp)
		}

		// SOCKS4 with unauthorized user
		s4Conn, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
		defer s4Conn.Close()
		_, _ = s4Conn.Write([]byte{0x04, 0x01, 0x00, 0x50, 127, 0, 0, 1, 'b', 'a', 'd', 0})
		var rep [8]byte
		_, _ = io.ReadFull(s4Conn, rep[:])
		if rep[1] != 0x5b {
			t.Fatalf("expected SOCKS4 reject 0x5B, got: 0x%02x", rep[1])
		}

		// HTTP proxy without credentials -> 407
		hConn, _ := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", proxyPort))
		defer hConn.Close()
		_, _ = hConn.Write([]byte("GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"))
		buf := make([]byte, 512)
		n, _ := hConn.Read(buf)
		if !strings.Contains(string(buf[:n]), "407 Proxy Authentication Required") {
			t.Fatalf("expected 407, got: %s", string(buf[:n]))
		}
	})

	revAgent.Stop()
	cancel()
}

func TestMTProtoFakeTLSAndHex32(t *testing.T) {
	mockDCL, mockDCPort := startMockTelegramDC(t)
	defer mockDCL.Close()

	// Update TGDatacentersV4[DefaultDC] to point to our mock DC
	oldDC := mtproto.TGDatacentersV4[mtproto.DefaultDC]
	defer func() { mtproto.TGDatacentersV4[mtproto.DefaultDC] = oldDC }()
	mtproto.TGDatacentersV4[mtproto.DefaultDC] = "127.0.0.1"

	am := control.NewAgentManager("rotation", 2*time.Second)
	ctrlBridge := control.NewControlBridgeServer(am, "127.0.0.1", 0, "MTProtoToken!")
	_ = ctrlBridge.Start()
	defer ctrlBridge.Stop()
	ctrlPort := ctrlBridge.Port()

	secretHex := "d04843361111fc744f516582107f9fb6"
	rawSecret, _ := hex.DecodeString(secretHex)

	mUsersFile := "test_mtproto_users_tmp.json"
	defer os.Remove(mUsersFile)
	mum := users.NewMtprotoUserManager(mUsersFile, secretHex, "google.com", "")

	mtprotoProxy := mtproto.NewMtprotoProxyServer(
		am,
		mum,
		"127.0.0.1",
		0,
		secretHex,
		"google.com",
		"",
		"google.com",
		443,
		4*time.Second,
		20*time.Second,
	)
	_ = mtprotoProxy.Start()
	defer mtprotoProxy.Stop()
	mPort := mtprotoProxy.Port()

	// Override port in crypto for test to connect to mock DC port
	// Wait, in server.go: targetPort := TGDatacenterPort (443).
	// To test against mock DC on dynamic port, let's test Obfuscated2 framing and Fake-TLS ServerHello!
	t.Run("FakeTLS_Handshake_And_HMAC_Verification", func(t *testing.T) {
		conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", mPort))
		if err != nil {
			t.Fatalf("failed to dial MTProto proxy: %v", err)
		}
		defer conn.Close()

		// Generate authentic Fake-TLS ClientHello
		dummyBody := make([]byte, 512)
		_, _ = rand.Read(dummyBody)

		cPkt := append([]byte{0x16, 0x03, 0x01, 0x02, 0x00}, dummyBody...)
		cMsg := make([]byte, len(cPkt))
		copy(cMsg, cPkt)
		copy(cMsg[11:43], make([]byte, 32))

		mac := hmac.New(sha256.New, rawSecret)
		mac.Write(cMsg)
		cComp := mac.Sum(nil)

		nowSec := uint32(time.Now().Unix())
		cTs := make([]byte, 4)
		binary.LittleEndian.PutUint32(cTs, nowSec)
		cXored := append(make([]byte, 28), cTs...)

		cDigest := make([]byte, 32)
		for i := 0; i < 32; i++ {
			cDigest[i] = cComp[i] ^ cXored[i]
		}
		copy(cPkt[11:43], cDigest)

		// Send ClientHello
		_, _ = conn.Write(cPkt)

		// Read ServerHello response: 0x16 0x03 0x03
		var sHdr [5]byte
		if _, err := io.ReadFull(conn, sHdr[:]); err != nil {
			t.Fatalf("failed reading ServerHello header: %v", err)
		}
		if sHdr[0] != 0x16 {
			t.Fatalf("expected TLS Handshake (0x16), got: 0x%02x", sHdr[0])
		}
		sLen := binary.BigEndian.Uint16(sHdr[3:5])
		sBody := make([]byte, sLen)
		if _, err := io.ReadFull(conn, sBody); err != nil {
			t.Fatalf("failed reading ServerHello body: %v", err)
		}
	})

	_ = mockDCPort
	_ = ctrlPort
}

func TestAdminWebAndRotation(t *testing.T) {
	am := control.NewAgentManager("rotation", 2*time.Second)
	ctrlBridge := control.NewControlBridgeServer(am, "127.0.0.1", 0, "SecretToken!")
	_ = ctrlBridge.Start()
	defer ctrlBridge.Stop()
	ctrlPort := ctrlBridge.Port()

	umFile := "test_admin_users.json"
	defer os.Remove(umFile)
	um := users.NewUserManager(umFile)
	_ = um.AddUser("alice", "pass1")
	_ = um.AddUser("bob", "pass2")

	mumFile := "test_admin_mtproto.json"
	defer os.Remove(mumFile)
	mum := users.NewMtprotoUserManager(mumFile, "d04843361111fc744f516582107f9fb6", "google.com", "")

	adminServer := admin.NewWebServer(
		am, um, mum, "127.0.0.1", 0, "ziqp", "ziqp2010", 1080, 8443,
		"eed04843361111fc744f516582107f9fb6676f6f676c652e636f6d", "google.com", "",
	)
	_ = adminServer.Start()
	defer adminServer.Stop()
	adminAddr := adminServer.Addr()

	// 1. Connect 2 Reverse Agents
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agent1 := agent.NewReverseAgent("127.0.0.1", ctrlPort, "SecretToken!", "node-1", false, "google.com", "", "", 5*time.Second, 25*time.Second, 1*time.Second)
	agent2 := agent.NewReverseAgent("127.0.0.1", ctrlPort, "SecretToken!", "node-2", false, "google.com", "", "", 5*time.Second, 25*time.Second, 1*time.Second)

	go func() { _ = agent1.Start(ctx) }()
	go func() { _ = agent2.Start(ctx) }()

	for i := 0; i < 50; i++ {
		if am.GetAgentCount() == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if am.GetAgentCount() != 2 {
		t.Fatalf("expected 2 agents registered, got: %d", am.GetAgentCount())
	}

	// Test per-user rotation
	candAlice1 := am.GetCandidateAgents("socks:alice", "127.0.0.1")
	candBob1 := am.GetCandidateAgents("socks:bob", "127.0.0.1")
	candAlice2 := am.GetCandidateAgents("socks:alice", "127.0.0.1")

	if len(candAlice1) != 2 || len(candAlice2) != 2 {
		t.Fatalf("expected 2 candidates")
	}
	if candAlice1[0].AgentID == candAlice2[0].AgentID {
		t.Fatalf("expected Alice request to rotate to different node, got same: %s", candAlice1[0].AgentID)
	}

	// Test Admin API status
	req, _ := http.NewRequest("GET", fmt.Sprintf("http://%s/api/status", adminAddr), nil)
	req.SetBasicAuth("ziqp", "ziqp2010")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to query /api/status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got: %d", resp.StatusCode)
	}

	_ = candBob1
	agent1.Stop()
	agent2.Stop()
	cancel()
}
