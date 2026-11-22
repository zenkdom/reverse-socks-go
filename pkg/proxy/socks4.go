package proxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

func (s *UniversalProxyServer) handleSocks4(conn net.Conn, clientIP string) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var cmdBuf [1]byte
	if _, err := io.ReadFull(conn, cmdBuf[:]); err != nil {
		return
	}
	cmd := cmdBuf[0]

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return
	}
	targetPort := int(binary.BigEndian.Uint16(portBuf[:]))

	var ipBuf [4]byte
	if _, err := io.ReadFull(conn, ipBuf[:]); err != nil {
		return
	}

	// Read USERID (null terminated)
	var useridBuf bytes.Buffer
	for useridBuf.Len() < 256 {
		var b [1]byte
		if _, err := io.ReadFull(conn, b[:]); err != nil {
			return
		}
		if b[0] == 0x00 {
			break
		}
		useridBuf.WriteByte(b[0])
	}
	userid := useridBuf.String()

	// Check SOCKS4a (0.0.0.x with x != 0)
	isSocks4a := ipBuf[0] == 0 && ipBuf[1] == 0 && ipBuf[2] == 0 && ipBuf[3] != 0
	targetHost := ""
	if isSocks4a {
		var domBuf bytes.Buffer
		for domBuf.Len() < 256 {
			var b [1]byte
			if _, err := io.ReadFull(conn, b[:]); err != nil {
				return
			}
			if b[0] == 0x00 {
				break
			}
			domBuf.WriteByte(b[0])
		}
		targetHost = domBuf.String()
	} else {
		targetHost = net.IP(ipBuf[:]).String()
	}

	// Auth check: if users are configured, enforce valid userid
	allUsers := s.userManager.GetAllUsers()
	if len(allUsers) > 0 && !s.userManager.HasUser(userid) {
		log.Printf("[%s] SOCKS4 auth failed: user '%s' not allowed", clientIP, userid)
		_, _ = conn.Write([]byte{0x00, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	if cmd != 0x01 { // Only CONNECT is supported
		log.Printf("[%s] Unsupported SOCKS4 command: 0x%02x", clientIP, cmd)
		_, _ = conn.Write([]byte{0x00, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	_ = conn.SetDeadline(time.Time{})
	userKey := "socks4:anon"
	if userid != "" {
		userKey = fmt.Sprintf("socks4:%s", userid)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agent, stream, _ := s.agentManager.EstablishStream(
		ctx,
		targetHost,
		targetPort,
		userKey,
		clientIP,
		s.fastTimeout,
		s.connectTimeout,
		"tcp",
	)

	if agent == nil || stream == nil {
		_, _ = conn.Write([]byte{0x00, 0x5b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}

	// Success response: 0x00, 0x5A, port(2), ip(4)
	rep := []byte{0x00, 0x5a, portBuf[0], portBuf[1], ipBuf[0], ipBuf[1], ipBuf[2], ipBuf[3]}
	if _, err := conn.Write(rep); err != nil {
		agent.RemoveStream(stream.StreamID, false)
		return
	}

	log.Printf("[SOCKS4 OK] [%s] [%s] Connected to %s:%d", clientIP, userKey, targetHost, targetPort)
	pipeClientAndAgent(conn, agent, stream, clientIP)
}
