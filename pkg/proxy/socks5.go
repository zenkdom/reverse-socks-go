package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"reverse-socks/pkg/control"
	"reverse-socks/pkg/protocol"
	"reverse-socks/pkg/users"
)

const (
	socksVersion = 0x05

	authNoAuth       = 0x00
	authUserPass     = 0x02
	authNoAcceptable = 0xFF

	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess              = 0x00
	repGeneralFailure       = 0x01
	repConnectionNotAllowed = 0x02
	repNetworkUnreachable   = 0x03
	repHostUnreachable      = 0x04
	repConnectionRefused    = 0x05
	repTTLExpired           = 0x06
	repCmdNotSupported      = 0x07
	repAtypNotSupported     = 0x08
)

func mapStatusToReply(status int) byte {
	switch status {
	case protocol.StatusConnectionRefused:
		return repConnectionRefused
	case protocol.StatusNetworkUnreachable:
		return repNetworkUnreachable
	case protocol.StatusHostUnreachable:
		return repHostUnreachable
	case protocol.StatusTimeout:
		return repTTLExpired
	default:
		return repGeneralFailure
	}
}

func sendSocks5Reply(w io.Writer, repCode byte, bindAddr net.Addr) {
	bndIP := net.IPv4(127, 0, 0, 1).To4()
	bndPort := uint16(0)

	if bindAddr != nil {
		if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok {
			if ip4 := tcpAddr.IP.To4(); ip4 != nil {
				bndIP = ip4
			}
			bndPort = uint16(tcpAddr.Port)
		} else if udpAddr, ok := bindAddr.(*net.UDPAddr); ok {
			if ip4 := udpAddr.IP.To4(); ip4 != nil {
				bndIP = ip4
			}
			bndPort = uint16(udpAddr.Port)
		}
	}

	reply := make([]byte, 10)
	reply[0] = socksVersion
	reply[1] = repCode
	reply[2] = 0x00
	reply[3] = atypIPv4
	copy(reply[4:8], bndIP)
	binary.BigEndian.PutUint16(reply[8:10], bndPort)

	_, _ = w.Write(reply)
}

func authenticateSocks5(r io.Reader, w io.Writer, userManager *users.UserManager, clientIP string) (string, error) {
	var nmethodsBuf [1]byte
	if _, err := io.ReadFull(r, nmethodsBuf[:]); err != nil {
		return "", err
	}
	nmethods := int(nmethodsBuf[0])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(r, methods); err != nil {
		return "", err
	}

	hasUserPass := false
	for _, m := range methods {
		if m == authUserPass {
			hasUserPass = true
			break
		}
	}

	// Strictly reject unauthenticated connections
	if !hasUserPass {
		log.Printf("[%s] SOCKS5 rejected: unauthenticated requests not allowed (requires user/pass)", clientIP)
		_, _ = w.Write([]byte{socksVersion, authNoAcceptable})
		return "", errors.New("auth method not acceptable")
	}

	if _, err := w.Write([]byte{socksVersion, authUserPass}); err != nil {
		return "", err
	}

	// RFC 1929 Auth subnegotiation
	var authVerBuf [1]byte
	if _, err := io.ReadFull(r, authVerBuf[:]); err != nil {
		return "", err
	}
	if authVerBuf[0] != 0x01 {
		return "", errors.New("unsupported auth subnegotiation version")
	}

	var ulenBuf [1]byte
	if _, err := io.ReadFull(r, ulenBuf[:]); err != nil {
		return "", err
	}
	ulen := int(ulenBuf[0])
	unameBuf := make([]byte, ulen)
	if _, err := io.ReadFull(r, unameBuf); err != nil {
		return "", err
	}
	uname := string(unameBuf)

	var plenBuf [1]byte
	if _, err := io.ReadFull(r, plenBuf[:]); err != nil {
		return "", err
	}
	plen := int(plenBuf[0])
	passwdBuf := make([]byte, plen)
	if _, err := io.ReadFull(r, passwdBuf); err != nil {
		return "", err
	}
	passwd := string(passwdBuf)

	if userManager.Authenticate(uname, passwd) {
		_, _ = w.Write([]byte{0x01, 0x00}) // Auth success
		log.Printf("[AUTH OK] [%s] SOCKS5 authenticated as user '%s'", clientIP, uname)
		return uname, nil
	}

	_, _ = w.Write([]byte{0x01, 0x01}) // Auth failure
	log.Printf("[AUTH FAIL] [%s] SOCKS5 failed auth for user '%s'", clientIP, uname)
	return "", errors.New("authentication failed")
}

func parseSocks5Request(r io.Reader) (cmd byte, targetHost string, targetPort int, err error) {
	var hdr [4]byte // VER, CMD, RSV, ATYP
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, "", 0, err
	}

	if hdr[0] != socksVersion {
		return 0, "", 0, fmt.Errorf("invalid SOCKS version: %d", hdr[0])
	}

	cmd = hdr[1]
	atyp := hdr[3]

	switch atyp {
	case atypIPv4:
		var ipBuf [4]byte
		if _, err := io.ReadFull(r, ipBuf[:]); err != nil {
			return 0, "", 0, err
		}
		targetHost = net.IP(ipBuf[:]).String()

	case atypDomain:
		var dlenBuf [1]byte
		if _, err := io.ReadFull(r, dlenBuf[:]); err != nil {
			return 0, "", 0, err
		}
		dlen := int(dlenBuf[0])
		domBuf := make([]byte, dlen)
		if _, err := io.ReadFull(r, domBuf); err != nil {
			return 0, "", 0, err
		}
		targetHost = string(domBuf)

	case atypIPv6:
		var ip6Buf [16]byte
		if _, err := io.ReadFull(r, ip6Buf[:]); err != nil {
			return 0, "", 0, err
		}
		targetHost = net.IP(ip6Buf[:]).String()

	default:
		return 0, "", 0, fmt.Errorf("unsupported ATYP 0x%02x", atyp)
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return 0, "", 0, err
	}
	targetPort = int(binary.BigEndian.Uint16(portBuf[:]))

	return cmd, targetHost, targetPort, nil
}

func (s *UniversalProxyServer) handleSocks5(conn net.Conn, clientIP string) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	username, err := authenticateSocks5(conn, conn, s.userManager, clientIP)
	if err != nil {
		return
	}

	cmd, targetHost, targetPort, err := parseSocks5Request(conn)
	if err != nil {
		log.Printf("[%s] Error parsing SOCKS5 request: %v", clientIP, err)
		return
	}

	_ = conn.SetDeadline(time.Time{})
	userKey := fmt.Sprintf("socks:%s", username)

	switch cmd {
	case cmdConnect:
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		agent, stream, status := s.agentManager.EstablishStream(
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
			log.Printf("[%s] [%s] SOCKS5 CONNECT to %s:%d failed: status=%d", clientIP, userKey, targetHost, targetPort, status)
			sendSocks5Reply(conn, mapStatusToReply(status), conn.LocalAddr())
			return
		}

		log.Printf("[ROUTE TCP] [%s] [%s] -> Routing request to %s:%d via Reverse Agent [%s] (Stream #%d)",
			clientIP, userKey, targetHost, targetPort, agent.AgentID, stream.StreamID)

		sendSocks5Reply(conn, repSuccess, conn.LocalAddr())
		pipeClientAndAgent(conn, agent, stream, clientIP)

	case cmdUDPAssociate:
		s.handleUDPAssociate(conn, clientIP, username)

	case cmdBind:
		s.handleBind(conn, clientIP, username, targetHost, targetPort)

	default:
		log.Printf("[%s] Unsupported SOCKS5 command: 0x%02x", clientIP, cmd)
		sendSocks5Reply(conn, repCmdNotSupported, conn.LocalAddr())
	}
}

const idleStreamTimeout = 300 * time.Second

func pipeClientAndAgent(clientConn net.Conn, agent *control.AgentSession, stream *control.StreamContext, clientIP string) {
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

	// Client -> Agent
	go func() {
		defer func() {
			closeBoth()
			wg.Done()
		}()
		buf := protocol.GetBuffer()
		defer protocol.PutBuffer(buf)

		for !agent.Closed.Load() && !stream.Closed.Load() {
			_ = clientConn.SetReadDeadline(time.Now().Add(idleStreamTimeout))
			n, err := clientConn.Read(*buf)
			if n > 0 {
				bytesUp += int64(n)
				agent.SendFrame(protocol.CmdData, streamID, (*buf)[:n])
			}
			if err != nil {
				break
			}
		}
		agent.SendFrameNoWait(protocol.CmdClose, streamID, nil)
	}()

	// Agent -> Client
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
			bytesDown += int64(len(chunk))
			_ = clientConn.SetWriteDeadline(time.Now().Add(idleStreamTimeout))
			if _, err := clientConn.Write(chunk); err != nil {
				break
			}
		}
	}()

	log.Printf("[TUNNEL OPEN] Stream #%d active: %s <-> %s:%d", streamID, clientIP, stream.Host, stream.Port)
	wg.Wait()
	agent.RemoveStream(streamID, true)
	closeBoth()
	log.Printf("[TUNNEL CLOSED] Stream #%d (%s:%d) finished. Sent: %d bytes, Received: %d bytes",
		streamID, stream.Host, stream.Port, bytesUp, bytesDown)
}
