package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"reverse-socks/pkg/protocol"
)

func (s *UniversalProxyServer) handleUDPAssociate(
	clientConn net.Conn,
	clientIP string,
	username string,
) {
	userKey := "socks:" + username

	// 1. Bind local UDP socket for client relay
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		log.Printf("[%s] [%s] Failed to allocate UDP relay: %v", clientIP, userKey, err)
		sendSocks5Reply(clientConn, repGeneralFailure, clientConn.LocalAddr())
		return
	}
	defer udpConn.Close()

	bndPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	reportedIP := net.IPv4(127, 0, 0, 1).To4()
	if tcpLocal, ok := clientConn.LocalAddr().(*net.TCPAddr); ok {
		if ip4 := tcpLocal.IP.To4(); ip4 != nil && !ip4.IsUnspecified() {
			reportedIP = ip4
		}
	}

	// 2. Establish UDP stream via reverse agent
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	agent, stream, _ := s.agentManager.EstablishStream(
		ctx,
		"0.0.0.0",
		0,
		userKey,
		clientIP,
		s.fastTimeout,
		s.connectTimeout,
		"udp",
	)

	var directTargetConn *net.UDPConn
	if agent == nil || stream == nil {
		log.Printf("[%s] [%s] No reverse agents for UDP; activating local direct UDP relay", clientIP, userKey)
		directConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err == nil {
			directTargetConn = directConn
			defer directTargetConn.Close()
		}
	}

	// 3. Send SOCKS5 success reply with BND.ADDR & BND.PORT
	reply := make([]byte, 10)
	reply[0] = socksVersion
	reply[1] = repSuccess
	reply[2] = 0x00
	reply[3] = atypIPv4
	copy(reply[4:8], reportedIP)
	binary.BigEndian.PutUint16(reply[8:10], uint16(bndPort))

	if _, err := clientConn.Write(reply); err != nil {
		return
	}

	targetNode := "Direct Local Relay"
	if agent != nil {
		targetNode = "Reverse Agent [" + agent.AgentID + "]"
	}
	log.Printf("[UDP ASSOCIATE OK] [%s] [%s] Relay on %s:%d -> %s", clientIP, userKey, reportedIP, bndPort, targetNode)

	// 4. Bi-directional UDP relaying
	var clientEndpoint atomic.Pointer[net.UDPAddr]
	var stopFlag atomic.Bool

	// Routine A: Receive UDP datagrams from Client, forward to Agent or Target
	go func() {
		buf := protocol.GetBuffer()
		defer protocol.PutBuffer(buf)

		for !stopFlag.Load() {
			n, clientAddr, err := udpConn.ReadFromUDP(*buf)
			if err != nil {
				break
			}
			clientEndpoint.Store(clientAddr)
			payload := make([]byte, n)
			copy(payload, (*buf)[:n])

			if agent != nil && stream != nil {
				agent.SendFrameNoWait(protocol.CmdUDPData, stream.StreamID, payload)
			} else if directTargetConn != nil {
				// Parse header and forward to direct target
				targetHost, targetPort, data, atyp, err := protocol.ParseSocks5UDPPacket(payload)
				if err == nil && targetPort > 0 {
					var dstAddr *net.UDPAddr
					if atyp == atypDomain {
						dstAddr, _ = net.ResolveUDPAddr("udp", net.JoinHostPort(targetHost, strconv.Itoa(targetPort)))
					} else {
						dstAddr = &net.UDPAddr{IP: net.ParseIP(targetHost), Port: targetPort}
					}
					if dstAddr != nil {
						_, _ = directTargetConn.WriteToUDP(data, dstAddr)
					}
				}
			}
		}
	}()

	// Routine B: Receive UDP datagrams from Agent, send back to Client
	if agent != nil && stream != nil {
		go func() {
			for !stopFlag.Load() {
				pkt, ok := <-stream.UDPQueue
				if !ok || pkt == nil {
					break
				}
				cAddr := clientEndpoint.Load()
				if cAddr != nil {
					_, _ = udpConn.WriteToUDP(pkt, cAddr)
				}
			}
		}()
	} else if directTargetConn != nil {
		// Routine B-direct: Receive from direct targets, wrap in SOCKS5 header, send back to Client
		go func() {
			buf := protocol.GetBuffer()
			defer protocol.PutBuffer(buf)

			for !stopFlag.Load() {
				n, targetAddr, err := directTargetConn.ReadFromUDP(*buf)
				if err != nil {
					break
				}
				cAddr := clientEndpoint.Load()
				if cAddr != nil {
					pkt := protocol.PackSocks5UDPPacket(targetAddr.IP.String(), targetAddr.Port, (*buf)[:n])
					_, _ = udpConn.WriteToUDP(pkt, cAddr)
				}
			}
		}()
	}

	// 5. Monitor TCP connection: when TCP closes, UDP terminates
	discardBuf := make([]byte, 1024)
	for {
		_, err := clientConn.Read(discardBuf)
		if err != nil {
			break
		}
	}

	stopFlag.Store(true)
	if agent != nil && stream != nil {
		agent.SendFrameNoWait(protocol.CmdClose, stream.StreamID, nil)
		agent.RemoveStream(stream.StreamID, false)
	}
	log.Printf("[UDP CLOSED] [%s] [%s] UDP association terminated.", clientIP, userKey)
}

func (s *UniversalProxyServer) handleBind(
	clientConn net.Conn,
	clientIP string,
	username string,
	targetHost string,
	targetPort int,
) {
	userKey := "socks:" + username

	bindListener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		log.Printf("[%s] [%s] SOCKS5 BIND failed to bind listener: %v", clientIP, userKey, err)
		sendSocks5Reply(clientConn, repGeneralFailure, clientConn.LocalAddr())
		return
	}
	defer bindListener.Close()

	bndPort := bindListener.Addr().(*net.TCPAddr).Port
	bndIP := net.IPv4(127, 0, 0, 1).To4()
	if tcpLocal, ok := clientConn.LocalAddr().(*net.TCPAddr); ok {
		if ip4 := tcpLocal.IP.To4(); ip4 != nil && !ip4.IsUnspecified() {
			bndIP = ip4
		}
	}

	// First reply: inform client of bound listener port
	sendSocks5Reply(clientConn, repSuccess, &net.TCPAddr{IP: bndIP, Port: bndPort})
	log.Printf("[BIND] [%s] [%s] Listening on %s:%d for incoming peer", clientIP, userKey, bndIP, bndPort)

	// Wait for incoming connection with 30-second timeout
	type acceptResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan acceptResult, 1)

	go func() {
		peerConn, err := bindListener.Accept()
		ch <- acceptResult{conn: peerConn, err: err}
	}()

	select {
	case res := <-ch:
		if res.err != nil {
			log.Printf("[BIND ERROR] [%s]: %v", clientIP, res.err)
			sendSocks5Reply(clientConn, repGeneralFailure, clientConn.LocalAddr())
			return
		}
		peerConn := res.conn
		defer peerConn.Close()

		peerAddr := peerConn.RemoteAddr()
		sendSocks5Reply(clientConn, repSuccess, peerAddr)
		log.Printf("[BIND CONNECTED] [%s] Incoming peer connected from %s", clientIP, peerAddr)

		// Pipe client <-> incoming peer
		var wg sync.WaitGroup
		wg.Add(2)

		pipe := func(dst, src net.Conn) {
			defer wg.Done()
			buf := protocol.GetBuffer()
			defer protocol.PutBuffer(buf)
			_, _ = io.CopyBuffer(dst, src, *buf)
		}

		go pipe(clientConn, peerConn)
		go pipe(peerConn, clientConn)
		wg.Wait()

	case <-time.After(30 * time.Second):
		log.Printf("[BIND TIMEOUT] [%s] Timed out waiting for incoming connection", clientIP)
		sendSocks5Reply(clientConn, repTTLExpired, clientConn.LocalAddr())
	}
}
