package mtproto

import (
	"fmt"
	"log"
	"net"
	"time"

	"reverse-socks/pkg/protocol"
)

// HandleBadClient handles active censorship probes (e.g. from Russian TSPU / DPI scanners).
// Forwards the probe to maskHost:maskPort (e.g. google.com:443) so the scanner sees
// a valid TLS certificate from Google!
func HandleBadClient(clientConn net.Conn, initialBytes []byte, maskHost string, maskPort int, clientIP string) {
	if maskHost == "" {
		maskHost = "google.com"
	}
	if maskPort <= 0 {
		maskPort = 443
	}

	targetAddr := fmt.Sprintf("%s:%d", maskHost, maskPort)
	dialer := net.Dialer{Timeout: 5 * time.Second}
	targetConn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		log.Printf("[%s] Probe forward failed to dial %s: %v", clientIP, targetAddr, err)
		return
	}
	defer targetConn.Close()

	if len(initialBytes) > 0 {
		if _, err := targetConn.Write(initialBytes); err != nil {
			return
		}
	}

	_ = clientConn.SetDeadline(time.Now().Add(30 * time.Second))
	_ = targetConn.SetDeadline(time.Now().Add(30 * time.Second))

	protocol.RelayStreams(clientConn, targetConn)
}
