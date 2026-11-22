package protocol

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"
)

// PerformHTTPConnectTunnel connects through an HTTP forward proxy (e.g. Squid on PythonAnywhere proxy.server:3128)
// using HTTP CONNECT to create a raw TCP tunnel to targetHost:targetPort.
func PerformHTTPConnectTunnel(proxyURL string, targetHost string, targetPort int, connectHost string, timeout time.Duration) (net.Conn, error) {
	cleaned := strings.TrimSpace(proxyURL)
	if !strings.Contains(cleaned, "://") {
		cleaned = "http://" + cleaned
	}
	parsed, err := url.Parse(cleaned)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	proxyHost := parsed.Hostname()
	if proxyHost == "" {
		proxyHost = "proxy.server"
	}
	proxyPort := parsed.Port()
	if proxyPort == "" {
		proxyPort = "3128"
	}

	proxyAddr := net.JoinHostPort(proxyHost, proxyPort)
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial HTTP proxy %s: %w", proxyAddr, err)
	}

	destHost := strings.TrimSpace(connectHost)
	if destHost == "" {
		destHost = targetHost
	}
	destAddr := fmt.Sprintf("%s:%d", destHost, targetPort)

	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nProxy-Connection: Keep-Alive\r\n", destAddr, destAddr)
	if parsed.User != nil {
		creds := base64.StdEncoding.EncodeToString([]byte(parsed.User.String()))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", creds)
	}
	req += "\r\n"

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}

	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed writing CONNECT request: %w", err)
	}

	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy closed connection before sending response: %w", err)
	}

	statusLine = strings.TrimSpace(statusLine)
	parts := strings.Split(statusLine, " ")
	if len(parts) < 2 || parts[1] != "200" {
		conn.Close()
		return nil, fmt.Errorf("HTTP Proxy CONNECT tunnel rejected: %s", statusLine)
	}

	// Consume remaining proxy headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// EnableSocketKeepalive enables TCP KeepAlive and disables Nagle's algorithm (NoDelay) for maximum speed.
func EnableSocketKeepalive(conn net.Conn) {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetKeepAlive(true)
		_ = tcpConn.SetKeepAlivePeriod(60 * time.Second)
		_ = tcpConn.SetNoDelay(true)
	}
}

// RelayStreams copies data bidirectionally between two connections using pooled buffers.
// Returns when both sides terminate or an error occurs.
func RelayStreams(c1, c2 net.Conn) (n1 int64, n2 int64) {
	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(dst, src net.Conn, written *int64) {
		defer wg.Done()
		buf := GetBuffer()
		defer PutBuffer(buf)

		for {
			nr, err := src.Read(*buf)
			if nr > 0 {
				nw, ew := dst.Write((*buf)[:nr])
				if nw > 0 {
					*written += int64(nw)
				}
				if ew != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		// Half-close if possible
		if tcp, ok := dst.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		} else {
			_ = dst.Close()
		}
	}

	go pipe(c1, c2, &n1)
	go pipe(c2, c1, &n2)

	wg.Wait()
	_ = c1.Close()
	_ = c2.Close()
	return n1, n2
}
