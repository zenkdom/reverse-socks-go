package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"reverse-socks/pkg/protocol"
)

func (s *UniversalProxyServer) handleHTTPProxy(conn net.Conn, clientIP string, firstByte byte) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	reader := bufio.NewReader(io.MultiReader(strings.NewReader(string(firstByte)), conn))

	reqLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Split(strings.TrimSpace(reqLine), " ")
	if len(parts) < 2 {
		return
	}
	method := strings.ToUpper(parts[0])
	targetURL := parts[1]

	// Read headers
	headers := make(map[string]string)
	for {
		line, err := reader.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		lineStr := strings.TrimSpace(line)
		if idx := strings.Index(lineStr, ":"); idx != -1 {
			headers[strings.ToLower(strings.TrimSpace(lineStr[:idx]))] = strings.TrimSpace(lineStr[idx+1:])
		}
	}

	// Auth check
	username := "anon"
	authenticated := false
	allUsers := s.userManager.GetAllUsers()
	if len(allUsers) == 0 {
		authenticated = true
	} else {
		pAuth := headers["proxy-authorization"]
		if strings.HasPrefix(strings.ToLower(pAuth), "basic ") {
			encoded := strings.TrimSpace(pAuth[6:])
			if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
				credParts := strings.SplitN(string(decoded), ":", 2)
				if len(credParts) == 2 {
					if s.userManager.Authenticate(credParts[0], credParts[1]) {
						username = credParts[0]
						authenticated = true
					}
				}
			}
		}
	}

	if !authenticated {
		log.Printf("[%s] HTTP proxy auth required", clientIP)
		resp := "HTTP/1.1 407 Proxy Authentication Required\r\n" +
			"Proxy-Authenticate: Basic realm=\"Reverse SOCKS Universal Proxy\"\r\n" +
			"Content-Length: 0\r\n" +
			"Connection: close\r\n\r\n"
		_, _ = conn.Write([]byte(resp))
		return
	}

	_ = conn.SetDeadline(time.Time{})
	userKey := fmt.Sprintf("http:%s", username)

	if method == "CONNECT" {
		// HTTPS Tunnel
		thost := targetURL
		tport := 443
		if strings.Contains(targetURL, ":") {
			hp := strings.SplitN(targetURL, ":", 2)
			thost = hp[0]
			if p, err := strconv.Atoi(hp[1]); err == nil {
				tport = p
			}
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		agent, stream, _ := s.agentManager.EstablishStream(
			ctx,
			thost,
			tport,
			userKey,
			clientIP,
			s.fastTimeout,
			s.connectTimeout,
			"tcp",
		)

		if agent == nil || stream == nil {
			_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			return
		}

		if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			agent.RemoveStream(stream.StreamID, false)
			return
		}

		log.Printf("[HTTP CONNECT OK] [%s] [%s] Tunnel to %s:%d", clientIP, userKey, thost, tport)
		pipeClientAndAgent(conn, agent, stream, clientIP)

	} else {
		// Standard HTTP GET/POST forward proxy
		parsed, err := url.Parse(targetURL)
		if err != nil {
			_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			return
		}

		thost := parsed.Hostname()
		if thost == "" {
			thost = strings.Split(headers["host"], ":")[0]
		}
		tport := 80
		if parsed.Port() != "" {
			if p, err := strconv.Atoi(parsed.Port()); err == nil {
				tport = p
			}
		} else if parsed.Scheme == "https" {
			tport = 443
		}

		if thost == "" {
			_, _ = conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"))
			return
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		agent, stream, _ := s.agentManager.EstablishStream(
			ctx,
			thost,
			tport,
			userKey,
			clientIP,
			s.fastTimeout,
			s.connectTimeout,
			"tcp",
		)

		if agent == nil || stream == nil {
			_, _ = conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
			return
		}

		// Forward modified request without proxy headers
		path := parsed.Path
		if path == "" {
			path = "/"
		}
		if parsed.RawQuery != "" {
			path += "?" + parsed.RawQuery
		}
		httpVer := "HTTP/1.1"
		if len(parts) > 2 {
			httpVer = parts[2]
		}

		var reqBuilder strings.Builder
		reqBuilder.WriteString(fmt.Sprintf("%s %s %s\r\n", method, path, httpVer))
		for k, v := range headers {
			if k == "proxy-authorization" || k == "proxy-connection" {
				continue
			}
			reqBuilder.WriteString(fmt.Sprintf("%s: %s\r\n", strings.Title(k), v))
		}
		reqBuilder.WriteString("\r\n")

		agent.SendFrame(protocol.CmdData, stream.StreamID, []byte(reqBuilder.String()))
		log.Printf("[HTTP FORWARD OK] [%s] [%s] %s http://%s:%d%s", clientIP, userKey, method, thost, tport, path)
		pipeClientAndAgent(conn, agent, stream, clientIP)
	}
}
