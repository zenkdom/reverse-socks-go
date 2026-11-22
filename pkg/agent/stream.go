package agent

import (
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"reverse-socks/pkg/protocol"
)

// TargetTCPStream manages an active outbound connection to an internet server.
type TargetTCPStream struct {
	StreamID uint32
	Host     string
	Port     int
	Conn     net.Conn
	Closed   atomic.Bool
	sendFunc func(cmd byte, streamID uint32, payload []byte)
	closeMu  sync.Mutex
}

// NewTargetTCPStream creates a new TargetTCPStream.
func NewTargetTCPStream(
	streamID uint32,
	host string,
	port int,
	conn net.Conn,
	sendFunc func(cmd byte, streamID uint32, payload []byte),
) *TargetTCPStream {
	s := &TargetTCPStream{
		StreamID: streamID,
		Host:     host,
		Port:     port,
		Conn:     conn,
		sendFunc: sendFunc,
	}
	go s.readerLoop()
	return s
}

func (s *TargetTCPStream) readerLoop() {
	buf := protocol.GetBuffer()
	defer protocol.PutBuffer(buf)

	for !s.Closed.Load() {
		n, err := s.Conn.Read(*buf)
		if n > 0 {
			s.sendFunc(protocol.CmdData, s.StreamID, (*buf)[:n])
		}
		if err != nil {
			break
		}
	}
	s.Close(true)
}

// WriteData writes payload to target internet connection.
func (s *TargetTCPStream) WriteData(payload []byte) {
	if s.Closed.Load() {
		return
	}
	if _, err := s.Conn.Write(payload); err != nil {
		s.Close(true)
	}
}

// Close closes the target connection and notifies control if requested.
func (s *TargetTCPStream) Close(notifyControl bool) {
	if s.Closed.CompareAndSwap(false, true) {
		s.closeMu.Lock()
		defer s.closeMu.Unlock()

		if s.Conn != nil {
			_ = s.Conn.Close()
		}
		if notifyControl {
			s.sendFunc(protocol.CmdClose, s.StreamID, nil)
		}
	}
}

// TargetUDPStream manages an active outbound UDP relay endpoint.
type TargetUDPStream struct {
	StreamID uint32
	UDPConn  *net.UDPConn
	Closed   atomic.Bool
	sendFunc func(cmd byte, streamID uint32, payload []byte)
}

// NewTargetUDPStream creates a new TargetUDPStream.
func NewTargetUDPStream(
	streamID uint32,
	sendFunc func(cmd byte, streamID uint32, payload []byte),
) (*TargetUDPStream, error) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, err
	}
	s := &TargetUDPStream{
		StreamID: streamID,
		UDPConn:  conn,
		sendFunc: sendFunc,
	}
	go s.readerLoop()
	return s, nil
}

func (s *TargetUDPStream) readerLoop() {
	buf := protocol.GetBuffer()
	defer protocol.PutBuffer(buf)

	for !s.Closed.Load() {
		n, remoteAddr, err := s.UDPConn.ReadFromUDP(*buf)
		if err != nil {
			break
		}
		pkt := protocol.PackSocks5UDPPacket(remoteAddr.IP.String(), remoteAddr.Port, (*buf)[:n])
		s.sendFunc(protocol.CmdUDPData, s.StreamID, pkt)
	}
	s.Close(true)
}

// SendDatagram parses a SOCKS5 UDP payload and transmits it to the destination.
func (s *TargetUDPStream) SendDatagram(payload []byte) {
	if s.Closed.Load() {
		return
	}
	targetHost, targetPort, data, atyp, err := protocol.ParseSocks5UDPPacket(payload)
	if err != nil || targetPort <= 0 {
		return
	}

	var dstAddr *net.UDPAddr
	if atyp == 0x03 { // Domain name
		dstAddr, err = net.ResolveUDPAddr("udp", net.JoinHostPort(targetHost, strconv.Itoa(targetPort)))
	} else {
		dstAddr = &net.UDPAddr{IP: net.ParseIP(targetHost), Port: targetPort}
	}

	if dstAddr != nil {
		_, _ = s.UDPConn.WriteToUDP(data, dstAddr)
	}
}

// Close closes the UDP socket.
func (s *TargetUDPStream) Close(notifyControl bool) {
	if s.Closed.CompareAndSwap(false, true) {
		if s.UDPConn != nil {
			_ = s.UDPConn.Close()
		}
		if notifyControl {
			s.sendFunc(protocol.CmdClose, s.StreamID, nil)
		}
	}
}
