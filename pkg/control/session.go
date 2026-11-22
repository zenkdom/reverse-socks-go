package control

import (
	"encoding/json"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"reverse-socks/pkg/protocol"
)

// StreamContext represents an active SOCKS5 / MTProto session stream (TCP or UDP).
type StreamContext struct {
	StreamID      uint32
	Host          string
	Port          int
	AgentID       string
	Proto         string // "tcp" or "udp"
	ConnectDone   chan struct{}
	ConnectStatus int
	ConnectError  string
	DataQueue     chan []byte
	UDPQueue      chan []byte
	Closed        atomic.Bool
	CreatedAt     time.Time
	once          sync.Once
}

// NewStreamContext creates a new StreamContext.
func NewStreamContext(streamID uint32, host string, port int, agentID, proto string) *StreamContext {
	return &StreamContext{
		StreamID:      streamID,
		Host:          host,
		Port:          port,
		AgentID:       agentID,
		Proto:         proto,
		ConnectDone:   make(chan struct{}),
		ConnectStatus: protocol.StatusGeneralFailure,
		DataQueue:     make(chan []byte, 500),
		UDPQueue:      make(chan []byte, 1000),
		CreatedAt:     time.Now(),
	}
}

// MarkConnected marks connection attempt completed.
func (s *StreamContext) MarkConnected(status int, errMsg string) {
	s.once.Do(func() {
		s.ConnectStatus = status
		s.ConnectError = errMsg
		close(s.ConnectDone)
	})
}

// Close closes the stream queues.
func (s *StreamContext) Close() {
	if s.Closed.CompareAndSwap(false, true) {
		s.MarkConnected(protocol.StatusGeneralFailure, "closed")
		// Safe close queues by letting GC or sentinel
		select {
		case s.DataQueue <- nil:
		default:
		}
		select {
		case s.UDPQueue <- nil:
		default:
		}
	}
}

// AgentSession represents a connection from a single reverse agent.
type AgentSession struct {
	AgentID       string
	Conn          net.Conn
	Reader        io.Reader
	Writer        io.Writer
	RemoteIP      string
	IsFakeTLS     bool
	SNIDomain     string
	ExitIP        string
	ConnectedAt   time.Time
	LastSeen      atomic.Int64 // Unix timestamp
	Streams       map[uint32]*StreamContext
	StreamsMu     sync.RWMutex
	SendQueue           chan []byte
	ActiveConns         atomic.Int64
	TotalHandled        atomic.Int64
	Closed              atomic.Bool
	ConsecutiveFailures atomic.Int32
	LastFailureTime     atomic.Int64
	closeChan           chan struct{}
	onStreamClose       func(agentID string, streamID uint32)
}

func (s *AgentSession) RecordSuccess() {
	s.ConsecutiveFailures.Store(0)
}

func (s *AgentSession) RecordFailure() {
	s.ConsecutiveFailures.Add(1)
	s.LastFailureTime.Store(time.Now().Unix())
}

func (s *AgentSession) IsHealthy(cooldown time.Duration) bool {
	if s.Closed.Load() {
		return false
	}
	fails := s.ConsecutiveFailures.Load()
	if fails == 0 {
		return true
	}
	lastFail := s.LastFailureTime.Load()
	return time.Since(time.Unix(lastFail, 0)) > cooldown
}

// NewAgentSession creates a new AgentSession.
func NewAgentSession(
	agentID string,
	conn net.Conn,
	reader io.Reader,
	writer io.Writer,
	remoteIP string,
	isFakeTLS bool,
	sniDomain string,
	exitIP string,
) *AgentSession {
	s := &AgentSession{
		AgentID:     agentID,
		Conn:        conn,
		Reader:      reader,
		Writer:      writer,
		RemoteIP:    remoteIP,
		IsFakeTLS:   isFakeTLS,
		SNIDomain:   sniDomain,
		ExitIP:      exitIP,
		ConnectedAt: time.Now(),
		Streams:     make(map[uint32]*StreamContext),
		SendQueue:   make(chan []byte, 10000),
		closeChan:   make(chan struct{}),
	}
	s.LastSeen.Store(time.Now().Unix())
	go s.writerLoop()
	return s
}

func (s *AgentSession) writerLoop() {
	for {
		select {
		case frame, ok := <-s.SendQueue:
			if !ok || frame == nil {
				return
			}
			if _, err := s.Writer.Write(frame); err != nil {
				s.Close()
				return
			}
		case <-s.closeChan:
			return
		}
	}
}

// SendFrame queues a binary frame for sending.
func (s *AgentSession) SendFrame(cmd byte, streamID uint32, payload []byte) {
	if s.Closed.Load() {
		return
	}
	frame := protocol.PackFrame(cmd, streamID, payload)
	select {
	case s.SendQueue <- frame:
	case <-s.closeChan:
	}
}

// SendFrameNoWait queues a binary frame without blocking.
func (s *AgentSession) SendFrameNoWait(cmd byte, streamID uint32, payload []byte) {
	if s.Closed.Load() {
		return
	}
	frame := protocol.PackFrame(cmd, streamID, payload)
	select {
	case s.SendQueue <- frame:
	default:
	}
}

// SendJSON queues a JSON frame for sending.
func (s *AgentSession) SendJSON(cmd byte, streamID uint32, data any) error {
	if s.Closed.Load() {
		return io.ErrClosedPipe
	}
	frame, err := protocol.PackJSON(cmd, streamID, data)
	if err != nil {
		return err
	}
	select {
	case s.SendQueue <- frame:
		return nil
	case <-s.closeChan:
		return io.ErrClosedPipe
	}
}

// RegisterStream registers an active stream on this agent.
func (s *AgentSession) RegisterStream(stream *StreamContext) {
	s.StreamsMu.Lock()
	s.Streams[stream.StreamID] = stream
	s.StreamsMu.Unlock()

	s.ActiveConns.Add(1)
	s.TotalHandled.Add(1)
}

// RemoveStream unregisters a stream and notifies agent if requested.
func (s *AgentSession) RemoveStream(streamID uint32, notifyAgent bool) {
	s.StreamsMu.Lock()
	stream, ok := s.Streams[streamID]
	if ok {
		delete(s.Streams, streamID)
	}
	s.StreamsMu.Unlock()

	if ok {
		s.ActiveConns.Add(-1)
		stream.Close()
		if notifyAgent && !s.Closed.Load() {
			s.SendFrameNoWait(protocol.CmdClose, streamID, nil)
		}
	}
}

// HandleIncomingFrame processes a frame received from this agent.
func (s *AgentSession) HandleIncomingFrame(cmd byte, streamID uint32, payload []byte) {
	s.LastSeen.Store(time.Now().Unix())

	switch cmd {
	case protocol.CmdConnectResp:
		s.StreamsMu.RLock()
		stream := s.Streams[streamID]
		s.StreamsMu.RUnlock()
		if stream != nil {
			var resp struct {
				Status int    `json:"status"`
				Error  string `json:"error"`
			}
			status := protocol.StatusGeneralFailure
			errMsg := "parse error"
			if err := json.Unmarshal(payload, &resp); err == nil {
				status = resp.Status
				errMsg = resp.Error
			}
			stream.MarkConnected(status, errMsg)
		}

	case protocol.CmdData:
		s.StreamsMu.RLock()
		stream := s.Streams[streamID]
		s.StreamsMu.RUnlock()
		if stream != nil && !stream.Closed.Load() {
			select {
			case stream.DataQueue <- payload:
			default:
				log.Printf("[%s] Stream %d buffer overflow, dropping packet", s.AgentID, streamID)
			}
		}

	case protocol.CmdUDPData:
		s.StreamsMu.RLock()
		stream := s.Streams[streamID]
		s.StreamsMu.RUnlock()
		if stream != nil && !stream.Closed.Load() {
			select {
			case stream.UDPQueue <- payload:
			default:
				log.Printf("[%s] Stream %d UDP buffer overflow, dropping packet", s.AgentID, streamID)
			}
		}

	case protocol.CmdClose:
		s.RemoveStream(streamID, false)

	case protocol.CmdPing:
		s.SendFrameNoWait(protocol.CmdPong, 0, nil)

	case protocol.CmdPong:
		// Pong received
	}
}

// Close gracefully closes the agent session and all associated streams.
func (s *AgentSession) Close() {
	if s.Closed.CompareAndSwap(false, true) {
		close(s.closeChan)

		s.StreamsMu.Lock()
		for _, stream := range s.Streams {
			stream.MarkConnected(protocol.StatusGeneralFailure, "Agent disconnected")
			stream.Close()
		}
		s.Streams = make(map[uint32]*StreamContext)
		s.StreamsMu.Unlock()

		if s.Conn != nil {
			_ = s.Conn.Close()
		}
	}
}
