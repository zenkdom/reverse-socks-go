package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Frame represents a single protocol frame
type Frame struct {
	Cmd      byte
	StreamID uint32
	Payload  []byte
}

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 32*1024)
		return &b
	},
}

// GetBuffer gets a pooled 32KB buffer
func GetBuffer() *[]byte {
	return bufPool.Get().(*[]byte)
}

// PutBuffer returns a pooled buffer
func PutBuffer(b *[]byte) {
	if b != nil {
		bufPool.Put(b)
	}
}

// PackFrame packs command, stream_id and payload into a binary frame.
func PackFrame(cmd byte, streamID uint32, payload []byte) []byte {
	length := len(payload)
	buf := make([]byte, HeaderSize+length)
	copy(buf[0:4], Magic)
	buf[4] = cmd
	binary.BigEndian.PutUint32(buf[5:9], streamID)
	binary.BigEndian.PutUint32(buf[9:13], uint32(length))
	if length > 0 {
		copy(buf[13:], payload)
	}
	return buf
}

// PackJSON packs a Go structure as JSON in a protocol frame.
func PackJSON(cmd byte, streamID uint32, data any) ([]byte, error) {
	payload, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return PackFrame(cmd, streamID, payload), nil
}

// ReadFrame reads a complete frame from an io.Reader.
// Returns (frame, nil) or (nil, err).
func ReadFrame(r io.Reader) (*Frame, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}

	if !bytes.Equal(header[0:4], Magic) {
		return nil, fmt.Errorf("invalid protocol magic: %v, expected %v", header[0:4], Magic)
	}

	cmd := header[4]
	streamID := binary.BigEndian.Uint32(header[5:9])
	length := binary.BigEndian.Uint32(header[9:13])

	var payload []byte
	if length > 0 {
		payload = make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}

	return &Frame{
		Cmd:      cmd,
		StreamID: streamID,
		Payload:  payload,
	}, nil
}

// WriteFrame writes a frame directly to an io.Writer.
func WriteFrame(w io.Writer, cmd byte, streamID uint32, payload []byte) error {
	var header [HeaderSize]byte
	copy(header[0:4], Magic)
	header[4] = cmd
	binary.BigEndian.PutUint32(header[5:9], streamID)
	binary.BigEndian.PutUint32(header[9:13], uint32(len(payload)))

	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}
