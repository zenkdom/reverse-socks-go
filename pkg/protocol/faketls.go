package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// FakeTLSReader unwraps TLS 1.3 Application Data records (\x17\x03\x03).
type FakeTLSReader struct {
	r   io.Reader
	buf bytes.Buffer
	mu  sync.Mutex
}

// NewFakeTLSReader creates a new FakeTLSReader.
func NewFakeTLSReader(r io.Reader) *FakeTLSReader {
	return &FakeTLSReader{r: r}
}

func (f *FakeTLSReader) readRecord() ([]byte, error) {
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(f.r, hdr[:]); err != nil {
			return nil, err
		}

		recType := hdr[0]
		recLen := binary.BigEndian.Uint16(hdr[3:5])

		data := make([]byte, recLen)
		if _, err := io.ReadFull(f.r, data); err != nil {
			return nil, err
		}

		if recType == 0x14 { // ChangeCipherSpec - ignore in TLS 1.3
			continue
		}
		if recType != 0x17 { // Application Data
			return nil, fmt.Errorf("unexpected TLS record type: 0x%02x", recType)
		}
		return data, nil
	}
}

func (f *FakeTLSReader) Read(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	for f.buf.Len() == 0 {
		rec, err := f.readRecord()
		if err != nil {
			return 0, err
		}
		f.buf.Write(rec)
	}

	return f.buf.Read(p)
}

// FakeTLSWriter wraps outgoing stream data into TLS 1.3 Application Data records (\x17\x03\x03).
type FakeTLSWriter struct {
	w  io.Writer
	mu sync.Mutex
}

const maxRecordLen = 16384

// NewFakeTLSWriter creates a new FakeTLSWriter.
func NewFakeTLSWriter(w io.Writer) *FakeTLSWriter {
	return &FakeTLSWriter{w: w}
}

func (f *FakeTLSWriter) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	total := len(p)
	for len(p) > 0 {
		chunkSize := len(p)
		if chunkSize > maxRecordLen {
			chunkSize = maxRecordLen
		}
		chunk := p[:chunkSize]
		p = p[chunkSize:]

		var hdr [5]byte
		hdr[0] = 0x17 // Application Data
		hdr[1] = 0x03 // TLS 1.2/1.3 legacy version
		hdr[2] = 0x03
		binary.BigEndian.PutUint16(hdr[3:5], uint16(len(chunk)))

		if _, err := f.w.Write(hdr[:]); err != nil {
			return 0, err
		}
		if _, err := f.w.Write(chunk); err != nil {
			return 0, err
		}
	}
	return total, nil
}

// BuildTLSClientHello constructs an authentic TLS 1.3 ClientHello record with SNI set to domain.
// Returns (recordBytes, sessionID).
func BuildTLSClientHello(domain string) ([]byte, []byte) {
	domainB := []byte(domain)

	// SNI extension
	sniEntry := make([]byte, 3+len(domainB))
	sniEntry[0] = 0x00 // host_name
	binary.BigEndian.PutUint16(sniEntry[1:3], uint16(len(domainB)))
	copy(sniEntry[3:], domainB)

	sniList := make([]byte, 2+len(sniEntry))
	binary.BigEndian.PutUint16(sniList[0:2], uint16(len(sniEntry)))
	copy(sniList[2:], sniEntry)

	extSNI := make([]byte, 4+len(sniList))
	binary.BigEndian.PutUint16(extSNI[0:2], 0x0000) // ext type 0 (server_name)
	binary.BigEndian.PutUint16(extSNI[2:4], uint16(len(sniList)))
	copy(extSNI[4:], sniList)

	// Supported groups (X25519, secp256r1)
	groups := []byte{0x00, 0x04, 0x00, 0x1d, 0x00, 0x17}
	extGroups := make([]byte, 4+len(groups))
	binary.BigEndian.PutUint16(extGroups[0:2], 0x000a)
	binary.BigEndian.PutUint16(extGroups[2:4], uint16(len(groups)))
	copy(extGroups[4:], groups)

	// Supported versions (TLS 1.3, TLS 1.2)
	versions := []byte{0x04, 0x03, 0x04, 0x03, 0x03}
	extVersions := make([]byte, 4+len(versions))
	binary.BigEndian.PutUint16(extVersions[0:2], 0x002b)
	binary.BigEndian.PutUint16(extVersions[2:4], uint16(len(versions)))
	copy(extVersions[4:], versions)

	// Key share (X25519 32-byte public key)
	pubKey := make([]byte, 32)
	_, _ = rand.Read(pubKey)
	ksEntry := make([]byte, 4+32)
	binary.BigEndian.PutUint16(ksEntry[0:2], 0x001d)
	binary.BigEndian.PutUint16(ksEntry[2:4], 32)
	copy(ksEntry[4:], pubKey)

	ksList := make([]byte, 2+len(ksEntry))
	binary.BigEndian.PutUint16(ksList[0:2], uint16(len(ksEntry)))
	copy(ksList[2:], ksEntry)

	extKS := make([]byte, 4+len(ksList))
	binary.BigEndian.PutUint16(extKS[0:2], 0x0033)
	binary.BigEndian.PutUint16(extKS[2:4], uint16(len(ksList)))
	copy(extKS[4:], ksList)

	// Signature algorithms
	sigs := []byte{0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x01}
	extSigs := make([]byte, 4+len(sigs))
	binary.BigEndian.PutUint16(extSigs[0:2], 0x000d)
	binary.BigEndian.PutUint16(extSigs[2:4], uint16(len(sigs)))
	copy(extSigs[4:], sigs)

	allExts := append(extSNI, extGroups...)
	allExts = append(allExts, extVersions...)
	allExts = append(allExts, extKS...)
	allExts = append(allExts, extSigs...)

	extSection := make([]byte, 2+len(allExts))
	binary.BigEndian.PutUint16(extSection[0:2], uint16(len(allExts)))
	copy(extSection[2:], allExts)

	randomBytes := make([]byte, 32)
	_, _ = rand.Read(randomBytes)
	sessionID := make([]byte, 32)
	_, _ = rand.Read(sessionID)

	cipherSuites := []byte{0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03}
	compression := []byte{0x01, 0x00}

	body := []byte{0x03, 0x03}
	body = append(body, randomBytes...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	body = append(body, cipherSuites...)
	body = append(body, compression...)
	body = append(body, extSection...)

	handshake := make([]byte, 4+len(body))
	handshake[0] = 0x01 // ClientHello
	handshake[1] = byte(len(body) >> 16)
	handshake[2] = byte(len(body) >> 8)
	handshake[3] = byte(len(body))
	copy(handshake[4:], body)

	record := make([]byte, 5+len(handshake))
	record[0] = 0x16 // Handshake
	record[1] = 0x03 // TLS 1.0 legacy
	record[2] = 0x01
	binary.BigEndian.PutUint16(record[3:5], uint16(len(handshake)))
	copy(record[5:], handshake)

	return record, sessionID
}

// ExtractSNIFromClientHello extracts the SNI hostname from TLS ClientHello data.
func ExtractSNIFromClientHello(data []byte) string {
	offset := 0
	if len(data) > 5 && data[0] == 0x16 {
		offset = 5
	}
	if offset+4 > len(data) || data[offset] != 0x01 {
		return ""
	}
	offset += 4 + 2 + 32 // skip handshake header, version, random
	if offset >= len(data) {
		return ""
	}
	sessIDLen := int(data[offset])
	offset += 1 + sessIDLen
	if offset+2 > len(data) {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2 + csLen
	if offset+1 > len(data) {
		return ""
	}
	compLen := int(data[offset])
	offset += 1 + compLen
	if offset+2 > len(data) {
		return ""
	}
	extTotalLen := int(binary.BigEndian.Uint16(data[offset : offset+2]))
	offset += 2
	endExt := offset + extTotalLen
	if endExt > len(data) {
		endExt = len(data)
	}

	for offset+4 <= endExt {
		extType := binary.BigEndian.Uint16(data[offset : offset+2])
		extLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if extType == 0 { // Server Name Indication
			if offset+5 <= len(data) {
				nameLen := int(binary.BigEndian.Uint16(data[offset+3 : offset+5]))
				if offset+5+nameLen <= len(data) {
					return string(data[offset+5 : offset+5+nameLen])
				}
			}
		}
		offset += extLen
	}
	return ""
}

// BuildTLSServerHello constructs a valid TLS 1.3 ServerHello response sequence.
func BuildTLSServerHello(sessionID []byte) []byte {
	srvRandom := make([]byte, 32)
	_, _ = rand.Read(srvRandom)

	sessID := sessionID
	if len(sessID) == 0 {
		sessID = make([]byte, 32)
		_, _ = rand.Read(sessID)
	}

	randKey := make([]byte, 32)
	_, _ = rand.Read(randKey)

	// Extensions: supported_versions (TLS 1.3 = 0x0304), key_share (X25519 = 0x001d, 32B)
	exts := []byte{
		0x00, 0x2b, 0x00, 0x02, 0x03, 0x04,
		0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20,
	}
	exts = append(exts, randKey...)

	srvHelloBody := []byte{0x03, 0x03}
	srvHelloBody = append(srvHelloBody, srvRandom...)
	srvHelloBody = append(srvHelloBody, byte(len(sessID)))
	srvHelloBody = append(srvHelloBody, sessID...)
	srvHelloBody = append(srvHelloBody, 0x13, 0x01, 0x00) // AES_128_GCM_SHA256, null compression

	extSection := make([]byte, 2+len(exts))
	binary.BigEndian.PutUint16(extSection[0:2], uint16(len(exts)))
	copy(extSection[2:], exts)
	srvHelloBody = append(srvHelloBody, extSection...)

	handshake := make([]byte, 4+len(srvHelloBody))
	handshake[0] = 0x02 // ServerHello
	handshake[1] = byte(len(srvHelloBody) >> 16)
	handshake[2] = byte(len(srvHelloBody) >> 8)
	handshake[3] = byte(len(srvHelloBody))
	copy(handshake[4:], srvHelloBody)

	recSH := make([]byte, 5+len(handshake))
	recSH[0] = 0x16
	recSH[1] = 0x03
	recSH[2] = 0x03
	binary.BigEndian.PutUint16(recSH[3:5], uint16(len(handshake)))
	copy(recSH[5:], handshake)

	// ChangeCipherSpec
	recCCS := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}

	// Dummy encrypted Application Data (64 bytes)
	dummyApp := make([]byte, 64)
	_, _ = rand.Read(dummyApp)
	recApp := make([]byte, 5+len(dummyApp))
	recApp[0] = 0x17
	recApp[1] = 0x03
	recApp[2] = 0x03
	binary.BigEndian.PutUint16(recApp[3:5], uint16(len(dummyApp)))
	copy(recApp[5:], dummyApp)

	result := append(recSH, recCCS...)
	return append(result, recApp...)
}

// ReadTLSServerHello reads and validates a TLS ServerHello response sequence.
func ReadTLSServerHello(r io.Reader, timeout time.Duration) error {
	type readResult struct {
		err error
	}
	done := make(chan readResult, 1)

	go func() {
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			done <- readResult{err: err}
			return
		}
		if hdr[0] != 0x16 {
			done <- readResult{err: fmt.Errorf("expected TLS ServerHello (0x16), got record type 0x%02x", hdr[0])}
			return
		}
		recLen := binary.BigEndian.Uint16(hdr[3:5])
		shData := make([]byte, recLen)
		if _, err := io.ReadFull(r, shData); err != nil {
			done <- readResult{err: err}
			return
		}

		// Read optional ChangeCipherSpec (0x14) and dummy ApplicationData (0x17)
		var hdr2 [5]byte
		if n, _ := io.ReadFull(r, hdr2[:]); n == 5 {
			if hdr2[0] == 0x14 {
				l2 := binary.BigEndian.Uint16(hdr2[3:5])
				discard := make([]byte, l2)
				_, _ = io.ReadFull(r, discard)

				var hdr3 [5]byte
				if n3, _ := io.ReadFull(r, hdr3[:]); n3 == 5 && hdr3[0] == 0x17 {
					l3 := binary.BigEndian.Uint16(hdr3[3:5])
					discard3 := make([]byte, l3)
					_, _ = io.ReadFull(r, discard3)
				}
			}
		}
		done <- readResult{err: nil}
	}()

	select {
	case res := <-done:
		return res.err
	case <-time.After(timeout):
		return errors.New("timeout reading TLS ServerHello")
	}
}

// PerformTLSClientHandshake performs the client-side Fake-TLS handshake.
func PerformTLSClientHandshake(conn net.Conn, domain string, timeout time.Duration) (*FakeTLSReader, *FakeTLSWriter, error) {
	if domain == "" {
		domain = "google.com"
	}
	chello, _ := BuildTLSClientHello(domain)
	if _, err := conn.Write(chello); err != nil {
		return nil, nil, err
	}

	if err := ReadTLSServerHello(conn, timeout); err != nil {
		return nil, nil, err
	}

	return NewFakeTLSReader(conn), NewFakeTLSWriter(conn), nil
}

// PerformTLSServerHandshake performs the server-side Fake-TLS handshake.
func PerformTLSServerHandshake(conn net.Conn, firstBytes []byte, timeout time.Duration) (*FakeTLSReader, *FakeTLSWriter, string, error) {
	var fullHdr [5]byte
	copy(fullHdr[:], firstBytes)
	needed := 5 - len(firstBytes)
	if needed > 0 {
		if _, err := io.ReadFull(conn, fullHdr[len(firstBytes):]); err != nil {
			return nil, nil, "", err
		}
	}

	if fullHdr[0] != 0x16 {
		return nil, nil, "", fmt.Errorf("expected TLS ClientHello (0x16), got 0x%02x", fullHdr[0])
	}

	recLen := binary.BigEndian.Uint16(fullHdr[3:5])
	body := make([]byte, recLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, nil, "", err
	}

	clientHelloData := append(fullHdr[:], body...)
	sni := ExtractSNIFromClientHello(clientHelloData)
	if sni == "" {
		sni = "unknown"
	}

	var sessionID []byte
	if len(body) > 39 {
		sLen := int(body[38])
		if len(body) >= 39+sLen {
			sessionID = body[39 : 39+sLen]
		}
	}

	srvHello := BuildTLSServerHello(sessionID)
	if _, err := conn.Write(srvHello); err != nil {
		return nil, nil, "", err
	}

	return NewFakeTLSReader(conn), NewFakeTLSWriter(conn), sni, nil
}
