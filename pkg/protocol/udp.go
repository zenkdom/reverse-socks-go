package protocol

import (
	"encoding/binary"
	"errors"
	"net"
)

// PackSocks5UDPPacket packs a SOCKS5 UDP datagram header (RFC 1928 Section 7):
// RSV (2B) + FRAG (1B) + ATYP (1B) + ADDR + PORT (2B) + DATA
func PackSocks5UDPPacket(ipStr string, port int, data []byte) []byte {
	ip := net.ParseIP(ipStr)
	var header []byte

	if ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			header = make([]byte, 10)
			header[0] = 0x00 // RSV
			header[1] = 0x00 // RSV
			header[2] = 0x00 // FRAG
			header[3] = 0x01 // ATYP IPv4
			copy(header[4:8], ip4)
			binary.BigEndian.PutUint16(header[8:10], uint16(port))
		} else {
			header = make([]byte, 22)
			header[0] = 0x00
			header[1] = 0x00
			header[2] = 0x00
			header[3] = 0x04 // ATYP IPv6
			copy(header[4:20], ip.To16())
			binary.BigEndian.PutUint16(header[20:22], uint16(port))
		}
	} else {
		// Domain name fallback
		dlen := len(ipStr)
		header = make([]byte, 7+dlen)
		header[0] = 0x00
		header[1] = 0x00
		header[2] = 0x00
		header[3] = 0x03 // ATYP Domain
		header[4] = byte(dlen)
		copy(header[5:5+dlen], ipStr)
		binary.BigEndian.PutUint16(header[5+dlen:7+dlen], uint16(port))
	}

	result := make([]byte, len(header)+len(data))
	copy(result, header)
	copy(result[len(header):], data)
	return result
}

// ParseSocks5UDPPacket parses SOCKS5 UDP datagram header (RFC 1928 Section 7).
// Returns (targetHost, targetPort, data, atyp, error).
func ParseSocks5UDPPacket(payload []byte) (string, int, []byte, byte, error) {
	if len(payload) < 7 {
		return "", 0, nil, 0, errors.New("UDP packet too short")
	}

	frag := payload[2]
	if frag != 0 {
		// RFC 1928 Section 7: Drop any datagram whose FRAG field is other than X'00'
		return "", 0, nil, 0, errors.New("unsupported fragmented UDP datagram")
	}

	atyp := payload[3]
	offset := 4
	var targetHost string

	switch atyp {
	case 0x01: // IPv4 (4 bytes)
		if len(payload) < offset+4+2 {
			return "", 0, nil, atyp, errors.New("IPv4 payload too short")
		}
		targetHost = net.IP(payload[offset : offset+4]).String()
		offset += 4

	case 0x03: // Domain name
		if len(payload) < offset+1 {
			return "", 0, nil, atyp, errors.New("domain payload too short")
		}
		dlen := int(payload[offset])
		offset++
		if len(payload) < offset+dlen+2 {
			return "", 0, nil, atyp, errors.New("domain payload truncated")
		}
		targetHost = string(payload[offset : offset+dlen])
		offset += dlen

	case 0x04: // IPv6 (16 bytes)
		if len(payload) < offset+16+2 {
			return "", 0, nil, atyp, errors.New("IPv6 payload too short")
		}
		targetHost = net.IP(payload[offset : offset+16]).String()
		offset += 16

	default:
		return "", 0, nil, atyp, errors.New("unsupported ATYP")
	}

	targetPort := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	data := payload[offset:]

	return targetHost, targetPort, data, atyp, nil
}
