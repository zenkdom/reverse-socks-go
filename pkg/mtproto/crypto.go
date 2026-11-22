package mtproto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
	"strconv"
)

// Telegram Data Centers IPv4
var TGDatacentersV4 = map[int]string{
	1: "149.154.175.50",
	2: "149.154.167.51",
	3: "149.154.175.100",
	4: "149.154.167.91",
	5: "149.154.171.5",
}

const (
	DefaultDC        = 2
	TGDatacenterPort = 443
	HandshakeLen     = 64
	SkipLen          = 8
	KeyLen           = 32
	IVLen            = 16
	ProtoTagPos      = 56
	DCIdxPos         = 60
)

var (
	ProtoTagAbridged     = []byte{0xef, 0xef, 0xef, 0xef}
	ProtoTagIntermediate = []byte{0xee, 0xee, 0xee, 0xee}
	ProtoTagSecure       = []byte{0xdd, 0xdd, 0xdd, 0xdd}
)

var reservedNonceBeginnings = [][]byte{
	{0x48, 0x45, 0x41, 0x44}, // HEAD
	{0x50, 0x4F, 0x53, 0x54}, // POST
	{0x47, 0x45, 0x54, 0x20}, // GET
	{0xee, 0xee, 0xee, 0xee},
	{0xdd, 0xdd, 0xdd, 0xdd},
	{0x16, 0x03, 0x01, 0x02},
}

// CreateAESCTR creates a hardware-accelerated AES-CTR stream cipher.
func CreateAESCTR(key []byte, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}

// GenX25519PublicKey generates a curve point for TLS ServerHello.
func GenX25519PublicKey() []byte {
	// p = 2^255 - 19
	p, _ := new(big.Int).SetString("7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd", 16)
	n, _ := rand.Int(rand.Reader, p)
	n2 := new(big.Int).Mul(n, n)
	n2.Mod(n2, p)
	b := n2.Bytes()
	res := make([]byte, 32)
	// little endian
	for i := 0; i < len(b) && i < 32; i++ {
		res[i] = b[len(b)-1-i]
	}
	return res
}

func reverseBytes(b []byte) []byte {
	res := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		res[i] = b[len(b)-1-i]
	}
	return res
}

// DecryptObfuscated2 attempts to decrypt a 64-byte handshake using rawSecret.
func DecryptObfuscated2(handshake []byte, rawSecret []byte) (protoTag []byte, dcNum int, clientDec cipher.Stream, clientEnc cipher.Stream, ok bool) {
	if len(handshake) != HandshakeLen {
		return nil, 0, nil, nil, false
	}

	// Make explicit copies to completely prevent slice append capacity aliasing/corruption
	decPrekey := make([]byte, KeyLen)
	copy(decPrekey, handshake[SkipLen:SkipLen+KeyLen])

	decIV := make([]byte, IVLen)
	copy(decIV, handshake[SkipLen+KeyLen:SkipLen+KeyLen+IVLen])

	encPrekeyAndIV := reverseBytes(handshake[SkipLen : SkipLen+KeyLen+IVLen])
	encPrekey := make([]byte, KeyLen)
	copy(encPrekey, encPrekeyAndIV[:KeyLen])

	encIV := make([]byte, IVLen)
	copy(encIV, encPrekeyAndIV[KeyLen:])

	decKeyHash := sha256.Sum256(append(decPrekey, rawSecret...))
	encKeyHash := sha256.Sum256(append(encPrekey, rawSecret...))

	decCipher, err := CreateAESCTR(decKeyHash[:], decIV)
	if err != nil {
		return nil, 0, nil, nil, false
	}

	encCipher, err := CreateAESCTR(encKeyHash[:], encIV)
	if err != nil {
		return nil, 0, nil, nil, false
	}

	// Decrypt handshake copy
	decrypted := make([]byte, len(handshake))
	decCipher.XORKeyStream(decrypted, handshake)

	tag := decrypted[ProtoTagPos : ProtoTagPos+4]
	if !bytes.Equal(tag, ProtoTagAbridged) && !bytes.Equal(tag, ProtoTagIntermediate) && !bytes.Equal(tag, ProtoTagSecure) {
		return nil, 0, nil, nil, false
	}

	dcIdx := int16(binary.LittleEndian.Uint16(decrypted[DCIdxPos : DCIdxPos+2]))
	dc := int(dcIdx)
	if dc < 0 {
		dc = -dc
	}
	if dc < 1 || dc > 5 {
		if dc == 0 {
			dc = DefaultDC
		} else {
			return nil, 0, nil, nil, false
		}
	}

	return tag, dc, decCipher, encCipher, true
}

// GenerateDCHandshake generates 64-byte Obfuscated2 greeting for Telegram DC (NO secret).
func GenerateDCHandshake(protoTag []byte) (handshake []byte, dcDec cipher.Stream, dcEnc cipher.Stream) {
	for {
		rnd := make([]byte, HandshakeLen)
		_, _ = rand.Read(rnd)
		if rnd[0] == 0xef {
			continue
		}
		isBad := false
		for _, b := range reservedNonceBeginnings {
			if bytes.Equal(rnd[:4], b) {
				isBad = true
				break
			}
		}
		if isBad {
			continue
		}
		if bytes.Equal(rnd[4:8], []byte{0, 0, 0, 0}) {
			continue
		}

		copy(rnd[ProtoTagPos:ProtoTagPos+4], protoTag)

		dcEncPrekeyAndIV := rnd[SkipLen : SkipLen+KeyLen+IVLen]
		dcDecPrekeyAndIV := reverseBytes(dcEncPrekeyAndIV)

		encCipher, _ := CreateAESCTR(dcEncPrekeyAndIV[:KeyLen], dcEncPrekeyAndIV[KeyLen:])
		decCipher, _ := CreateAESCTR(dcDecPrekeyAndIV[:KeyLen], dcDecPrekeyAndIV[KeyLen:])

		// Encrypt tail of DC handshake
		encTail := make([]byte, HandshakeLen)
		encCipher.XORKeyStream(encTail, rnd)

		result := make([]byte, HandshakeLen)
		copy(result[:ProtoTagPos], rnd[:ProtoTagPos])
		copy(result[ProtoTagPos:], encTail[ProtoTagPos:])

		return result, decCipher, encCipher
	}
}

// BuildTLSServerHelloPacket constructs standard Fake-TLS 1.3 ServerHello response.
func BuildTLSServerHelloPacket(clientHello []byte, clientDigest []byte, rawSecret []byte) []byte {
	tlsVers := []byte{0x03, 0x03}
	tlsCipherSuite := []byte{0x13, 0x01}
	tlsChangeCipher := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	tlsAppHdr := []byte{0x17, 0x03, 0x03}

	tlsExtensions := []byte{
		0x00, 0x2e,
		0x00, 0x33, 0x00, 0x24,
		0x00, 0x1d, 0x00, 0x20,
	}
	tlsExtensions = append(tlsExtensions, GenX25519PublicKey()...)
	tlsExtensions = append(tlsExtensions, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04)

	sessIDLen := 0
	var sessID []byte
	if len(clientHello) > 43 {
		sessIDLen = int(clientHello[43])
		if sessIDLen > 32 || len(clientHello) < 44+sessIDLen {
			if len(clientHello) > 44 {
				sessID = clientHello[44:]
			}
		} else {
			sessID = clientHello[44 : 44+sessIDLen]
		}
	}

	fakeCertLen := 1024 + int(randInt(2048))
	httpData := make([]byte, fakeCertLen)
	_, _ = rand.Read(httpData)

	srvHello := append([]byte(nil), tlsVers...)
	srvHello = append(srvHello, make([]byte, 32)...) // zero random
	srvHello = append(srvHello, byte(len(sessID)))
	srvHello = append(srvHello, sessID...)
	srvHello = append(srvHello, tlsCipherSuite...)
	srvHello = append(srvHello, 0x00) // compression
	srvHello = append(srvHello, tlsExtensions...)

	helloPkt := []byte{0x16, 0x03, 0x03}
	helloLen := len(srvHello) + 4
	helloPkt = append(helloPkt, byte(helloLen>>8), byte(helloLen))
	helloPkt = append(helloPkt, 0x02, byte(len(srvHello)>>16), byte(len(srvHello)>>8), byte(len(srvHello)))
	helloPkt = append(helloPkt, srvHello...)
	helloPkt = append(helloPkt, tlsChangeCipher...)
	helloPkt = append(helloPkt, tlsAppHdr...)
	helloPkt = append(helloPkt, byte(len(httpData)>>8), byte(len(httpData)))
	helloPkt = append(helloPkt, httpData...)

	// Compute HMAC
	mac := hmac.New(sha256.New, rawSecret)
	mac.Write(clientDigest)
	mac.Write(helloPkt)
	computedDigest := mac.Sum(nil)

	copy(helloPkt[11:43], computedDigest)
	return helloPkt
}

func randInt(max int64) int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(max))
	return n.Int64()
}

// GetTGLinks returns telegram proxy URLs.
func GetTGLinks(serverHost string, port int, fakeTLSSecret string, rawSecretHex string) map[string]string {
	pStr := strconv.Itoa(port)
	links := map[string]string{
		"tg_link":  "tg://proxy?server=" + serverHost + "&port=" + pStr + "&secret=" + fakeTLSSecret,
		"tme_link": "https://t.me/proxy?server=" + serverHost + "&port=" + pStr + "&secret=" + fakeTLSSecret,
	}
	if rawSecretHex != "" {
		links["tg_link_hex32"] = "tg://proxy?server=" + serverHost + "&port=" + pStr + "&secret=" + rawSecretHex
		links["tme_link_hex32"] = "https://t.me/proxy?server=" + serverHost + "&port=" + pStr + "&secret=" + rawSecretHex
	}
	return links
}
