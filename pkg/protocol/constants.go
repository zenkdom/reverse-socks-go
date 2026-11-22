package protocol

// Magic bytes identifying reverse socks protocol packets (4 bytes)
var Magic = []byte("RSX5")

const (
	MagicString = "RSX5"
	HeaderSize  = 13 // 4 bytes Magic + 1 byte Cmd + 4 bytes StreamID + 4 bytes Length
)

// Command IDs
const (
	CmdAuthReq     byte = 0x01 // Reverse -> Control: {"token": "...", "agent_id": "...", "exit_ip": "..."}
	CmdAuthResp    byte = 0x02 // Control -> Reverse: {"status": "ok"|"error", "message": "..."}
	CmdConnectReq  byte = 0x03 // Control -> Reverse: {"host": "...", "port": int, "proto": "tcp"|"udp"}
	CmdConnectResp byte = 0x04 // Reverse -> Control: {"status": 0|code, "error": "..."}
	CmdData        byte = 0x05 // Bi-directional: raw stream bytes
	CmdClose       byte = 0x06 // Bi-directional: close stream notification
	CmdPing        byte = 0x07 // Bi-directional: keepalive ping
	CmdPong        byte = 0x08 // Bi-directional: keepalive pong
	CmdUDPData     byte = 0x09 // Bi-directional: SOCKS5 encapsulated UDP datagram
)

// Status codes for CmdConnectResp
const (
	StatusSuccess            = 0
	StatusGeneralFailure     = 1
	StatusConnectionRefused  = 2
	StatusNetworkUnreachable = 3
	StatusHostUnreachable    = 4
	StatusTimeout            = 5
)

// CommandNames mapping for logging
var CommandNames = map[byte]string{
	CmdAuthReq:     "AUTH_REQ",
	CmdAuthResp:    "AUTH_RESP",
	CmdConnectReq:  "CONNECT_REQ",
	CmdConnectResp: "CONNECT_RESP",
	CmdData:        "DATA",
	CmdClose:       "CLOSE",
	CmdPing:        "PING",
	CmdPong:        "PONG",
	CmdUDPData:     "UDP_DATA",
}
