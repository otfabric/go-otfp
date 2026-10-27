// SPDX-License-Identifier: MIT

// Package iso builds and parses the ISO-on-TCP layers shared by MMS and
// S7comm: TPKT (RFC 1006) and the ISO 8073 / X.224 class 0 connection
// TPDUs (COTP).
package iso

import (
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-otfp/internal/wire"
)

// TPKT and COTP constants.
const (
	TPKTVersion   = 0x03
	TPKTHeaderLen = 4

	TPDUConnectRequest    = 0xE0
	TPDUConnectConfirm    = 0xD0
	TPDUDisconnectRequest = 0x80
	TPDUError             = 0x70
	TPDUData              = 0xF0

	ParamTPDUSize   = 0xC0
	ParamCallingTSAP = 0xC1
	ParamCalledTSAP = 0xC2
)

// TPKT wraps payload in a TPKT header.
func TPKT(payload []byte) []byte {
	b := make([]byte, TPKTHeaderLen+len(payload))
	b[0] = TPKTVersion
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[4:], payload)
	return b
}

// Framer reads one TPKT frame.
var Framer = wire.FixedHeader(TPKTHeaderLen, func(h []byte) int {
	if h[0] != TPKTVersion || h[1] != 0 {
		return -1
	}
	return int(binary.BigEndian.Uint16(h[2:4]))
})

// ConnectRequest returns a TPKT-framed COTP CR with the given source
// reference, calling and called TSAPs and a TPDU size code (0x0A = 1024
// bytes).
func ConnectRequest(srcRef uint16, calling, called []byte, sizeCode byte) []byte {
	cr := []byte{0, TPDUConnectRequest, 0, 0, byte(srcRef >> 8), byte(srcRef), 0x00}
	cr = append(cr, ParamTPDUSize, 1, sizeCode)
	cr = append(cr, ParamCallingTSAP, byte(len(calling)))
	cr = append(cr, calling...)
	cr = append(cr, ParamCalledTSAP, byte(len(called)))
	cr = append(cr, called...)
	cr[0] = byte(len(cr) - 1)
	return TPKT(cr)
}

// Data returns payload as a TPKT-framed COTP DT TPDU with EOT set.
func Data(payload []byte) []byte {
	return TPKT(append([]byte{0x02, TPDUData, 0x80}, payload...))
}

// Confirm is a parsed COTP Connection Confirm.
type Confirm struct {
	DstRef, SrcRef uint16
	Class          byte
	// Params maps parameter codes to their values.
	Params map[byte][]byte
}

// TPDUType returns the COTP TPDU code of a TPKT frame (the high nibble of
// the second COTP byte for CR/CC/DR/ER, the full byte for DT), or 0 when
// frame is not TPKT/COTP.
func TPDUType(frame []byte) byte {
	if len(frame) < TPKTHeaderLen+2 || frame[0] != TPKTVersion || frame[1] != 0 {
		return 0
	}
	li := int(frame[4])
	if li < 1 || TPKTHeaderLen+1+li > len(frame) {
		return 0
	}
	t := frame[5]
	if t == TPDUData {
		return t
	}
	return t & 0xF0
}

// ParseConfirm parses a TPKT frame holding a COTP CC.
func ParseConfirm(frame []byte) (Confirm, error) {
	if TPDUType(frame) != TPDUConnectConfirm {
		return Confirm{}, fmt.Errorf("not a COTP connection confirm")
	}
	if tl := int(binary.BigEndian.Uint16(frame[2:4])); tl != len(frame) {
		return Confirm{}, fmt.Errorf("TPKT length %d, frame %d bytes", tl, len(frame))
	}
	li := int(frame[4])
	if li < 6 {
		return Confirm{}, fmt.Errorf("COTP CC length indicator %d too short", li)
	}
	c := Confirm{
		DstRef: binary.BigEndian.Uint16(frame[6:8]),
		SrcRef: binary.BigEndian.Uint16(frame[8:10]),
		Class:  frame[10] >> 4,
		Params: map[byte][]byte{},
	}
	p := frame[11 : 5+li]
	for len(p) >= 2 {
		code, n := p[0], int(p[1])
		if 2+n > len(p) {
			return c, fmt.Errorf("COTP parameter 0x%02x overruns the TPDU", code)
		}
		c.Params[code] = p[2 : 2+n]
		p = p[2+n:]
	}
	return c, nil
}

// Payload returns the user data of a TPKT frame holding a COTP DT TPDU.
func Payload(frame []byte) ([]byte, bool) {
	if TPDUType(frame) != TPDUData {
		return nil, false
	}
	li := int(frame[4])
	if li < 2 {
		return nil, false
	}
	return frame[TPKTHeaderLen+1+li:], true
}
