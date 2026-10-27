// SPDX-License-Identifier: MIT

package otfp_test

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/iso"
	"github.com/otfabric/go-otfp/internal/mbap"
	"github.com/otfabric/go-otfp/internal/testsrv"
	"github.com/otfabric/go-otfp/protocols/dnp3"
	"github.com/otfabric/go-otfp/protocols/iec104"
)

// speakers are minimal responders that speak one protocol correctly
// (answering that protocol's probes as a device would) and answer anything
// else the way a device of that protocol would treat foreign bytes.
func speakers() map[core.Protocol]testsrv.Handler {
	return map[core.Protocol]testsrv.Handler{
		core.ProtocolModbus: func(req []byte) ([]byte, bool) {
			if len(req) < 8 || req[2] != 0 || req[3] != 0 {
				return nil, true // not MBAP: drop the connection
			}
			tid := binary.BigEndian.Uint16(req)
			return mbap.Request(tid, req[6], req[7]|0x80, 0x01), false // illegal function
		},
		core.ProtocolDNP3: func(req []byte) ([]byte, bool) {
			n := dnp3.FrameLen(at(req, 2))
			if n < 0 || n > len(req) {
				return nil, false // a DNP3 link layer resyncs silently
			}
			h, err := dnp3.ParseHeader(req[:n])
			if err != nil {
				return nil, false
			}
			return dnp3.Frame(0x0B, h.Src, h.Dst, nil), false
		},
		core.ProtocolIEC104: func(req []byte) ([]byte, bool) {
			if len(req) == 6 && req[0] == 0x68 && req[2] == 0x43 {
				return iec104.U(0x83), false
			}
			return nil, true // a protocol error closes an IEC 104 link
		},
		core.ProtocolS7: func(req []byte) ([]byte, bool) {
			switch {
			case iso.TPDUType(req) == iso.TPDUConnectRequest:
				return iso.TPKT([]byte{0x06, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00}), false
			case len(req) > 7 && req[7] == 0x32:
				return iso.Data([]byte{0x32, 0x03, 0, 0, 0, 1, 0, 8, 0, 0, 0, 0, 0xF0, 0, 0, 1, 0, 1, 0x01, 0xE0}), false
			}
			return nil, true
		},
		core.ProtocolOPCUA: func(req []byte) ([]byte, bool) {
			if len(req) >= 8 && string(req[:4]) == "HELF" {
				ack := []byte("ACKF\x1c\x00\x00\x00\x00\x00\x00\x00\xff\xff\x00\x00\xff\xff\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00")
				return ack, false
			}
			return []byte("ERRF\x10\x00\x00\x00\x00\x00\x7e\x80\xff\xff\xff\xff"), true // BadTcpMessageTypeInvalid
		},
		core.ProtocolENIP: func(req []byte) ([]byte, bool) {
			if len(req) < 24 || binary.LittleEndian.Uint16(req) != 0x0063 {
				return nil, true
			}
			item := make([]byte, 2+16+15)
			binary.LittleEndian.PutUint16(item[18:], 1) // vendor 1
			reply := make([]byte, 24, 24+6+len(item))
			binary.LittleEndian.PutUint16(reply, 0x0063)
			copy(reply[12:20], req[12:20])
			reply = binary.LittleEndian.AppendUint16(reply, 1)
			reply = binary.LittleEndian.AppendUint16(reply, 0x000C)
			reply = binary.LittleEndian.AppendUint16(reply, uint16(len(item)))
			reply = append(reply, item...)
			binary.LittleEndian.PutUint16(reply[2:], uint16(len(reply)-24))
			return reply, false
		},
		core.ProtocolOCPP: func(req []byte) ([]byte, bool) {
			if strings.Contains(string(req), "Sec-WebSocket-Protocol: ocpp") {
				return []byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: ocpp1.6\r\n\r\n"), false
			}
			return []byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"), true
		},
		core.ProtocolCAN: func(req []byte) ([]byte, bool) {
			switch {
			case len(req) == 2 && req[0] == 'V' && req[1] == '\r':
				return []byte("V1013\r"), false
			case len(req) == 2 && req[0] == 'N' && req[1] == '\r':
				return []byte("NA1B2\r"), false
			}
			return []byte{0x07}, false // SLCAN answers an unknown command with BEL
		},
	}
}

func at(b []byte, i int) byte {
	if i < len(b) {
		return b[i]
	}
	return 0
}

// Every TCP fingerprinter against every speaker: a speaker is detected as
// its own protocol, and no other fingerprinter claims it.
func TestCrossProtocolMatrix(t *testing.T) {
	var fps []core.Fingerprinter
	for _, fp := range otfp.Fingerprinters() {
		if fp.Info().Network == core.TCP {
			fps = append(fps, fp)
		}
	}
	for speaker, handler := range speakers() {
		target := testsrv.TCP(t, handler)
		target.Timeout = 300 * time.Millisecond
		for _, fp := range fps {
			p := fp.Info().Protocol
			t.Run(fmt.Sprintf("%s-on-%s", p.Slug(), speaker.Slug()), func(t *testing.T) {
				t.Parallel()
				for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
					r, err := fp.Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: core.ReadOnly})
					fuzzkit.Check(t, p, r, err)
					switch {
					case p == speaker && !r.Matched:
						t.Fatalf("%s: did not detect its own protocol: %v (%v)", mode, r, err)
					case p != speaker && r.Matched:
						t.Fatalf("%s: false positive on a %s device: %v", mode, speaker, r)
					}
				}
			})
		}
	}
}
