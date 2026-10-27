// SPDX-License-Identifier: MIT

package iso

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestConnectRequestAndTPKT(t *testing.T) {
	cr := ConnectRequest(0x0001, []byte{0, 1}, []byte{0, 1}, 0x0a)
	if cr[0] != TPKTVersion || TPDUType(cr) != TPDUConnectRequest {
		t.Fatalf("cr % x", cr)
	}
	// Round trips a fabricated CC.
	ccPayload := []byte{0x11, TPDUConnectConfirm, 0x00, 0x01, 0x00, 0x01, 0x00, 0xc0, 0x01, 0x0a, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02}
	cc := TPKT(ccPayload)
	if TPDUType(cc) != TPDUConnectConfirm {
		t.Fatalf("cc type 0x%02x", TPDUType(cc))
	}
	conf, err := ParseConfirm(cc)
	if err != nil || conf.DstRef != 1 || conf.SrcRef != 1 {
		t.Fatalf("%+v %v", conf, err)
	}
	if _, ok := conf.Params[ParamTPDUSize]; !ok {
		t.Fatal("missing TPDU size param")
	}
}

func TestData(t *testing.T) {
	d := Data([]byte{0x32, 0x01})
	p, ok := Payload(d)
	if !ok || !bytes.Equal(p, []byte{0x32, 0x01}) {
		t.Fatalf("payload %x %v", p, ok)
	}
}

func TestFramerAndBadInput(t *testing.T) {
	cr := ConnectRequest(1, []byte{0, 1}, []byte{0, 1}, 0x0a)
	if Framer(cr) != len(cr) {
		t.Fatal("framer length")
	}
	if Framer([]byte{0x00, 0x00, 0x00, 0x04}) != -1 {
		t.Fatal("non-TPKT should be rejected")
	}
	if TPDUType([]byte{0x03, 0x00}) != 0 {
		t.Fatal("short frame")
	}
	if _, err := ParseConfirm(TPKT([]byte{0x06, TPDUDisconnectRequest, 0, 0, 0, 0})); err == nil {
		t.Fatal("DR should not parse as CC")
	}
}

func FuzzParseConfirm(f *testing.F) {
	f.Add(hexDecode("0300001811d0000100010000c0010ac1020100c2020102"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if TPDUType(b) == TPDUConnectConfirm {
			_, _ = ParseConfirm(b)
		}
		_, _ = Payload(b)
	})
}

func hexDecode(s string) []byte { b, _ := hex.DecodeString(s); return b }
