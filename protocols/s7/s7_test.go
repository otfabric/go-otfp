// SPDX-License-Identifier: MIT

package s7

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/iso"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// Frames of the snap7-interop native server (Snap7, rack 0 slot 2).
var (
	snap7Confirm  = unhex("03 00 00 16 11 d0 00 01 00 01 00 c0 01 0a c1 02 01 00 c2 02 01 02")
	snap7SetupAck = unhex("03 00 00 1b 02 f0 80 32 03 00 00 00 01 00 08 00 00 00 00 f0 00 00 01 00 01 01 e0")
	snap7SZLError = unhex("03 00 00 21 02 f0 80 32 07 00 00 00 02 00 0c 00 04 00 01 12 08 12 84 01 00 00 00 d4 02 0a 00 00 00")
)

func szlResponse(id uint16, recLen int, recs ...[]byte) []byte {
	params := []byte{0x00, 0x01, 0x12, 0x08, 0x12, 0x84, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00}
	list := binary.BigEndian.AppendUint16(nil, id)
	list = append(list, 0, 0)
	list = binary.BigEndian.AppendUint16(list, uint16(recLen))
	list = binary.BigEndian.AppendUint16(list, uint16(len(recs)))
	for _, r := range recs {
		list = append(list, r...)
	}
	data := append([]byte{0xFF, 0x09}, binary.BigEndian.AppendUint16(nil, uint16(len(list)))...)
	data = append(data, list...)
	return iso.Data(header(rosctrUserData, 2, params, data))
}

func rec0011(index uint16, order string, tail ...byte) []byte {
	r := binary.BigEndian.AppendUint16(nil, index)
	o := make([]byte, 20)
	copy(o, order)
	return append(append(r, o...), tail...)
}

func rec001c(index uint16, text string) []byte {
	r := binary.BigEndian.AppendUint16(nil, index)
	t := make([]byte, 32)
	copy(t, text)
	return append(r, t...)
}

func TestProbeBytes(t *testing.T) {
	want := unhex("03 00 00 19 02 f0 80 32 01 00 00 00 01 00 08 00 00 f0 00 00 01 00 01 01 e0")
	if got := iso.Data(setupComm(1, 480)); !bytes.Equal(got, want) {
		t.Fatalf("setup % x", got)
	}
}

func TestDetectSnap7(t *testing.T) {
	target := testsrv.TCP(t, testsrv.Script(snap7Confirm, snap7SetupAck, snap7SZLError, snap7SZLError))
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain {
		t.Fatalf("%v %v", r, err)
	}
	if r.Fingerprint.Signature != "tsap=0x0102;pdu=480;amq=1/1" || r.Fingerprint.Metadata["slot"] != "2" {
		t.Fatalf("fingerprint %+v", r.Fingerprint)
	}
	if r.Identity != nil {
		t.Fatalf("identity %+v", r.Identity)
	}
	if len(r.Exchanges) != 4 {
		t.Fatalf("%d exchanges", len(r.Exchanges))
	}
}

func TestIdentifySZL(t *testing.T) {
	m11 := szlResponse(szlModuleID, 28,
		rec0011(1, "6ES7 315-2EH14-0AB0", 0, 0, 0, 0, 0, 0),
		rec0011(6, "6ES7 315-2EH14-0AB0", 0, 0, 0, 0, 0, 5),
		rec0011(7, "", 0, 0, 'V', 3, 2, 8))
	m1c := szlResponse(szlComponentID, 34,
		rec001c(1, "Line 3 PLC"), rec001c(2, "CPU 315-2 PN/DP"), rec001c(3, "PLANT-A"),
		rec001c(4, "Original Siemens Equipment"), rec001c(5, "S C-X4U421302009"),
		rec001c(7, "CPU 315-2 PN/DP"), rec001c(11, "Hall 2"))
	target := testsrv.TCP(t, testsrv.Script(snap7Confirm, snap7SetupAck, m11, m1c))
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	id := r.Identity
	if id.Vendor != "Siemens" || id.Product != "6ES7 315-2EH14-0AB0" || id.Version != "3.2.8" ||
		id.Model != "CPU 315-2 PN/DP" || id.Name != "Line 3 PLC" || id.Serial != "S C-X4U421302009" ||
		id.Attributes["family"] != "S7-300" || id.Attributes["plantId"] != "PLANT-A" ||
		id.Attributes["hardwareVersion"] != "5" || id.Attributes["location"] != "Hall 2" {
		t.Fatalf("identity %+v", id)
	}
}

func TestTSAPFallback(t *testing.T) {
	dr := unhex("03 00 00 0b 06 80 00 01 00 02 00")
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		if bytes.Contains(req, []byte{0xc2, 0x02, 0x01, 0x02}) {
			return dr, true
		}
		if iso.TPDUType(req) == iso.TPDUConnectRequest {
			return snap7Confirm, false
		}
		return snap7SetupAck, false
	})
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Fingerprint.Metadata["slot"] != "1" {
		t.Fatalf("%v %v %+v", r, err, r.Fingerprint)
	}
}

func TestS7Plus(t *testing.T) {
	plus := iso.Data([]byte{0x72, 0x01, 0x00, 0x00})
	target := testsrv.TCP(t, testsrv.Script(snap7Confirm, plus))
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Variant != "S7comm-plus" {
		t.Fatalf("%v %v", r, err)
	}
}

func TestNotS7(t *testing.T) {
	// An MMS server: confirms, then answers the S7 PDU with a session
	// refusal.
	mmsLike := iso.Data([]byte{0x0c, 0x00})
	target := testsrv.TCP(t, testsrv.Script(snap7Confirm, mmsLike))
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched || r.Confidence != core.ConfidenceLow {
		t.Fatalf("mms: %v %v", r, err)
	}
	target = testsrv.TCP(t, testsrv.Script([]byte("220 ftp ready\r\n")))
	r, err = New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched || r.Confidence != 0 {
		t.Fatalf("ftp: %v %v", r, err)
	}
	closer := testsrv.TCP(t, func([]byte) ([]byte, bool) { return nil, true })
	closer.Timeout = 300 * time.Millisecond
	r, err = New().Detect(context.Background(), closer, core.Options{})
	if err != nil || r.Matched {
		t.Fatalf("closer: %v %v", r, err)
	}
}

func TestSetupRefused(t *testing.T) {
	refused := unhex("03 00 00 13 02 f0 80 32 03 00 00 00 01 00 00 00 00 81 04")
	target := testsrv.TCP(t, testsrv.Script(snap7Confirm, refused))
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || !r.Matched || r.Confidence != core.ConfidenceMedium {
		t.Fatalf("%v %v", r, err)
	}
}

func TestFamily(t *testing.T) {
	for in, want := range map[string]string{
		"6ES7 516-3AN01-0AB0": "S7-1500", "6ES7 214-1AG40-0XB0": "S7-1200", "6ES7 416-3XR05-0AB0": "S7-400",
		"CPU 315-2 DP": "S7-300", "6ED1052-1MD08-0BA1": "LOGO!", "SNAP7-SERVER": "",
	} {
		if got := family(in); got != want {
			t.Errorf("%s: %q, want %q", in, got, want)
		}
	}
}

func FuzzParse(f *testing.F) {
	f.Add(snap7SetupAck[7:])
	f.Add(snap7SZLError[7:])
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseSetupAck(b)
		_, _, _, _ = parseSZL(b)
		_ = version(b)
	})
}
