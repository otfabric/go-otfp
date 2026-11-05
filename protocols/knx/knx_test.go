// SPDX-License-Identifier: MIT

package knx

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// DESCRIPTION_RESPONSEs captured from the reference servers (route-back
// requests over Docker NAT): calimero-server 3.0-M1 (friendly name
// "calimero-otfp", tunnelling v2, KNX addresses and manufacturer DIBs) and
// knxd 0.14.73 ("knxd-otfp", v1 families).
const (
	calimeroResp = "0610020400623601020011000000000000000000000000" +
		"00f2523f6ced0363616c696d65726f2d6f74667000000000000000000000000000000000" +
		"0008020202030204021205110a110b110c110d110e110f111011110cfe0000626d323031312020"
	knxdResp = "0610020400443601020011000000000000000000e000170c1ae2516ecb96" +
		"6b6e78642d6f7466700000000000000000000000000000000000000000000802020103010401"
)

// frame builds a KNXnet/IP frame of service svc around body.
func frame(svc uint16, body ...[]byte) []byte {
	b := []byte{headerLen, version10, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[2:], svc)
	for _, p := range body {
		b = append(b, p...)
	}
	binary.BigEndian.PutUint16(b[4:], uint16(len(b)))
	return b
}

// devInfo builds a DEVICE_INFO DIB.
func devInfo(medium, status byte, addr, project uint16, serial [6]byte, mcast [4]byte, mac [6]byte, name []byte) []byte {
	b := []byte{deviceInfoLen, dibDeviceInfo, medium, status, 0, 0, 0, 0}
	binary.BigEndian.PutUint16(b[4:], addr)
	binary.BigEndian.PutUint16(b[6:], project)
	b = append(b, serial[:]...)
	b = append(b, mcast[:]...)
	b = append(b, mac[:]...)
	n := make([]byte, 30)
	copy(n, name)
	return append(b, n...)
}

// dib builds a DIB of type typ around body.
func dib(typ byte, body ...byte) []byte {
	return append([]byte{byte(len(body) + 2), typ}, body...)
}

func plainInfo() []byte {
	return devInfo(0x20, 0, 0x1101, 0, [6]byte{}, [4]byte{}, [6]byte{}, []byte("plain"))
}

func coreSvc() []byte { return dib(dibSuppSvc, famCore, 1, famTunnelling, 1) }

// isRequest reports a DESCRIPTION_REQUEST and returns its HPAI.
func isRequest(req []byte, host byte) (net.IP, uint16, bool) {
	if len(req) != 14 || binary.BigEndian.Uint16(req[2:]) != svcDescReq || req[6] != hpaiLen || req[7] != host {
		return nil, 0, false
	}
	return net.IP(req[8:12]), binary.BigEndian.Uint16(req[12:]), true
}

// server answers DESCRIPTION_REQUESTs with resp.
func server(host byte, resp []byte) testsrv.Handler {
	return func(req []byte) ([]byte, bool) {
		if _, _, ok := isRequest(req, host); ok {
			return resp, false
		}
		return nil, true
	}
}

func identify(t *testing.T, fp *Fingerprinter, target core.Target) core.Result {
	t.Helper()
	r, err := fp.Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, Trace: true})
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	return r
}

func TestInfo(t *testing.T) {
	if New().Info().Network != core.UDP || NewTCP().Info().Network != core.TCP {
		t.Fatal("networks")
	}
	i := New().Info()
	if i.Protocol != core.ProtocolKNX || i.Ports[0] != 3671 || i.Intrusiveness != core.Passive || i.Description == "" {
		t.Fatalf("info %+v", i)
	}
}

func TestProbeBytes(t *testing.T) {
	if got := descriptionRequest(hostUDP, nil, 0); !bytes.Equal(got, unhex("06 10 02 03 00 0e 08 01 00 00 00 00 00 00")) {
		t.Fatalf("route back %x", got)
	}
	if got := descriptionRequest(hostTCP, nil, 0); !bytes.Equal(got, unhex("06 10 02 03 00 0e 08 02 00 00 00 00 00 00")) {
		t.Fatalf("tcp %x", got)
	}
	if got := descriptionRequest(hostUDP, net.IPv4(192, 168, 1, 2), 0xABCD); !bytes.Equal(got, unhex("06 10 02 03 00 0e 08 01 c0 a8 01 02 ab cd")) {
		t.Fatalf("explicit %x", got)
	}
}

func TestDetectCalimero(t *testing.T) {
	hpais := make(chan []byte, 8)
	target := testsrv.UDP(t, func(req []byte) ([]byte, bool) {
		hpais <- append([]byte(nil), req[6:]...)
		return server(hostUDP, unhex(calimeroResp))(req)
	})
	r := identify(t, New(), target)
	if !r.Matched || r.Confidence != core.ConfidenceCertain || r.Variant != "tunnelling-v2" {
		t.Fatalf("%+v", r)
	}
	if hpai := <-hpais; !bytes.Equal(hpai, unhex("08 01 00 00 00 00 00 00")) {
		t.Fatalf("hpai %x: want route back", hpai)
	}
	id := r.Identity
	a := id.Attributes
	if id.Name != "calimero-otfp" || id.Serial != "" || id.VendorID != "" ||
		a["individualAddress"] != "1.1.0" || a["medium"] != "TP1" || a["mac"] != "f2:52:3f:6c:ed:03" ||
		a["serviceFamilies"] != "core v2, device-management v2, tunnelling v2" || a["tunnellingV2"] != "true" ||
		a["additionalAddresses"] != "1.1.10,1.1.11,1.1.12,1.1.13,1.1.14,1.1.15,1.1.16,1.1.17" ||
		a["multicastAddress"] != "" || a["secure"] != "" {
		t.Fatalf("identity %+v", id)
	}
	if r.Fingerprint == nil || r.Fingerprint.Signature != "svc=description;medium=TP1;families=022,032,042" {
		t.Fatalf("fingerprint %+v", r.Fingerprint)
	}
	if len(r.Exchanges) != 1 {
		t.Fatalf("exchanges %d", len(r.Exchanges))
	}
}

func TestDetectKnxd(t *testing.T) {
	r := identify(t, New(), testsrv.UDP(t, server(hostUDP, unhex(knxdResp))))
	a := r.Identity.Attributes
	if !r.Matched || r.Variant != "tunnelling" || r.Identity.Name != "knxd-otfp" ||
		a["multicastAddress"] != "224.0.23.12" || a["mac"] != "1a:e2:51:6e:cb:96" ||
		a["serviceFamilies"] != "core v1, device-management v1, tunnelling v1" || a["tunnellingV2"] != "" {
		t.Fatalf("%+v %+v", r, r.Identity)
	}
}

func TestDetectTCP(t *testing.T) {
	target := testsrv.TCP(t, server(hostTCP, unhex(calimeroResp)))
	r := identify(t, NewTCP(), target)
	if !r.Matched || r.Confidence != core.ConfidenceCertain || r.Identity.Name != "calimero-otfp" {
		t.Fatalf("%+v", r)
	}
	// A UDP-style request is not answered by this server: the TCP
	// fingerprinter must send the TCP host protocol code.
	r, err := NewTCP().Detect(context.Background(), testsrv.TCP(t, server(hostUDP, unhex(calimeroResp))), core.Options{})
	if err != nil || r.Matched {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestDetectTCPRejects(t *testing.T) {
	for name, resp := range map[string][]byte{
		"not knx":   []byte("HTTP/1.1 400 Bad Request\r\n\r\n"),
		"oversized": unhex("06 10 02 04 ff ff"),
		"echo":      descriptionRequest(hostTCP, nil, 0),
		"short":     unhex("06 10 02 04 00 40 36 01"),
	} {
		r, err := NewTCP().Detect(context.Background(), testsrv.TCP(t, testsrv.Script(resp)), core.Options{})
		if err != nil || r.Matched {
			t.Fatalf("%s: %+v %v", name, r, err)
		}
	}
}

func TestSecureAndOptionalDIBs(t *testing.T) {
	info := devInfo(0x20, 0x01, 0x11FF, 0x0123, [6]byte{0x00, 0xFA, 0x12, 0x34, 0x56, 0x78},
		[4]byte{224, 0, 23, 12}, [6]byte{2, 0, 0, 0, 0, 1}, []byte("Z\xfcrich\x01\x85\x7f GW\x00junk"))
	resp := frame(svcDescRes, info,
		dib(dibSuppSvc, famCore, 2, famDevMgmt, 1, famTunnelling, 2, famRouting, 1, famRemoteLog, 1, famRemoteConf, 1, famObjServer, 1, famSecurity, 1),
		dib(dibSecuredSvc, famTunnelling, 1, famRouting, 1),
		dib(dibIPConfig, 192, 168, 1, 10, 255, 255, 255, 0, 192, 168, 1, 1, 0, 0, 0, 0),
		dib(dibTunnelInfo, 0, 254, 0x11, 0x0A, 0, 5, 0x11, 0x0B, 0, 7),
		dib(dibExtDevInfo, 1, 0, 0, 254, 0x09, 0x1A),
		dib(dibMfrData, 0x00, 0x83, 1, 2),
		dib(0x7F, 1, 2, 3), // unknown DIB: skipped
	)
	r := identify(t, New(), testsrv.UDP(t, server(hostUDP, resp)))
	id := r.Identity
	a := id.Attributes
	if !r.Matched || r.Variant != "secure+tunnelling-v2+routing" {
		t.Fatalf("%+v", r)
	}
	want := map[string]string{
		"medium": "IP", "individualAddress": "1.1.255", "projectInstallationId": "18.3",
		"multicastAddress": "224.0.23.12", "mac": "02:00:00:00:00:01", "programmingMode": "on",
		"secure": "true", "tunnellingV2": "true", "securedServiceFamilies": "tunnelling v1, routing v1",
		"tunnellingSlots": "2", "maskVersion": "0x091A", "maxApduLength": "254", "ipAddress": "192.168.1.10",
		"serviceFamilies": "core v2, device-management v1, tunnelling v2, routing v1, remote-logging v1, remote-configuration v1, object-server v1, security v1",
	}
	for k, v := range want {
		if a[k] != v {
			t.Errorf("%s = %q, want %q", k, a[k], v)
		}
	}
	if id.Name != "Zürich GW" || id.Serial != "00FA:12345678" || id.VendorID != "131" {
		t.Fatalf("identity %+v", id)
	}
}

func TestVendorFromSerialAndNoCore(t *testing.T) {
	info := devInfo(0x10, 0, 0, 0, [6]byte{0x00, 0xFA, 0, 0, 0, 1}, [4]byte{}, [6]byte{}, nil)
	r := identify(t, New(), testsrv.UDP(t, server(hostUDP, frame(svcDescRes, info, dib(dibSuppSvc, famRouting, 1, 0x42, 1)))))
	if !r.Matched || r.Confidence != core.ConfidenceHigh || r.Variant != "routing" || r.Identity.VendorID != "250" ||
		r.Identity.Attributes["medium"] != "RF" || !strings.Contains(r.Identity.Attributes["serviceFamilies"], "0x42 v1") {
		t.Fatalf("%+v %+v", r, r.Identity)
	}
	// No families at all: no variant.
	r = identify(t, New(), testsrv.UDP(t, server(hostUDP, frame(svcDescRes, devInfo(0x04, 0, 0, 0, [6]byte{}, [4]byte{}, [6]byte{}, nil), dib(dibSuppSvc)))))
	if !r.Matched || r.Variant != "" || r.Identity.Attributes["medium"] != "PL110" {
		t.Fatalf("%+v", r)
	}
}

func TestExplicitHPAIFallback(t *testing.T) {
	resp := unhex(knxdResp)
	target := testsrv.UDP(t, func(req []byte) ([]byte, bool) {
		ip, port, ok := isRequest(req, hostUDP)
		if !ok || ip.IsUnspecified() || port == 0 {
			return nil, false // no route back: stay silent
		}
		return resp, false
	})
	target.Timeout = 300 * time.Millisecond
	r := identify(t, New(), target)
	if !r.Matched || !strings.Contains(strings.Join(r.Evidence, ";"), "local socket") {
		t.Fatalf("%+v", r)
	}
}

func TestSilent(t *testing.T) {
	target := testsrv.UDP(t, func([]byte) ([]byte, bool) { return nil, false })
	target.Timeout = 200 * time.Millisecond
	r, err := New().Detect(context.Background(), target, core.Options{Trace: true})
	var te *core.TimeoutError
	if r.Matched || !errors.As(err, &te) {
		t.Fatalf("%+v %v", r, err)
	}
	if len(r.Exchanges) != 2 {
		t.Fatalf("want route-back and explicit attempts, got %d exchanges", len(r.Exchanges))
	}
}

func TestTCPClosedAndRefused(t *testing.T) {
	target := testsrv.TCP(t, func([]byte) ([]byte, bool) { return nil, true })
	r, err := NewTCP().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := NewTCP().Detect(context.Background(), testsrv.Closed(t), core.Options{}); err == nil {
		t.Fatal("refused: want error")
	}
}

func TestNetworkMismatch(t *testing.T) {
	r, err := New().Detect(context.Background(), core.Target{Host: "127.0.0.1", Port: 1, Network: core.TCP}, core.Options{})
	if err != nil || r.Matched {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestEchoDoesNotMatch(t *testing.T) {
	target := testsrv.UDP(t, func(req []byte) ([]byte, bool) { return req, false })
	r, err := New().Detect(context.Background(), target, core.Options{})
	if err != nil || r.Matched || r.Confidence != 0 || !strings.Contains(strings.Join(r.Evidence, ";"), "echoed") {
		t.Fatalf("%+v %v", r, err)
	}
}

// TestStrayDiscarded checks that a KNXnet/IP frame of another service (a
// routing indication) is skipped and the response after it is taken.
func TestStrayDiscarded(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close() //nolint:errcheck
	go func() {
		buf := make([]byte, 1500)
		_, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(frame(0x0530, []byte{0x29, 0x00}), from)
		_, _ = pc.WriteTo(unhex(knxdResp), from)
	}()
	ua := pc.LocalAddr().(*net.UDPAddr)
	r := identify(t, New(), core.Target{Host: "127.0.0.1", Port: ua.Port, Network: core.UDP, Timeout: 2 * time.Second})
	if !r.Matched || len(r.Exchanges) != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestRejects(t *testing.T) {
	good := unhex(knxdResp)
	mut := func(f func(b []byte) []byte) []byte { return f(append([]byte(nil), good...)) }
	cases := map[string]struct {
		resp []byte
		hint bool // a low-confidence hint
	}{
		"empty":            {[]byte{}, false},
		"truncated header": {good[:4], false},
		"header length 7":  {mut(func(b []byte) []byte { b[0] = 7; return b }), false},
		"version 0x20":     {mut(func(b []byte) []byte { b[1] = 0x20; return b }), true},
		"length mismatch":  {mut(func(b []byte) []byte { return b[:len(b)-1] }), true},
		"wrong service":    {mut(func(b []byte) []byte { b[3] = 0x02; return b }), true},
		"search response":  {frame(0x0202, plainInfo(), coreSvc()), true},
		"no DIBs":          {frame(svcDescRes), true},
		"DIB length 0":     {frame(svcDescRes, plainInfo(), []byte{0, 2, 0, 0}), true},
		"DIB length 1":     {frame(svcDescRes, []byte{1, 1}), true},
		"truncated DIB":    {frame(svcDescRes, plainInfo(), coreSvc(), []byte{0x05}), true},
		"oversized DIB":    {frame(svcDescRes, plainInfo(), []byte{0xFF, dibSuppSvc, 2, 1}), true},
		"short dev info":   {frame(svcDescRes, append([]byte{0x30, dibDeviceInfo}, make([]byte, 0x2E)...), coreSvc()), true},
		"long dev info":    {frame(svcDescRes, append(append([]byte{0x38, dibDeviceInfo}, make([]byte, 0x34)...), 0, 0), coreSvc()), true},
		"svc first":        {frame(svcDescRes, coreSvc(), plainInfo()), true},
		"second not svc":   {frame(svcDescRes, plainInfo(), dib(dibMfrData, 0, 1)), true},
		"dev info twice":   {frame(svcDescRes, plainInfo(), coreSvc(), plainInfo()), true},
		"svc twice":        {frame(svcDescRes, plainInfo(), coreSvc(), coreSvc()), true},
		"svc odd length":   {frame(svcDescRes, plainInfo(), dib(dibSuppSvc, famCore, 1, famTunnelling)), true},
		"family version 0": {frame(svcDescRes, plainInfo(), dib(dibSuppSvc, famCore, 0)), true},
		"family id 0":      {frame(svcDescRes, plainInfo(), dib(dibSuppSvc, 0, 1)), true},
		"family repeated":  {frame(svcDescRes, plainInfo(), dib(dibSuppSvc, famCore, 1, famCore, 2)), true},
		"secured odd":      {frame(svcDescRes, plainInfo(), coreSvc(), dib(dibSecuredSvc, famTunnelling)), true},
		"only dev info":    {frame(svcDescRes, plainInfo()), true},
	}
	for name, c := range cases {
		r, err := New().Detect(context.Background(), testsrv.UDP(t, testsrv.Script(c.resp)), core.Options{})
		if err != nil {
			// An empty datagram is a valid UDP read of zero octets.
			t.Fatalf("%s: %v", name, err)
		}
		if r.Matched {
			t.Fatalf("%s: matched %+v", name, r)
		}
		if c.hint != (r.Confidence == core.ConfidenceLow) {
			t.Fatalf("%s: confidence %v, hint %v (%v)", name, r.Confidence, c.hint, r.Evidence)
		}
	}
}

func TestFriendlyName(t *testing.T) {
	for in, want := range map[string]string{
		"KNX IP\x00garbage":     "KNX IP",
		"  pad  \x00":           "pad",
		"a\x01b\x1fc\x7fd\x9fe": "abcde",
		"\xe9t\xe9":             "été",
		"":                      "",
	} {
		raw := make([]byte, 30)
		copy(raw, in)
		if got := friendlyName(raw); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
	full := bytes.Repeat([]byte{'x'}, 30)
	if got := friendlyName(full); got != string(full) {
		t.Fatalf("unterminated name %q", got)
	}
}

func TestHelpers(t *testing.T) {
	if individual(0xFFFF) != "15.15.255" || individual(0x1203) != "1.2.3" {
		t.Fatal("individual")
	}
	if mediumName(0x99) != "0x99" || mediumName(0x02) != "TP1" {
		t.Fatal("medium")
	}
	for id := byte(0); id < 0x0B; id++ {
		if familyName(id) == "" {
			t.Fatal("family name")
		}
	}
	if _, _, ok := localHPAI(&net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 1}); ok {
		t.Fatal("tcp addr")
	}
	if _, _, ok := localHPAI(&net.UDPAddr{IP: net.IPv4zero, Port: 1}); ok {
		t.Fatal("unspecified")
	}
	if _, _, ok := localHPAI(&net.UDPAddr{IP: net.ParseIP("::1"), Port: 1}); ok {
		t.Fatal("ipv6")
	}
	if _, _, ok := localHPAI(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 70000}); ok {
		t.Fatal("port range")
	}
	if ip, port, ok := localHPAI(&net.UDPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 3671}); !ok || port != 3671 || !ip.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatal("valid")
	}
	if framer(unhex("06 20 02 04 00 10")) != -1 || framer(unhex("06 10 02 04 ff ff")) != -1 || framer(unhex("06 10")) != 0 {
		t.Fatal("framer")
	}
	if !answers([]byte("x")) || answers(frame(0x0530)) || !answers(unhex(knxdResp)) || !answers(frame(0x0202)) {
		t.Fatal("answers")
	}
	// Short optional DIBs are tolerated but yield nothing.
	d, err := parseDIBs(append(append(plainInfo(), coreSvc()...), append(append(append(dib(dibIPCurConfig, 1), dib(dibTunnelInfo)...), dib(dibExtDevInfo, 1)...), dib(dibMfrData, 1)...)...))
	if err != nil || d.ipAddress != "" || d.tunnelSlots != 0 || d.mask != 0 || d.mfr != 0 {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestCancelled(t *testing.T) {
	target := testsrv.UDP(t, func([]byte) ([]byte, bool) { return nil, false })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, _ := New().Detect(ctx, target, core.Options{})
	if r.Matched {
		t.Fatal("matched")
	}
}
