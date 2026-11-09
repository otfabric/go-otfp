// SPDX-License-Identifier: MIT

package main

import (
	"strconv"
	"strings"
	"testing"

	"github.com/otfabric/go-otfp/cmd/otprobe/internal/socks5test"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// detect goes through --proxy: the proxy sees a CONNECT to the target and
// the device is detected.
func TestProxy_Detect(t *testing.T) {
	plc := modbus(t)
	px := socks5test.Start(t)
	code, out, errw := exec("detect", addr(plc), "--protocol", "modbus", "--identify", "--proxy", px.URL())
	if code != exitOK || !strings.Contains(out, "Acme") {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, errw)
	}
	reqs := px.Requests()
	if len(reqs) == 0 {
		t.Fatal("the proxy saw no CONNECT")
	}
	for _, r := range reqs {
		if r.Host != plc.Host || r.Port != plc.Port {
			t.Errorf("CONNECT %+v, want %s", r, addr(plc))
		}
	}
}

// A sweep of an address only the proxy can reach: every CONNECT names it,
// and the proxy forwards each to the fake device.
func TestProxy_SweepOnlyThroughTheProxy(t *testing.T) {
	plc := modbus(t)
	px := socks5test.Start(t)
	px.Forward = func(string) string { return addr(plc) }
	code, out, errw := exec("detect", "192.0.2.1", "--ports", "502,503", "--protocol", "modbus", "-t", "2s", "--proxy", px.URL())
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, errw)
	}
	seen := map[int]bool{}
	for _, r := range px.Requests() {
		if r.Host != "192.0.2.1" {
			t.Errorf("CONNECT %+v, want 192.0.2.1", r)
		}
		seen[r.Port] = true
	}
	if !seen[502] || !seen[503] {
		t.Errorf("CONNECT ports %v, want 502 and 503", seen)
	}
}

// socks5h sends the host name to the proxy, which resolves it.
func TestProxy_RemoteNameResolution(t *testing.T) {
	plc := modbus(t)
	px := socks5test.Start(t)
	px.Forward = func(string) string { return addr(plc) }
	code, out, errw := exec("detect", "plc.invalid:502", "--protocol", "modbus", "--proxy", "socks5h://"+px.Addr)
	if code != exitOK {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, errw)
	}
	if r := px.Requests(); len(r) == 0 || r[0].AddrType != 3 || r[0].Host != "plc.invalid" || r[0].Port != 502 {
		t.Errorf("proxy saw %+v, want the name plc.invalid:502", r)
	}
}

// TLS runs over the proxied connection: a target that is not TLS fails the
// handshake (transport), after the CONNECT.
func TestProxy_TLSOverTheProxy(t *testing.T) {
	closer := testsrv.TCP(t, func([]byte) ([]byte, bool) { return nil, true })
	px := socks5test.Start(t)
	if code, out, errw := exec("detect", "tls://"+addr(closer), "--protocol", "modbus", "--proxy", px.URL()); code != exitTransport {
		t.Fatalf("exit %d, want %d\nstdout: %s\nstderr: %s", code, exitTransport, out, errw)
	}
	if len(px.Requests()) == 0 {
		t.Error("the TLS probe did not go through the proxy")
	}
}

// A proxy that refuses the CONNECT is a transport failure, and the reason
// reaches the output.
func TestProxy_RefusedIsTransport(t *testing.T) {
	plc := modbus(t)
	px := socks5test.Start(t)
	px.Reply = 2
	code, out, errw := exec("detect", addr(plc), "--protocol", "modbus", "--format", "json", "--proxy", px.URL())
	if code != exitTransport || !strings.Contains(out+errw, "not allowed by ruleset") {
		t.Fatalf("exit %d, want %d with the proxy's reason\nstdout: %s\nstderr: %s", code, exitTransport, out, errw)
	}
}

// --source-addr binds TCP and UDP probes.
func TestSourceAddr(t *testing.T) {
	if code, out, errw := exec("detect", addr(modbus(t)), "--protocol", "modbus", "--source-addr", "127.0.0.1"); code != exitOK {
		t.Fatalf("tcp: exit %d\nstdout: %s\nstderr: %s", code, out, errw)
	}
	silent := testsrv.UDP(t, testsrv.Script())
	udp := "udp://127.0.0.1:" + strconv.Itoa(silent.Port)
	if code, out, errw := exec("detect", udp, "--protocol", "bacnet", "-t", "200ms", "--source-addr", "127.0.0.1"); code != exitTimeout {
		t.Fatalf("udp: exit %d, want %d (the probe was sent and not answered)\nstdout: %s\nstderr: %s", code, exitTimeout, out, errw)
	}
}

// Invalid values, and --proxy on UDP, are invalid input (exit 3) before
// anything is sent.
func TestDialFlags_Invalid(t *testing.T) {
	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"http proxy", []string{"detect", "127.0.0.1:502", "--proxy", "http://127.0.0.1:8080"}, "--proxy"},
		{"proxy credentials", []string{"detect", "127.0.0.1:502", "--proxy", "socks5://u:p@127.0.0.1:1080"}, "credentials"},
		{"source not an IP", []string{"detect", "127.0.0.1:502", "--source-addr", "eth0"}, "--source-addr"},
		{"proxy over udp scheme", []string{"detect", "udp://127.0.0.1:47808", "--proxy", "socks5://127.0.0.1:1080"}, "TCP only"},
		{"proxy over --network udp", []string{"detect", "127.0.0.1", "--network", "udp", "--proxy", "socks5://127.0.0.1:1080"}, "TCP only"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out, errw := exec(c.args...)
			if code != exitInvalidInput || !strings.Contains(out+errw, c.want) {
				t.Fatalf("exit %d, want %d mentioning %q\nstdout: %s\nstderr: %s", code, exitInvalidInput, c.want, out, errw)
			}
		})
	}
}
