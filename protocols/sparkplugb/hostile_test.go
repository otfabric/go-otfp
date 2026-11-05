// SPDX-License-Identifier: MIT

package sparkplugb

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
	"github.com/otfabric/go-otfp/protocols/mqtt"
)

// readOnly is what the fingerprinter needs to send anything.
var readOnly = core.Options{MaxIntrusiveness: core.ReadOnly}

// hostBroker carries the retained Sparkplug 3.0 STATE of a host
// application and an edge node's NBIRTH.
func hostBroker() *broker {
	return &broker{connack: accept, msgs: [][]byte{
		pub("spBv1.0/STATE/scada", []byte(state3), true),
		pub("spBv1.0/plant/NBIRTH/edge1", birth(1, "Inputs/Temperature"), false),
	}}
}

func TestChaos(t *testing.T) {
	// A short window: identify listens for all of it on every run.
	fp := &Fingerprinter{Window: 300 * time.Millisecond}
	t.Run("host-application", chaos.Suite{
		FP:      fp,
		Options: readOnly,
		TCP:     func(t testing.TB, cfg chaos.Config) core.Target { return chaos.Raw(t, cfg, hostBroker().serve) },
	}.Run)
	t.Run("sparkplug-2", chaos.Suite{
		FP:      fp,
		Options: readOnly,
		TCP: func(t testing.TB, cfg chaos.Config) core.Target {
			b := &broker{connack: accept, msgs: [][]byte{pub("STATE/scada", []byte("ONLINE"), true)}}
			return chaos.Raw(t, cfg, b.serve)
		},
		Seeds: 1,
	}.Run)
}

// tap records every byte a client sends on one connection.
type tap struct {
	net.Conn
	buf bytes.Buffer
}

func (c *tap) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.buf.Write(b[:n])
	return n, err
}

// streams records, per connection, every byte the fingerprinter sends.
type streams struct {
	mu    sync.Mutex
	all   [][]byte
	conns int
}

// serve runs fn on a tapped connection, then half-closes it and reads on
// until the client closes, so that nothing sent after the broker stopped
// reading escapes.
func (s *streams) serve(fn func(net.Conn)) func(net.Conn) {
	return func(c net.Conn) {
		s.mu.Lock()
		s.conns++
		s.mu.Unlock()
		tc := &tap{Conn: c}
		fn(tc)
		if hc, ok := c.(interface{ CloseWrite() error }); ok {
			_ = hc.CloseWrite()
		}
		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, _ = io.Copy(io.Discard, tc)
		s.mu.Lock()
		s.all = append(s.all, tc.buf.Bytes())
		s.mu.Unlock()
	}
}

func (s *streams) get() (all [][]byte, conns int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.all), s.conns
}

func readStr(t *testing.T, b []byte) (string, []byte) {
	t.Helper()
	if len(b) < 2 || len(b)-2 < int(binary.BigEndian.Uint16(b)) {
		t.Fatalf("string % x", b)
	}
	n := int(binary.BigEndian.Uint16(b))
	return string(b[2 : 2+n]), b[2+n:]
}

// checkStream decodes one connection's bytes and fails on anything but
// CONNECT (clean session, no will, no credentials), a QoS 0 SUBSCRIBE to
// exactly the documented filters, UNSUBSCRIBE of them, PINGREQ and
// DISCONNECT. It returns the SUBSCRIBEs seen.
func checkStream(t *testing.T, stream []byte) int {
	t.Helper()
	r := bufio.NewReader(bytes.NewReader(stream))
	level, subs := byte(0), 0
	for i := 0; ; i++ {
		raw, err := readPacket(r)
		if err == io.EOF {
			return subs
		}
		if err != nil {
			t.Fatalf("bytes after the last whole packet: %v (% x)", err, stream)
		}
		p, err := mqtt.ParsePacket(raw)
		if err != nil {
			t.Fatalf("packet % x: %v", raw, err)
		}
		if (i == 0) != (p.Type == mqtt.TypeConnect) {
			t.Fatalf("packet %d is %s", i, mqtt.TypeName(p.Type))
		}
		b := p.Body
		switch p.Type {
		case mqtt.TypeConnect:
			if len(b) < 10 || string(b[:6]) != "\x00\x04MQTT" || (b[6] != mqtt.Level311 && b[6] != mqtt.Level5) {
				t.Fatalf("CONNECT % x", b)
			}
			if b[7] != 0x02 { // clean session; no will, user name or password
				t.Fatalf("CONNECT flags 0x%02x", b[7])
			}
			level, b = b[6], b[10:]
			if level >= mqtt.Level5 {
				if len(b) == 0 || b[0] != 0 {
					t.Fatalf("CONNECT properties % x", b)
				}
				b = b[1:]
			}
			if id, rest := readStr(t, b); id == "" || len(rest) != 0 {
				t.Fatalf("CONNECT payload % x: a will or credentials follow the client identifier", b)
			}
		case mqtt.TypePingreq, mqtt.TypeDisconnect:
			if len(b) != 0 {
				t.Fatalf("%s with a body % x", mqtt.TypeName(p.Type), b)
			}
		case mqtt.TypeSubscribe, mqtt.TypeUnsubscribe:
			if len(b) < 2 {
				t.Fatalf("%s % x", mqtt.TypeName(p.Type), b)
			}
			b = b[2:]
			if level >= mqtt.Level5 {
				if len(b) == 0 || b[0] != 0 {
					t.Fatalf("properties % x", b)
				}
				b = b[1:]
			}
			var fs []string
			for len(b) > 0 {
				var f string
				f, b = readStr(t, b)
				fs = append(fs, f)
				if p.Type == mqtt.TypeSubscribe {
					if len(b) == 0 || b[0] != 0 { // QoS 0, no other option
						t.Fatalf("subscription options of %q: % x", f, b)
					}
					b = b[1:]
				}
			}
			if !slices.Equal(fs, Filters) {
				t.Fatalf("%s of %q, want %q", mqtt.TypeName(p.Type), fs, Filters)
			}
			if p.Type == mqtt.TypeSubscribe {
				subs++
			}
		default:
			t.Fatalf("%s sent", mqtt.TypeName(p.Type))
		}
	}
}

// The safety contract, on the wire: CONNECT (clean session, no will, no
// credentials), one QoS 0 SUBSCRIBE to exactly spBv1.0/STATE/+, STATE/+,
// spBv1.0/+/+/+ and spBv1.0/+/+/+/+, UNSUBSCRIBE, DISCONNECT. Never a
// PUBLISH (no NCMD, DCMD, rebirth request or STATE), never an
// acknowledgement of the broker's QoS 1 messages, and nothing at all when
// only passive probes are allowed.
func TestSafetyContract(t *testing.T) {
	brokers := map[string]func() *broker{
		"host-application": hostBroker,
		"quiet":            func() *broker { return &broker{connack: accept} },
		"refuses-subscriptions": func() *broker {
			return &broker{connack: accept, codes: []byte{0x80, 0x80, 0x80, 0x80}}
		},
		"v5-only": func() *broker {
			return &broker{connack: func(l byte) []byte {
				if l >= mqtt.Level5 {
					return []byte{0x20, 0x03, 0x00, 0x00, 0x00}
				}
				return []byte{0x20, 0x02, 0x00, 0x01}
			}, msgs: [][]byte{pkt(0x31, append(str("spBv1.0/STATE/scada"), append([]byte{0}, state3...)...))}}
		},
		"auth-refused": func() *broker { return &broker{connack: func(byte) []byte { return []byte{0x20, 0x02, 0x00, 0x05} }} },
		// A QoS 1 message must not be acknowledged (no PUBACK).
		"qos1-message": func() *broker {
			m := pkt(0x32, append(append(str("spBv1.0/STATE/scada"), 0x00, 0x07), state3...))
			return &broker{connack: accept, msgs: [][]byte{m}}
		},
	}
	for name, mk := range brokers {
		for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				t.Run(name+"/"+level.String()+"/"+mode.String(), func(t *testing.T) {
					t.Parallel()
					rec := &streams{}
					target := testsrv.Raw(t, rec.serve(mk().serve))
					target.Timeout = 300 * time.Millisecond
					fp := &Fingerprinter{Window: 200 * time.Millisecond}
					r, err := fp.Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level})
					if err != nil {
						t.Fatalf("%v %v", r, err)
					}
					if level < core.ReadOnly {
						time.Sleep(50 * time.Millisecond)
						if _, conns := rec.get(); conns != 0 || r.Matched {
							t.Fatalf("%d connections with passive probes only: %v", conns, r)
						}
						return
					}
					var all [][]byte
					for range 100 { // a stream is recorded as the client closes
						var conns int
						if all, conns = rec.get(); conns > 0 && len(all) == conns {
							break
						}
						time.Sleep(10 * time.Millisecond)
					}
					if len(all) == 0 {
						t.Fatal("nothing sent")
					}
					subs := 0
					for _, s := range all {
						subs += checkStream(t, s)
					}
					if name != "auth-refused" && subs != 1 {
						t.Fatalf("%d SUBSCRIBEs", subs)
					}
				})
			}
		}
	}
}
