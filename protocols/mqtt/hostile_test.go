// SPDX-License-Identifier: MIT

package mqtt

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
)

// goodBroker is a broker that accepts MQTT 5 and 3.1.1, answers PINGREQ,
// SUBSCRIBE and UNSUBSCRIBE and holds a retained $SYS/broker/version.
func goodBroker() *fake {
	return &fake{
		connack:  byLevel(connack5(0, 0), connack4(0, 0)),
		ping:     true,
		unsuback: true,
		after:    publish(Level5, "$SYS/broker/version", []byte("broker version 2.0.18"), 0x01),
	}
}

func TestChaos(t *testing.T) {
	t.Run("broker", chaos.Suite{
		FP:      &Fingerprinter{Window: 300 * time.Millisecond},
		Options: core.Options{MaxIntrusiveness: core.ReadOnly},
		TCP:     func(t testing.TB, cfg chaos.Config) core.Target { return chaos.Raw(t, cfg, goodBroker().serve) },
	}.Run)
	t.Run("passive", chaos.Suite{
		FP:  &Fingerprinter{Window: 300 * time.Millisecond},
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.Raw(t, cfg, goodBroker().serve) },
	}.Run)
	t.Run("v5-only", chaos.Suite{
		FP: New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target {
			f := &fake{connack: byLevel(connack5(0, 0), connack4(0, 1)), ping: true}
			return chaos.Raw(t, cfg, f.serve)
		},
		Modes: []core.Mode{core.ModeDetect},
	}.Run)
	t.Run("auth-refused", chaos.Suite{
		FP: New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target {
			f := &fake{connack: byLevel(connack5(0, 0x87), connack4(0, 5))}
			return chaos.Raw(t, cfg, f.serve)
		},
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
	mu  sync.Mutex
	all [][]byte
}

// serve runs fn on a tapped connection, then half-closes it (the broker
// is done, as a closing broker is) and reads on until the client closes,
// so that nothing sent after the broker stopped reading escapes.
func (s *streams) serve(fn func(net.Conn)) func(net.Conn) {
	return func(c net.Conn) {
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

func (s *streams) get() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.all)
}

// filters decodes the topic filters of a SUBSCRIBE (options true) or
// UNSUBSCRIBE body after the packet identifier, and the subscription
// options octets.
func filters(t *testing.T, level byte, b []byte, options bool) (out []string, opts []byte) {
	t.Helper()
	if level >= Level5 {
		n, k, err := Varint(b)
		if err != nil || n != 0 {
			t.Fatalf("SUBSCRIBE/UNSUBSCRIBE properties % x", b)
		}
		b = b[k:]
	}
	for len(b) > 0 {
		f, rest, err := readString(b)
		if err != nil {
			t.Fatalf("topic filter % x: %v", b, err)
		}
		out, b = append(out, f), rest
		if options {
			if len(b) == 0 {
				t.Fatal("subscription options missing")
			}
			opts, b = append(opts, b[0]), b[1:]
		}
	}
	return out, opts
}

// checkStream decodes one connection's bytes and fails on anything but
// CONNECT (clean session, no will, no credentials), PINGREQ, a QoS 0
// SUBSCRIBE to the $SYS version topics when subscribe is allowed,
// UNSUBSCRIBE of them and DISCONNECT. It returns the SUBSCRIBEs seen.
func checkStream(t *testing.T, stream []byte, subscribe bool) int {
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
		p, err := ParsePacket(raw)
		if err != nil {
			t.Fatalf("packet % x: %v", raw, err)
		}
		if i == 0 && p.Type != TypeConnect {
			t.Fatalf("first packet %s", TypeName(p.Type))
		}
		switch p.Type {
		case TypeConnect:
			if i != 0 {
				t.Fatal("a second CONNECT on one connection")
			}
			b := p.Body
			if len(b) < 10 || string(b[:6]) != "\x00\x04MQTT" || (b[6] != Level311 && b[6] != Level5) {
				t.Fatalf("CONNECT % x", b)
			}
			// Clean session only: no will flag, will QoS or retain, no
			// user name, no password.
			if b[7] != 0x02 || binary.BigEndian.Uint16(b[8:]) != KeepAlive {
				t.Fatalf("CONNECT flags 0x%02x keep-alive % x", b[7], b[8:10])
			}
			level, b = b[6], b[10:]
			if level >= Level5 {
				if len(b) == 0 || b[0] != 0 {
					t.Fatalf("CONNECT properties % x", b)
				}
				b = b[1:]
			}
			id, rest, err := readString(b)
			if err != nil || id == "" || len(rest) != 0 {
				t.Fatalf("CONNECT payload % x: a will or credentials follow the client identifier", b)
			}
		case TypePingreq, TypeDisconnect:
			if len(p.Body) != 0 {
				t.Fatalf("%s with a body % x", TypeName(p.Type), p.Body)
			}
		case TypeSubscribe, TypeUnsubscribe:
			if len(p.Body) < 2 {
				t.Fatalf("%s % x", TypeName(p.Type), p.Body)
			}
			if p.Type == TypeSubscribe {
				if !subscribe {
					t.Fatal("SUBSCRIBE without identify mode and read-only probes")
				}
				subs++
			}
			fs, opts := filters(t, level, p.Body[2:], p.Type == TypeSubscribe)
			if len(fs) == 0 {
				t.Fatalf("%s without a filter", TypeName(p.Type))
			}
			for _, f := range fs {
				if !slices.Contains(sysFilters, f) {
					t.Fatalf("%s of %q", TypeName(p.Type), f)
				}
			}
			for _, o := range opts {
				if o != 0 { // QoS 0, and in MQTT 5 no other option
					t.Fatalf("subscription options 0x%02x", o)
				}
			}
		default:
			t.Fatalf("%s sent", TypeName(p.Type))
		}
	}
}

// The safety contract, on the wire: CONNECT (clean session, no will, no
// credentials), PINGREQ, UNSUBSCRIBE, DISCONNECT and, only in identify
// mode with read-only probes allowed, a QoS 0 SUBSCRIBE to
// $SYS/broker/version and $SYS/brokers/+/version. Never PUBLISH, PUBACK,
// PUBREC, PUBREL, PUBCOMP or AUTH, never QoS above 0.
func TestSafetyContract(t *testing.T) {
	brokers := map[string]func() *fake{
		"accepting": goodBroker,
		"v5-refuses-311": func() *fake {
			return &fake{connack: byLevel(connack5(0, 0), connack4(0, 1)), ping: true, unsuback: true}
		},
		"311-only": func() *fake {
			f := goodBroker()
			f.connack = byLevel(connack5(0, 0x84), connack4(0, 0))
			return f
		},
		"closes-v5": func() *fake {
			f := goodBroker()
			f.connack = byLevel(nil, connack4(0, 0))
			return f
		},
		"auth-refused": func() *fake { return &fake{connack: always(connack4(0, 5))} },
		// A QoS 1 PUBLISH must not be acknowledged (no PUBACK).
		"qos1-publish": func() *fake {
			f := goodBroker()
			f.after = publish(Level5, "$SYS/broker/version", []byte("x"), 0x02)
			return f
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
					if err != nil || !r.Matched {
						t.Fatalf("%v %v", r, err)
					}
					allowed := mode == core.ModeIdentify && level >= core.ReadOnly
					var all [][]byte
					for range 100 { // the server records a stream as the client closes
						if all = rec.get(); len(all) > 0 && len(all) >= connections(r) {
							break
						}
						time.Sleep(10 * time.Millisecond)
					}
					if len(all) == 0 {
						t.Fatal("nothing sent")
					}
					subs := 0
					for _, s := range all {
						subs += checkStream(t, s, allowed)
					}
					if allowed && name == "accepting" && subs != 1 {
						t.Fatalf("%d SUBSCRIBEs to an accepting broker", subs)
					}
				})
			}
		}
	}
}

// connections is the number of connections a result's evidence implies:
// one, or two after a closed or refused first CONNECT.
func connections(r core.Result) int {
	for _, e := range r.Evidence {
		if bytes.Contains([]byte(e), []byte("closed on an MQTT")) || bytes.Contains([]byte(e), []byte(" refused: ")) {
			return 2
		}
	}
	return 1
}
