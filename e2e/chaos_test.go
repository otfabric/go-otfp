// SPDX-License-Identifier: MIT

package e2e_test

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/testsrv"
	"github.com/otfabric/go-otfp/protocols/mqtt"
)

// mqttBroker is a minimal MQTT broker: it accepts MQTT 3.1.1 and 5
// CONNECTs, answers PINGREQ, grants every SUBSCRIBE and acknowledges every
// UNSUBSCRIBE, and closes the connection, as a broker must, on a first
// packet that is not a CONNECT and on anything that is not MQTT.
func mqttBroker(c net.Conn) {
	var buf []byte
	chunk := make([]byte, 4096)
	frame := mqtt.Framer(mqtt.DefaultMaxPacket)
	level := byte(0)
	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := c.Read(chunk)
		if err != nil {
			return
		}
		buf = append(buf, chunk[:n]...)
		for len(buf) > 0 {
			want := frame(buf)
			if want < 0 {
				return
			}
			if want == 0 || len(buf) < want {
				break
			}
			p, err := mqtt.ParsePacket(buf[:want])
			buf = buf[want:]
			if err != nil || (level == 0) != (p.Type == mqtt.TypeConnect) {
				return
			}
			var resp []byte
			v5 := level >= mqtt.Level5
			switch p.Type {
			case mqtt.TypeConnect:
				if len(p.Body) < 7 || (p.Body[6] != mqtt.Level311 && p.Body[6] != mqtt.Level5) {
					return
				}
				level = p.Body[6]
				resp = []byte{0x20, 0x02, 0x00, 0x00}
				if level >= mqtt.Level5 {
					resp = []byte{0x20, 0x03, 0x00, 0x00, 0x00}
				}
			case mqtt.TypePingreq:
				resp = []byte{0xD0, 0x00}
			case mqtt.TypeSubscribe, mqtt.TypeUnsubscribe:
				if len(p.Body) < 2 {
					return
				}
				body := []byte{p.Body[0], p.Body[1]}
				if v5 {
					body = append(body, 0x00)
				}
				head := byte(0xB0)
				if p.Type == mqtt.TypeSubscribe {
					head = 0x90
					body = append(body, 0x00, 0x00) // two filters granted at QoS 0
				} else if v5 {
					body = append(body, 0x00, 0x00) // two reason codes: success
				}
				resp = append([]byte{head, byte(len(body))}, body...)
			default: // DISCONNECT, or a packet a client does not send
				return
			}
			if _, err := c.Write(resp); err != nil {
				return
			}
		}
	}
}

// tcpSpeakers are the TCP speakers of the matrix behind a fault: those of
// speakers() and the MQTT broker, which needs a connection of its own.
func tcpSpeakers() map[core.Protocol]func(t testing.TB, cfg chaos.Config) core.Target {
	out := map[core.Protocol]func(t testing.TB, cfg chaos.Config) core.Target{
		core.ProtocolMQTT: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.Raw(t, cfg, mqttBroker) },
	}
	for p, h := range speakers() {
		out[p] = func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, h) }
	}
	return out
}

func echo(req []byte) ([]byte, bool) { return req, false }

// An echo service (TCP/UDP 7, a debugging loopback, a misconfigured
// gateway) returns each probe unchanged. The probe carries the
// fingerprinter's own header, transaction identifiers and function codes,
// so a fingerprinter that only checks the echoed fields matches its own
// request: none may.
func TestEchoIsNoProtocol(t *testing.T) {
	targets := map[core.Network]core.Target{
		core.TCP: testsrv.TCP(t, echo),
		core.UDP: testsrv.UDP(t, echo),
	}
	for _, fp := range otfp.Fingerprinters() {
		info := fp.Info()
		target := targets[info.Network]
		target.Timeout = 300 * time.Millisecond
		t.Run(info.Protocol.Slug()+"-"+info.Network.String(), func(t *testing.T) {
			t.Parallel()
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				r, err := fp.Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: core.ReadOnly})
				fuzzkit.Check(t, info.Protocol, r, err)
				if r.Matched {
					t.Fatalf("%s: an echo service matched: %v", mode, r)
				}
			}
		})
	}
}

// The cross-protocol matrix behind chaos: through fragmented writes every
// speaker is still detected as its own protocol and no other; through a
// flipped bit no other fingerprinter reaches a certain match.
func TestCrossProtocolMatrixUnderChaos(t *testing.T) {
	var fps []core.Fingerprinter
	for _, fp := range otfp.Fingerprinters() {
		if fp.Info().Network == core.TCP {
			fps = append(fps, fp)
		}
	}
	faults := []chaos.Config{
		{Fault: chaos.OneByte},
		{Fault: chaos.Chunks, Seed: 7},
		{Fault: chaos.BitFlip, Seed: 1},
		{Fault: chaos.BitFlip, Seed: 2},
		{Fault: chaos.BitFlip, Seed: 3},
		{Fault: chaos.BitFlip, Seed: 4, After: 1},
	}
	// One goroutine per case: most cases wait out a foreign fingerprinter's
	// timeout, so running them all at once keeps the matrix to seconds.
	var wg sync.WaitGroup
	for speaker, serve := range tcpSpeakers() {
		for _, cfg := range faults {
			served := serve(t, cfg)
			for _, fp := range fps {
				p := fp.Info().Protocol
				target := served
				target.Timeout = 300 * time.Millisecond
				if cfg.Fault.Complete() && p == speaker {
					// Room for a response written one octet at a time
					// under -race on a loaded runner.
					target.Timeout = chaos.CompleteTimeout
				}
				name := fmt.Sprintf("%s-on-%s/%s/seed%d/after%d", p.Slug(), speaker.Slug(), cfg.Fault, cfg.Seed, cfg.After)
				wg.Go(func() {
					for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
						r, err := fp.Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: core.ReadOnly})
						if msg := fuzzkit.Violation(p, r, err); msg != "" {
							t.Errorf("%s %s: %s", name, mode, msg)
						}
						switch {
						case cfg.Fault.Complete() && p == speaker && !r.Matched:
							t.Errorf("%s %s: did not detect its own protocol: %v (%v)", name, mode, r, err)
						case cfg.Fault.Complete() && p != speaker && r.Matched:
							t.Errorf("%s %s: false positive on a %s device: %v", name, mode, speaker, r)
						case p != speaker && r.Confidence >= core.ConfidenceCertain:
							t.Errorf("%s %s: certain match on a corrupted %s reply: %v", name, mode, speaker, r)
						}
					}
				})
			}
		}
	}
	wg.Wait()
}
