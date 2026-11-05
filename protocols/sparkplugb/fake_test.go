// SPDX-License-Identifier: MIT

package sparkplugb

import (
	"bufio"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
	"github.com/otfabric/go-otfp/protocols/mqtt"
)

// broker is a scripted MQTT broker carrying Sparkplug traffic.
type broker struct {
	// connack answers a CONNECT of the given level; nil closes.
	connack func(level byte) []byte
	// codes are the SUBACK codes; nil grants every filter.
	codes []byte
	// msgs are sent after the SUBACK.
	msgs [][]byte
	// delay is waited before each message.
	delay time.Duration

	mu   sync.Mutex
	seen []byte
	pubs int
}

func (b *broker) wait(n int) []byte {
	for range 100 {
		b.mu.Lock()
		got := append([]byte(nil), b.seen...)
		b.mu.Unlock()
		if len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.seen...)
}

func readPacket(r *bufio.Reader) ([]byte, error) {
	h, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	out := []byte{h}
	rem, mult := 0, 1
	for range 4 {
		c, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		out = append(out, c)
		rem += int(c&0x7F) * mult
		mult *= 128
		if c&0x80 == 0 {
			break
		}
	}
	body := make([]byte, rem)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(out, body...), nil
}

func (b *broker) serve(c net.Conn) {
	r := bufio.NewReader(c)
	level := mqtt.Level311
	for {
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		raw, err := readPacket(r)
		if err != nil {
			return
		}
		p, err := mqtt.ParsePacket(raw)
		if err != nil {
			return
		}
		b.mu.Lock()
		b.seen = append(b.seen, p.Type)
		if p.Type == mqtt.TypePublish {
			b.pubs++
		}
		b.mu.Unlock()
		switch p.Type {
		case mqtt.TypeConnect:
			level = p.Body[6]
			if b.connack == nil {
				return
			}
			resp := b.connack(level)
			if resp == nil {
				return
			}
			_, _ = c.Write(resp)
		case mqtt.TypeSubscribe:
			codes := b.codes
			if codes == nil {
				codes = make([]byte, len(Filters))
			}
			body := []byte{p.Body[0], p.Body[1]}
			if level >= mqtt.Level5 {
				body = append(body, 0)
			}
			_, _ = c.Write(pkt(0x90, append(body, codes...)))
			go func() {
				for _, m := range b.msgs {
					time.Sleep(b.delay)
					if _, err := c.Write(m); err != nil {
						return
					}
				}
			}()
		case mqtt.TypeUnsubscribe:
			_, _ = c.Write(pkt(0xB0, []byte{p.Body[0], p.Body[1]}))
		case mqtt.TypeDisconnect:
			return
		}
	}
}

func (b *broker) target(t *testing.T) core.Target {
	tg := testsrv.Raw(t, b.serve)
	tg.Timeout = time.Second
	return tg
}

func pkt(header byte, body []byte) []byte {
	return append(mqtt.AppendVarint([]byte{header}, len(body)), body...)
}

func str(s string) []byte { return append([]byte{byte(len(s) >> 8), byte(len(s) & 0xFF)}, s...) }

// pub is a QoS 0 MQTT 3.1.1 PUBLISH.
func pub(topic string, payload []byte, retain bool) []byte {
	h := byte(0x30)
	if retain {
		h |= 0x01
	}
	return pkt(h, append(str(topic), payload...))
}

func accept(byte) []byte { return []byte{0x20, 0x02, 0x00, 0x00} }

// Protocol Buffers encoders for the payloads.
func pbVarintEnc(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v&0x7F)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

func pbKey(num uint64, wt byte) []byte { return pbVarintEnc(num<<3 | uint64(wt)) }

func pbUint(num, v uint64) []byte { return append(pbKey(num, wtVarint), pbVarintEnc(v)...) }

func pbBytes(num uint64, b []byte) []byte {
	out := append(pbKey(num, wtBytes), pbVarintEnc(uint64(len(b)))...)
	return append(out, b...)
}

func metricPB(name string, datatype, value uint64) []byte {
	m := pbBytes(1, []byte(name))
	m = append(m, pbUint(4, datatype)...)
	return append(m, pbUint(11, value)...)
}

// birth is an NBIRTH payload: timestamp, bdSeq, the named metrics, seq 0.
func birth(bdSeq uint64, names ...string) []byte {
	p := pbUint(1, 1700000000000)
	p = append(p, pbBytes(2, metricPB("bdSeq", 8, bdSeq))...)
	for _, n := range names {
		p = append(p, pbBytes(2, metricPB(n, 11, 1))...)
	}
	return append(p, pbUint(3, 0)...)
}
