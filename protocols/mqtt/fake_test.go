// SPDX-License-Identifier: MIT

package mqtt

import (
	"bufio"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// fake is a scripted MQTT broker for the tests.
type fake struct {
	// connack answers a CONNECT of the given level; nil closes.
	connack func(level byte) []byte
	// ping answers PINGREQ with PINGRESP.
	ping bool
	// suback answers SUBSCRIBE; nil uses a granted SUBACK.
	suback func(level byte, id uint16, n int) []byte
	// after is sent after the SUBACK (PUBLISH packets).
	after []byte
	// silentSub sends nothing on SUBSCRIBE.
	silentSub bool
	// unsuback answers UNSUBSCRIBE.
	unsuback bool

	mu   sync.Mutex
	seen []byte // packet types received, in order
}

func (f *fake) types() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]byte(nil), f.seen...)
}

// wait returns the packet types once n have arrived (or after a second).
func (f *fake) wait(n int) []byte {
	for range 100 {
		if got := f.types(); len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	return f.types()
}

// readPacket reads one control packet.
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

func (f *fake) serve(c net.Conn) {
	r := bufio.NewReader(c)
	level := Level311
	for {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		raw, err := readPacket(r)
		if err != nil {
			return
		}
		p, err := ParsePacket(raw)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.seen = append(f.seen, p.Type)
		f.mu.Unlock()
		var resp []byte
		switch p.Type {
		case TypeConnect:
			level = p.Body[6]
			if f.connack == nil {
				return
			}
			if resp = f.connack(level); resp == nil {
				return
			}
		case TypePingreq:
			if !f.ping {
				continue
			}
			resp = []byte{0xD0, 0x00}
		case TypeSubscribe:
			if f.silentSub {
				continue
			}
			id := uint16(p.Body[0])<<8 | uint16(p.Body[1])
			n := countFilters(level, p.Body[2:], true)
			if f.suback != nil {
				resp = f.suback(level, id, n)
			} else {
				resp = suback(level, id, make([]byte, n)...)
			}
			resp = append(resp, f.after...)
		case TypeUnsubscribe:
			if !f.unsuback {
				continue
			}
			id := []byte{p.Body[0], p.Body[1]}
			if level >= Level5 {
				resp = packet(0xB0, append(id, 0x00, 0x00, 0x00))
			} else {
				resp = packet(0xB0, id)
			}
		case TypeDisconnect:
			return
		}
		if _, err := c.Write(resp); err != nil {
			return
		}
	}
}

func countFilters(level byte, b []byte, options bool) int {
	if level >= Level5 {
		b = b[1:]
	}
	n := 0
	for len(b) >= 2 {
		l := int(b[0])<<8 | int(b[1])
		b = b[2+l:]
		if options {
			b = b[1:]
		}
		n++
	}
	return n
}

func (f *fake) target(t *testing.T) core.Target {
	return testsrv.Raw(t, f.serve)
}

func connack4(sp, rc byte) []byte { return []byte{0x20, 0x02, sp, rc} }

func connack5(sp, rc byte, props ...byte) []byte {
	body := []byte{sp, rc}
	body = AppendVarint(body, len(props))
	return packet(0x20, append(body, props...))
}

func suback(level byte, id uint16, codes ...byte) []byte {
	body := appendU16(nil, id)
	if level >= Level5 {
		body = append(body, 0x00)
	}
	return packet(0x90, append(body, codes...))
}

func publish(level byte, topic string, payload []byte, flags byte) []byte {
	body := appendString(nil, topic)
	if flags&0x06 != 0 {
		body = appendU16(body, 7)
	}
	if level >= Level5 {
		body = append(body, 0x00)
	}
	return packet(TypePublish<<4|flags, append(body, payload...))
}

// always answers every CONNECT with the same CONNACK.
func always(b []byte) func(byte) []byte { return func(byte) []byte { return b } }

// byLevel answers MQTT 5 and 3.1.1 CONNECTs differently.
func byLevel(v5, v4 []byte) func(byte) []byte {
	return func(l byte) []byte {
		if l >= Level5 {
			return v5
		}
		return v4
	}
}
