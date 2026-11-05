// SPDX-License-Identifier: MIT

package mqtt

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestVarint(t *testing.T) {
	for _, v := range []int{0, 1, 127, 128, 16383, 16384, 2097151, 2097152, MaxRemaining} {
		b := AppendVarint(nil, v)
		got, n, err := Varint(b)
		if err != nil || got != v || n != len(b) {
			t.Fatalf("%d: %d %d %v", v, got, n, err)
		}
	}
	if b := AppendVarint(nil, MaxRemaining+1); !bytes.Equal(b, []byte{0xFF, 0xFF, 0xFF, 0x7F}) {
		t.Fatalf("clamp % x", b)
	}
	if b := AppendVarint(nil, -1); !bytes.Equal(b, []byte{0}) {
		t.Fatalf("clamp % x", b)
	}
	if _, _, err := Varint([]byte{0x80, 0x80}); !errors.Is(err, errIncomplete) {
		t.Fatal(err)
	}
	if _, _, err := Varint([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x01}); err == nil || errors.Is(err, errIncomplete) {
		t.Fatal(err)
	}
}

func TestFramer(t *testing.T) {
	fr := Framer(64)
	for _, c := range []struct {
		in   []byte
		want int
	}{
		{[]byte{0x20}, 0},
		{[]byte{0x20, 0x02}, 4},
		{[]byte{0x00, 0x02}, -1},                   // reserved type
		{[]byte{0x21, 0x02}, -1},                   // CONNACK flags
		{[]byte{0x36, 0x02}, -1},                   // PUBLISH QoS 3
		{[]byte{0x82, 0x02}, 4},                    // SUBSCRIBE
		{[]byte{0x80, 0x02}, -1},                   // SUBSCRIBE flags
		{[]byte{0x30, 0x80}, 0},                    // varint incomplete
		{[]byte{0x30, 0xFF, 0xFF, 0xFF, 0xFF}, -1}, // five bytes
		{[]byte{0x30, 0x40}, -1},                   // over the limit
	} {
		if got := fr(c.in); got != c.want {
			t.Errorf("% x: %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParsePacket(t *testing.T) {
	for _, b := range [][]byte{{0x20}, {0x00, 0x00}, {0x20, 0x80}, {0x20, 0x02, 0x00}, {0x20, 0x01, 0x00, 0x00}} {
		if _, err := ParsePacket(b); err == nil {
			t.Errorf("% x accepted", b)
		}
	}
	p, err := ParsePacket([]byte{0xD0, 0x00})
	if err != nil || p.Type != TypePingresp || TypeName(p.Type) != "PINGRESP" {
		t.Fatal(p, err)
	}
}

func TestBuilders(t *testing.T) {
	want := []byte{0x10, 0x0E, 0, 4, 'M', 'Q', 'T', 'T', 4, 0x02, 0, 10, 0, 2, 'i', 'd'}
	if got := Connect(Level311, "id", 10); !bytes.Equal(got, want) {
		t.Fatalf("connect v4 % x", got)
	}
	want5 := []byte{0x10, 0x0F, 0, 4, 'M', 'Q', 'T', 'T', 5, 0x02, 0, 10, 0, 0, 2, 'i', 'd'}
	if got := Connect(Level5, "id", 10); !bytes.Equal(got, want5) {
		t.Fatalf("connect v5 % x", got)
	}
	if got := Subscribe(Level311, 1, "a"); !bytes.Equal(got, []byte{0x82, 0x06, 0, 1, 0, 1, 'a', 0}) {
		t.Fatalf("subscribe % x", got)
	}
	if got := Subscribe(Level5, 1, "a"); !bytes.Equal(got, []byte{0x82, 0x07, 0, 1, 0, 0, 1, 'a', 0}) {
		t.Fatalf("subscribe v5 % x", got)
	}
	if got := Unsubscribe(Level5, 2, "a"); !bytes.Equal(got, []byte{0xA2, 0x06, 0, 2, 0, 0, 1, 'a'}) {
		t.Fatalf("unsubscribe % x", got)
	}
	if got := Unsubscribe(Level311, 2, "a"); !bytes.Equal(got, []byte{0xA2, 0x05, 0, 2, 0, 1, 'a'}) {
		t.Fatalf("unsubscribe % x", got)
	}
	if !bytes.Equal(PingReq(), []byte{0xC0, 0}) || !bytes.Equal(Disconnect(), []byte{0xE0, 0}) {
		t.Fatal("ping/disconnect")
	}
	long := strings.Repeat("x", 70000)
	if b := appendString(nil, long); len(b) != 2+0xFFFF {
		t.Fatalf("long string %d", len(b))
	}
}

func TestParseConnack(t *testing.T) {
	ok := []struct {
		sent byte
		in   []byte
		v5   bool
		code byte
	}{
		{4, connack4(0, 0), false, 0},
		{4, connack4(1, 0), false, 0},
		{4, connack4(0, 5), false, 5},
		{5, connack4(0, 1), false, 1},
		{4, connack5(0, 0x84), true, 0x84},
		{5, connack5(0, 0), true, 0},
		{5, connack5(0, 0x87), true, 0x87},
		{5, connack5(0, 0, v5Props...), true, 0},
	}
	for _, c := range ok {
		a, err := ParseConnack(c.sent, c.in)
		if err != nil || a.V5 != c.v5 || a.Code != c.code {
			t.Errorf("% x: %+v %v", c.in, a, err)
		}
	}
	bad := []struct {
		sent byte
		in   []byte
	}{
		{4, []byte{0xD0, 0x00}},
		{4, []byte{0x20, 0x02, 0x00}},
		{4, []byte{0x20, 0x01, 0x00}},
		{4, connack4(2, 0)},
		{4, connack4(1, 1)},
		{4, connack4(0, 6)},
		{5, connack4(0, 0)},
		{4, connack5(0, 0)},
		{5, connack5(0, 0x01)},
		{5, append(connack5(0, 0), 0x00)[:4]},
		{5, connack5(0, 0, 0x01, 0x00)},          // payload format: not a CONNACK property
		{5, connack5(0, 0, 0x13, 0x00)},          // cut short
		{5, packet(0x20, []byte{0, 0, 0, 0xFF})}, // trailing byte after empty properties
		{5, packet(0x20, []byte{0, 0, 0x05})},    // property length beyond the packet
		{5, packet(0x20, []byte{0, 0, 0x80})},    // property length cut short
	}
	for _, c := range bad {
		if a, err := ParseConnack(c.sent, c.in); err == nil {
			t.Errorf("% x accepted: %+v", c.in, a)
		}
	}
}

func TestConnackNames(t *testing.T) {
	for _, c := range []struct {
		a    Connack
		name string
		auth bool
		ver  bool
	}{
		{Connack{Code: 0}, "connection accepted", false, false},
		{Connack{Code: 1}, "unacceptable protocol version", false, true},
		{Connack{Code: 4}, "bad user name or password", true, false},
		{Connack{Code: 9}, "unknown", false, false},
		{Connack{V5: true, Code: 0x84}, "unsupported protocol version", false, true},
		{Connack{V5: true, Code: 0x86}, "bad user name or password", true, false},
		{Connack{V5: true, Code: 0x8C}, "bad authentication method", true, false},
		{Connack{V5: true, Code: 0x01}, "unknown", false, false},
	} {
		if c.a.CodeName() != c.name || c.a.AuthRefused() != c.auth || c.a.VersionRefused() != c.ver {
			t.Errorf("%+v: %q %v %v", c.a, c.a.CodeName(), c.a.AuthRefused(), c.a.VersionRefused())
		}
	}
}

func TestProperties(t *testing.T) {
	ps, rest, err := ParseProperties(append(AppendVarint(nil, len(v5Props)), append(v5Props, 0xAA)...), connackProps)
	if err != nil || !bytes.Equal(rest, []byte{0xAA}) {
		t.Fatal(err, rest)
	}
	if p, ok := ps.Get(0x26); !ok || p.String() != "k=v" || p.Name() != "" {
		t.Fatalf("%+v", p)
	}
	if p, ok := ps.Get(0x16); !ok || p.String() != "" {
		t.Fatalf("%+v", p)
	}
	if _, ok := ps.Get(0x29); ok {
		t.Fatal("absent property found")
	}
	pub := []byte{0x0B, 0x81, 0x01, 0x01, 0x01, 0x02, 0, 0, 0, 5, 0x23, 0, 1, 0x03, 0, 1, 'j', 0x09, 0, 1, 1}
	ps, _, err = ParseProperties(append(AppendVarint(nil, len(pub)), pub...), publishProps)
	if err != nil || len(ps) != 6 {
		t.Fatal(err, ps)
	}
	if p, _ := ps.Get(0x0B); p.Value != 129 {
		t.Fatalf("subscription identifier %d", p.Value)
	}
	for _, b := range [][]byte{
		{0x04, 0x24, 0x01, 0x24, 0x01}, // repeated
		{0x01, 0x24},                   // byte cut short
		{0x01, 0x21},                   // u16 cut short
		{0x01, 0x27},                   // u32 cut short
		{0x02, 0x16, 0x00},             // binary cut short
		{0x03, 0x16, 0x00, 0x05},       // binary longer than the packet
		{0x01, 0x12},                   // string cut short
		{0x04, 0x12, 0x00, 0x01, 0xFF}, // invalid UTF-8
		{0x04, 0x12, 0x00, 0x01, 0x00}, // U+0000
		{0x04, 0x26, 0x00, 0x01, 'k'},  // pair without value
		{0x01, 0x7F},                   // unknown identifier
	} {
		if _, _, err := ParseProperties(b, connackProps); err == nil {
			t.Errorf("% x accepted", b)
		}
	}
	if _, _, err := ParseProperties([]byte{0x02, 0x0B, 0x80}, publishProps); err == nil {
		t.Error("cut varint accepted")
	}
	var many []byte
	for range 40 {
		many = append(many, 0x26, 0, 1, 'k', 0, 1, 'v')
	}
	ps, _, err = ParseProperties(append(AppendVarint(nil, len(many)), many...), connackProps)
	if err != nil || len(ps) != maxProperties {
		t.Fatal(err, len(ps))
	}
}

func TestParsePublish(t *testing.T) {
	p, _ := ParsePacket(publish(4, "a/b", []byte("hi"), 0x03))
	m, err := ParsePublish(4, p)
	if err != nil || m.Topic != "a/b" || m.QoS != 1 || !m.Retain || m.PacketID != 7 || string(m.Payload) != "hi" {
		t.Fatalf("%+v %v", m, err)
	}
	p, _ = ParsePacket(publish(5, "a", []byte("x"), 0))
	if m, err := ParsePublish(5, p); err != nil || string(m.Payload) != "x" {
		t.Fatalf("%+v %v", m, err)
	}
	bad := []Packet{
		{Type: TypeSuback},
		{Type: TypePublish, Body: []byte{0x00}},
		{Type: TypePublish, Body: []byte{0x00, 0x00}},
		{Type: TypePublish, Body: []byte{0x00, 0x01, '#'}},
		{Type: TypePublish, Body: []byte{0x00, 0x01, '+'}},
		{Type: TypePublish, Flags: 0x02, Body: []byte{0x00, 0x01, 'a', 0x00}},
		{Type: TypePublish, Flags: 0x02, Body: []byte{0x00, 0x01, 'a', 0x00, 0x00}},
		{Type: TypePublish, Flags: 0x08, Body: []byte{0x00, 0x01, 'a'}},
	}
	for _, p := range bad {
		if _, err := ParsePublish(4, p); err == nil {
			t.Errorf("%+v accepted", p)
		}
	}
	if _, err := ParsePublish(5, Packet{Type: TypePublish, Body: []byte{0x00, 0x01, 'a', 0x05}}); err == nil {
		t.Error("bad v5 properties accepted")
	}
}

func TestParseSuback(t *testing.T) {
	p, _ := ParsePacket(suback(4, 3, 0x00, 0x80))
	if codes, err := ParseSuback(4, p, 3, 2); err != nil || len(codes) != 2 {
		t.Fatal(codes, err)
	}
	p5, _ := ParsePacket(suback(5, 3, 0x01, 0x87))
	if _, err := ParseSuback(5, p5, 3, 2); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		p       Packet
		id      uint16
		filters int
	}{
		{Packet{Type: TypeUnsuback}, 3, 1},
		{p, 4, 2},
		{p, 3, 1},
		{Packet{Type: TypeSuback, Body: []byte{0}}, 0, 0},
		{Packet{Type: TypeSuback, Body: []byte{0, 3, 0x03}}, 3, 1},
	} {
		if _, err := ParseSuback(4, c.p, c.id, c.filters); err == nil {
			t.Errorf("%+v accepted", c)
		}
	}
	if _, err := ParseSuback(5, Packet{Type: TypeSuback, Body: []byte{0, 3, 0x09}}, 3, 0); err == nil {
		t.Error("bad v5 properties accepted")
	}
	u, _ := ParsePacket([]byte{0xB0, 0x02, 0x00, 0x05})
	if !IsUnsuback(4, u, 5) || IsUnsuback(4, u, 6) || IsUnsuback(4, p, 3) {
		t.Fatal("IsUnsuback")
	}
}

func TestPeekTopic(t *testing.T) {
	full := publish(4, "spBv1.0/g/NBIRTH/e", make([]byte, 100), 0)
	if topic, err := PeekTopic(full[:30]); err != nil || topic != "spBv1.0/g/NBIRTH/e" {
		t.Fatal(topic, err)
	}
	for _, b := range [][]byte{{0x20, 0x02}, {0x30}, {0x30, 0x80}, {0x30, 0x05, 0x00}} {
		if _, err := PeekTopic(b); err == nil {
			t.Errorf("% x accepted", b)
		}
	}
}

func TestSanitize(t *testing.T) {
	if got := Sanitize("a\x00b\xffc\x1b", 10); got != "abc" {
		t.Fatalf("%q", got)
	}
	if got := Sanitize("ééééé", 3); got != "ééé" {
		t.Fatalf("%q", got)
	}
	if LevelName(Level5) != "5.0" || LevelName(Level311) != "3.1.1" || other(Level5) != Level311 {
		t.Fatal("levels")
	}
	if isSysVersion("$SYS/brokers//version") || isSysVersion("$SYS/brokers/a/b/version") || isSysVersion("$SYS/x") || isSysVersion("$SYS/brokers/a/uptime") {
		t.Fatal("isSysVersion")
	}
	e := &NotConnackError{Reply: []byte{1}, Err: errIncomplete}
	if !errors.Is(e, errIncomplete) || !strings.Contains(e.Error(), "not a CONNACK") {
		t.Fatal(e)
	}
}
