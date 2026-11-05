// SPDX-License-Identifier: MIT

// Package mqtt fingerprints MQTT brokers.
//
// Detection sends one CONNECT — MQTT 3.1.1 (protocol level 4), a clean
// session, a 10-second keep-alive, a random client identifier, no will and
// no credentials — and accepts only a strict CONNACK: packet type 2 with
// zero flags, a remaining length of 2, zero reserved acknowledge flags and
// a return code of 0..5. A refusal (bad credentials, not authorised,
// unacceptable protocol version) proves an MQTT broker as well as an
// acceptance does. An accepted session is cross-checked with PINGREQ /
// PINGRESP and closed with DISCONNECT.
//
// An MQTT 5-only broker may close the connection on a 3.1.1 CONNECT
// instead of refusing it. Detection retries with an MQTT 5 CONNECT only on
// the well-known ports 1883 and 8883 (or in identify mode): elsewhere a
// silent close is far more likely a service that is not MQTT, and a second
// connection to every such endpoint would double the probe's footprint.
//
// Identify mode connects with MQTT 5 first, to read the CONNACK properties
// (Assigned Client Identifier, Server Keep Alive, Maximum Packet Size,
// Receive Maximum, Retain/Wildcard/Shared Subscription Available, Topic
// Alias Maximum, Response Information, Server Reference, Reason String),
// and falls back to 3.1.1 when the broker refuses or closes. When the scan
// allows read-only probes it subscribes, at QoS 0, to $SYS/broker/version
// (the Eclipse broker and compatible ones retain it) and $SYS/brokers/+/version
// (EMQX), waits a short bounded window for the value, unsubscribes and
// disconnects. Nothing is ever published.
package mqtt

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolMQTT

// The well-known ports: MQTT over TCP and over TLS.
const (
	PortTCP = 1883
	PortTLS = 8883
)

// sysFilters are the broker version topics read in identify mode.
var sysFilters = []string{"$SYS/broker/version", "$SYS/brokers/+/version"}

// Fingerprinter detects MQTT.
type Fingerprinter struct {
	// Window bounds the wait for the $SYS version in identify mode. Zero
	// means one second, capped by the target timeout.
	Window time.Duration
	// ClientID, when set, replaces the random client identifier.
	ClientID string
}

// New returns an MQTT fingerprinter.
func New() *Fingerprinter { return &Fingerprinter{} }

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{PortTCP, PortTLS},
		Priority:      80,
		Intrusiveness: core.Passive,
		Description:   "MQTT 3.1.1 CONNECT/CONNACK, PINGREQ, DISCONNECT; MQTT 5 CONNACK properties and $SYS/broker/version in identify mode",
	}
}

// WellKnown reports whether port is an MQTT port.
func WellKnown(port int) bool { return port == PortTCP || port == PortTLS }

func other(level byte) byte {
	if level == Level5 {
		return Level311
	}
	return Level5
}

// LevelName returns "3.1.1" or "5.0".
func LevelName(level byte) string {
	if level >= Level5 {
		return "5.0"
	}
	return "3.1.1"
}

// attempt is one connection: its client (open after a CONNACK) and outcome.
type attempt struct {
	c     *Client
	level byte
	ack   Connack
	err   error
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	var trace []core.Exchange
	clientID := f.ClientID
	if clientID == "" {
		clientID = ClientID()
	}
	try := func(level byte) (attempt, error) {
		c, err := Dial(ctx, proto, target, opts, 0)
		if err != nil {
			return attempt{}, err
		}
		ack, err := c.Connect(level, clientID)
		a := attempt{c: c, level: level, ack: ack, err: err}
		if err != nil {
			_ = c.Close()
			trace = append(trace, c.S.Exchanges()...)
		}
		return a, nil
	}
	identify := opts.Mode == core.ModeIdentify
	first := Level311
	if identify {
		first = Level5
	}
	a, err := try(first)
	if err != nil {
		return b.Result("mqtt.connect", "no MQTT response", nil), err
	}
	var refused *attempt
	switch {
	case errors.Is(a.err, wire.ErrClosed) && (identify || WellKnown(target.Port)):
		b.Evidence(fmt.Sprintf("closed on an MQTT %s CONNECT", LevelName(first)))
		if a, err = try(other(first)); err != nil {
			return b.Result("mqtt.connect", "no MQTT response", nil).WithExchanges(trace), err
		}
	case a.err == nil && a.ack.VersionRefused() && identify:
		// MQTT is proven; reconnect with the other level for a session.
		prev := a
		_ = prev.c.Close()
		trace = append(trace, prev.c.S.Exchanges()...)
		prev.c = nil
		if next, err := try(other(first)); err == nil && next.err == nil {
			refused, a = &prev, next
		} else {
			a = prev
		}
	}
	if a.err != nil {
		f.hint(b, a.err)
		if b.Confidence() == 0 && wire.IsTransport(a.err) {
			return b.Result("mqtt.connect", "no MQTT response", nil).WithExchanges(trace), a.err
		}
		return b.Result("mqtt.connect", "no CONNACK", nil).WithExchanges(trace), nil
	}
	if refused != nil {
		b.Score(core.ConfidenceHigh, connackEvidence(refused.level, refused.ack))
		b.Evidence(fmt.Sprintf("MQTT %s refused: %s", LevelName(refused.level), refused.ack.CodeName()))
	}
	ack := a.ack
	b.Score(core.ConfidenceHigh, connackEvidence(a.level, ack))
	b.Sig("connack", fmt.Sprintf("%d", ack.Code))
	if ack.AuthRefused() {
		b.Evidence("the broker requires authentication: " + ack.CodeName())
	}
	level := a.level
	if ack.VersionRefused() {
		level = other(a.level)
	}
	if !ack.VersionRefused() || ack.V5 {
		b.Variant("MQTT " + LevelName(level))
		b.Sig("level", LevelName(level))
	}
	id := b.Identity()
	if ack.Accepted() && a.c != nil {
		if a.c.Ping() {
			b.Score(core.ConfidenceCertain, "PINGRESP answers PINGREQ")
			b.Sig("ping", "resp")
		}
	}
	if identify {
		id.Set("protocolVersion", LevelName(level))
		id.Set("returnCode", fmt.Sprintf("%d (%s)", ack.Code, ack.CodeName()))
		if ack.Accepted() {
			id.Set("sessionPresent", fmt.Sprint(ack.SessionPresent))
		}
		if refused != nil {
			id.Set("mqtt"+strings.ReplaceAll(LevelName(refused.level), ".", ""), "refused: "+refused.ack.CodeName())
		}
		for _, p := range ack.Properties {
			if n := p.Name(); n != "" {
				id.Set(n, Sanitize(p.String(), 128))
			}
		}
		if ack.Accepted() && a.c != nil && opts.MaxIntrusiveness >= core.ReadOnly {
			f.sysVersion(b, a.c, target)
		}
	}
	details := "MQTT broker"
	if !ack.Accepted() {
		details = "MQTT broker (connection refused: " + ack.CodeName() + ")"
	}
	if a.c != nil {
		_ = a.c.Close()
		trace = append(trace, a.c.S.Exchanges()...)
	}
	return b.Result("mqtt.connect", details, nil).WithExchanges(trace), nil
}

func connackEvidence(level byte, ack Connack) string {
	format := "3.1.1"
	if ack.V5 {
		format = "MQTT 5"
	}
	return fmt.Sprintf("%s-format CONNACK to an MQTT %s CONNECT: code 0x%02x (%s)", format, LevelName(level), ack.Code, ack.CodeName())
}

// hint scores a reply that is not a valid CONNACK but is MQTT-shaped:
// a CONNACK that fails a check, or a packet only a server sends.
func (f *Fingerprinter) hint(b *fpx.Builder, err error) {
	var nc *NotConnackError
	if !errors.As(err, &nc) {
		return
	}
	p, perr := ParsePacket(nc.Reply)
	if perr != nil {
		return
	}
	switch p.Type {
	case TypeConnack:
		b.Score(core.ConfidenceLow, "CONNACK header, but "+nc.Err.Error())
	case TypeConnect, TypeSubscribe, TypeUnsubscribe, TypePingreq:
		// Client packets: an echo of the probe, not a broker.
	default:
		b.Score(core.ConfidenceLow, TypeName(p.Type)+" before CONNACK")
	}
}

// sysVersion subscribes to the $SYS version topics and waits for a value.
func (f *Fingerprinter) sysVersion(b *fpx.Builder, c *Client, target core.Target) {
	id, err := c.Subscribe(sysFilters...)
	if err != nil {
		return
	}
	window := f.Window
	if window <= 0 {
		window = time.Second
	}
	deadline := time.Now().Add(min(window, target.EffectiveTimeout()))
	suback, refused := false, false
	var version, topic string
	for i := 0; i < 32 && !refused && (!suback || version == ""); i++ {
		raw, err := c.ReadPacket(deadline)
		if err != nil {
			break
		}
		p, err := ParsePacket(raw)
		if err != nil {
			break
		}
		switch p.Type {
		case TypeSuback:
			codes, err := ParseSuback(c.Level, p, id, len(sysFilters))
			if err != nil {
				continue
			}
			suback = true
			refused = true
			for _, code := range codes {
				refused = refused && code >= 0x80
			}
		case TypePublish:
			m, err := ParsePublish(c.Level, p)
			if err == nil && version == "" && isSysVersion(m.Topic) {
				version, topic = Sanitize(string(m.Payload), 128), m.Topic
			}
		}
	}
	if suback {
		b.Score(core.ConfidenceCertain, "SUBACK echoes the SUBSCRIBE packet identifier")
	}
	if refused {
		b.Evidence("$SYS subscription refused")
	}
	if version != "" {
		id := b.Identity()
		id.Set("brokerVersion", version)
		b.Evidence(fmt.Sprintf("%s: %q", topic, version))
		product, ver, ok := strings.Cut(version, " version ")
		switch {
		case ok:
			id.Product, id.Version = product, ver
		case strings.HasPrefix(topic, "$SYS/brokers/"):
			id.Product, id.Version = "EMQX", version
		default:
			id.Version = version
		}
		b.Meta("brokerVersion", version)
	}
	if suback && !refused {
		c.Unsubscribe(sysFilters...)
	}
}

func isSysVersion(topic string) bool {
	if topic == sysFilters[0] {
		return true
	}
	rest, ok := strings.CutPrefix(topic, "$SYS/brokers/")
	if !ok {
		return false
	}
	node, ok := strings.CutSuffix(rest, "/version")
	return ok && node != "" && !strings.Contains(node, "/")
}

// Sanitize returns s as printable UTF-8 of at most max runes: invalid
// sequences and control characters are dropped.
func Sanitize(s string, max int) string {
	s = fpx.Clean(strings.ToValidUTF8(s, ""))
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max])
}
