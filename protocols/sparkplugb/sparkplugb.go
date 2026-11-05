// SPDX-License-Identifier: MIT

// Package sparkplugb fingerprints Sparkplug B infrastructures on an MQTT
// broker: host applications and edge nodes that use the spBv1.0 topic
// namespace.
//
// Sparkplug B refines MQTT: the fingerprinter connects like the MQTT one
// (MQTT 3.1.1, clean session, a random client identifier, no will, no
// credentials) and subscribes, at QoS 0, to the host application STATE
// topics of Sparkplug 3.0 (spBv1.0/STATE/+, retained) and 2.x (STATE/+),
// and to the node and device message topics (spBv1.0/+/+/+ and
// spBv1.0/+/+/+/+: births, deaths, data and commands). It listens for a
// short bounded window, then unsubscribes and disconnects. It never
// publishes: no NCMD, DCMD, rebirth request or STATE.
//
// A message on an spBv1.0 topic whose payload decodes as a Sparkplug B
// protobuf Payload with a timestamp, or a retained 3.0 STATE with the JSON
// {"online": bool, "timestamp": n}, is certain; a 2.x STATE of "ONLINE" or
// "OFFLINE" is high. Births are not retained, so an edge node is seen only
// when it publishes during the window: the retained STATE of a host
// application is the usual evidence.
//
// Subscribing reads application data, so the fingerprinter is read-only.
// Detection stops at the first certain message; identify mode listens for
// the whole window and reports the group, edge node, device and host
// application IDs, the STATE version, and from NBIRTH payloads the bdSeq
// and the metric count and names (all bounded).
package sparkplugb

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/wire"
	"github.com/otfabric/go-otfp/protocols/mqtt"
)

const proto = core.ProtocolSparkplugB

// Filters are the topic filters subscribed to.
var Filters = []string{"spBv1.0/STATE/+", "STATE/+", "spBv1.0/+/+/+", "spBv1.0/+/+/+/+"}

// Bounds.
const (
	// MaxPacket bounds one MQTT packet read (an NBIRTH of a large edge
	// node runs to tens of kilobytes).
	MaxPacket = 256 * 1024
	// DefaultMaxMessages bounds the messages read in one window.
	DefaultMaxMessages = 256
	// maxIDs bounds each list of IDs kept.
	maxIDs = 16
)

// Fingerprinter detects Sparkplug B.
type Fingerprinter struct {
	// Window is how long to listen after subscribing. Zero means two
	// seconds, capped by the target timeout.
	Window time.Duration
	// MaxMessages bounds the messages read; zero means DefaultMaxMessages.
	MaxMessages int
	// ClientID, when set, replaces the random client identifier.
	ClientID string
}

// New returns a Sparkplug B fingerprinter.
func New() *Fingerprinter { return &Fingerprinter{} }

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{mqtt.PortTCP, mqtt.PortTLS},
		Priority:      81,
		Intrusiveness: core.ReadOnly,
		Refines:       core.ProtocolMQTT,
		Description:   "MQTT CONNECT, QoS 0 SUBSCRIBE to spBv1.0/STATE/+, STATE/+ and the spBv1.0 node/device topics for a bounded window; UNSUBSCRIBE, DISCONNECT",
	}
}

// Detect probes target. Subscribing reads application data, so nothing
// is sent unless opts allows read-only probes: a direct call with the
// zero Options (passive only) returns no match without connecting, as the
// engine would not have run the fingerprinter at all.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	if opts.MaxIntrusiveness < core.ReadOnly {
		b.Evidence("not run: Sparkplug B subscribes, which needs read-only probes allowed")
		return b.Result("sparkplugb.subscribe", "read-only probes not allowed; nothing sent", nil), nil
	}
	var trace []core.Exchange
	clientID := f.ClientID
	if clientID == "" {
		clientID = mqtt.ClientID()
	}
	connect := func(level byte) (*mqtt.Client, mqtt.Connack, error, error) {
		c, err := mqtt.Dial(ctx, proto, target, opts, MaxPacket)
		if err != nil {
			return nil, mqtt.Connack{}, nil, err
		}
		ack, cerr := c.Connect(level, clientID)
		if cerr != nil || !ack.Accepted() {
			_ = c.Close()
			trace = append(trace, c.S.Exchanges()...)
			return nil, ack, cerr, nil
		}
		return c, ack, nil, nil
	}
	c, ack, cerr, err := connect(mqtt.Level311)
	if err == nil && c == nil && (ack.VersionRefused() || (errors.Is(cerr, wire.ErrClosed) && mqtt.WellKnown(target.Port))) {
		c, ack, cerr, err = connect(mqtt.Level5)
	}
	if err != nil {
		return b.Result("sparkplugb.subscribe", "no MQTT response", nil).WithExchanges(trace), err
	}
	if c == nil {
		if cerr != nil {
			if wire.IsTransport(cerr) {
				return b.Result("sparkplugb.subscribe", "no MQTT response", nil).WithExchanges(trace), cerr
			}
			return b.Result("sparkplugb.subscribe", "not an MQTT broker", nil).WithExchanges(trace), nil
		}
		b.Evidence("MQTT broker refused the connection: " + ack.CodeName())
		return b.Result("sparkplugb.subscribe", "MQTT broker refused the connection; Sparkplug B not checked", nil).WithExchanges(trace), nil
	}
	o := newObserver(b)
	f.listen(ctx, c, target, opts, o)
	_ = c.Close()
	trace = append(trace, c.S.Exchanges()...)
	o.report(opts.Mode == core.ModeIdentify)
	details := "no Sparkplug B traffic on the broker"
	if b.Confidence() >= core.MatchThreshold {
		details = "Sparkplug B on an MQTT broker"
	}
	return b.Result("sparkplugb.subscribe", details, nil).WithExchanges(trace), nil
}

// listen subscribes and reads the messages of the window.
func (f *Fingerprinter) listen(ctx context.Context, c *mqtt.Client, target core.Target, opts core.Options, o *observer) {
	id, err := c.Subscribe(Filters...)
	if err != nil {
		return
	}
	window := f.Window
	if window <= 0 {
		window = 2 * time.Second
	}
	deadline := time.Now().Add(min(window, target.EffectiveTimeout()))
	maxMsgs := f.MaxMessages
	if maxMsgs <= 0 {
		maxMsgs = DefaultMaxMessages
	}
	subscribed := false
	for reads := 0; reads < maxMsgs+8 && o.messages < maxMsgs && ctx.Err() == nil; reads++ {
		if opts.Mode != core.ModeIdentify && o.b.Confidence() >= core.ConfidenceCertain {
			break
		}
		raw, err := c.ReadPacket(deadline)
		if err != nil {
			break
		}
		p, err := mqtt.ParsePacket(raw)
		if err != nil {
			if topic, terr := mqtt.PeekTopic(raw); terr == nil {
				o.oversized(topic)
			}
			break // the stream is no longer aligned on packets
		}
		switch p.Type {
		case mqtt.TypeSuback:
			codes, err := mqtt.ParseSuback(c.Level, p, id, len(Filters))
			if err != nil {
				continue
			}
			granted := 0
			for _, code := range codes {
				if code < 0x80 {
					granted++
				}
			}
			if granted == 0 {
				o.b.Evidence("the broker refused every Sparkplug B subscription")
				return
			}
			subscribed = true
		case mqtt.TypePublish:
			if m, err := mqtt.ParsePublish(c.Level, p); err == nil {
				o.publish(m)
			}
		}
	}
	if subscribed {
		c.Unsubscribe(Filters...)
	}
}

// idset is a bounded, ordered set of IDs.
type idset struct {
	seen map[string]bool
	list []string
	more int
}

func (s *idset) add(v string) {
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	if v == "" || s.seen[v] {
		return
	}
	if len(s.list) >= maxIDs {
		s.more++
		return
	}
	s.seen[v] = true
	s.list = append(s.list, v)
}

func (s *idset) String() string {
	out := strings.Join(s.list, ",")
	if s.more > 0 {
		out += fmt.Sprintf(" (+%d more)", s.more)
	}
	return out
}

// observer accumulates what the window showed.
type observer struct {
	b                      *fpx.Builder
	messages               int
	types                  idset
	groups, nodes, devices idset
	hosts                  idset
	births                 idset
	names                  []string
	v2, v3, spb            bool
}

func newObserver(b *fpx.Builder) *observer { return &observer{b: b} }

func (o *observer) oversized(topic string) {
	if t, err := ParseTopic(topic); err == nil && !t.V2 {
		o.b.Score(core.ConfidenceMedium, fmt.Sprintf("%s message on %s larger than %d bytes", t.Type, clean(topic), MaxPacket))
		o.spb = true
	}
}

func (o *observer) publish(m mqtt.Publish) {
	t, err := ParseTopic(m.Topic)
	if err != nil {
		return
	}
	first := !o.types.seen[t.Type]
	switch {
	case t.Type == "STATE" && t.V2:
		st, err := ParseState2(m.Payload)
		if err != nil {
			return // STATE/+ is not reserved outside Sparkplug 2.x
		}
		o.v2 = true
		o.state(t, st, first, core.ConfidenceHigh)
	case t.Type == "STATE":
		o.spb = true
		st, err := ParseState3(m.Payload)
		if err != nil {
			o.b.Score(core.ConfidenceMedium, "spBv1.0/STATE topic, but "+err.Error())
			break
		}
		o.v3 = true
		o.state(t, st, first, core.ConfidenceCertain)
	default:
		o.spb = true
		o.groups.add(clean(t.Group))
		o.nodes.add(clean(t.Group) + "/" + clean(t.EdgeNode))
		if t.Device != "" {
			o.devices.add(clean(t.Group) + "/" + clean(t.EdgeNode) + "/" + clean(t.Device))
		}
		p, err := DecodePayload(m.Payload)
		if err != nil || !p.HasTimestamp {
			why := "no timestamp"
			if err != nil {
				why = err.Error()
			}
			o.b.Score(core.ConfidenceMedium, fmt.Sprintf("%s on an spBv1.0 topic, but the payload is not a Sparkplug B payload: %s", t.Type, why))
			break
		}
		if first {
			o.b.Score(core.ConfidenceCertain, fmt.Sprintf("%s from %s/%s decodes as a Sparkplug B payload", t.Type, clean(t.Group), clean(t.EdgeNode)))
		}
		if t.Type == "NBIRTH" {
			birth := fmt.Sprintf("%s/%s metrics=%d", clean(t.Group), clean(t.EdgeNode), p.Metrics)
			if p.HasBdSeq {
				birth += " bdSeq=" + strconv.FormatUint(p.BdSeq, 10)
			}
			o.births.add(birth)
			if o.names == nil {
				o.names = p.Names
			}
		}
	}
	o.messages++
	o.types.add(t.Type)
}

func (o *observer) state(t Topic, st State, first bool, c core.Confidence) {
	state := "offline"
	if st.Online {
		state = "online"
	}
	host := clean(t.Host)
	o.hosts.add(host + "=" + state)
	if first || c > o.b.Confidence() {
		o.b.Score(c, fmt.Sprintf("Sparkplug %s STATE of host application %q: %s", st.Version, host, state))
	}
}

// report fills the variant, signature and identity.
func (o *observer) report(identify bool) {
	if o.b.Confidence() < core.MatchThreshold {
		return
	}
	var versions []string
	if o.v2 {
		versions = append(versions, "2.x")
	}
	if o.v3 {
		versions = append(versions, "3.0")
	}
	switch {
	case o.v3:
		o.b.Variant("Sparkplug B 3.0")
	case o.v2 && !o.spb:
		o.b.Variant("Sparkplug B 2.x")
	default:
		o.b.Variant("Sparkplug B")
	}
	if o.spb {
		o.b.Sig("namespace", Namespace)
	}
	if len(versions) > 0 {
		o.b.Sig("state", strings.Join(versions, ","))
	}
	if !identify {
		return
	}
	id := o.b.Identity()
	id.Set("sparkplugVersion", strings.Join(versions, ","))
	id.Set("messages", strconv.Itoa(o.messages))
	id.Set("messageTypes", o.types.String())
	id.Set("groups", o.groups.String())
	id.Set("edgeNodes", o.nodes.String())
	id.Set("devices", o.devices.String())
	id.Set("hostApplications", o.hosts.String())
	id.Set("births", strings.ReplaceAll(o.births.String(), ",", "; "))
	id.Set("metricNames", strings.Join(o.names, ","))
}
