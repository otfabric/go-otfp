// SPDX-License-Identifier: MIT

package mqtt

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/wire"
)

// KeepAlive is the keep-alive, in seconds, of the CONNECTs the
// fingerprinters send: a session lasts a few seconds at most.
const KeepAlive = 10

// ClientID returns a random client identifier, "otfp" and 16 hexadecimal
// digits: 20 characters of [0-9a-z], which every MQTT 3.1.1 broker must
// accept, and unlikely to take over another client's session.
func ClientID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "otfp" + hex.EncodeToString(b[:])
}

// NotConnackError is the reply to a CONNECT that is not a valid CONNACK.
type NotConnackError struct {
	// Reply is what arrived.
	Reply []byte
	// Err is why it is not a CONNACK.
	Err error
}

func (e *NotConnackError) Error() string { return "not a CONNACK: " + e.Err.Error() }

func (e *NotConnackError) Unwrap() error { return e.Err }

// Client is a minimal, read-only MQTT client session for fingerprinting:
// it connects, subscribes at QoS 0, reads, unsubscribes and disconnects.
// It never publishes.
type Client struct {
	// S is the session.
	S *wire.Session
	// Level is the protocol level of the CONNECT sent.
	Level byte
	// Ack is the CONNACK, once Connect has succeeded.
	Ack Connack

	limit     int
	id        uint16
	connected bool
}

// Dial opens a session to target for protocol p (the protocol its errors
// are attributed to). limit bounds the packets read; zero means
// DefaultMaxPacket.
func Dial(ctx context.Context, p core.Protocol, target core.Target, opts core.Options, limit int) (*Client, error) {
	s, err := wire.Dial(ctx, p, target, opts)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = DefaultMaxPacket
	}
	return &Client{S: s, limit: limit}, nil
}

// Connect sends a CONNECT of the given level and reads the CONNACK. It
// returns the session's transport error or wire.ErrClosed when nothing
// arrived, and a *NotConnackError when the reply is not a CONNACK valid
// for the level.
func (c *Client) Connect(level byte, clientID string) (Connack, error) {
	c.Level = level
	resp, err := c.S.RoundTrip(fmt.Sprintf("connect-v%d", level), Connect(level, clientID, KeepAlive), Framer(c.limit), c.limit)
	if err != nil {
		return Connack{}, err
	}
	ack, err := ParseConnack(level, resp)
	if err != nil {
		return Connack{}, &NotConnackError{Reply: resp, Err: err}
	}
	c.Ack = ack
	c.connected = ack.Accepted()
	return ack, nil
}

// Ping sends PINGREQ and reports whether the next packet is PINGRESP.
func (c *Client) Ping() bool {
	resp, err := c.S.RoundTrip("pingreq", PingReq(), Framer(c.limit), c.limit)
	if err != nil {
		return false
	}
	p, err := ParsePacket(resp)
	return err == nil && p.Type == TypePingresp && len(p.Body) == 0
}

// Subscribe sends a SUBSCRIBE of the filters at QoS 0 and returns its
// packet identifier.
func (c *Client) Subscribe(filters ...string) (uint16, error) {
	c.id++
	b := Subscribe(c.Level, c.id, filters...)
	c.S.Record("subscribe", b, nil)
	return c.id, c.S.Send(b)
}

// ReadPacket reads the next packet before deadline. The bytes returned
// may not be a whole packet (a malformed or oversized one); ParsePacket
// tells.
func (c *Client) ReadPacket(deadline time.Time) ([]byte, error) {
	resp, err := c.S.ReadUntil(Framer(c.limit), c.limit, deadline)
	if err == nil {
		c.S.Record("packet", nil, resp)
	}
	return resp, err
}

// Unsubscribe sends an UNSUBSCRIBE of the filters and waits, up to the
// session's idle gap, for the UNSUBACK, discarding the packets before it.
func (c *Client) Unsubscribe(filters ...string) bool {
	c.id++
	id := c.id
	b := Unsubscribe(c.Level, id, filters...)
	c.S.Record("unsubscribe", b, nil)
	if c.S.Send(b) != nil {
		return false
	}
	deadline := time.Now().Add(min(c.S.Timeout(), 500*time.Millisecond))
	for range 16 {
		resp, err := c.ReadPacket(deadline)
		if err != nil {
			return false
		}
		p, err := ParsePacket(resp)
		if err != nil {
			return false
		}
		if IsUnsuback(c.Level, p, id) {
			return true
		}
	}
	return false
}

// Close sends DISCONNECT when the broker accepted the connection, and
// closes the session.
func (c *Client) Close() error {
	if c.connected {
		c.connected = false
		_ = c.S.Send(Disconnect())
		c.S.Record("disconnect", Disconnect(), nil)
	}
	return c.S.Close()
}
