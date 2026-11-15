// SPDX-License-Identifier: MIT

package mqtt

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
)

// Framer asks for more when nothing has arrived yet.
func TestFramerEmpty(t *testing.T) {
	for _, b := range [][]byte{nil, {}} {
		if n := Framer(64)(b); n != 0 {
			t.Fatalf("Framer(64)(%v) = %d, want 0", b, n)
		}
	}
}

// Close twice (lifecycle matrix, L1): the second call does nothing and
// returns nil, and sends no second DISCONNECT. After Close the operations
// fail with the documented error.
func TestClientCloseTwice(t *testing.T) {
	f := &fake{connack: always(connack4(0, 0)), ping: true}
	c, err := Dial(context.Background(), proto, f.target(t), core.Options{Trace: true}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ack, err := c.Connect(Level311, "otfp-test"); err != nil || !ack.Accepted() {
		t.Fatalf("Connect: %+v %v", ack, err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v, want nil", err)
	}
	disconnects := 0
	for _, x := range c.S.Exchanges() {
		if x.Label == "disconnect" {
			disconnects++
		}
	}
	if disconnects != 1 {
		t.Errorf("%d DISCONNECT packets recorded, want 1", disconnects)
	}

	closed := func(name string, err error) {
		t.Helper()
		var de *core.DetectError
		if !errors.As(err, &de) || !errors.Is(err, net.ErrClosed) {
			t.Errorf("%s after Close: %v, want a DetectError that matches net.ErrClosed", name, err)
		}
	}
	_, err = c.Subscribe("a/b")
	closed("Subscribe", err)
	_, err = c.ReadPacket(time.Now().Add(time.Second))
	closed("ReadPacket", err)
	_, err = c.Connect(Level311, "otfp-test")
	closed("Connect", err)
	if c.Ping() || c.Unsubscribe("a/b") {
		t.Error("Ping or Unsubscribe reported true after Close")
	}
}
