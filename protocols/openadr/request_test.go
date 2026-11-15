// SPDX-License-Identifier: MIT

package openadr

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/otfabric/go-otfp/core"
)

// A host that cannot be the value of one Host header is refused before a
// connection is opened, also through a Dialer of the caller's.
func TestHostThatIsNotOneHeaderValueIsRefused(t *testing.T) {
	var dials atomic.Int64
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("not reached")
	}
	for _, host := range []string{"vtn\r\nX-Second: 1", "vtn\r\n\r\nPOST /x HTTP/1.1", "vtn x", "vtn/x", "vtn\x00"} {
		for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
			r, err := New().Detect(context.Background(), core.Target{Host: host, Port: 8080}, core.Options{MaxIntrusiveness: level, Dialer: dial})
			var de *core.DetectError
			if !errors.As(err, &de) || de.Op != "request" || r.Matched {
				t.Errorf("host %+q: result %v, error %v; want a DetectError of operation request", host, r, err)
			}
		}
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("%d connections opened, want 0", n)
	}
}
