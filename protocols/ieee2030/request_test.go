// SPDX-License-Identifier: MIT

package ieee2030

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"

	"github.com/otfabric/go-otfp/core"
)

// A host that cannot be the value of the Host header of the /dcap request
// is refused before a connection is opened, also through a Dialer of the
// caller's.
func TestHostThatIsNotOneHeaderValueIsRefused(t *testing.T) {
	var dials atomic.Int64
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("not reached")
	}
	for _, host := range []string{"server\r\nX-Second: 1", "server x", "server/x", "server\x00"} {
		r, err := New().Detect(context.Background(), core.Target{Host: host, Port: 443}, core.Options{Dialer: dial})
		var de *core.DetectError
		if !errors.As(err, &de) || de.Op != "request" || r.Matched {
			t.Errorf("host %+q: result %v, error %v; want a DetectError of operation request", host, r, err)
		}
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("%d connections opened, want 0", n)
	}
}
