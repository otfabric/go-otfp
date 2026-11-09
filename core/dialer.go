// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"
	"net"
	"time"
)

// Dialer opens the connection of a fingerprinter to addr ("host:port") over
// network "tcp" or "udp", for example to apply an address allowlist, to dial
// through a proxy or to bind a source address. Like net.Dialer, it returns a
// non-nil connection exactly when the error is nil. With
// EngineConfig.Parallel it is called from several goroutines at once.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

var errNoConnection = errors.New("dialer returned no connection")

// Dial opens a connection for a fingerprinter: with o.Dialer, or, when it is
// nil, with a net.Dialer bounded by timeout. A custom Dialer is called with
// a context that already carries timeout (when positive) and should honour
// it; that context is cancelled once Dial returns, so the connection must
// not depend on it. A Dialer that returns no connection and no error fails;
// a connection returned together with an error is closed. Fingerprinters
// outside this module (see examples/custom) dial through it so that the
// caller's Dialer covers them too.
func (o Options) Dial(ctx context.Context, network, addr string, timeout time.Duration) (net.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dial := o.Dialer
	if dial == nil {
		d := net.Dialer{Timeout: timeout}
		dial = d.DialContext
	} else if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	conn, err := dial(ctx, network, addr)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, err
	}
	if conn == nil {
		return nil, errNoConnection
	}
	return conn, nil
}
