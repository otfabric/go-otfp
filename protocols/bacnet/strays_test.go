// SPDX-License-Identifier: MIT

package bacnet

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/wire"
)

// keepAnswering is a peer that, once it has received a datagram, sends
// valid BACnet replies to an invoke ID the fingerprinter did not use for as
// long as the test runs: each is a datagram the fingerprinter discards.
func keepAnswering(t *testing.T) core.Target {
	t.Helper()
	uc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	stale := bvlc(bvlcUnicastNPDU, []byte{npduVersion, 0x00, apduSimpleACK, 200, svcReadProperty})
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = uc.Close(); wg.Wait() })
	wg.Go(func() {
		buf := make([]byte, 1500)
		var from netip.AddrPort
		for {
			// Follow the socket the fingerprinter is using, without
			// waiting for it.
			_ = uc.SetReadDeadline(time.Now().Add(time.Millisecond))
			if _, a, err := uc.ReadFromUDPAddrPort(buf); err == nil {
				from = a
			} else if !isTimeout(err) {
				return
			}
			if !from.IsValid() {
				continue
			}
			for range 256 {
				if _, err := uc.WriteToUDPAddrPort(stale, from); err != nil && errors.Is(err, net.ErrClosed) {
					return
				}
			}
		}
	})
	a := uc.LocalAddr().(*net.UDPAddr)
	return core.Target{Host: a.IP.String(), Port: a.Port, Network: core.UDP}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// A round trip reads a bounded number of datagrams that are not its answer
// (wire.MaxStrays), however many the peer sends before the timeout: the
// fingerprinter returns "could not decide", and the trace and the memory
// allocated are bounded by that number, not by the timeout.
func TestDiscardedDatagramsAreBounded(t *testing.T) {
	for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
		target := keepAnswering(t)
		target.Timeout = 2 * time.Second
		var r core.Result
		var err error
		allocated := fuzzkit.Allocated(func() {
			r, err = New().Detect(context.Background(), target, core.Options{Mode: mode, Trace: true})
		})
		fuzzkit.Check(t, proto, r, err)
		var de *core.DetectError
		if r.Matched || !errors.As(err, &de) || de.Op != "read" {
			t.Fatalf("%s: %v, %v; want no match and a DetectError of operation read", mode, r, err)
		}
		// Two round trips (the wildcard read and Who-Is), each with its
		// strays and its own entry.
		if n, bound := len(r.Exchanges), 2*(wire.MaxStrays+1); n > bound {
			t.Errorf("%s: %d exchanges in the trace, want at most %d", mode, n, bound)
		}
		const budget = 4 << 20
		if allocated > budget {
			t.Errorf("%s: %d octets allocated, budget %d", mode, allocated, budget)
		}
	}
}
