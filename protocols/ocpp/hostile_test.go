// SPDX-License-Identifier: MIT

package ocpp

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

const upgrade101 = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: ocpp2.0.1\r\n\r\n"

func TestChaos(t *testing.T) {
	chaos.Suite{
		FP:  New(),
		TCP: func(t testing.TB, cfg chaos.Config) core.Target { return chaos.Raw(t, cfg, httpReply(upgrade101)) },
	}.Run(t)
}

// The safety contract: one GET with a WebSocket upgrade offering the OCPP
// subprotocols, and nothing after the upgrade (no BootNotification or any
// other WebSocket frame).
func TestSafetyContract(t *testing.T) {
	for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
		for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
			var mu sync.Mutex
			var streams [][]byte
			target := testsrv.Raw(t, func(c net.Conn) {
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				var got []byte
				buf := make([]byte, 4096)
				for !bytes.Contains(got, []byte("\r\n\r\n")) {
					n, err := c.Read(buf)
					got = append(got, buf[:n]...)
					if err != nil {
						break
					}
				}
				_, _ = c.Write([]byte(upgrade101))
				rest, _ := io.ReadAll(c) // what the client sends after the upgrade
				mu.Lock()
				streams = append(streams, append(got, rest...))
				mu.Unlock()
			})
			r, err := New().Detect(context.Background(), target, core.Options{Mode: mode, MaxIntrusiveness: level})
			if err != nil || !r.Matched {
				t.Fatalf("%v %v", r, err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				mu.Lock()
				n := len(streams)
				mu.Unlock()
				if n > 0 || time.Now().After(deadline) {
					break
				}
				time.Sleep(5 * time.Millisecond)
			}
			mu.Lock()
			got := append([][]byte(nil), streams...)
			mu.Unlock()
			if len(got) != 1 {
				t.Fatalf("%s/%s: %d connections, want 1", mode, level, len(got))
			}
			head, tail, ok := strings.Cut(string(got[0]), "\r\n\r\n")
			if !ok {
				t.Fatalf("no request header: %q", got[0])
			}
			if !strings.HasPrefix(head, "GET /ocpp/") || !strings.Contains(head, "\r\nUpgrade: websocket") ||
				!strings.Contains(head, "\r\nSec-WebSocket-Protocol: ocpp2.1, ocpp2.0.1, ocpp1.6") {
				t.Fatalf("%s/%s: request is not the OCPP WebSocket upgrade:\n%s", mode, level, head)
			}
			if tail != "" {
				t.Fatalf("%s/%s: %d octets sent after the upgrade: % x", mode, level, len(tail), tail)
			}
		}
	}
}
