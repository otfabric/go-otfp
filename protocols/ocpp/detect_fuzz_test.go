// SPDX-License-Identifier: MIT

package ocpp

import (
	"testing"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// FuzzDetect runs the fingerprinter end to end against a server replying
// with fuzzed bytes, seeded with replies captured from reference servers,
// and checks the Fingerprinter contract on every result (see fuzzkit).
func FuzzDetect(f *testing.F) {
	f.Add(fuzzkit.Join([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Protocol: ocpp2.0.1\r\n\r\n")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzkit.Detect(t, New(), data)
	})
}
