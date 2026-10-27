// SPDX-License-Identifier: MIT

package modbus

import (
	"testing"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/mbap"
)

// FuzzDetect runs the fingerprinter end to end against a server replying
// with fuzzed bytes, seeded with replies captured from reference servers,
// and checks the Fingerprinter contract on every result (see fuzzkit).
func FuzzDetect(f *testing.F) {
	f.Add(fuzzkit.Join(mbap.Request(probeTID, 1, 0x2B, 0x0E, 0x02, 0x82, 0xFF, 0x01, 1, 0, 4, 'A', 'c', 'm', 'e'), mbap.Request(probeTID, 1, 0x2B, 0x0E, 0x02, 0x82, 0, 0, 1, 1, 2, 'X', '1')))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzkit.Detect(t, New(), data)
	})
}
