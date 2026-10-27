// SPDX-License-Identifier: MIT

package dnp3

import (
	"testing"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// FuzzDetect runs the fingerprinter end to end against a server replying
// with fuzzed bytes, seeded with replies captured from reference servers,
// and checks the Fingerprinter contract on every result (see fuzzkit).
func FuzzDetect(f *testing.F) {
	f.Add(fuzzkit.Join(Frame(fcLinkStatus, 1, 10, nil), Frame(0x44, 1, 10, []byte{0xC0, 0xC0, 0x81, 0, 0, 0, 252, 0, 0, 0, 1, 4, 'A', 'c', 'm', 'e'})))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzkit.Detect(t, New(), data)
	})
}
