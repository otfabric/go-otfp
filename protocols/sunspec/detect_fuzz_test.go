// SPDX-License-Identifier: MIT

package sunspec

import (
	"testing"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
	"github.com/otfabric/go-otfp/internal/mbap"
)

// FuzzDetect runs the fingerprinter end to end against a server replying
// with fuzzed bytes, seeded with replies captured from reference servers,
// and checks the Fingerprinter contract on every result (see fuzzkit).
func FuzzDetect(f *testing.F) {
	f.Add(fuzzkit.Join(mbap.Request(0x5301, 1, 3, 4, 0x53, 0x75, 0x6E, 0x53), mbap.Request(0x5302, 1, 3, 4, 0, 1, 0, 66)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzkit.Detect(t, New(), data)
	})
}
