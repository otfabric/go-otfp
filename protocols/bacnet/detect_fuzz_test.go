// SPDX-License-Identifier: MIT

package bacnet

import (
	"testing"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// FuzzDetect runs the fingerprinter end to end against a server replying
// with fuzzed bytes, seeded with replies captured from reference servers,
// and checks the Fingerprinter contract on every result (see fuzzkit).
func FuzzDetect(f *testing.F) {
	f.Add(fuzzkit.Join(unhex("810a0017010030010c0c020004d2194b3ec4020004d23f"), unhex("810a0022010030020c0c020004d2194d3e750e00496e7465726f704465766963653f")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzkit.Detect(t, New(), data)
	})
}
