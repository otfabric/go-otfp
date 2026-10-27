// SPDX-License-Identifier: MIT

package iec104

import (
	"testing"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// FuzzDetect runs the fingerprinter end to end against a server replying
// with fuzzed bytes, seeded with replies captured from reference servers,
// and checks the Fingerprinter contract on every result (see fuzzkit).
func FuzzDetect(f *testing.F) {
	f.Add(fuzzkit.Join(U(uTestCon), U(uStartCon), []byte{0x68, 0x0E, 0, 0, 0, 0, 70, 1, 4, 0, 1, 0, 0, 0, 0, 0}, U(uStopCon)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzkit.Detect(t, New(), data)
	})
}
