// SPDX-License-Identifier: MIT

package enip

import (
	"testing"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// FuzzDetect runs the fingerprinter end to end against a server replying
// with fuzzed bytes, seeded with replies captured from reference servers,
// and checks the Fingerprinter contract on every result (see fuzzkit).
func FuzzDetect(f *testing.F) {
	f.Add(fuzzkit.Join(encap(cmdListIdentity, 0, [8]byte{}, unhex(openerBody)), encap(cmdRegisterSession, 1, [8]byte{}, []byte{1, 0, 0, 0})))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzkit.Detect(t, New(), data)
	})
}

// FuzzDetectUDP is FuzzDetect over UDP ListIdentity.
func FuzzDetectUDP(f *testing.F) {
	f.Add(fuzzkit.Join(encap(cmdListIdentity, 0, [8]byte{}, unhex(openerBody))))
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzkit.Detect(t, NewUDP(), data)
	})
}
