// SPDX-License-Identifier: MIT

package canopen

import (
	"testing"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// FuzzDetect runs the fingerprinter end to end against a server replying
// with fuzzed bytes, seeded with replies captured from CANopenNode's
// canopend gateway (the sequence numbers cannot match the fuzzed run's, so
// the seeds exercise the stale-response path), and checks the
// Fingerprinter contract on every result (see fuzzkit).
func FuzzDetect(f *testing.F) {
	f.Add(fuzzkit.Join([]byte("\r\n[1234567] ERROR:100 #Request not supported.\r\n"), []byte("[12] 0\r\n"),
		[]byte("[13] \"otfabric canopen-interop device\"\r\n")))
	f.Add(fuzzkit.Join([]byte("[21] ERROR:101 #Syntax error.\r\n[777] ERROR:100 #Request not supported.\r\n")))
	f.Add([]byte("HTTP/1.1 400 Bad Request\r\n"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzkit.Detect(t, New(), data)
	})
}
