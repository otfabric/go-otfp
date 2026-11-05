// SPDX-License-Identifier: MIT

package fpx

import (
	"context"
	"testing"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
	"github.com/otfabric/go-otfp/internal/wire"
)

// An empty metadata value is not recorded, and a result built with a
// session carries the session's trace.
func TestMetaAndTrace(t *testing.T) {
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) { return req, false })
	s, err := wire.Dial(context.Background(), core.ProtocolModbus, target, core.Options{Trace: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if _, err := s.RoundTrip("ping", []byte("ping"), nil, 16); err != nil {
		t.Fatal(err)
	}
	b := New(core.ProtocolModbus)
	b.Score(core.ConfidenceHigh, "x")
	b.Sig("k", "v")
	b.Meta("empty", "")
	b.Meta("set", "1")
	r := b.Result("probe", "details", s)
	if _, ok := r.Fingerprint.Metadata["empty"]; ok || r.Fingerprint.Metadata["set"] != "1" {
		t.Fatalf("metadata %v", r.Fingerprint.Metadata)
	}
	if len(r.Exchanges) != 1 || string(r.Exchanges[0].Probe) != "ping" {
		t.Fatalf("exchanges %+v", r.Exchanges)
	}
}
