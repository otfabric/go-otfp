// SPDX-License-Identifier: MIT

package fpx

import (
	"testing"

	"github.com/otfabric/go-otfp/core"
)

func TestBuilderScoring(t *testing.T) {
	b := New(core.ProtocolModbus)
	b.Score(core.ConfidenceLow, "weak")
	b.Score(core.ConfidenceCertain, "strong")
	b.Score(core.ConfidenceMedium, "medium") // must not lower confidence
	if b.Confidence() != core.ConfidenceCertain {
		t.Fatalf("confidence %v", b.Confidence())
	}
	b.Sig("a", "1")
	b.Sig("b", "2")
	b.Meta("m", "v")
	b.Variant("X")
	if !b.VariantSet() {
		t.Fatal("variant")
	}
	b.Identity().Vendor = "Acme"
	r := b.Result("modbus.test", "ok", nil)
	if !r.Matched || r.Variant != "X" || r.Fingerprint.Signature != "a=1;b=2" || r.Fingerprint.Metadata["m"] != "v" {
		t.Fatalf("result %+v fp %+v", r, r.Fingerprint)
	}
	if r.Identity == nil || r.Identity.Vendor != "Acme" {
		t.Fatalf("identity %+v", r.Identity)
	}
	if len(r.Evidence) != 3 {
		t.Fatalf("evidence %v", r.Evidence)
	}
}

func TestNoMatchResult(t *testing.T) {
	b := New(core.ProtocolS7)
	b.Evidence("saw something")
	r := b.Result("s7.test", "nope", nil)
	if r.Matched || r.Confidence != 0 || r.Fingerprint != nil {
		t.Fatalf("result %+v", r)
	}
}

func TestClean(t *testing.T) {
	if Clean("  Ac\x00me\x0e  ") != "Acme" {
		t.Fatalf("clean %q", Clean("  Ac\x00me\x0e  "))
	}
	if Clean("\x00\x00") != "" {
		t.Fatal("all-control")
	}
}

func TestSortedKeys(t *testing.T) {
	k := SortedKeys(map[string]int{"b": 1, "a": 2, "c": 3})
	if len(k) != 3 || k[0] != "a" || k[2] != "c" {
		t.Fatalf("keys %v", k)
	}
}
