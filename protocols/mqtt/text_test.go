// SPDX-License-Identifier: MIT

package mqtt

import (
	"testing"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// The topic and the payload of the $SYS version message reach the result
// as text only.
func TestSysVersionIsText(t *testing.T) {
	nt := fuzzkit.NonText[:len(fuzzkit.NonText)-1] // a topic is valid UTF-8
	f := &fake{connack: always(connack5(0, 0)), ping: true,
		after: publish(5, "$SYS/brokers/node"+nt+"1/version", []byte("5.8"+fuzzkit.NonText+".0"), 0)}
	r := run(t, f.target(t), identify)
	fuzzkit.Check(t, proto, r, nil)
	if r.Identity.Product != "EMQX" || r.Identity.Version != "5.8.0" {
		t.Fatalf("identity %+v", r.Identity)
	}
	if want := `$SYS/brokers/node1/version: "5.8.0"`; !hasEvidence(r, want) {
		t.Fatalf("evidence %q, want %q", r.Evidence, want)
	}
}

func TestSanitizeDropsWhatIsNotText(t *testing.T) {
	if got := Sanitize("a"+fuzzkit.NonText+"b", 10); got != "ab" {
		t.Fatalf("%q", got)
	}
	if got := Sanitize("abc", -1); got != "" {
		t.Fatalf("negative bound: %q", got)
	}
}
