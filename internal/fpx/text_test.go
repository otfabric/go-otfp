// SPDX-License-Identifier: MIT

package fpx

import (
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// Clean keeps graphic characters of every script and drops the rest.
func TestCleanKeepsTextOnly(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"ascii", "Acme PLC 1.0", "Acme PLC 1.0"},
		{"padding and spaces", "  Ac\x00me\x0e \x00\x00 ", "Acme"},
		{"other scripts", "Zürich Größe 東京 Ωmega", "Zürich Größe 東京 Ωmega"},
		{"no-break space inside", "Schneider\U000000a0Electric", "Schneider\U000000a0Electric"},
		{"escape", "a\x1b[2Jb", "a[2Jb"},
		{"bell, carriage return, line feed, tab", "a\a\r\n\tb", "ab"},
		{"delete", "a\x7fb", "ab"},
		{"next line (C1)", "a\u0085b", "ab"},
		{"control sequence introducer (C1)", "a\u009b31mb", "a31mb"},
		{"directional override", "a\U0000202eb", "ab"},
		{"zero-width space", "a\U0000200bb", "ab"},
		{"byte order mark", "\U0000feffab", "ab"},
		{"line and paragraph separators", "a\U00002028b\U00002029c", "abc"},
		{"replacement character", "a\U0000fffdb", "ab"},
		{"octets that are not UTF-8", "a\xff\xfeb\xc3", "ab"},
		{"only characters that are dropped", fuzzkit.NonText, ""},
	}
	for _, tc := range cases {
		if got := Clean(tc.in); got != tc.want {
			t.Errorf("%s: Clean(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

// Clean, Line and Text cut at their bound, counted in runes after the
// characters that are dropped.
func TestTextBounds(t *testing.T) {
	for _, tc := range []struct {
		name        string
		f           func(string) string
		runes, want int
	}{
		{"Clean, one below the bound", Clean, MaxText - 1, MaxText - 1},
		{"Clean, at the bound", Clean, MaxText, MaxText},
		{"Clean, one above the bound", Clean, MaxText + 1, MaxText},
		{"Clean, far above the bound", Clean, 1 << 20, MaxText},
		{"Line, at the bound", Line, MaxLine, MaxLine},
		{"Line, one above the bound", Line, MaxLine + 1, MaxLine},
		{"Text, bound 0", func(s string) string { return Text(s, 0) }, 5, 0},
		{"Text, bound 1", func(s string) string { return Text(s, 1) }, 5, 1},
		{"Text, negative bound", func(s string) string { return Text(s, -1) }, 5, 0},
	} {
		for _, unit := range []string{"a", "é", "\x1bé"} { // one kept rune per unit
			got := tc.f(strings.Repeat(unit, tc.runes))
			if n := utf8.RuneCountInString(got); n != tc.want {
				t.Errorf("%s, unit %q: %d runes kept of %d, want %d", tc.name, unit, n, tc.runes, tc.want)
			}
		}
	}
	// A cut that would end in a space ends before it.
	if got := Text("ab  cd", 3); got != "ab" {
		t.Errorf("Text(%q, 3) = %q, want %q", "ab  cd", got, "ab")
	}
}

func TestGraphic(t *testing.T) {
	for r, want := range map[rune]bool{
		'a': true, ' ': true, 'é': true, '東': true, '€': true, '\U000000a0': true,
		0x00: false, 0x1b: false, 0x7f: false, 0x85: false, 0x9b: false,
		0x200b: false, 0x202e: false, 0x2028: false, 0xfeff: false, utf8.RuneError: false,
	} {
		if Graphic(r) != want {
			t.Errorf("Graphic(%U) = %v, want %v", r, !want, want)
		}
	}
}

// Whatever a fingerprinter puts into its builder, every string of the
// Result is text: graphic characters only, bounded.
func TestResultHoldsTextOnly(t *testing.T) {
	const nt = fuzzkit.NonText
	b := New(core.ProtocolModbus)
	b.Score(core.ConfidenceCertain, "reply "+nt+"valid")
	b.Evidence(nt) // nothing left: not recorded
	b.Evidence(strings.Repeat("x", MaxLine+100))
	b.Sig("k"+nt, "v"+nt)
	b.Meta("meta"+nt, "value"+nt)
	b.Meta("gone", nt)
	b.Variant("variant" + nt)
	id := b.Identity()
	id.Vendor, id.VendorID, id.Product, id.Model = "vendor"+nt, "7"+nt, "product"+nt, "model"+nt
	id.Version, id.Serial, id.Name = "1.0"+nt, "serial"+nt, "name"+nt
	id.Set("attr"+nt, "value"+nt)
	id.Set("gone", nt+" "+nt)
	r := b.Result("probe"+nt, "details"+nt, nil)

	fuzzkit.Check(t, core.ProtocolModbus, r, nil)
	if r.Details != "details" || r.Variant != "variant" {
		t.Errorf("details %q, variant %q", r.Details, r.Variant)
	}
	if len(r.Evidence) != 2 || r.Evidence[0] != "reply valid" || utf8.RuneCountInString(r.Evidence[1]) != MaxLine {
		t.Errorf("evidence %q", r.Evidence)
	}
	if fp := r.Fingerprint; fp.ID != "probe" || fp.Signature != "k=v" || len(fp.Metadata) != 1 || fp.Metadata["meta"] != "value" {
		t.Errorf("fingerprint %+v", fp)
	}
	want := core.Identity{Vendor: "vendor", VendorID: "7", Product: "product", Model: "model",
		Version: "1.0", Serial: "serial", Name: "name", Attributes: map[string]string{"attr": "value"}}
	got := *r.Identity
	if got.Vendor != want.Vendor || got.VendorID != want.VendorID || got.Product != want.Product || got.Model != want.Model ||
		got.Version != want.Version || got.Serial != want.Serial || got.Name != want.Name ||
		len(got.Attributes) != 1 || got.Attributes["attr"] != "value" {
		t.Errorf("identity %+v, want %+v", got, want)
	}
	for _, s := range []string{r.String(), r.Identity.String(), r.Fingerprint.String()} {
		for _, c := range s {
			if !unicode.IsGraphic(c) {
				t.Errorf("%U in %q", c, s)
			}
		}
	}

	// An identity of dropped characters only is no identity.
	b = New(core.ProtocolModbus)
	b.Score(core.ConfidenceHigh, "x")
	b.Identity().Name = nt
	b.Identity().Set("a", nt)
	if r := b.Result("probe", "details", nil); r.Identity != nil {
		t.Errorf("identity %+v, want none", r.Identity)
	}
}
