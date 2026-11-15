// SPDX-License-Identifier: MIT

package sparkplugb

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// clean keeps text only, without the separators of the identity lists,
// bounded in runes.
func TestCleanKeepsTextOnly(t *testing.T) {
	for in, want := range map[string]string{
		"":                          "",
		"Plant 1":                   "Plant 1",
		"  a,b;c  ":                 "abc",
		"Größe 東京":                  "Größe 東京",
		"a" + fuzzkit.NonText + "b": "ab",
		fuzzkit.NonText:             "",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, want %q", in, got, want)
		}
	}
	for _, n := range []int{maxNameLen - 1, maxNameLen, maxNameLen + 1, 100 * maxNameLen} {
		if got := utf8.RuneCountInString(clean(strings.Repeat("é", n))); got != min(n, maxNameLen) {
			t.Errorf("%d runes: %d kept, want %d", n, got, min(n, maxNameLen))
		}
	}
}
