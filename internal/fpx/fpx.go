// SPDX-License-Identifier: MIT

// Package fpx is the scoring helper of the built-in fingerprinters: it
// accumulates evidence, the fingerprint signature and the identity, and
// produces the core.Result.
package fpx

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/wire"
)

// Limits on the text of a result.
const (
	// MaxText is the most runes Clean keeps of one string read off the
	// wire: a name, a version, a URI.
	MaxText = 512
	// MaxLine is the most runes of any one string of a Result: an evidence
	// line, the signature, an identity value that lists several items.
	MaxLine = 4096
)

// Builder accumulates the outcome of one detection.
type Builder struct {
	proto    core.Protocol
	conf     core.Confidence
	evidence []string
	sig      []string
	meta     map[string]string
	variant  string
	identity core.Identity
}

// New returns a builder for protocol p.
func New(p core.Protocol) *Builder { return &Builder{proto: p} }

// Score raises the confidence to at least c, recording why. Confidence is
// the strongest single piece of evidence, not a sum: two weak hints do not
// make a strong match.
func (b *Builder) Score(c core.Confidence, evidence string) {
	if c > b.conf {
		b.conf = c
	}
	b.Evidence(evidence)
}

// Evidence records an observation without changing the confidence.
func (b *Builder) Evidence(e string) {
	if e != "" {
		b.evidence = append(b.evidence, e)
	}
}

// Confidence returns the confidence so far.
func (b *Builder) Confidence() core.Confidence { return b.conf }

// Sig appends key=value to the fingerprint signature.
func (b *Builder) Sig(key, value string) {
	b.sig = append(b.sig, key+"="+value)
}

// Meta records fingerprint metadata.
func (b *Builder) Meta(key, value string) {
	if value == "" {
		return
	}
	if b.meta == nil {
		b.meta = map[string]string{}
	}
	b.meta[key] = value
}

// Variant sets the variant.
func (b *Builder) Variant(v string) { b.variant = v }

// VariantSet reports whether a variant has been set.
func (b *Builder) VariantSet() bool { return b.variant != "" }

// Identity returns the identity being filled.
func (b *Builder) Identity() *core.Identity { return &b.identity }

// Result returns the result, with a fingerprint of the given probe ID when
// any signature was recorded, and the session's exchanges when s is not
// nil.
//
// Every string of the result is text for a person or a log: the variant,
// the details, each evidence line, the signature, the metadata and every
// identity field and attribute hold graphic characters only (see Line) and
// at most MaxLine runes, whatever a fingerprinter put into them. An evidence
// line, a metadata value or an attribute that is empty after that is left
// out.
func (b *Builder) Result(probeID, details string, s *wire.Session) core.Result {
	details = Line(details)
	r := core.Match(b.proto, b.conf, details)
	if b.conf == 0 {
		r = core.NoMatch(b.proto)
		r.Details = details
	}
	r.Variant = Line(b.variant)
	for _, e := range b.evidence {
		if e = Line(e); e != "" {
			r.Evidence = append(r.Evidence, e)
		}
	}
	if len(b.sig) > 0 {
		r.Fingerprint = &core.Fingerprint{ID: Line(probeID), Signature: Line(strings.Join(b.sig, ";")), Metadata: lines(b.meta)}
	}
	id := b.identity
	id.Vendor, id.VendorID, id.Product = Line(id.Vendor), Line(id.VendorID), Line(id.Product)
	id.Model, id.Version, id.Serial, id.Name = Line(id.Model), Line(id.Version), Line(id.Serial), Line(id.Name)
	id.Attributes = lines(id.Attributes)
	r = r.WithIdentity(&id)
	if s != nil {
		r = r.WithExchanges(s.Exchanges())
	}
	return r
}

// lines returns a copy of m with every key and value passed through Line;
// entries whose key or value is empty afterwards are left out. It returns
// nil when nothing is left.
func lines(m map[string]string) map[string]string {
	var out map[string]string
	for k, v := range m {
		if k, v = Line(k), Line(v); k == "" || v == "" {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(m))
		}
		out[k] = v
	}
	return out
}

// Clean returns a string read off the wire as text: without NUL padding,
// control characters (C0, DEL, C1), format characters (zero-width and
// directional marks), line and paragraph separators, unassigned and
// private-use code points and octets that are not UTF-8; without leading
// and trailing spaces; and cut to MaxText runes. Letters, marks, digits,
// punctuation, symbols and spaces of every script are kept.
func Clean(s string) string { return Text(s, MaxText) }

// Line is Clean with the larger bound MaxLine, for a whole line of a result
// that fixed text and several cleaned strings were joined into.
func Line(s string) string { return Text(s, MaxLine) }

// Graphic reports whether r is kept by Clean and Line: a graphic character
// as Unicode defines it (unicode.IsGraphic), other than the replacement
// character that stands for octets that are not UTF-8.
func Graphic(r rune) bool { return r != utf8.RuneError && unicode.IsGraphic(r) }

// Text is Clean with a bound of limit runes; a negative limit keeps nothing.
func Text(s string, limit int) string {
	limit = max(limit, 0)
	// The common case, checked without allocating: nothing to drop.
	keep, n := true, 0
	for i, r := range s {
		if !Graphic(r) || n == limit || (i == 0 && unicode.IsSpace(r)) {
			keep = false
			break
		}
		n++
	}
	if keep {
		return strings.TrimRightFunc(s, unicode.IsSpace)
	}
	var b strings.Builder
	n = 0
	for _, r := range s {
		if !Graphic(r) || (n == 0 && unicode.IsSpace(r)) {
			continue
		}
		if n == limit {
			break
		}
		b.WriteRune(r)
		n++
	}
	return strings.TrimRightFunc(b.String(), unicode.IsSpace)
}

// SortedKeys returns the keys of m in order.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
