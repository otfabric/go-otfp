// SPDX-License-Identifier: MIT

// Package fpx is the scoring helper of the built-in fingerprinters: it
// accumulates evidence, the fingerprint signature and the identity, and
// produces the core.Result.
package fpx

import (
	"sort"
	"strings"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/wire"
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
func (b *Builder) Result(probeID, details string, s *wire.Session) core.Result {
	r := core.Match(b.proto, b.conf, details)
	if b.conf == 0 {
		r = core.NoMatch(b.proto)
		r.Details = details
	}
	r.Variant = b.variant
	r.Evidence = b.evidence
	if len(b.sig) > 0 {
		r.Fingerprint = &core.Fingerprint{ID: probeID, Signature: strings.Join(b.sig, ";"), Metadata: b.meta}
	}
	id := b.identity
	r = r.WithIdentity(&id)
	if s != nil {
		r = r.WithExchanges(s.Exchanges())
	}
	return r
}

// Clean trims NUL padding, spaces and non-printable bytes from a string
// read off the wire.
func Clean(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == 0xfffd {
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
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
