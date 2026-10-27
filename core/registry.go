// SPDX-License-Identifier: MIT

package core

import (
	"fmt"
	"sort"
	"sync"
)

// Registry holds fingerprinters, at most one per protocol and network. It is
// safe for concurrent use.
type Registry struct {
	mu  sync.RWMutex
	fps []Fingerprinter
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry { return &Registry{} }

// Register adds fp. It fails when a fingerprinter for the same protocol and
// network is already registered, or when Info reports an invalid protocol.
func (r *Registry) Register(fp Fingerprinter) error {
	info := fp.Info()
	if !info.Protocol.IsValid() {
		return fmt.Errorf("register: invalid protocol %d", info.Protocol)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, have := range r.fps {
		hi := have.Info()
		if hi.Protocol == info.Protocol && hi.Network == info.Network {
			return fmt.Errorf("register: %s over %s already registered", info.Protocol, info.Network)
		}
	}
	r.fps = append(r.fps, fp)
	return nil
}

// MustRegister is Register that panics on error, for package-level setup.
func (r *Registry) MustRegister(fps ...Fingerprinter) *Registry {
	for _, fp := range fps {
		if err := r.Register(fp); err != nil {
			panic(err)
		}
	}
	return r
}

// Get returns the fingerprinter for protocol p over network n, or nil.
func (r *Registry) Get(p Protocol, n Network) Fingerprinter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, fp := range r.fps {
		if i := fp.Info(); i.Protocol == p && i.Network == n {
			return fp
		}
	}
	return nil
}

// All returns every fingerprinter, ordered by Priority then protocol.
func (r *Registry) All() []Fingerprinter {
	r.mu.RLock()
	out := append([]Fingerprinter(nil), r.fps...)
	r.mu.RUnlock()
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i].Info(), out[j].Info()
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		return a.Protocol < b.Protocol
	})
	return out
}

// Protocols returns the distinct protocols registered, in numeric order.
func (r *Registry) Protocols() []Protocol {
	seen := map[Protocol]bool{}
	for _, fp := range r.All() {
		seen[fp.Info().Protocol] = true
	}
	out := make([]Protocol, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Plan returns the fingerprinters that apply to target, in the order the
// engine runs them: those of target.Network only; first those whose
// well-known ports include target.Port, then the rest, each group by
// Priority.
func (r *Registry) Plan(target Target) []Fingerprinter {
	var likely, rest []Fingerprinter
	for _, fp := range r.All() {
		info := fp.Info()
		if info.Network != target.Network {
			continue
		}
		if hasPort(info.Ports, target.Port) {
			likely = append(likely, fp)
		} else {
			rest = append(rest, fp)
		}
	}
	return append(likely, rest...)
}

func hasPort(ports []int, p int) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}
