// SPDX-License-Identifier: MIT

package sparkplugb

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
)

// New keeps a copy of Filters: a later change of the variable, of the
// slice or of one of its elements, does not reach the fingerprinter. The
// SUBSCRIBE it sends carries the filters of construction.
func TestFiltersAreCopied(t *testing.T) {
	saved := slices.Clone(Filters)
	original := Filters
	t.Cleanup(func() { Filters = original; copy(Filters, saved) })

	f := New()
	f.Window = 200 * time.Millisecond
	Filters[0] = "changed/+"
	if got := strings.Split(f.filters, "\x00"); !slices.Equal(got, saved) {
		t.Fatalf("filters %q after an element of Filters changed, want %q", got, saved)
	}
	b := &broker{connack: accept}
	sub := subscribePacket(t, runFP(t, f, b.target(t), detect))
	for _, s := range saved {
		if !bytes.Contains(sub, str(s)) {
			t.Errorf("SUBSCRIBE % x does not carry the filter %q of construction", sub, s)
		}
	}
	if bytes.Contains(sub, []byte("changed/+")) {
		t.Errorf("SUBSCRIBE % x carries the filter written to Filters after New", sub)
	}

	Filters = []string{"other/#"}
	if got := strings.Split(f.filters, "\x00"); !slices.Equal(got, saved) {
		t.Fatalf("filters %q after Filters was replaced, want %q", got, saved)
	}
	// The copy is taken when New runs.
	if got := strings.Split(New().filters, "\x00"); !slices.Equal(got, []string{"other/#"}) {
		t.Fatalf("New after the change keeps %q, want the filters of that moment", got)
	}
}

// subscribePacket returns the SUBSCRIBE the trace of r holds.
func subscribePacket(t *testing.T, r core.Result) []byte {
	t.Helper()
	for _, x := range r.Exchanges {
		if len(x.Probe) > 0 && x.Probe[0] == 0x82 {
			return x.Probe
		}
	}
	t.Fatalf("no SUBSCRIBE in the trace of %v", r)
	return nil
}

// A fingerprinter made by New does not read Filters during Detect: the
// variable may be changed while it runs (under -race, a read would be
// reported).
func TestDetectDoesNotReadFilters(t *testing.T) {
	original := Filters
	t.Cleanup(func() { Filters = original })
	f := New()
	f.Window = 100 * time.Millisecond
	b := &broker{connack: accept, codes: make([]byte, len(Filters))} // the broker does not read Filters either
	target := b.target(t)
	done := make(chan error, 1)
	go func() {
		_, err := f.Detect(context.Background(), target, detect)
		done <- err
	}()
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			return
		default:
			Filters = []string{"other/#"}
			time.Sleep(time.Millisecond)
		}
	}
}
