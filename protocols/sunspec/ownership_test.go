// SPDX-License-Identifier: MIT

package sunspec

import (
	"context"
	"encoding/binary"
	"slices"
	"sync"
	"testing"

	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/mbap"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// plainModbus answers every read with "illegal data address", so that the
// fingerprinter walks all of its base addresses.
func plainModbus(req []byte) ([]byte, bool) {
	if len(req) < 8 {
		return nil, true
	}
	return mbap.Request(binary.BigEndian.Uint16(req), req[6], req[7]|0x80, 0x02), false
}

// addresses returns the register addresses of the recorded read requests.
func addresses(rec *chaos.Recorder) []uint16 {
	var out []uint16
	for _, req := range rec.Requests() {
		if len(req) >= 10 {
			out = append(out, binary.BigEndian.Uint16(req[8:]))
		}
	}
	return out
}

// NewWithConfig keeps a copy of Config.Bases: the caller's slice is the
// caller's, and changing it afterwards does not change the addresses read.
func TestBasesAreCopied(t *testing.T) {
	bases := []uint16{40000, 50000}
	f := NewWithConfig(Config{Bases: bases})
	bases[0], bases[1] = 7, 8

	rec := &chaos.Recorder{}
	target := testsrv.TCP(t, rec.Wrap(plainModbus))
	if _, err := f.Detect(context.Background(), target, readOnly); err != nil {
		t.Fatal(err)
	}
	got := addresses(rec)
	if len(got) == 0 {
		t.Fatal("no read request recorded")
	}
	for _, a := range got {
		if a != 40000 && a != 50000 {
			t.Fatalf("read at %v after the caller changed its slice, want 40000 and 50000 only", got)
		}
	}
}

// A fingerprinter keeps the default addresses it was constructed with:
// a later change of DefaultBases does not reach it.
func TestDefaultBasesAreCopied(t *testing.T) {
	saved := slices.Clone(DefaultBases)
	t.Cleanup(func() { copy(DefaultBases, saved) })
	f := New()
	for i := range DefaultBases {
		DefaultBases[i] = 9
	}
	if !slices.Equal(f.bases, saved) {
		t.Fatalf("bases %v after DefaultBases changed, want %v", f.bases, saved)
	}
	rec := &chaos.Recorder{}
	target := testsrv.TCP(t, rec.Wrap(plainModbus))
	if _, err := f.Detect(context.Background(), target, readOnly); err != nil {
		t.Fatal(err)
	}
	if got := addresses(rec); len(got) == 0 || got[0] != saved[0] || slices.Contains(got, 9) {
		t.Fatalf("read at %v, want the addresses of construction %v", got, saved)
	}
}

// The caller may go on using its slice while scans run, from another
// goroutine: under the race detector this test fails when the fingerprinter
// reads the caller's slice.
func TestCallerWritesItsSliceDuringScans(t *testing.T) {
	bases := []uint16{40000, 0, 50000}
	f := NewWithConfig(Config{Bases: bases})
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				bases[i%len(bases)] = uint16(60000 + i%100)
			}
		}
	})
	rec := &chaos.Recorder{}
	target := testsrv.TCP(t, rec.Wrap(plainModbus))
	for range 20 {
		if _, err := f.Detect(context.Background(), target, readOnly); err != nil {
			t.Fatal(err)
		}
	}
	close(stop)
	wg.Wait()
	for _, a := range addresses(rec) {
		if a != 40000 && a != 0 && a != 50000 {
			t.Fatalf("read at %d, which is not an address of construction", a)
		}
	}
}
