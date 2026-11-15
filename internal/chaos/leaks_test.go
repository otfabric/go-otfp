// SPDX-License-Identifier: MIT

package chaos

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

// stays blocks until released; its name is what the leak report shows.
func stays(release <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	<-release
}

// The helper compares goroutines, not their number: a goroutine that
// starts and stays is reported with its stack even though another one
// ended in the meantime and the count is what it was.
func TestLeakedNamesTheGoroutineThatStays(t *testing.T) {
	endEarly, earlyDone := make(chan struct{}), make(chan struct{})
	go func() { defer close(earlyDone); <-endEarly }() // exists at the baseline

	b := Snapshot()
	if g, fds := b.Leaked(0); len(g) != 0 || fds != 0 {
		t.Fatalf("nothing started: %d goroutines and %d file descriptors reported\n%s", len(g), fds, strings.Join(g, "\n\n"))
	}
	count := runtime.NumGoroutine()

	release, done := make(chan struct{}), make(chan struct{})
	go stays(release, done)
	close(endEarly)
	<-earlyDone

	// A check by count sees nothing: once the early goroutine has left,
	// the number is what it was at the baseline. Polling a condition with a
	// deadline: the goroutine leaves shortly after it closed earlyDone.
	for deadline := time.Now().Add(3 * time.Second); runtime.NumGoroutine() > count; {
		if time.Now().After(deadline) {
			t.Fatalf("%d goroutines, %d at the baseline: the early goroutine did not end", runtime.NumGoroutine(), count)
		}
		time.Sleep(5 * time.Millisecond)
	}

	g, _ := b.Leaked(100 * time.Millisecond)
	if len(g) != 1 || !strings.Contains(g[0], "chaos.stays") {
		t.Fatalf("%d goroutines reported, want the one running stays:\n%s", len(g), strings.Join(g, "\n\n"))
	}

	// Check fails the test with the stack of that goroutine.
	saved := leakWait
	leakWait = 50 * time.Millisecond
	rec := &failures{TB: t}
	b.Check(rec)
	leakWait = saved
	if !strings.Contains(rec.fatal, "1 goroutine(s)") || !strings.Contains(rec.fatal, "chaos.stays") {
		t.Fatalf("Check reported %q, want the goroutine running stays", rec.fatal)
	}

	// Once it has ended, nothing is reported: a goroutine that is ending is
	// waited for.
	close(release)
	<-done
	if g, _ := b.Leaked(3 * time.Second); len(g) != 0 {
		t.Fatalf("after release: %d goroutines reported:\n%s", len(g), strings.Join(g, "\n\n"))
	}
	rec = &failures{TB: t}
	b.Check(rec)
	if rec.fatal != "" {
		t.Fatalf("Check failed with nothing left: %s", rec.fatal)
	}
}

// File descriptors opened after the baseline are counted beyond a slack of
// two.
func TestLeakedCountsFileDescriptors(t *testing.T) {
	if FDs() < 0 {
		t.Skip("file descriptors cannot be counted on this platform")
	}
	b := Snapshot()
	var open []net.Listener
	defer func() {
		for _, ln := range open {
			_ = ln.Close()
		}
	}()
	for range 8 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, ln)
	}
	if _, fds := b.Leaked(0); fds < 8 {
		t.Fatalf("%d file descriptors reported with 8 listeners open", fds)
	}
	for _, ln := range open {
		_ = ln.Close()
	}
	open = nil
	if g, fds := b.Leaked(3 * time.Second); fds != 0 || len(g) != 0 {
		t.Fatalf("after closing: %d file descriptors, %d goroutines reported", fds, len(g))
	}
}

// failures records a fatal failure instead of ending the test.
type failures struct {
	testing.TB
	fatal string
}

func (f *failures) Helper() {}

func (f *failures) Fatalf(format string, args ...any) { f.fatal = fmt.Sprintf(format, args...) }
