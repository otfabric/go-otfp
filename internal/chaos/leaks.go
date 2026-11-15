// SPDX-License-Identifier: MIT

package chaos

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Baseline is what a leak check compares with: the goroutines that exist
// when it is taken, each known by its identifier, and the number of open
// file descriptors. It is the one leak helper of the repository: the chaos
// suites and the end-to-end tests use it.
type Baseline struct {
	goroutines map[uint64]bool
	fds        int
}

// Snapshot returns the baseline of this moment. Take it after the test's
// own servers are started, so that their goroutines are part of it.
func Snapshot() Baseline {
	settle()
	b := Baseline{goroutines: map[uint64]bool{}, fds: FDs()}
	for id := range stacks() {
		b.goroutines[id] = true
	}
	return b
}

// Leaked waits up to wait for every goroutine that was started after the
// baseline to end, and returns the stacks of those still running: the
// comparison is by goroutine, not by count, so a goroutine that stays is
// reported even when another one ended in the meantime, and it is reported
// with the stack that says what it is. The second result is the number of
// file descriptors open beyond the baseline (0 where they cannot be
// counted), with a slack of two for the runtime's own.
func (b Baseline) Leaked(wait time.Duration) (goroutines []string, fds int) {
	deadline := time.Now().Add(wait)
	for {
		goroutines = goroutines[:0]
		for id, stack := range stacks() {
			if !b.goroutines[id] {
				goroutines = append(goroutines, stack)
			}
		}
		fds = 0
		if now := FDs(); b.fds >= 0 && now > b.fds+2 {
			fds = now - b.fds
		}
		if (len(goroutines) == 0 && fds == 0) || !time.Now().Before(deadline) {
			return goroutines, fds
		}
		// Polling a condition with a deadline: goroutines that are ending
		// leave the list shortly after their work is done.
		settle()
	}
}

// leakWait is how long Check waits for goroutines that are ending.
var leakWait = 3 * time.Second

// Check fails t when, within 3 s, a goroutine started after the baseline is
// still running or file descriptors are still open beyond it.
func (b Baseline) Check(t testing.TB) {
	t.Helper()
	goroutines, fds := b.Leaked(leakWait)
	if len(goroutines) == 0 && fds == 0 {
		return
	}
	t.Fatalf("leak: %d goroutine(s) started since the baseline are still running, %d file descriptor(s) more are open\n\n%s",
		len(goroutines), fds, strings.Join(goroutines, "\n\n"))
}

// stacks returns the stack of every goroutine but the calling one, by
// goroutine identifier.
func stacks() map[uint64]string {
	buf := make([]byte, 1<<16)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	out := map[uint64]string{}
	// Blocks of "goroutine N [state]:" and the frames below; the first is
	// the goroutine that asked.
	for i, g := range strings.Split(strings.TrimSpace(string(buf)), "\n\n") {
		if i == 0 {
			continue
		}
		rest, ok := strings.CutPrefix(g, "goroutine ")
		if !ok {
			continue
		}
		num, _, _ := strings.Cut(rest, " ")
		if id, err := strconv.ParseUint(num, 10, 64); err == nil {
			out[id] = g
		}
	}
	return out
}

func settle() {
	runtime.GC()
	time.Sleep(20 * time.Millisecond)
}

// FDs returns the number of open file descriptors of the process, or -1
// where it cannot be counted.
func FDs() int {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		return -1
	}
	ents, err := os.ReadDir("/dev/fd")
	if err != nil {
		return -1
	}
	return len(ents)
}
