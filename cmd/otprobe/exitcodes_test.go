// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/otfabric/go-otfp/core"
)

// TestClassify: every error a command can return maps to its exit code.
func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"cobra usage", errors.New(`unknown command "probe" for "otprobe"`), exitUsage},
		{"flag", fail(kindUsage, codeInvalidInput, "unknown flag: --bogus"), exitUsage},
		{"invalid input", fail(kindInvalidInput, codeInvalidTarget, "bad port"), exitInvalidInput},
		{"transport", fail(kindTransport, codeInvalidInput, "refused"), exitTransport},
		{"timeout", fail(kindTimeout, codeInvalidInput, "late"), exitTimeout},
		{"output", fail(kindOutput, codeOutputFailed, "write output: broken pipe"), exitInternal},
		{"internal", fail(kindInternal, codeInternal, "bug"), exitInternal},
		{"interrupted", fail(kindInterrupted, codeContextCanceled, "interrupted"), exitInterrupted},
		{"wrapped interrupted", fmt.Errorf("run: %w", fail(kindInterrupted, codeContextCanceled, "interrupted")), exitInterrupted},
		{"bare context canceled", fmt.Errorf("execute: %w", context.Canceled), exitInterrupted},
	}
	for _, c := range cases {
		if got := classify(c.err).exitCode(); got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
}

// TestOutcome: the scan results map to the exit code, with the documented
// precedence, by the library's typed errors.
func TestOutcome(t *testing.T) {
	p := core.ProtocolModbus
	high := core.Result{Protocol: p, Matched: true, Confidence: core.ConfidenceHigh}
	medium := core.Result{Protocol: p, Matched: true, Confidence: core.ConfidenceHigh / 2}
	nomatch := core.NoMatch(p)
	refused := core.ErrorResult(p, &core.ConnectionError{Protocol: p, Addr: "x:1", Err: errors.New("connection refused")})
	timedOut := core.ErrorResult(p, &core.TimeoutError{Protocol: p, Addr: "x:1", Op: "read", Err: os.ErrDeadlineExceeded})
	tlsFail := core.ErrorResult(p, &core.DetectError{Protocol: p, Op: "tls", Err: x509.UnknownAuthorityError{}})
	reset := core.ErrorResult(p, &core.DetectError{Protocol: p, Op: "read", Err: errors.New("connection reset by peer")})
	panicked := core.ErrorResult(p, &core.DetectError{Protocol: p, Op: "detect", Err: errors.New("fingerprinter panicked: boom")})
	deadline := core.ErrorResult(p, fmt.Errorf("modbus: %w", context.DeadlineExceeded))

	cases := []struct {
		name    string
		results []core.Result
		want    int
	}{
		{"detected", []core.Result{refused, high}, exitOK},
		{"partial", []core.Result{nomatch, medium, refused}, exitPartial},
		{"detected beats partial", []core.Result{medium, high}, exitOK},
		{"no match", []core.Result{nomatch, refused, timedOut}, exitFindings},
		{"refused", []core.Result{refused, timedOut}, exitTransport},
		{"tls handshake", []core.Result{tlsFail}, exitTransport},
		{"reset", []core.Result{reset}, exitTransport},
		{"timeout", []core.Result{timedOut}, exitTimeout},
		{"context deadline", []core.Result{deadline}, exitTimeout},
		{"panic", []core.Result{panicked}, exitInternal},
		{"transport beats panic", []core.Result{panicked, refused}, exitTransport},
		{"nothing probed", nil, exitFindings},
	}
	for _, c := range cases {
		got := outcome([]scan{{report: core.Report{Results: c.results}}})
		if got != c.want {
			t.Errorf("%s: exit %d, want %d", c.name, got, c.want)
		}
	}
}

// An interrupt (the root context cancelled) exits 130, rendered as an
// "interrupted" error in either format.
func TestInterrupted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errw bytes.Buffer
	if code := run(ctx, []string{"detect", "127.0.0.1:1", "--protocol", "modbus"}, &out, &errw); code != exitInterrupted || !strings.Contains(errw.String(), "interrupted") {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out.String(), errw.String())
	}
	out.Reset()
	errw.Reset()
	if code := run(ctx, []string{"detect", "127.0.0.1:1", "--protocol", "modbus", "-o", "json"}, &out, &errw); code != exitInterrupted || !strings.Contains(out.String(), `"kind": "interrupted"`) {
		t.Fatalf("json: exit %d\nstdout: %s\nstderr: %s", code, out.String(), errw.String())
	}
}

type brokenWriter struct{}

func (brokenWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A result that cannot be written exits 10, with the error on stderr.
func TestOutputFailed(t *testing.T) {
	for _, args := range [][]string{{"list"}, {"version"}, {"detect", addr(modbus(t)), "--protocol", "modbus"}} {
		var errw bytes.Buffer
		if code := run(context.Background(), args, brokenWriter{}, &errw); code != exitInternal || !strings.Contains(errw.String(), "write output") {
			t.Errorf("%v: exit %d, stderr %q", args, code, errw.String())
		}
	}
}
