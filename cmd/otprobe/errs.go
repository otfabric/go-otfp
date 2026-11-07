// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Exit codes, stable for scripting; see docs/exitcodes.md. They are the
// OT Fabric organisation table (engineering standards/api-design.md).
const (
	exitOK           = 0   // ok: a protocol was identified at high confidence
	exitFindings     = 1   // findings: the scan completed and no protocol matched
	exitUsage        = 2   // usage: unknown command or flag, wrong number of arguments
	exitInvalidInput = 3   // invalid input: a value that does not make sense; nothing was sent
	exitTransport    = 4   // transport: refused, unreachable, reset, TLS handshake failed
	exitTimeout      = 5   // timeout: nothing answered in time, or --deadline cut the scan
	exitPartial      = 7   // partial: matched, but below the high-confidence threshold
	exitInternal     = 10  // internal: output failed, or an unexpected error
	exitInterrupted  = 130 // interrupted: SIGINT/SIGTERM before a result
)

// kind classifies a fatal error; it selects the exit code.
type kind string

const (
	kindUsage        kind = "usage"
	kindInvalidInput kind = "invalid_input"
	kindTransport    kind = "transport"
	kindTimeout      kind = "timeout"
	kindOutput       kind = "output"
	kindInternal     kind = "internal"
	kindInterrupted  kind = "interrupted"
)

// Stable machine codes of the JSON error object.
const (
	codeInvalidInput     = "invalid_input"
	codeInvalidTarget    = "invalid_target"
	codeInvalidProtocol  = "invalid_protocol"
	codeInvalidFormat    = "invalid_format"
	codeInvalidFlags     = "invalid_flag_combination"
	codeNoFingerprinters = "no_fingerprinters"
	codeOutputFailed     = "output_write_failed"
	codeContextCanceled  = "context_canceled"
	codeInternal         = "internal_unexpected"
)

// cliError is a fatal error of a command.
type cliError struct {
	kind    kind
	code    string
	message string
}

func (e *cliError) Error() string { return e.message }

func fail(k kind, code, format string, args ...any) *cliError {
	return &cliError{kind: k, code: code, message: fmt.Sprintf(format, args...)}
}

func (e *cliError) exitCode() int {
	switch e.kind {
	case kindUsage:
		return exitUsage
	case kindInvalidInput:
		return exitInvalidInput
	case kindTransport:
		return exitTransport
	case kindTimeout:
		return exitTimeout
	case kindInterrupted:
		return exitInterrupted
	}
	return exitInternal
}

// render writes err once: as an "error:" line on stderr, or, with JSON
// output, as a single {"error": {...}} object on stdout. It returns the
// exit code.
func render(err error, jsonOut bool, stdout, stderr io.Writer) int {
	ce := classify(err)
	if jsonOut {
		doc := map[string]any{"error": map[string]string{
			"kind": string(ce.kind), "code": ce.code, "message": ce.message,
		}}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(doc)
	} else {
		fmt.Fprintln(stderr, "error:", ce.message)
	}
	return ce.exitCode()
}

// exitStatus carries a non-zero outcome (findings, partial, unreachable)
// out of a command that did write its result.
type exitStatus struct{ code int }

func (e *exitStatus) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// classify turns any error a command returns into a cliError. Errors the
// commands raise are cliErrors already; the rest come from cobra itself
// (unknown command, wrong number of arguments) and are usage errors, except
// a cancelled context, which is an interrupt.
func classify(err error) *cliError {
	if ce, ok := errors.AsType[*cliError](err); ok {
		return ce
	}
	if errors.Is(err, context.Canceled) {
		return &cliError{kind: kindInterrupted, code: codeContextCanceled, message: "interrupted"}
	}
	return &cliError{kind: kindUsage, code: codeInvalidInput, message: err.Error()}
}
