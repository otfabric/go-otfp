// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// Exit codes, stable for scripting; see docs/exitcodes.md. They follow the
// OT Fabric CLI convention (2 usage, 3 invalid input, 4 transport, 5
// timeout, 7 partial, 10 output/internal), plus the scanner outcome 1.
const (
	exitDetected     = 0  // a protocol was identified at high confidence
	exitNoMatch      = 1  // the target answered, but no protocol matched
	exitUsage        = 2  // unknown command or flag, wrong number of arguments
	exitInvalidInput = 3  // a value that does not make sense; nothing was sent
	exitTransport    = 4  // the target could not be reached (refused, unreachable, TLS)
	exitTimeout      = 5  // nothing answered in time
	exitPartial      = 7  // matched, but below the high-confidence threshold
	exitInternal     = 10 // interrupted, output failed, or an unexpected error
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
	}
	return exitInternal
}

// render writes err once: as an "error:" line on stderr, or, with JSON
// output, as a single {"error": {...}} object on stdout. It returns the
// exit code.
func render(err error, jsonOut bool, stdout, stderr io.Writer) int {
	var ce *cliError
	if !errors.As(err, &ce) {
		ce = &cliError{kind: kindUsage, code: codeInvalidInput, message: err.Error()}
	}
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

// exitStatus carries a non-zero outcome (no match, partial, unreachable)
// out of a command that did write its result.
type exitStatus struct{ code int }

func (e *exitStatus) Error() string { return fmt.Sprintf("exit status %d", e.code) }
