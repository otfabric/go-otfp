// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

// ErrNoFingerprinters is returned by the engine when no registered
// fingerprinter applies to the target (for example a UDP target and only
// TCP fingerprinters selected).
var ErrNoFingerprinters = errors.New("no fingerprinter applies to the target")

// DetectError is an I/O failure during detection other than a timeout.
type DetectError struct {
	Protocol Protocol
	// Op is the step that failed, e.g. "write", "read", "tls".
	Op  string
	Err error
}

func (e *DetectError) Error() string {
	return fmt.Sprintf("%s %s: %v", e.Protocol.Slug(), e.Op, e.Err)
}

// Unwrap returns the underlying error.
func (e *DetectError) Unwrap() error { return e.Err }

// TimeoutError is a dial, write or read that exceeded its deadline.
type TimeoutError struct {
	Protocol Protocol
	Addr     string
	// Op is the step that timed out: "dial", "write" or "read".
	Op  string
	Err error
}

func (e *TimeoutError) Error() string {
	return fmt.Sprintf("%s %s %s: timeout: %v", e.Protocol.Slug(), e.Op, e.Addr, e.Err)
}

// Unwrap returns the underlying error.
func (e *TimeoutError) Unwrap() error { return e.Err }

// ConnectionError is a dial failure other than a timeout: refused,
// unreachable, reset, name resolution.
type ConnectionError struct {
	Protocol Protocol
	Addr     string
	Err      error
}

func (e *ConnectionError) Error() string {
	return fmt.Sprintf("%s connect %s: %v", e.Protocol.Slug(), e.Addr, e.Err)
}

// Unwrap returns the underlying error.
func (e *ConnectionError) Unwrap() error { return e.Err }

// Refused reports whether the connection was actively refused (TCP RST, or
// ICMP port unreachable on a connected UDP socket): nothing listens there.
func (e *ConnectionError) Refused() bool {
	return errors.Is(e.Err, syscall.ECONNREFUSED)
}

// InvalidResponseError is a response that was recognisably this protocol
// but malformed. Fingerprinters return it in Result.Error only when the
// distinction matters; most wrong responses are plain NoMatch.
type InvalidResponseError struct {
	Protocol Protocol
	Reason   string
}

func (e *InvalidResponseError) Error() string {
	return fmt.Sprintf("%s invalid response: %s", e.Protocol.Slug(), e.Reason)
}

// ProtocolNotFoundError is returned when a requested protocol has no
// registered fingerprinter.
type ProtocolNotFoundError struct {
	Protocol Protocol
}

func (e *ProtocolNotFoundError) Error() string {
	return "no fingerprinter registered for " + e.Protocol.String()
}

// ClassifyDial maps a dial failure to *TimeoutError or *ConnectionError.
func ClassifyDial(p Protocol, addr string, err error) error {
	if err == nil {
		return nil
	}
	if IsTimeout(err) {
		return &TimeoutError{Protocol: p, Addr: addr, Op: "dial", Err: err}
	}
	return &ConnectionError{Protocol: p, Addr: addr, Err: err}
}

// ClassifyIO maps a write or read failure to *TimeoutError, to
// *ConnectionError when the peer refused (UDP port unreachable), or to
// *DetectError.
func ClassifyIO(p Protocol, addr, op string, err error) error {
	if err == nil {
		return nil
	}
	if IsTimeout(err) {
		return &TimeoutError{Protocol: p, Addr: addr, Op: op, Err: err}
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return &ConnectionError{Protocol: p, Addr: addr, Err: err}
	}
	return &DetectError{Protocol: p, Op: op, Err: err}
}

// IsTimeout reports whether err is a deadline or timeout error.
func IsTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
