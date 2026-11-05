// SPDX-License-Identifier: MIT

package wire

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
)

// readResult is one scripted Read of a fakeConn.
type readResult struct {
	data []byte
	err  error
}

// fakeConn is a net.Conn whose Reads return scripted results and whose
// Writes fail with writeErr.
type fakeConn struct {
	net.Conn
	reads    []readResult
	writeErr error
}

func (c *fakeConn) Read(b []byte) (int, error) {
	if len(c.reads) == 0 {
		return 0, &net.OpError{Op: "read", Err: timeoutErr{}}
	}
	r := c.reads[0]
	c.reads = c.reads[1:]
	return copy(b, r.data), r.err
}
func (c *fakeConn) Write(b []byte) (int, error)      { return len(b), c.writeErr }
func (c *fakeConn) Close() error                     { return nil }
func (c *fakeConn) SetDeadline(time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(time.Time) error { return nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func fakeSession(c *fakeConn) *Session {
	return newSession(context.Background(), core.ProtocolBACnet, "192.0.2.1:47808", c, true, 100*time.Millisecond, core.Options{})
}

// The Windows read errors: WSAEMSGSIZE discards the datagram and the read
// goes on; WSAECONNRESET (the ICMP port unreachable) is a refused
// connection.
func TestWindowsDatagramErrors(t *testing.T) {
	tooLarge, unreachable := errors.New("WSAEMSGSIZE"), errors.New("WSAECONNRESET")
	savedM, savedP := msgTooLarge, portUnreachable
	t.Cleanup(func() { msgTooLarge, portUnreachable = savedM, savedP })
	msgTooLarge = func(err error) bool { return errors.Is(err, tooLarge) }
	portUnreachable = func(err error) bool { return errors.Is(err, unreachable) }

	s := fakeSession(&fakeConn{reads: []readResult{{make([]byte, 8), tooLarge}, {[]byte("answer"), nil}}})
	if got, err := s.RoundTripDatagram("x", []byte("x"), 8, nil); err != nil || string(got) != "answer" {
		t.Fatalf("message too large: %q %v", got, err)
	}
	s = fakeSession(&fakeConn{reads: []readResult{{nil, unreachable}}})
	_, err := s.RoundTripDatagram("x", []byte("x"), 8, nil)
	var ce *core.ConnectionError
	if !errors.As(err, &ce) {
		t.Fatalf("port unreachable: %T %v", err, err)
	}
	// Elsewhere the same errors are ordinary I/O errors.
	msgTooLarge, portUnreachable = savedM, savedP
	s = fakeSession(&fakeConn{reads: []readResult{{nil, syscall.EINVAL}}})
	var de *core.DetectError
	if _, err := s.RoundTripDatagram("x", []byte("x"), 8, nil); !errors.As(err, &de) {
		t.Fatalf("other error: %T %v", err, err)
	}
}

// A negative Retries means no retransmission (it divided the timeout by
// zero before); a failed write ends the exchange.
func TestDatagramEdges(t *testing.T) {
	s := fakeSession(&fakeConn{})
	s.Retries = -1
	if _, err := s.RoundTripDatagram("x", []byte("x"), 8, nil); !core.IsTimeout(err) {
		t.Fatalf("negative retries: %v", err)
	}
	s = fakeSession(&fakeConn{writeErr: syscall.EPIPE})
	if _, err := s.RoundTripDatagram("x", []byte("x"), 8, nil); err == nil {
		t.Fatal("write error ignored")
	}
	if isReset(errors.New("plain")) {
		t.Fatal("a plain error is not a reset")
	}
}
