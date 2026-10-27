// SPDX-License-Identifier: MIT

// Package wire is the transport layer of the fingerprinters: a dial over
// TCP, TLS or UDP with error classification, framed reads that wait for a
// whole protocol frame instead of trusting a single read, UDP
// retransmission, context cancellation and exchange tracing.
package wire

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"

	"github.com/otfabric/go-otfp/core"
)

// ErrClosed is returned when the peer closed the connection (or sent
// nothing at all on UDP before the deadline, see Session.RoundTrip) without
// a response. For most fingerprinters it means "not this protocol".
var ErrClosed = errors.New("peer closed the connection without a response")

// Framer tells a TCP read when a frame is complete. Given the bytes read so
// far, it returns the total length of the frame once it is known (the read
// then continues until that many bytes have arrived), 0 when more bytes are
// needed to know, or -1 when the bytes cannot be a frame of the protocol
// (the read stops and returns what it has).
type Framer func(b []byte) int

// FixedHeader returns a Framer for frames whose total length follows from
// a fixed-size header: length(header) returns the total frame length, or a
// negative value when the header is not the protocol's.
func FixedHeader(headerLen int, length func(h []byte) int) Framer {
	return func(b []byte) int {
		if len(b) < headerLen {
			return 0
		}
		n := length(b[:headerLen])
		if n < headerLen {
			return -1
		}
		return n
	}
}

// Session is one connection of a fingerprinter to its target.
type Session struct {
	proto   core.Protocol
	addr    string
	conn    net.Conn
	udp     bool
	timeout time.Duration
	trace   bool
	log     core.Logger
	stop    func() bool
	ex      []core.Exchange
	pending []byte // bytes read past the end of the last frame
	// Retries is the number of retransmissions of a UDP request when no
	// response arrives (default 1).
	Retries int
}

// Dial opens a session to target over its network, with TLS when
// target.TLS is set on TCP. Errors are classified with core.ClassifyDial.
func Dial(ctx context.Context, p core.Protocol, target core.Target, opts core.Options) (*Session, error) {
	addr := target.Addr()
	timeout := target.EffectiveTimeout()
	d := net.Dialer{Timeout: timeout}
	network := "tcp"
	if target.Network == core.UDP {
		network = "udp"
	}
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return nil, core.ClassifyDial(p, addr, err)
	}
	if target.Network == core.TCP && target.TLS != nil {
		cfg := target.TLS.Clone()
		if cfg.ServerName == "" && net.ParseIP(target.Host) == nil {
			cfg.ServerName = target.Host
		}
		tc := tls.Client(conn, cfg)
		hctx, cancel := context.WithTimeout(ctx, timeout)
		err := tc.HandshakeContext(hctx)
		cancel()
		if err != nil {
			_ = conn.Close()
			if core.IsTimeout(err) {
				return nil, &core.TimeoutError{Protocol: p, Addr: addr, Op: "tls", Err: err}
			}
			return nil, &core.DetectError{Protocol: p, Op: "tls", Err: err}
		}
		conn = tc
	}
	return newSession(ctx, p, addr, conn, target.Network == core.UDP, timeout, opts), nil
}

// Wrap makes a session of an established connection, e.g. one a
// fingerprinter upgraded to TLS itself.
func Wrap(ctx context.Context, p core.Protocol, target core.Target, conn net.Conn, opts core.Options) *Session {
	return newSession(ctx, p, target.Addr(), conn, target.Network == core.UDP, target.EffectiveTimeout(), opts)
}

func newSession(ctx context.Context, p core.Protocol, addr string, conn net.Conn, udp bool, timeout time.Duration, opts core.Options) *Session {
	s := &Session{
		proto: p, addr: addr, conn: conn, udp: udp, timeout: timeout,
		trace: opts.Trace, log: opts.Log(), Retries: 1,
	}
	// Unblock pending I/O when the scan is cancelled.
	s.stop = context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	return s
}

// Conn returns the underlying connection.
func (s *Session) Conn() net.Conn { return s.conn }

// Timeout returns the per-operation timeout.
func (s *Session) Timeout() time.Duration { return s.timeout }

// Close closes the connection.
func (s *Session) Close() error {
	s.stop()
	return s.conn.Close()
}

// Exchanges returns the recorded exchanges (nil unless tracing).
func (s *Session) Exchanges() []core.Exchange { return s.ex }

// Record adds an exchange to the trace, e.g. for a fingerprinter that does
// its own I/O on Conn.
func (s *Session) Record(label string, probe, resp []byte) {
	s.log.Debugf("otfp: %s %s %s: sent % x, received % x", s.proto.Slug(), s.addr, label, probe, resp)
	if s.trace {
		s.ex = append(s.ex, core.Exchange{
			Label:    label,
			Probe:    append([]byte(nil), probe...),
			Response: append([]byte(nil), resp...),
		})
	}
}

// Send writes b.
func (s *Session) Send(b []byte) error {
	if err := s.conn.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return core.ClassifyIO(s.proto, s.addr, "write", err)
	}
	if _, err := s.conn.Write(b); err != nil {
		return core.ClassifyIO(s.proto, s.addr, "write", err)
	}
	return nil
}

// RoundTrip sends probe and reads the response: on TCP until frame reports
// a whole frame (or max bytes), on UDP one datagram, retransmitting the
// probe Retries times. It returns ErrClosed when the peer closed without
// sending anything, a *core.TimeoutError when nothing arrived in time, and
// otherwise whatever arrived, possibly an incomplete frame, with a nil
// error: the caller validates it.
func (s *Session) RoundTrip(label string, probe []byte, frame Framer, max int) ([]byte, error) {
	var (
		resp []byte
		err  error
	)
	if s.udp {
		resp, err = s.udpRoundTrip(probe, max)
	} else {
		if err = s.Send(probe); err == nil {
			resp, err = s.Read(frame, max)
		}
	}
	s.Record(label, probe, resp)
	return resp, err
}

// Read reads one frame from a TCP session; see RoundTrip. Bytes that
// arrive after the frame are kept for the next Read.
func (s *Session) Read(frame Framer, max int) ([]byte, error) {
	return s.ReadUntil(frame, max, time.Now().Add(s.timeout))
}

// ReadUntil is Read with an explicit deadline, for listening windows.
func (s *Session) ReadUntil(frame Framer, max int, deadline time.Time) ([]byte, error) {
	buf := s.pending
	s.pending = nil
	if frame != nil && len(buf) > 0 {
		if want := frame(buf); want > 0 && len(buf) >= want {
			s.pending = buf[want:]
			return buf[:want:want], nil
		}
	}
	if err := s.conn.SetReadDeadline(deadline); err != nil {
		return nil, core.ClassifyIO(s.proto, s.addr, "read", err)
	}
	chunk := make([]byte, min(max, 4096))
	for len(buf) < max {
		n, err := s.conn.Read(chunk[:min(len(chunk), max-len(buf))])
		buf = append(buf, chunk[:n]...)
		if frame != nil && len(buf) > 0 {
			switch want := frame(buf); {
			case want < 0:
				return buf, nil
			case want > 0 && len(buf) >= want:
				s.pending = buf[want:]
				return buf[:want:want], nil
			}
		}
		if err != nil {
			if len(buf) > 0 {
				return buf, nil
			}
			if errors.Is(err, io.EOF) || isReset(err) {
				return nil, ErrClosed
			}
			return nil, core.ClassifyIO(s.proto, s.addr, "read", err)
		}
		if frame == nil {
			return buf, nil
		}
	}
	return buf, nil
}

// Next reads the next frame without sending, recording it under label;
// see RoundTrip.
func (s *Session) Next(label string, frame Framer, max int) ([]byte, error) {
	resp, err := s.Read(frame, max)
	if resp != nil || err == nil {
		s.Record(label, nil, resp)
	}
	return resp, err
}

func (s *Session) udpRoundTrip(probe []byte, max int) ([]byte, error) {
	buf := make([]byte, max)
	attempts := s.Retries + 1
	per := s.timeout / time.Duration(attempts)
	for i := 0; i < attempts; i++ {
		if err := s.Send(probe); err != nil {
			return nil, err
		}
		if err := s.conn.SetReadDeadline(time.Now().Add(per)); err != nil {
			return nil, core.ClassifyIO(s.proto, s.addr, "read", err)
		}
		n, err := s.conn.Read(buf)
		if err == nil {
			return buf[:n], nil
		}
		if !core.IsTimeout(err) || i == attempts-1 {
			return nil, core.ClassifyIO(s.proto, s.addr, "read", err)
		}
	}
	return nil, core.ClassifyIO(s.proto, s.addr, "read", context.DeadlineExceeded)
}

func isReset(err error) bool {
	var op *net.OpError
	if errors.As(err, &op) {
		return !op.Timeout() && op.Op == "read"
	}
	return false
}
