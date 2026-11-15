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
	"fmt"
	"io"
	"math"
	"net"
	"time"

	"github.com/otfabric/go-otfp/core"
)

// ErrClosed is returned when the peer closed the connection (or sent
// nothing at all on UDP before the deadline, see Session.RoundTrip) without
// a response. For most fingerprinters it means "not this protocol".
var ErrClosed = errors.New("peer closed the connection without a response")

// IsTransport reports whether err is a transport failure (a timeout, a
// refused or unreachable connection, an I/O error): the only errors a
// Fingerprinter returns, since they mean "could not decide". ErrClosed and
// parse failures are not: they mean "not this protocol".
func IsTransport(err error) bool {
	var te *core.TimeoutError
	var ce *core.ConnectionError
	var de *core.DetectError
	return errors.As(err, &te) || errors.As(err, &ce) || errors.As(err, &de)
}

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

// Bounds of one session, whatever the peer sends and however long a
// listening window is.
const (
	// MaxExchanges and MaxTraceBytes bound the exchange trace
	// (core.Options.Trace): at most MaxExchanges exchanges and
	// MaxTraceBytes octets of probes and responses are kept. What does not
	// fit is counted, and Exchanges ends with one entry that says how much
	// was left out.
	MaxExchanges  = 256
	MaxTraceBytes = 4 << 20

	// MaxStrays bounds the datagrams one UDP round trip reads that are not
	// its answer (late or duplicate answers, other peers' traffic, foreign
	// datagrams): after that many the round trip ends as it does when its
	// window ends. The first maxStraysLogged are logged with their octets,
	// the rest as a count.
	MaxStrays       = 64
	maxStraysLogged = 4
)

// errStrays ends a UDP round trip that read MaxStrays datagrams without
// its answer among them.
var errStrays = fmt.Errorf("no answer among %d datagrams", MaxStrays)

// Session is one connection of a fingerprinter to its target. It belongs to
// one Detect call and is used from one goroutine: its methods, Close
// included, are not safe for concurrent use. The scan's context ends its
// pending I/O from outside.
type Session struct {
	ctx     context.Context
	proto   core.Protocol
	addr    string
	conn    net.Conn
	udp     bool
	timeout time.Duration
	trace   bool
	log     core.Logger
	stop    func() bool
	closed  bool
	ex      []core.Exchange
	exBytes int    // octets of probes and responses in ex
	left    int    // exchanges not recorded: a bound was reached
	leftLen uint64 // their octets
	pending []byte // bytes read past the end of the last frame
	idle    time.Duration
	// Retries is the number of retransmissions of a UDP request when no
	// response arrives (default 1).
	Retries int
}

// Dial opens a session to target over its network, with TLS when
// target.TLS is set on TCP. Errors are classified with core.ClassifyDial.
func Dial(ctx context.Context, p core.Protocol, target core.Target, opts core.Options) (*Session, error) {
	addr := target.Addr()
	timeout := target.EffectiveTimeout()
	network := "tcp"
	if target.Network == core.UDP {
		network = "udp"
	}
	conn, err := opts.Dial(ctx, network, addr, timeout)
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
		ctx: ctx, proto: p, addr: addr, conn: conn, udp: udp, timeout: timeout,
		trace: opts.Trace, log: opts.Log(), Retries: 1,
		idle: max(250*time.Millisecond, timeout/4),
	}
	// Unblock pending I/O when the scan is cancelled. Every operation also
	// re-checks the context after arming its own deadline (see arm), since
	// that deadline would otherwise override the one set here.
	// The hook runs on its own goroutine, where a caller Dialer's conn
	// whose SetDeadline does not return normally would end the process:
	// recover it (the operations still fail on the context's error).
	s.stop = context.AfterFunc(ctx, func() {
		defer func() { _ = recover() }()
		_ = conn.SetDeadline(time.Unix(1, 0))
	})
	return s
}

// deadline returns now+d, capped at the context's deadline.
func (s *Session) deadline(d time.Duration) time.Time {
	t := time.Now().Add(d)
	if cd, ok := s.ctx.Deadline(); ok && cd.Before(t) {
		return cd
	}
	return t
}

// arm sets a read or write deadline, then fails when the context is already
// done: a cancellation that fired before the deadline was set would
// otherwise be overridden and the operation would wait out its timeout.
func (s *Session) arm(set func(time.Time) error, t time.Time, op string) error {
	if err := set(t); err != nil {
		return s.classify(op, err)
	}
	if err := s.ctx.Err(); err != nil {
		return core.ClassifyIO(s.proto, s.addr, op, err)
	}
	return nil
}

// classify maps an I/O error, preferring the context's error when the
// failure was caused by cancellation (the past deadline set on cancel
// would otherwise read as an ordinary timeout).
func (s *Session) classify(op string, err error) error {
	if cerr := s.ctx.Err(); cerr != nil {
		return core.ClassifyIO(s.proto, s.addr, op, cerr)
	}
	return core.ClassifyIO(s.proto, s.addr, op, err)
}

// Conn returns the underlying connection.
func (s *Session) Conn() net.Conn { return s.conn }

// Protocol returns the protocol the session's errors are attributed to.
func (s *Session) Protocol() core.Protocol { return s.proto }

// Timeout returns the per-operation timeout.
func (s *Session) Timeout() time.Duration { return s.timeout }

// Close releases the session's hook on the scan's context and closes the
// connection. The first call returns the connection's close error; a later
// call does nothing and returns nil. After Close every operation fails
// with the connection's error (a *core.DetectError that matches
// net.ErrClosed).
func (s *Session) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	s.stop()
	return s.conn.Close()
}

// Exchanges returns the recorded exchanges (nil unless tracing): at most
// MaxExchanges of them, holding at most MaxTraceBytes octets, and, when
// more were made than that, one last entry without octets whose label
// counts what was left out.
func (s *Session) Exchanges() []core.Exchange {
	if s.left == 0 {
		return s.ex
	}
	return append(s.ex[:len(s.ex):len(s.ex)], core.Exchange{
		Label: fmt.Sprintf("not recorded: %d exchanges, %d octets (a trace holds %d exchanges and %d octets per connection)",
			s.left, s.leftLen, MaxExchanges, MaxTraceBytes),
	})
}

// Record adds an exchange to the trace, e.g. for a fingerprinter that does
// its own I/O on Conn. The trace is bounded; see Exchanges.
func (s *Session) Record(label string, probe, resp []byte) {
	s.debugf("otfp: %s %s %s: sent % x, received % x", s.proto.Slug(), s.addr, label, probe, resp)
	s.keep(label, probe, resp)
}

// debugf passes one line to the caller's Logger. A Logger that does not
// return normally closes the session first: the panic goes on to the
// engine, which reports it as the probe's error, and the connection does
// not outlive the probe, whether or not the fingerprinter defers Close.
func (s *Session) debugf(format string, args ...any) {
	returned := false
	defer func() {
		if !returned {
			_ = s.Close()
		}
	}()
	s.log.Debugf(format, args...)
	returned = true
}

// keep adds an exchange to the trace when tracing and within the bounds.
func (s *Session) keep(label string, probe, resp []byte) {
	if !s.trace {
		return
	}
	n := len(probe) + len(resp)
	if len(s.ex) >= MaxExchanges || n > MaxTraceBytes-s.exBytes {
		s.left++
		s.leftLen += uint64(n)
		return
	}
	s.exBytes += n
	s.ex = append(s.ex, core.Exchange{
		Label:    label,
		Probe:    append([]byte(nil), probe...),
		Response: append([]byte(nil), resp...),
	})
}

// Send writes b.
func (s *Session) Send(b []byte) error {
	if err := s.arm(s.conn.SetWriteDeadline, s.deadline(s.timeout), "write"); err != nil {
		return err
	}
	if _, err := s.conn.Write(b); err != nil {
		return s.classify("write", err)
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
		resp, err = s.udpRoundTrip(probe, max, nil)
	} else {
		if err = s.Send(probe); err == nil {
			resp, err = s.Read(frame, max)
		}
	}
	s.Record(label, probe, resp)
	return resp, err
}

// RoundTripUDP is RoundTrip for a datagram exchange whose answers can be
// correlated with the request: datagrams accept rejects (late or duplicate
// answers to earlier requests, other peers' traffic) are discarded and the
// read continues within the same retransmission window, for at most
// MaxStrays such datagrams.
func (s *Session) RoundTripUDP(label string, probe []byte, max int, accept func([]byte) bool) ([]byte, error) {
	return s.RoundTripDatagram(label, probe, max, func(dg []byte) Verdict {
		if accept(dg) {
			return Answer
		}
		return Discard
	})
}

// Verdict classifies a datagram received while waiting for an answer.
type Verdict uint8

// Verdicts.
const (
	// Discard: not the answer (a late or duplicate answer to an earlier
	// request, another peer's traffic): keep listening.
	Discard Verdict = iota
	// Answer: the answer to the request.
	Answer
	// Foreign: not a frame of the protocol at all. Kept, and returned
	// when no answer arrives in the retransmission window, so that a
	// spoofed or stray datagram ahead of the real answer cannot hide it,
	// while a foreign service is still told apart from a silent one.
	Foreign
)

// RoundTripDatagram is RoundTripUDP with a three-way classification of the
// datagrams received; see Verdict. Empty datagrams are always foreign.
// After MaxStrays datagrams that are not the answer the round trip ends
// without waiting for its window: with the first foreign datagram when
// there was one, otherwise with a *core.DetectError of operation "read".
func (s *Session) RoundTripDatagram(label string, probe []byte, max int, classify func([]byte) Verdict) ([]byte, error) {
	resp, err := s.udpRoundTrip(probe, max, classify)
	s.Record(label, probe, resp)
	return resp, err
}

// Read reads one frame from a TCP session; see RoundTrip. Bytes that
// arrive after the frame are kept for the next Read.
func (s *Session) Read(frame Framer, max int) ([]byte, error) {
	return s.ReadUntil(frame, max, s.deadline(s.timeout))
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
	if cd, ok := s.ctx.Deadline(); ok && cd.Before(deadline) {
		deadline = cd
	}
	if err := s.arm(s.conn.SetReadDeadline, deadline, "read"); err != nil {
		return nil, err
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
			// A frame has started: the rest must follow within the idle
			// gap (and the overall deadline), so that a peer that sent a
			// short reply does not cost the full timeout.
			if n > 0 && err == nil {
				gap := time.Now().Add(s.idle)
				if gap.After(deadline) {
					gap = deadline
				}
				if aerr := s.arm(s.conn.SetReadDeadline, gap, "read"); aerr != nil {
					return nil, aerr
				}
			}
		}
		if err != nil {
			if len(buf) > 0 {
				return buf, nil
			}
			if s.ctx.Err() == nil && (errors.Is(err, io.EOF) || isReset(err)) {
				return nil, ErrClosed
			}
			return nil, s.classify("read", err)
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

func (s *Session) udpRoundTrip(probe []byte, max int, classify func([]byte) Verdict) ([]byte, error) {
	buf := make([]byte, max)
	attempts := 1 // a negative Retries is no retransmission
	if s.Retries > 0 {
		attempts += s.Retries
	}
	per := s.timeout / time.Duration(attempts)
	var (
		foreign    []byte
		hasForeign bool
		strays     int
	)
	// stray counts and records a datagram that is not the answer, and
	// reports whether the round trip goes on listening.
	stray := func(dg []byte) bool {
		strays++
		if strays <= maxStraysLogged {
			s.Record("discarded", nil, dg)
		} else {
			s.keep("discarded", nil, dg)
		}
		return strays < MaxStrays
	}
	defer func() {
		if strays > maxStraysLogged {
			s.debugf("otfp: %s %s: %d more datagrams discarded", s.proto.Slug(), s.addr, strays-maxStraysLogged)
		}
	}()
	// ended is the outcome once MaxStrays datagrams were not the answer.
	ended := func() ([]byte, error) {
		if hasForeign {
			return foreign, nil
		}
		return nil, &core.DetectError{Protocol: s.proto, Op: "read", Err: errStrays}
	}
	for i := range attempts {
		if err := s.Send(probe); err != nil {
			return nil, err
		}
		window := s.deadline(per)
		for {
			if err := s.arm(s.conn.SetReadDeadline, window, "read"); err != nil {
				return nil, err
			}
			n, err := s.conn.Read(buf)
			if err != nil && s.ctx.Err() == nil && msgTooLarge(err) {
				// Windows reports a datagram larger than the buffer as
				// an error (WSAEMSGSIZE): it is not an answer.
				if !stray(buf[:min(n, len(buf))]) {
					return ended()
				}
				continue
			}
			if err != nil {
				if s.ctx.Err() == nil && core.IsTimeout(err) && hasForeign {
					return foreign, nil
				}
				if s.ctx.Err() != nil || !core.IsTimeout(err) || i == attempts-1 {
					if s.ctx.Err() == nil && portUnreachable(err) {
						return nil, &core.ConnectionError{Protocol: s.proto, Addr: s.addr, Err: err}
					}
					return nil, s.classify("read", err)
				}
				break // retransmit
			}
			dg := buf[:n]
			v := Answer
			switch {
			case n == 0:
				// No protocol answers with an empty datagram, but a
				// peer that sends only those is not a silent one.
				v = Foreign
			case classify != nil:
				v = classify(dg)
			}
			switch v {
			case Answer:
				return append([]byte(nil), dg...), nil
			case Foreign:
				if !hasForeign {
					foreign, hasForeign = append([]byte{}, dg...), true
				}
			}
			// A stray datagram (a late answer to an earlier request,
			// a duplicate, another peer's traffic): keep listening in
			// the same window, for a bounded number of them.
			if !stray(dg) {
				return ended()
			}
		}
	}
	return nil, s.classify("read", context.DeadlineExceeded)
}

func isReset(err error) bool {
	if op, ok := errors.AsType[*net.OpError](err); ok {
		return !op.Timeout() && op.Op == "read"
	}
	return false
}

// Len8, Len16 and Len32 return n for a length field of a frame the probes
// build. Those frames are made of the probes' own fixed fields, so a
// length out of range is a programming error: they panic rather than put a
// wrapped length on the wire. Lengths that depend on input are checked by
// the caller before they get here.
func Len8(n int) uint8 {
	if n < 0 || n > math.MaxUint8 {
		panic(fmt.Sprintf("wire: length %d does not fit an 8-bit field", n))
	}
	return uint8(n)
}

// Len16 is Len8 for a 16-bit field.
func Len16(n int) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic(fmt.Sprintf("wire: length %d does not fit a 16-bit field", n))
	}
	return uint16(n)
}

// Len32 is Len8 for a 32-bit field.
func Len32(n int) uint32 {
	if n < 0 || int64(n) > math.MaxUint32 {
		panic(fmt.Sprintf("wire: length %d does not fit a 32-bit field", n))
	}
	return uint32(n)
}
