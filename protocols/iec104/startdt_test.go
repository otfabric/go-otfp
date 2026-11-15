// SPDX-License-Identifier: MIT

package iec104

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fuzzkit"
)

// fakeStation is a controlled station with one redundancy group and an
// event queue, as far as the fingerprinter and a control centre can tell:
//
//   - TESTFR act is confirmed on every connection, in any state;
//   - STARTDT act gives data transfer to the connection that sent it (the
//     connection that had it is stopped) and is confirmed; the events not
//     acknowledged so far are sent on it, numbered from 0;
//   - an S-format APDU acknowledges the events sent on the connection up
//     to its N(R): they leave the queue;
//   - STOPDT act stops data transfer and is confirmed;
//   - an event raised while a connection is started is sent on it at once.
type fakeStation struct {
	ln net.Listener
	wg sync.WaitGroup

	mu      sync.Mutex
	conns   []*stationConn
	started *stationConn
	queue   [][]byte // the ASDUs of the events not acknowledged
}

// stationConn is one connection to the station.
type stationConn struct {
	c      net.Conn
	closed chan struct{} // closed when the peer's end of the connection is read

	// Guarded by the station's mu.
	received [][]byte // the APDUs the peer sent
	ns       uint16   // the next send sequence number
	sent     int      // events of the queue sent on this connection
}

func newFakeStation(t *testing.T) *fakeStation {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	st := &fakeStation{ln: ln}
	t.Cleanup(func() {
		_ = ln.Close()
		st.mu.Lock()
		for _, sc := range st.conns {
			_ = sc.c.Close()
		}
		st.mu.Unlock()
		st.wg.Wait()
	})
	st.wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			sc := &stationConn{c: c, closed: make(chan struct{})}
			st.mu.Lock()
			st.conns = append(st.conns, sc)
			st.mu.Unlock()
			st.wg.Go(func() { st.serve(sc) })
		}
	})
	return st
}

func (st *fakeStation) target() core.Target {
	host, port, _ := net.SplitHostPort(st.ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return core.Target{Host: host, Port: p, Timeout: 2 * time.Second}
}

func (st *fakeStation) serve(sc *stationConn) {
	defer close(sc.closed)
	head := make([]byte, 2)
	for {
		if _, err := io.ReadFull(sc.c, head); err != nil {
			return
		}
		apdu := append(append([]byte(nil), head...), make([]byte, int(head[1]))...)
		if _, err := io.ReadFull(sc.c, apdu[2:]); err != nil {
			return
		}
		a, err := Parse(apdu)
		st.mu.Lock()
		sc.received = append(sc.received, apdu)
		switch {
		case err != nil:
		case a.Format == 'U' && a.U == uTestAct:
			_, _ = sc.c.Write(U(uTestCon))
		case a.Format == 'U' && a.U == uStartAct:
			st.started = sc
			sc.ns, sc.sent = 0, 0
			_, _ = sc.c.Write(U(uStartCon))
			st.sendQueued(sc)
		case a.Format == 'U' && a.U == uStopAct:
			if st.started == sc {
				st.started = nil
			}
			_, _ = sc.c.Write(U(uStopCon))
		case a.Format == 'S' && st.started == sc:
			nr := int(apdu[4])>>1 | int(apdu[5])<<7
			acked := min(nr, sc.sent)
			st.queue = st.queue[acked:]
			sc.sent -= acked
		}
		st.mu.Unlock()
	}
}

// sendQueued sends, on the started connection, the events it has not been
// sent yet. The caller holds mu.
func (st *fakeStation) sendQueued(sc *stationConn) {
	for ; sc.sent < len(st.queue); sc.sent++ {
		asdu := st.queue[sc.sent]
		apdu := []byte{startByte, byte(4 + len(asdu)), byte(sc.ns << 1), byte(sc.ns >> 7), 0, 0}
		_, _ = sc.c.Write(append(apdu, asdu...))
		sc.ns = (sc.ns + 1) & 0x7FFF
	}
}

// raise queues a spontaneous single-point event (M_SP_NA_1, cause 3) of the
// common address and sends it when a connection is started.
func (st *fakeStation) raise(ca uint16, ioa byte) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.queue = append(st.queue, []byte{1, 0x01, 0x03, 0x00, byte(ca), byte(ca >> 8), ioa, 0, 0, 1})
	if st.started != nil {
		st.sendQueued(st.started)
	}
}

// state returns the events not acknowledged and the connection data
// transfer is started on.
func (st *fakeStation) state() (queued int, started *stationConn) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.queue), st.started
}

// conn returns the i-th connection the station accepted, once the peer has
// closed it, with the APDUs received on it.
func (st *fakeStation) conn(t *testing.T, i int) (*stationConn, [][]byte) {
	t.Helper()
	st.mu.Lock()
	if i >= len(st.conns) {
		n := len(st.conns)
		st.mu.Unlock()
		t.Fatalf("the station accepted %d connections, want more than %d", n, i)
	}
	sc := st.conns[i]
	st.mu.Unlock()
	select {
	case <-sc.closed:
	case <-time.After(5 * time.Second):
		t.Fatalf("connection %d was not closed by its peer", i)
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return sc, append([][]byte(nil), sc.received...)
}

// controlCentre is the controlling station's connection.
type controlCentre struct {
	t *testing.T
	c net.Conn
}

// connectControlCentre connects and starts data transfer.
func connectControlCentre(t *testing.T, st *fakeStation) *controlCentre {
	t.Helper()
	c, err := net.Dial("tcp", st.target().Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	cc := &controlCentre{t: t, c: c}
	if _, err := c.Write(U(uStartAct)); err != nil {
		t.Fatal(err)
	}
	if a := cc.read(); a.Format != 'U' || a.U != uStartCon {
		t.Fatalf("control centre: %+v in answer to STARTDT act, want STARTDT con", a)
	}
	return cc
}

// read reads the next APDU.
func (cc *controlCentre) read() APDU {
	cc.t.Helper()
	_ = cc.c.SetReadDeadline(time.Now().Add(5 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(cc.c, head); err != nil {
		cc.t.Fatalf("control centre: no APDU: %v", err)
	}
	apdu := append(head, make([]byte, int(head[1]))...)
	if _, err := io.ReadFull(cc.c, apdu[2:]); err != nil {
		cc.t.Fatalf("control centre: APDU cut short: %v", err)
	}
	a, err := Parse(apdu)
	if err != nil {
		cc.t.Fatalf("control centre: % x: %v", apdu, err)
	}
	return a
}

// events reads n events and checks their send sequence numbers and
// information object addresses.
func (cc *controlCentre) events(n int, firstNS uint16, firstIOA byte) {
	cc.t.Helper()
	for i := range n {
		a := cc.read()
		if a.Format != 'I' || a.SendSeq != firstNS+uint16(i) || len(a.ASDU) < 7 || a.ASDU[6] != firstIOA+byte(i) {
			cc.t.Fatalf("control centre: event %d of %d is %+v, want N(S) %d and object %d", i+1, n, a, firstNS+uint16(i), firstIOA+byte(i))
		}
	}
}

// By default the fingerprinter leaves data transfer alone, in both modes
// and at every intrusiveness level: the station receives TESTFR act and
// nothing else, the control centre keeps data transfer, no event is
// acknowledged, and the control centre receives every event, those raised
// before the probe and those raised after it.
func TestDefaultLeavesDataTransferToTheControlCentre(t *testing.T) {
	st := newFakeStation(t)
	for i := range 5 {
		st.raise(4711, byte(i))
	}
	cc := connectControlCentre(t, st)
	cc.events(5, 0, 0)
	_, ccConn := st.state()

	probes := 0
	for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
		for _, level := range []core.Intrusiveness{core.Passive, core.ReadOnly} {
			r, err := New().Detect(context.Background(), st.target(), core.Options{Mode: mode, MaxIntrusiveness: level, Trace: true})
			fuzzkit.Check(t, proto, r, err)
			if err != nil || !r.Matched || r.Confidence != core.ConfidenceCertain || r.Fingerprint.Signature != "testfr=con" || r.Identity != nil {
				t.Fatalf("%s/%s: %v (%v), signature %q, identity %+v", mode, level, r, err, r.Fingerprint.Signature, r.Identity)
			}
			probes++
			_, got := st.conn(t, probes) // connection 0 is the control centre's
			if len(got) != 1 || string(got[0]) != string(U(uTestAct)) {
				t.Errorf("%s/%s: the station received % x, want TESTFR act only", mode, level, got)
			}
		}
	}
	if queued, started := st.state(); queued != 5 || started != ccConn {
		t.Errorf("after the probes: %d events not acknowledged and data transfer on the control centre's connection: %v; want 5 and true", queued, started == ccConn)
	}
	st.raise(4711, 5)
	cc.events(1, 5, 5)

	// A control centre that connects after the probes gets the whole queue.
	st2 := newFakeStation(t)
	for i := range 5 {
		st2.raise(4711, byte(i))
	}
	if r, err := New().Detect(context.Background(), st2.target(), core.Options{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly}); err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	st2.conn(t, 0)
	connectControlCentre(t, st2).events(5, 0, 0)
}

// With the StartDT option identify mode starts data transfer: the station
// receives TESTFR act, STARTDT act, one S-format APDU that acknowledges
// what it sent, and STOPDT act. The events are acknowledged to the probe,
// and data transfer is taken from the control centre.
func TestStartDTOptionStartsDataTransfer(t *testing.T) {
	st := newFakeStation(t)
	for i := range 5 {
		st.raise(4711, byte(i))
	}
	cc := connectControlCentre(t, st)
	cc.events(5, 0, 0)

	f := &Fingerprinter{Window: 200 * time.Millisecond, StartDT: true}
	r, err := f.Detect(context.Background(), st.target(), core.Options{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly})
	fuzzkit.Check(t, proto, r, err)
	if err != nil || !r.Matched || r.Fingerprint.Signature != "testfr=con;startdt=con" {
		t.Fatalf("%v (%v), signature %q", r, err, r.Fingerprint.Signature)
	}
	if r.Identity == nil || r.Identity.Attributes["commonAddress"] != "4711" || r.Identity.Attributes["asduTypes"] != "1" {
		t.Fatalf("identity %+v", r.Identity)
	}
	_, got := st.conn(t, 1)
	want := [][]byte{U(uTestAct), U(uStartAct), sFormat(4), U(uStopAct)}
	if len(got) != len(want) {
		t.Fatalf("the station received % x, want % x", got, want)
	}
	for i := range want {
		if string(got[i]) != string(want[i]) {
			t.Errorf("APDU %d the station received: % x, want % x", i, got[i], want[i])
		}
	}
	if queued, started := st.state(); queued != 0 || started != nil {
		t.Errorf("after the probe: %d events not acknowledged, data transfer started: %v; want 0 and false", queued, started != nil)
	}

	// In detect mode the option adds nothing.
	r, err = f.Detect(context.Background(), st.target(), core.Options{MaxIntrusiveness: core.ReadOnly})
	if err != nil || !r.Matched || r.Fingerprint.Signature != "testfr=con" {
		t.Fatalf("detect mode: %v (%v)", r, err)
	}
	if _, got := st.conn(t, 2); len(got) != 1 || string(got[0]) != string(U(uTestAct)) {
		t.Errorf("detect mode: the station received % x, want TESTFR act only", got)
	}
}

// The StartDT option and a scan limited to passive probes contradict each
// other: Detect returns an error and opens no connection, in both modes,
// directly and through an engine with core.SafeEngineConfig.
func TestStartDTIsRefusedUnderAPassiveScan(t *testing.T) {
	st := newFakeStation(t)
	var dials atomic.Int64
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	f := &Fingerprinter{StartDT: true}
	check := func(name string, r core.Result, err error) {
		t.Helper()
		var de *core.DetectError
		if !errors.As(err, &de) || de.Op != "startdt" || de.Protocol != proto || r.Matched || !strings.Contains(err.Error(), "passive") {
			t.Errorf("%s: result %v, error %v; want a DetectError of operation startdt", name, r, err)
		}
	}
	for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
		r, err := f.Detect(context.Background(), st.target(), core.Options{Mode: mode, MaxIntrusiveness: core.Passive, Dialer: dial})
		fuzzkit.Check(t, proto, r, err)
		check(mode.String(), r, err)

		cfg := core.SafeEngineConfig()
		cfg.Mode, cfg.Dialer = mode, dial
		engine := core.NewEngine(core.NewRegistry().MustRegister(f), cfg)
		rep, err := engine.Scan(context.Background(), st.target())
		if err != nil || len(rep.Results) != 1 {
			t.Fatalf("safe engine, %s: %v, %d results", mode, err, len(rep.Results))
		}
		check("safe engine, "+mode.String(), rep.Results[0], rep.Results[0].Error)
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("%d connections opened, want 0", n)
	}
	// The same fingerprinter runs once read-only probes are allowed.
	cfg := core.DefaultEngineConfig()
	cfg.Dialer = dial
	rep, err := core.NewEngine(core.NewRegistry().MustRegister(f), cfg).Scan(context.Background(), st.target())
	if err != nil || !rep.Best.Matched {
		t.Fatalf("default engine: %v %v", rep.Best, err)
	}
}

// keepSending answers TESTFR and STARTDT and then sends S-format APDUs for
// as long as the connection lasts.
func keepSending(t *testing.T) core.Target {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	t.Cleanup(func() { _ = ln.Close(); wg.Wait() })
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() {
				defer c.Close() //nolint:errcheck
				buf := make([]byte, 6)
				for _, answer := range [][]byte{U(uTestCon), U(uStartCon)} {
					if _, err := io.ReadFull(c, buf); err != nil {
						return
					}
					if _, err := c.Write(answer); err != nil {
						return
					}
				}
				burst := make([]byte, 0, 6*512)
				for range 512 {
					burst = append(burst, startByte, 0x04, 0x01, 0x00, 0x00, 0x00)
				}
				for {
					if _, err := c.Write(burst); err != nil {
						return
					}
				}
			})
		}
	})
	host, port, _ := net.SplitHostPort(ln.Addr().String())
	p, _ := strconv.Atoi(port)
	return core.Target{Host: host, Port: p}
}

// The listening window of the StartDT exchange reads at most MaxAPDUs
// APDUs, however many the station sends in it: the exchange ends with what
// it has, the trace and the memory allocated stay bounded.
func TestListeningWindowIsBounded(t *testing.T) {
	target := keepSending(t)
	target.Timeout = 2 * time.Second
	f := &Fingerprinter{Window: 2 * time.Second, StartDT: true}
	var r core.Result
	var err error
	allocated := fuzzkit.Allocated(func() {
		r, err = f.Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly, Trace: true})
	})
	fuzzkit.Check(t, proto, r, err)
	if err != nil || !r.Matched {
		t.Fatalf("%v %v", r, err)
	}
	// TESTFR, STARTDT and its answer, the APDUs of the window, STOPDT.
	if n := len(r.Exchanges); n > MaxAPDUs+3 {
		t.Errorf("%d exchanges in the trace, want at most %d", n, MaxAPDUs+3)
	}
	stopped := false
	for _, e := range r.Evidence {
		stopped = stopped || e == "listening stopped after "+strconv.Itoa(MaxAPDUs)+" APDUs"
	}
	if !stopped {
		t.Errorf("evidence %q does not say that listening stopped at the bound", r.Evidence)
	}
	// Each APDU read is at most 255 octets, kept once in the trace.
	const budget = 4 << 20
	if allocated > budget {
		t.Errorf("%d octets allocated for a window of at most %d APDUs, budget %d", allocated, MaxAPDUs, budget)
	}
}

// The identity lists the lowest common addresses and type identifiers, at
// most 16 of each, and counts the rest.
func TestIdentityListsAreBounded(t *testing.T) {
	for _, n := range []int{1, maxListed - 1, maxListed, maxListed + 1, 40} {
		st := newFakeStation(t)
		for i := range n {
			st.raise(uint16(1000+i), byte(i))
		}
		f := &Fingerprinter{Window: 200 * time.Millisecond, StartDT: true}
		r, err := f.Detect(context.Background(), st.target(), core.Options{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly})
		if err != nil || !r.Matched || r.Identity == nil {
			t.Fatalf("%d common addresses: %v %v", n, r, err)
		}
		got := r.Identity.Attributes["commonAddress"]
		list, more, _ := strings.Cut(got, " (+")
		listed := strings.Split(list, ",")
		if len(listed) != min(n, maxListed) || listed[0] != "1000" || listed[len(listed)-1] != strconv.Itoa(1000+len(listed)-1) {
			t.Errorf("%d common addresses: commonAddress %q", n, got)
		}
		wantMore := ""
		if n > maxListed {
			wantMore = strconv.Itoa(n-maxListed) + " more)"
		}
		if more != wantMore {
			t.Errorf("%d common addresses: commonAddress %q, want the rest counted as %q", n, got, wantMore)
		}
	}
}
