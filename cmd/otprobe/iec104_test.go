// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// iec104Station answers TESTFR, STARTDT and STOPDT like a controlled
// station, sends one spontaneous ASDU of common address 4711 after STARTDT,
// and records the APDUs it receives on each connection.
type iec104Station struct {
	target core.Target
	mu     sync.Mutex
	conns  [][][]byte
	closed chan struct{} // receives one value per connection the peer closed
}

func newIEC104Station(t *testing.T) *iec104Station {
	st := &iec104Station{closed: make(chan struct{}, 64)}
	st.target = testsrv.Raw(t, func(c net.Conn) {
		st.mu.Lock()
		i := len(st.conns)
		st.conns = append(st.conns, nil)
		st.mu.Unlock()
		defer func() { st.closed <- struct{}{} }()
		head := make([]byte, 2)
		for {
			_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
			if _, err := io.ReadFull(c, head); err != nil {
				return
			}
			apdu := append(append([]byte(nil), head...), make([]byte, int(head[1]))...)
			if _, err := io.ReadFull(c, apdu[2:]); err != nil {
				return
			}
			st.mu.Lock()
			st.conns[i] = append(st.conns[i], apdu)
			st.mu.Unlock()
			u := func(ctrl byte) []byte { return []byte{0x68, 0x04, ctrl, 0, 0, 0} }
			switch apdu[2] {
			case 0x43: // TESTFR act
				_, _ = c.Write(u(0x83))
			case 0x07: // STARTDT act: confirm, then an end of initialisation
				_, _ = c.Write(append(u(0x0B), 0x68, 0x0E, 0, 0, 0, 0, 70, 1, 4, 0, 0x67, 0x12, 0, 0, 0, 0))
			case 0x13: // STOPDT act
				_, _ = c.Write(u(0x23))
			}
		}
	})
	return st
}

// received returns the APDUs of every connection, once n connections were
// closed by the tool.
func (st *iec104Station) received(t *testing.T, n int) [][][]byte {
	t.Helper()
	for range n {
		select {
		case <-st.closed:
		case <-time.After(5 * time.Second):
			t.Fatal("the tool did not close its connection to the station")
		}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	return append([][][]byte(nil), st.conns...)
}

var (
	testfrAct  = []byte{0x68, 0x04, 0x43, 0, 0, 0}
	startdtAct = []byte{0x68, 0x04, 0x07, 0, 0, 0}
	stopdtAct  = []byte{0x68, 0x04, 0x13, 0, 0, 0}
)

// Without --iec104-startdt the tool sends an IEC 104 station TESTFR act and
// nothing else, with and without --identify and with --safe: no STARTDT, no
// acknowledgement, no STOPDT.
func TestIEC104DefaultSendsNoStartDT(t *testing.T) {
	for _, args := range [][]string{nil, {"--identify"}, {"--identify", "--safe"}, {"--safe"}} {
		st := newIEC104Station(t)
		code, out, errw := exec(append([]string{"detect", addr(st.target), "--protocol", "iec104"}, args...)...)
		if code != exitOK || !strings.Contains(out, "fingerprint  iec104.apci:testfr=con\n") {
			t.Fatalf("%v: exit %d\nstdout: %s\nstderr: %s", args, code, out, errw)
		}
		conns := st.received(t, 1)
		if len(conns) != 1 || len(conns[0]) != 1 || !bytes.Equal(conns[0][0], testfrAct) {
			t.Errorf("%v: the station received % x, want TESTFR act only", args, conns)
		}
		identify := len(args) > 0 && args[0] == "--identify"
		if said := strings.Contains(out, "data transfer not started"); said != identify {
			t.Errorf("%v: \"data transfer not started\" in the output: %v, want %v\n%s", args, said, identify, out)
		}
		if strings.Contains(out, "commonAddress") || strings.Contains(out, "STARTDT con") {
			t.Errorf("%v: the output reports what only STARTDT reads:\n%s", args, out)
		}
	}
}

// With --identify --iec104-startdt --yes the tool starts data transfer, reads the
// common address, acknowledges and stops.
func TestIEC104StartDTFlag(t *testing.T) {
	st := newIEC104Station(t)
	code, out, errw := exec("detect", addr(st.target), "--protocol", "iec104", "--identify", "--iec104-startdt", "--yes")
	if code != exitOK || !strings.Contains(out, "testfr=con;startdt=con") || !strings.Contains(out, "commonAddress  4711") {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, errw)
	}
	conns := st.received(t, 1)
	if len(conns) != 1 || len(conns[0]) != 4 {
		t.Fatalf("the station received % x, want TESTFR act, STARTDT act, an acknowledgement and STOPDT act", conns)
	}
	got := conns[0]
	ack := []byte{0x68, 0x04, 0x01, 0x00, 0x02, 0x00} // S-format, N(R) = 1
	if !bytes.Equal(got[0], testfrAct) || !bytes.Equal(got[1], startdtAct) || !bytes.Equal(got[2], ack) || !bytes.Equal(got[3], stopdtAct) {
		t.Errorf("the station received % x, want TESTFR act, STARTDT act, the acknowledgement of one APDU and STOPDT act", got)
	}
}

// --iec104-startdt is refused with --safe, and without --identify, before
// anything is sent, with or without --yes.
func TestIEC104StartDTFlagIsRefused(t *testing.T) {
	st := newIEC104Station(t)
	for _, args := range [][]string{
		{"--identify", "--iec104-startdt", "--safe"},
		{"--identify", "--iec104-startdt", "--safe", "--yes"},
		{"--iec104-startdt", "--safe"},
		{"--iec104-startdt"},
		{"--iec104-startdt", "--yes"},
	} {
		code, out, errw := exec(append([]string{"detect", addr(st.target), "--protocol", "iec104"}, args...)...)
		if code != exitInvalidInput || !strings.Contains(errw, "--iec104-startdt") || out != "" {
			t.Errorf("%v: exit %d, want %d and an error that names the flag\nstdout: %s\nstderr: %s", args, code, exitInvalidInput, out, errw)
		}
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(st.conns) != 0 {
		t.Errorf("the station accepted %d connections, want 0", len(st.conns))
	}
}

// --identify --iec104-startdt without --yes is a usage error (exit 2, code
// confirmation_required) and nothing is sent; --yes alone changes nothing.
func TestIEC104StartDTNeedsYes(t *testing.T) {
	st := newIEC104Station(t)
	code, out, errw := exec("detect", addr(st.target), "--protocol", "iec104", "--identify", "--iec104-startdt")
	if code != exitUsage || !strings.Contains(errw, "--yes") || out != "" {
		t.Errorf("exit %d, want %d and an error that names --yes\nstdout: %s\nstderr: %s", code, exitUsage, out, errw)
	}
	code, out, _ = exec("detect", addr(st.target), "--protocol", "iec104", "--identify", "--iec104-startdt", "--format", "json")
	if code != exitUsage || !strings.Contains(out, `"code": "confirmation_required"`) || !strings.Contains(out, `"kind": "usage"`) {
		t.Errorf("JSON: exit %d, want %d and code confirmation_required\n%s", code, exitUsage, out)
	}
	st.mu.Lock()
	n := len(st.conns)
	st.mu.Unlock()
	if n != 0 {
		t.Fatalf("the station accepted %d connections, want 0", n)
	}
	code, out, errw = exec("detect", addr(st.target), "--protocol", "iec104", "--identify", "--yes")
	if code != exitOK || strings.Contains(out, "startdt=con") {
		t.Errorf("--yes without --iec104-startdt: exit %d, want %d and no STARTDT\nstdout: %s\nstderr: %s", code, exitOK, out, errw)
	}
}

// otprobe list describes the IEC 104 probe as the tool sends it.
func TestListDescribesTheIEC104Probe(t *testing.T) {
	code, out, _ := exec("list")
	if code != exitOK || !strings.Contains(out, "APCI TESTFR act/con; with ") || strings.Contains(out, "APCI TESTFR act/con; STARTDT") {
		t.Fatalf("exit %d: the IEC 104 line of the list does not say that STARTDT is an option:\n%s", code, out)
	}
}
