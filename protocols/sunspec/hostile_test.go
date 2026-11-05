// SPDX-License-Identifier: MIT

package sunspec

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/chaos"
	"github.com/otfabric/go-otfp/internal/mbap"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

var readOnly = core.Options{MaxIntrusiveness: core.ReadOnly}

func TestChaos(t *testing.T) {
	for name, fc := range map[string]byte{"holding": mbap.FCReadHoldingRegisters, "input": mbap.FCReadInputRegisters} {
		t.Run(name, chaos.Suite{
			FP:      New(),
			Options: readOnly,
			// The marker search makes up to eleven exchanges, each of
			// which a stalled peer can hold for a timeout.
			Exchanges: 12,
			TCP:       func(t testing.TB, cfg chaos.Config) core.Target { return chaos.TCP(t, cfg, device(40000, fc)) },
		}.Run)
	}
}

// The safety contract: register reads (FC 03 holding, FC 04 input) of at
// most the common model's 68 registers. Never a write (05, 06, 0F, 10, 16,
// 17), a diagnostic (08) or Read Device Identification.
func TestSafetyContract(t *testing.T) {
	for _, base := range []uint16{40000, 50001} {
		for _, fc := range []byte{mbap.FCReadHoldingRegisters, mbap.FCReadInputRegisters} {
			for _, mode := range []core.Mode{core.ModeDetect, core.ModeIdentify} {
				rec := &chaos.Recorder{}
				target := testsrv.TCP(t, rec.Wrap(device(base, fc)))
				opts := readOnly
				opts.Mode = mode
				if _, err := New().Detect(context.Background(), target, opts); err != nil {
					t.Fatal(err)
				}
				reqs := rec.Requests()
				if len(reqs) == 0 {
					t.Fatal("nothing sent")
				}
				for _, req := range reqs {
					r, err := mbap.Parse(req)
					if err != nil {
						t.Fatalf("request % x: %v", req, err)
					}
					if r.FC != mbap.FCReadHoldingRegisters && r.FC != mbap.FCReadInputRegisters {
						t.Fatalf("base %d fc %d %s: function code 0x%02x sent", base, fc, mode, r.FC)
					}
					if len(r.Data) != 4 || binary.BigEndian.Uint16(r.Data[2:]) > 68 {
						t.Fatalf("read % x exceeds the common model", r.Data)
					}
				}
			}
		}
	}
}

// Regression: a scan cancelled between two marker reads, after the device
// had already answered as Modbus, returned NoMatch with a nil error, as if
// the device had been probed completely.
func TestCancelBetweenReadsIsAnError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	target := testsrv.Raw(t, func(c net.Conn) {
		buf := make([]byte, 260)
		n, err := c.Read(buf)
		if err != nil || n < 8 {
			return
		}
		// Illegal data address: Modbus, but no marker here.
		_, _ = c.Write(mbap.Request(binary.BigEndian.Uint16(buf), buf[6], buf[7]|0x80, 0x02))
		time.Sleep(50 * time.Millisecond)
		cancel()
		_, _ = c.Read(buf)
	})
	r, err := New().Detect(ctx, target, readOnly)
	if err == nil || r.Matched || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled scan: %v, err %v", r, err)
	}
}

// Error paths: a silent target is a transport error; a register count that
// does not match the request is not Modbus; a first model other than the
// common model, a model chain that stops answering and one that runs off
// the address space end the walk.
func TestOddDevices(t *testing.T) {
	silent := testsrv.TCP(t, testsrv.Script())
	silent.Timeout = 150 * time.Millisecond
	if _, err := New().Detect(context.Background(), silent, readOnly); err == nil {
		t.Fatal("silent: no error")
	}

	short := testsrv.TCP(t, func(req []byte) ([]byte, bool) {
		return mbap.Request(binary.BigEndian.Uint16(req), req[6], req[7], 2, 0x53), false
	})
	if r, err := New().Detect(context.Background(), short, readOnly); err != nil || r.Matched {
		t.Fatalf("short registers: %v %v", r, err)
	}

	// regs answers reads from a register map; missing registers are an
	// exception, and reads at or past stopAt are not answered.
	regs := func(m map[uint16]uint16, stopAt uint32) testsrv.Handler {
		return func(req []byte) ([]byte, bool) {
			tid := binary.BigEndian.Uint16(req)
			addr := binary.BigEndian.Uint16(req[8:])
			qty := binary.BigEndian.Uint16(req[10:])
			if uint32(addr) >= stopAt {
				return nil, true
			}
			pdu := []byte{req[7], byte((2 * qty) & 0xFF)}
			for i := range qty {
				v, ok := m[addr+i]
				if !ok {
					return mbap.Request(tid, req[6], req[7]|0x80, 0x02), false
				}
				pdu = binary.BigEndian.AppendUint16(pdu, v)
			}
			return mbap.Request(tid, req[6], pdu...), false
		}
	}
	// The first model is 101, not the common model; the next header is
	// not answered.
	notCommon := map[uint16]uint16{40000: marker0, 40001: marker1, 40002: 101, 40003: 2, 40004: 0, 40005: 0}
	r, err := New().Detect(context.Background(), testsrv.TCP(t, regs(notCommon, 40006)), core.Options{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly})
	if err != nil || !r.Matched || r.Identity.Attributes["models"] != "101" {
		t.Fatalf("not common: %v %v %+v", r, err, r.Identity)
	}
	// A model whose length runs past register 65535.
	past := map[uint16]uint16{0: marker0, 1: marker1, 2: 7, 3: 0xFFFF}
	f := NewWithConfig(Config{Bases: []uint16{0}})
	r, err = f.Detect(context.Background(), testsrv.TCP(t, regs(past, 1<<20)), core.Options{Mode: core.ModeIdentify, MaxIntrusiveness: core.ReadOnly})
	if err != nil || !r.Matched || r.Identity.Attributes["models"] != "7" {
		t.Fatalf("past the end: %v %v %+v", r, err, r.Identity)
	}
}

// A direct call with passive-only options must send nothing: reading the
// marker reads holding registers.
func TestPassiveSendsNothing(t *testing.T) {
	var got int
	target := testsrv.TCP(t, func(req []byte) ([]byte, bool) { got++; return nil, true })
	r, err := New().Detect(context.Background(), target, core.Options{Mode: core.ModeIdentify})
	if err != nil || r.Matched {
		t.Fatalf("passive: %v, %v", r, err)
	}
	if got != 0 {
		t.Fatalf("passive sent %d requests", got)
	}
}
