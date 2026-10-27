// SPDX-License-Identifier: MIT

// Package iec104 fingerprints IEC 60870-5-104.
//
// Detection sends TESTFR act, a U-format APCI that a controlled station
// answers with TESTFR con in any state without starting data transfer. The
// reply must be the confirmation (0x83), not an echo of the activation, so
// echo services do not match.
//
// In identify mode data transfer is started (STARTDT act/con), the frames
// the station sends on its own within a short window are decoded for the
// ASDU common address and type identifiers (an end of initialisation,
// M_EI_NA_1, is common), acknowledged, and data transfer is stopped again
// (STOPDT). No interrogation or command is sent: IEC 104 has no identity
// object, and a general interrogation makes the station send its whole
// process image.
package iec104

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolIEC104

// APCI constants.
const (
	startByte = 0x68
	maxAPDU   = 255

	uTestAct  = 0x43
	uTestCon  = 0x83
	uStartAct = 0x07
	uStartCon = 0x0B
	uStopAct  = 0x13
	uStopCon  = 0x23

	maxFrames = 4
)

// Fingerprinter detects IEC 60870-5-104.
type Fingerprinter struct {
	// Window is how long identify mode listens for spontaneous frames
	// after STARTDT. Zero means one second (capped by the target timeout).
	Window time.Duration
}

// New returns an IEC 104 fingerprinter.
func New() *Fingerprinter { return &Fingerprinter{} }

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{2404, 19998},
		Priority:      30,
		Intrusiveness: core.Passive,
		Description:   "APCI TESTFR act/con; STARTDT/STOPDT and the spontaneous ASDUs in between in identify mode",
	}
}

// U returns a U-format APDU with the given control octet.
func U(ctrl byte) []byte { return []byte{startByte, 0x04, ctrl, 0x00, 0x00, 0x00} }

// Framer reads one APDU.
var Framer wire.Framer = func(b []byte) int {
	if b[0] != startByte {
		return -1
	}
	if len(b) < 2 {
		return 0
	}
	if b[1] < 4 || b[1] > 253 {
		return -1
	}
	return int(b[1]) + 2
}

// APDU is a parsed APCI with its ASDU, if any.
type APDU struct {
	// Format is 'I', 'S' or 'U'.
	Format byte
	// U is the U-format function octet (e.g. 0x83 TESTFR con).
	U byte
	// SendSeq is N(S) of an I-format APDU.
	SendSeq uint16
	ASDU    []byte
}

// Parse validates one APDU.
func Parse(b []byte) (APDU, error) {
	if len(b) < 6 || b[0] != startByte {
		return APDU{}, fmt.Errorf("not an APDU")
	}
	if int(b[1])+2 != len(b) || b[1] < 4 {
		return APDU{}, fmt.Errorf("APDU length %d does not match %d octets", b[1], len(b))
	}
	c := b[2:6]
	switch {
	case c[0]&0x01 == 0:
		if c[2]&0x01 != 0 {
			return APDU{}, fmt.Errorf("i-format with odd receive sequence octet")
		}
		return APDU{Format: 'I', SendSeq: (uint16(c[0])>>1 | uint16(c[1])<<7), ASDU: b[6:]}, nil
	case c[0] == 0x01:
		if c[1] != 0 || c[2]&0x01 != 0 || len(b) != 6 {
			return APDU{}, fmt.Errorf("malformed S-format APCI")
		}
		return APDU{Format: 'S'}, nil
	}
	if c[1] != 0 || c[2] != 0 || c[3] != 0 || len(b) != 6 {
		return APDU{}, fmt.Errorf("malformed U-format APCI")
	}
	switch c[0] {
	case uTestAct, uTestCon, uStartAct, uStartCon, uStopAct, uStopCon:
		return APDU{Format: 'U', U: c[0]}, nil
	}
	return APDU{}, fmt.Errorf("u-format function 0x%02x is not defined", c[0])
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	s, err := wire.Dial(ctx, proto, target, opts)
	if err != nil {
		return core.NoMatch(proto), err
	}
	defer s.Close() //nolint:errcheck

	resp, err := s.RoundTrip("testfr", U(uTestAct), Framer, maxAPDU)
	confirmed := false
	for i := 0; i < maxFrames && err == nil; i++ {
		a, perr := Parse(resp)
		if perr != nil {
			if len(resp) > 0 && resp[0] == startByte {
				b.Score(core.ConfidenceLow, "start octet 0x68, but "+perr.Error())
			}
			break
		}
		if a.Format == 'U' && a.U == uTestCon {
			b.Score(core.ConfidenceCertain, "TESTFR con answers TESTFR act")
			b.Sig("testfr", "con")
			confirmed = true
			break
		}
		// The station spoke first (a spontaneous frame, its own TESTFR
		// act). A TESTFR act is not answered here: an echo service would
		// turn the answer into the confirmation we wait for.
		if a.Format == 'U' && a.U == uTestAct {
			b.Score(core.ConfidenceLow, "TESTFR act received while waiting for TESTFR con")
		} else {
			b.Score(core.ConfidenceHigh, fmt.Sprintf("valid %c-format APCI before TESTFR con", a.Format))
		}
		resp, err = s.Next("frame", Framer, maxAPDU)
	}
	if !confirmed {
		if b.Confidence() == 0 && err != nil && !errors.Is(err, wire.ErrClosed) {
			return b.Result("iec104.apci", "no IEC 104 response", s), err
		}
		return b.Result("iec104.apci", "no TESTFR con", s), nil
	}
	if opts.Mode == core.ModeIdentify {
		f.identify(ctx, b, s, target)
	}
	return b.Result("iec104.apci", "IEC 60870-5-104 controlled station", s), nil
}

func (f *Fingerprinter) identify(ctx context.Context, b *fpx.Builder, s *wire.Session, target core.Target) {
	resp, err := s.RoundTrip("startdt", U(uStartAct), Framer, maxAPDU)
	if err != nil {
		b.Evidence("STARTDT not confirmed")
		return
	}
	window := f.Window
	if window <= 0 {
		window = time.Second
	}
	window = min(window, target.EffectiveTimeout())
	deadline := time.Now().Add(window)
	started := false
	cas := map[uint16]bool{}
	types := map[byte]bool{}
	var recv uint16
	for ctx.Err() == nil {
		if a, perr := Parse(resp); perr == nil {
			switch {
			case a.Format == 'U' && a.U == uStartCon:
				started = true
				b.Sig("startdt", "con")
			case a.Format == 'U' && a.U == uTestAct:
				_ = s.Send(U(uTestCon))
			case a.Format == 'I':
				recv = a.SendSeq + 1
				if t, ca, ok := asduHeader(a.ASDU); ok {
					types[t] = true
					cas[ca] = true
				}
			}
		}
		if time.Now().After(deadline) {
			break
		}
		resp, err = s.ReadUntil(Framer, maxAPDU, deadline)
		if err != nil {
			break
		}
		s.Record("spontaneous", nil, resp)
	}
	if !started {
		b.Evidence("STARTDT not confirmed")
		return
	}
	b.Evidence("STARTDT con")
	if recv > 0 {
		_ = s.Send([]byte{startByte, 0x04, 0x01, 0x00, byte(recv << 1), byte(recv >> 7)})
	}
	_, _ = s.RoundTrip("stopdt", U(uStopAct), Framer, maxAPDU)

	id := b.Identity()
	if len(cas) > 0 {
		var list []int
		for ca := range cas {
			list = append(list, int(ca))
		}
		sort.Ints(list)
		id.Set("commonAddress", joinInts(list))
		b.Evidence(fmt.Sprintf("common address %s", joinInts(list)))
	}
	if len(types) > 0 {
		var list []int
		for t := range types {
			list = append(list, int(t))
		}
		sort.Ints(list)
		id.Set("asduTypes", joinInts(list))
		if types[70] {
			b.Evidence("end of initialisation (M_EI_NA_1) received")
		}
	}
}

// asduHeader returns the type identification and common address of an
// ASDU with the standard IEC 104 field sizes (COT 2, CA 2 octets).
func asduHeader(a []byte) (typeID byte, ca uint16, ok bool) {
	if len(a) < 6 || a[0] == 0 {
		return 0, 0, false
	}
	return a[0], uint16(a[4]) | uint16(a[5])<<8, true
}

func joinInts(v []int) string {
	s := ""
	for i, x := range v {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprint(x)
	}
	return s
}
