// SPDX-License-Identifier: MIT

// Package dnp3 fingerprints DNP3 over TCP (IEEE 1815).
//
// Detection sends data-link REQUEST_LINK_STATUS frames, which carry no
// application data and are answered in any state: first to the self
// address 0xFFFC, then, in the same write, to the configured candidate
// outstation addresses. A LINK_STATUS reply with the 0x0564 start octets,
// a valid header CRC and the secondary direction proves DNP3 and reveals the
// outstation and master addresses. Broadcast addresses are useless here:
// outstations never answer them.
//
// In identify mode the device attributes (group 0, variation 254, all
// attributes) are read with an unconfirmed READ.
package dnp3

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolDNP3

// Link-layer constants.
const (
	start0, start1 = 0x05, 0x64
	headerLen      = 10
	maxFrame       = 292

	ctrlDIR = 0x80
	ctrlPRM = 0x40
	ctrlDFC = 0x10

	fcRequestLinkStatus = 0x09 // primary
	fcUnconfirmedData   = 0x04 // primary
	fcLinkStatus        = 0x0B // secondary
	fcNotSupported      = 0x0F // secondary

	selfAddress = 0xFFFC
	maxFrames   = 8
)

// Config configures the fingerprinter.
type Config struct {
	// Outstations are the addresses probed after the self address 0xFFFC.
	// The default is 10, 1, 1024, 0, 3 and 4.
	Outstations []uint16
	// Master is the source address of the probes. The default is 1;
	// outstations commonly answer their configured master only.
	Master uint16
}

// Fingerprinter detects DNP3.
type Fingerprinter struct {
	outstations []uint16
	master      uint16
}

// New returns a DNP3 fingerprinter with the default addresses.
func New() *Fingerprinter { return NewWithConfig(Config{}) }

// NewWithConfig returns a fingerprinter with the given configuration.
func NewWithConfig(c Config) *Fingerprinter {
	f := &Fingerprinter{outstations: c.Outstations, master: c.Master}
	if len(f.outstations) == 0 {
		f.outstations = []uint16{10, 1, 1024, 0, 3, 4}
	}
	if f.master == 0 {
		f.master = 1
	}
	return f
}

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{20000, 19999},
		Priority:      40,
		Intrusiveness: core.Passive,
		Description:   "data link REQUEST_LINK_STATUS to 0xFFFC and candidate outstations; READ g0v254 device attributes in identify mode",
	}
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	s, err := wire.Dial(ctx, proto, target, opts)
	if err != nil {
		return core.NoMatch(proto), err
	}
	defer s.Close() //nolint:errcheck

	var burst []byte
	dests := append([]uint16{selfAddress}, f.outstations...)
	for _, d := range dests {
		if d == selfAddress && len(burst) > 0 {
			continue
		}
		burst = append(burst, Frame(ctrlDIR|ctrlPRM|fcRequestLinkStatus, d, f.master, nil)...)
	}
	resp, err := s.RoundTrip("link-status", burst, Framer, maxFrame)
	var status *Header
	for i := 0; i < maxFrames; i++ {
		if err != nil {
			break
		}
		if h, ok := f.judge(b, resp); ok {
			status = &h
			break
		}
		if b.Confidence() == 0 && len(resp) > 0 && (len(resp) < 2 || resp[0] != start0 || resp[1] != start1) {
			break // not DNP3 at all
		}
		resp, err = s.Next("frame", Framer, maxFrame)
	}
	if status == nil {
		if err != nil && !errors.Is(err, wire.ErrClosed) && b.Confidence() == 0 {
			return b.Result("dnp3.link", "no DNP3 response", s), err
		}
		if b.Confidence() >= core.MatchThreshold {
			return b.Result("dnp3.link", "DNP3 frames, but no link status", s), nil
		}
		return b.Result("dnp3.link", "no DNP3 link status", s), nil
	}
	if opts.Mode == core.ModeIdentify {
		f.identify(b, s, status.Src, status.Dst)
	}
	return b.Result("dnp3.link", fmt.Sprintf("DNP3 outstation %d", status.Src), s), nil
}

// judge scores one frame; it reports true for a secondary LINK_STATUS (or
// NOT_SUPPORTED) reply.
func (f *Fingerprinter) judge(b *fpx.Builder, frame []byte) (Header, bool) {
	h, err := ParseHeader(frame)
	if err != nil {
		if len(frame) >= 2 && frame[0] == start0 && frame[1] == start1 {
			b.Score(core.ConfidenceLow, "DNP3 start octets, but "+err.Error())
		}
		return h, false
	}
	if h.Ctrl&ctrlDIR != 0 || h.Ctrl&ctrlPRM != 0 {
		b.Score(core.ConfidenceMedium, "valid DNP3 frame, but not a secondary reply")
		return h, false
	}
	fc := h.Ctrl & 0x0F
	if fc != fcLinkStatus && fc != fcNotSupported {
		b.Score(core.ConfidenceMedium, fmt.Sprintf("valid DNP3 secondary frame with function %d", fc))
		return h, false
	}
	b.Score(core.ConfidenceCertain, fmt.Sprintf("LINK_STATUS from outstation %d to master %d, header CRC valid", h.Src, h.Dst))
	b.Sig("ctrl", fmt.Sprintf("0x%02x", h.Ctrl))
	b.Sig("dfc", fmt.Sprint(h.Ctrl&ctrlDFC != 0))
	b.Meta("outstation", fmt.Sprint(h.Src))
	b.Meta("master", fmt.Sprint(h.Dst))
	b.Identity().Set("outstationAddress", fmt.Sprint(h.Src))
	if fc == fcNotSupported {
		b.Variant("link status not supported")
	}
	return h, true
}

// identify reads all device attributes.
func (f *Fingerprinter) identify(b *fpx.Builder, s *wire.Session, outstation, master uint16) {
	// Transport FIR|FIN seq 0; application FIR|FIN seq 0, READ, g0v254
	// qualifier 0x06 (all objects).
	user := []byte{0xC0, 0xC0, 0x01, 0x00, 0xFE, 0x06}
	req := Frame(ctrlDIR|ctrlPRM|fcUnconfirmedData, outstation, master, user)
	frame, err := s.RoundTrip("read-g0v254", req, Framer, maxFrame)
	var apdu []byte
	for i := 0; i < 32 && err == nil; i++ {
		h, herr := ParseHeader(frame)
		if herr == nil && h.Ctrl&ctrlDIR == 0 && h.Ctrl&ctrlPRM != 0 && len(h.Data) > 0 {
			th := h.Data[0]
			if th&0x40 != 0 { // FIR restarts the fragment
				apdu = apdu[:0]
			}
			apdu = append(apdu, h.Data[1:]...)
			if th&0x80 != 0 { // FIN
				break
			}
		}
		frame, err = s.Next("response", Framer, maxFrame)
	}
	attrs, err := ParseAttributes(apdu)
	if err != nil {
		b.Evidence("device attributes not read: " + err.Error())
		return
	}
	id := b.Identity()
	for v, a := range attrs {
		switch v {
		case 252:
			id.Vendor = a
		case 250:
			id.Product = a
		case 242:
			id.Version = a
		case 248:
			id.Serial = a
		case 247:
			id.Name = a
		case 243:
			id.Set("hardwareVersion", a)
		case 245:
			id.Set("location", a)
		case 246:
			id.Set("userId", a)
		case 244:
			id.Set("owner", a)
		case 249:
			id.Set("subsetAndConformance", a)
		default:
			id.Set(fmt.Sprintf("g0v%d", v), a)
		}
	}
	b.Evidence(fmt.Sprintf("device attributes: %d read", len(attrs)))
}

// Header is a parsed data-link frame.
type Header struct {
	Ctrl     byte
	Dst, Src uint16
	// Data is the user data with the block CRCs removed.
	Data []byte
}

// Framer reads one data-link frame.
var Framer wire.Framer = func(b []byte) int {
	if len(b) >= 1 && b[0] != start0 || len(b) >= 2 && b[1] != start1 {
		return -1
	}
	if len(b) < 3 {
		return 0
	}
	return FrameLen(b[2])
}

// FrameLen returns the octets of a frame with the given LENGTH field, or -1
// when the length is invalid.
func FrameLen(length byte) int {
	if length < 5 {
		return -1
	}
	n := int(length) - 5
	return headerLen + n + 2*int(math.Ceil(float64(n)/16))
}

// ParseHeader validates a frame's start octets, length and CRCs.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < headerLen {
		return Header{}, fmt.Errorf("%d octets is shorter than a link header", len(b))
	}
	if b[0] != start0 || b[1] != start1 {
		return Header{}, fmt.Errorf("start octets 0x%02x%02x, want 0x0564", b[0], b[1])
	}
	if CRC(b[:8]) != binary.LittleEndian.Uint16(b[8:10]) {
		return Header{}, fmt.Errorf("header CRC mismatch")
	}
	n := FrameLen(b[2])
	if n < 0 || n != len(b) {
		return Header{}, fmt.Errorf("LENGTH %d does not match %d octets", b[2], len(b))
	}
	h := Header{Ctrl: b[3], Dst: binary.LittleEndian.Uint16(b[4:6]), Src: binary.LittleEndian.Uint16(b[6:8])}
	for p := b[headerLen:]; len(p) > 0; {
		k := min(16, len(p)-2)
		if k <= 0 || CRC(p[:k]) != binary.LittleEndian.Uint16(p[k:k+2]) {
			return h, fmt.Errorf("data block CRC mismatch")
		}
		h.Data = append(h.Data, p[:k]...)
		p = p[k+2:]
	}
	return h, nil
}

// Frame encodes a data-link frame.
func Frame(ctrl byte, dst, src uint16, data []byte) []byte {
	b := []byte{start0, start1, byte(5 + len(data)), ctrl, byte(dst), byte(dst >> 8), byte(src), byte(src >> 8)}
	b = binary.LittleEndian.AppendUint16(b, CRC(b))
	for len(data) > 0 {
		k := min(16, len(data))
		b = append(b, data[:k]...)
		b = binary.LittleEndian.AppendUint16(b, CRC(data[:k]))
		data = data[k:]
	}
	return b
}

var crcTable = func() (t [256]uint16) {
	for i := range t {
		c := uint16(i)
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = c>>1 ^ 0xA6BC
			} else {
				c >>= 1
			}
		}
		t[i] = c
	}
	return t
}()

// CRC returns the DNP3 CRC-16 of b.
func CRC(b []byte) uint16 {
	var c uint16
	for _, x := range b {
		c = c>>8 ^ crcTable[byte(c)^x]
	}
	return ^c
}

// ParseAttributes decodes the group 0 objects of an application response
// fragment (control, function 0x81 or 0x82, IIN, objects) into visible
// string attributes by variation. Numeric attributes are rendered in
// decimal.
func ParseAttributes(apdu []byte) (map[uint8]string, error) {
	if len(apdu) < 4 {
		return nil, fmt.Errorf("no application response")
	}
	if apdu[1] != 0x81 && apdu[1] != 0x82 {
		return nil, fmt.Errorf("application function 0x%02x is not a response", apdu[1])
	}
	out := map[uint8]string{}
	p := apdu[4:]
	for len(p) >= 3 {
		group, variation, qual := p[0], p[1], p[2]
		if group != 0 {
			break
		}
		p = p[3:]
		var count int
		switch qual {
		case 0x00:
			if len(p) < 2 || p[1] < p[0] {
				return out, fmt.Errorf("bad range")
			}
			count, p = int(p[1])-int(p[0])+1, p[2:]
		case 0x01:
			if len(p) < 4 {
				return out, fmt.Errorf("bad range")
			}
			lo, hi := binary.LittleEndian.Uint16(p), binary.LittleEndian.Uint16(p[2:])
			if hi < lo {
				return out, fmt.Errorf("bad range")
			}
			count, p = int(hi-lo)+1, p[4:]
		default:
			return out, nil // qualifier we do not decode: keep what we have
		}
		for i := 0; i < count; i++ {
			if len(p) < 2 {
				return out, fmt.Errorf("attribute truncated")
			}
			typ, n := p[0], int(p[1])
			if len(p) < 2+n {
				return out, fmt.Errorf("attribute value truncated")
			}
			if v := attrString(typ, p[2:2+n]); v != "" {
				out[variation] = v
			}
			p = p[2+n:]
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no device attributes in the response")
	}
	return out, nil
}

func attrString(typ byte, v []byte) string {
	switch typ {
	case 1: // visible string
		return fpx.Clean(string(v))
	case 2: // unsigned integer
		var x uint64
		for i := len(v) - 1; i >= 0; i-- {
			x = x<<8 | uint64(v[i])
		}
		return fmt.Sprint(x)
	}
	return ""
}
