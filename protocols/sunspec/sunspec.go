// SPDX-License-Identifier: MIT

// Package sunspec fingerprints SunSpec Modbus devices: inverters, meters,
// batteries and other DER that publish the SunSpec information model over
// Modbus TCP.
//
// Detection reads two holding registers at the SunSpec base addresses
// 40000, 0 and 50000 (and their off-by-one variants) looking for the
// "SunS" marker (0x5375 0x6E53), retrying with input registers for devices
// that map the model there. SunSpec refines Modbus: it is a read-only
// probe of application registers, so the engine runs it only when
// read-only probes are allowed, and after a Modbus match.
//
// In identify mode the common model (model 1: manufacturer, model,
// options, version, serial number, device address) is read, and the model
// chain is walked to list the models the device implements.
package sunspec

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/mbap"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolSunSpec

// Marker registers "SunS" and the end-of-chain model ID.
const (
	marker0  = 0x5375
	marker1  = 0x6E53
	endModel = 0xFFFF

	commonModel = 1
	maxModels   = 32
)

// DefaultBases are the base addresses tried, in order.
var DefaultBases = []uint16{40000, 0, 50000, 39999, 40001, 1, 49999, 50001}

// Config configures the fingerprinter.
type Config struct {
	// UnitID is the Modbus unit probed; zero means 1.
	UnitID byte
	// Bases are the base addresses tried; nil means DefaultBases.
	Bases []uint16
}

// Fingerprinter detects SunSpec.
type Fingerprinter struct {
	unit  byte
	bases []uint16
}

// New returns a SunSpec fingerprinter probing unit 1.
func New() *Fingerprinter { return NewWithConfig(Config{}) }

// NewWithConfig returns a fingerprinter with the given configuration.
func NewWithConfig(c Config) *Fingerprinter {
	f := &Fingerprinter{unit: c.UnitID, bases: c.Bases}
	if f.unit == 0 {
		f.unit = 1
	}
	if len(f.bases) == 0 {
		f.bases = DefaultBases
	}
	return f
}

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{502, 1502},
		Priority:      61,
		Intrusiveness: core.ReadOnly,
		Refines:       core.ProtocolModbus,
		Description:   "Modbus FC 03/04 of the \"SunS\" marker at 40000, 0, 50000; common model 1 and the model chain in identify mode",
	}
}

type reader struct {
	s    *wire.Session
	unit byte
	tid  uint16
}

var errException = errors.New("exception")

// read returns qty registers at addr, or errException with the code.
func (r *reader) read(label string, fc byte, addr, qty uint16) ([]uint16, byte, error) {
	r.tid++
	resp, err := r.s.RoundTrip(label, mbap.ReadRegisters(r.tid, r.unit, fc, addr, qty), mbap.Framer, mbap.MaxADU)
	if err != nil {
		return nil, 0, err
	}
	m, err := mbap.Parse(resp)
	if err != nil {
		return nil, 0, err
	}
	if err := m.Check(r.tid, fc); err != nil {
		return nil, 0, err
	}
	if m.IsException() {
		return nil, m.Exception, errException
	}
	regs, err := mbap.Registers(m.Data, int(qty))
	return regs, 0, err
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	s, err := wire.Dial(ctx, proto, target, opts)
	if err != nil {
		return core.NoMatch(proto), err
	}
	defer s.Close() //nolint:errcheck
	r := &reader{s: s, unit: f.unit, tid: 0x5300}

	base, fc, modbus, err := f.findMarker(ctx, r)
	if err != nil && !modbus {
		if errors.Is(err, wire.ErrClosed) {
			return b.Result("sunspec.marker", "connection closed", s), nil
		}
		return b.Result("sunspec.marker", "no Modbus response", s), err
	}
	if fc == 0 {
		if modbus {
			b.Evidence("Modbus device, but no SunSpec marker at the base addresses")
		}
		return b.Result("sunspec.marker", "no SunSpec marker", s), nil
	}
	b.Score(core.ConfidenceCertain, fmt.Sprintf("\"SunS\" marker at %d (FC 0x%02x)", base, fc))
	b.Variant(fmt.Sprintf("base %d", base))
	b.Sig("base", fmt.Sprint(base))
	b.Sig("fc", fmt.Sprintf("0x%02x", fc))
	b.Meta("baseAddress", fmt.Sprint(base))

	if opts.Mode == core.ModeIdentify {
		f.identify(ctx, b, r, fc, base)
	}
	return b.Result("sunspec.marker", "SunSpec Modbus device", s), nil
}

// findMarker tries the base addresses with FC 03, then FC 04. modbus
// reports whether any proper Modbus response was seen.
func (f *Fingerprinter) findMarker(ctx context.Context, r *reader) (base uint16, fc byte, modbus bool, err error) {
	for _, fc := range []byte{mbap.FCReadHoldingRegisters, mbap.FCReadInputRegisters} {
		illegalFunction := false
		bases := f.bases
		if fc == mbap.FCReadInputRegisters && len(bases) > 3 {
			bases = bases[:3] // the main bases only; input-register maps are rare
		}
		for _, a := range bases {
			if ctx.Err() != nil {
				return 0, 0, modbus, ctx.Err()
			}
			regs, exc, err := r.read(fmt.Sprintf("fc%02x-%d", fc, a), fc, a, 2)
			switch {
			case err == nil:
				modbus = true
				if regs[0] == marker0 && regs[1] == marker1 {
					return a, fc, true, nil
				}
			case errors.Is(err, errException):
				modbus = true
				if exc == 0x01 {
					illegalFunction = true
				}
			default:
				return 0, 0, modbus, err
			}
			if illegalFunction {
				break
			}
		}
		if !modbus {
			break
		}
	}
	return 0, 0, modbus, nil
}

func (f *Fingerprinter) identify(ctx context.Context, b *fpx.Builder, r *reader, fc byte, base uint16) {
	addr := uint32(base) + 2
	regs, _, err := r.read("model1", fc, uint16(addr), 68)
	if err != nil {
		// Some devices reject long reads: fall back to the header.
		regs, _, err = r.read("model1-header", fc, uint16(addr), 2)
	}
	if err != nil {
		b.Evidence("common model not readable")
		return
	}
	var models []string
	if regs[0] == commonModel && len(regs) >= 66 {
		c := Common(regs[2:])
		id := b.Identity()
		id.Vendor, id.Model, id.Version, id.Serial = c.Manufacturer, c.Model, c.Version, c.Serial
		id.Set("options", c.Options)
		if c.DeviceAddress != 0 && c.DeviceAddress != 0xFFFF {
			id.Set("deviceAddress", fmt.Sprint(c.DeviceAddress))
		}
		b.Evidence(fmt.Sprintf("common model, length %d", regs[1]))
	} else if regs[0] != commonModel {
		b.Evidence(fmt.Sprintf("first model is %d, not the common model", regs[0]))
	}
	// Walk the model chain.
	for i := 0; i < maxModels && ctx.Err() == nil; i++ {
		if i > 0 {
			hdr, _, err := r.read(fmt.Sprintf("model-%d", i), fc, uint16(addr), 2)
			if err != nil {
				break
			}
			regs = hdr
		}
		if regs[0] == endModel || addr > 0xFFFF-2 {
			models = append(models, "end")
			break
		}
		models = append(models, strconv.Itoa(int(regs[0])))
		addr += 2 + uint32(regs[1])
		if addr > 0xFFFF {
			break
		}
	}
	if len(models) > 0 {
		b.Identity().Set("models", strings.Join(models, ","))
		b.Sig("models", strings.Join(models, ","))
	}
}

// CommonModel holds the points of SunSpec model 1.
type CommonModel struct {
	Manufacturer, Model, Options, Version, Serial string
	DeviceAddress                                 uint16
}

// Common decodes model 1 from its 66 body registers (the registers after
// the ID and length).
func Common(body []uint16) CommonModel {
	str := func(off, n int) string {
		if off+n > len(body) {
			return ""
		}
		var sb strings.Builder
		for _, r := range body[off : off+n] {
			sb.WriteByte(byte(r >> 8))
			sb.WriteByte(byte(r))
		}
		return fpx.Clean(sb.String())
	}
	c := CommonModel{
		Manufacturer: str(0, 16),
		Model:        str(16, 16),
		Options:      str(32, 8),
		Version:      str(40, 8),
		Serial:       str(48, 16),
	}
	if len(body) > 64 {
		c.DeviceAddress = body[64]
	}
	return c
}
