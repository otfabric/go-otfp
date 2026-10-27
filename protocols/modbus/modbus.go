// SPDX-License-Identifier: MIT

// Package modbus fingerprints Modbus TCP.
//
// Detection sends Read Device Identification (function 43, MEI 14, basic
// stream) to unit 1. Any answer with the probe's transaction identifier,
// protocol identifier 0, a consistent MBAP length and either the function
// code or its standard exception proves Modbus: even "illegal function"
// means a Modbus stack parsed the request. Stacks that close the
// connection on an unsupported function (digitalpetri, NModbus) are probed
// again on a new connection with a read of one holding register, when the
// scan allows read-only probes.
//
// In identify mode the regular identification category is requested
// (vendor name, product code, revision, vendor URL, product name, model
// name, user application name), following the pages a device announces.
package modbus

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/mbap"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolModbus

// Read Device Identification codes and object identifiers.
const (
	readBasic   = 0x01
	readRegular = 0x02

	objVendorName         = 0x00
	objProductCode        = 0x01
	objRevision           = 0x02
	objVendorURL          = 0x03
	objProductName        = 0x04
	objModelName          = 0x05
	objUserAppName        = 0x06
	maxPages              = 8
	probeTID       uint16 = 0x4F54 // "OT"
)

// Config configures the fingerprinter.
type Config struct {
	// UnitID is the unit identifier probed. The zero value is 1; set
	// UnitIDSet to probe unit 0.
	UnitID    byte
	UnitIDSet bool
}

// Fingerprinter detects Modbus TCP.
type Fingerprinter struct {
	unit byte
}

// New returns a Modbus TCP fingerprinter probing unit 1.
func New() *Fingerprinter { return NewWithConfig(Config{}) }

// NewWithConfig returns a fingerprinter with the given configuration.
func NewWithConfig(c Config) *Fingerprinter {
	u := c.UnitID
	if u == 0 && !c.UnitIDSet {
		u = 1
	}
	return &Fingerprinter{unit: u}
}

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{502, 802, 1502, 5020},
		Priority:      60,
		Intrusiveness: core.Passive,
		Description:   "MBAP: Read Device Identification (FC 43/14); FC 03 of one register as fallback when read-only probes are allowed",
	}
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	var trace []core.Exchange

	code := byte(readBasic)
	if opts.Mode == core.ModeIdentify {
		code = readRegular
	}
	resp, s, err := f.exchange(ctx, target, opts, "fc43", deviceIDRequest(f.unit, code, objVendorName))
	if s != nil {
		trace = append(trace, s.Exchanges()...)
	}
	if err == nil {
		if r, ok := f.judge(b, resp, mbap.FCEncapsulated); ok {
			if !r.IsException() {
				f.identify(ctx, b, s, r, code)
				trace = s.Exchanges()
			} else if r.Exception == 0x03 && code == readRegular {
				// Regular category not supported: fall back to basic.
				f.basicAfterRegular(ctx, b, s)
				trace = s.Exchanges()
			}
			_ = s.Close()
			return f.finish(b, trace), nil
		}
		_ = s.Close()
		if len(resp) > 0 {
			// Something answered, but not Modbus.
			return f.finish(b, trace), nil
		}
	} else if s != nil {
		_ = s.Close()
	}

	// No answer to FC 43: closed, silent or reset. Some stacks drop the
	// connection on any function they do not implement.
	if !errors.Is(err, wire.ErrClosed) && !core.IsTimeout(err) {
		return f.finish(b, trace), err
	}
	if opts.MaxIntrusiveness < core.ReadOnly {
		if errors.Is(err, wire.ErrClosed) {
			b.Evidence("connection closed on Read Device Identification")
			return f.finish(b, trace), nil
		}
		return f.finish(b, trace), err
	}
	b.Evidence("no answer to Read Device Identification, trying FC 03")
	resp2, s2, err2 := f.exchange(ctx, target, opts, "fc03", mbap.ReadRegisters(probeTID+1, f.unit, mbap.FCReadHoldingRegisters, 0, 1))
	if s2 != nil {
		trace = append(trace, s2.Exchanges()...)
		_ = s2.Close()
	}
	if err2 != nil {
		if errors.Is(err2, wire.ErrClosed) {
			return f.finish(b, trace), nil
		}
		return f.finish(b, trace), err2
	}
	f.judgeTID(b, resp2, mbap.FCReadHoldingRegisters, probeTID+1)
	return f.finish(b, trace), nil
}

func (f *Fingerprinter) exchange(ctx context.Context, target core.Target, opts core.Options, label string, req []byte) ([]byte, *wire.Session, error) {
	s, err := wire.Dial(ctx, proto, target, opts)
	if err != nil {
		return nil, nil, err
	}
	resp, err := s.RoundTrip(label, req, mbap.Framer, mbap.MaxADU)
	return resp, s, err
}

func (f *Fingerprinter) judge(b *fpx.Builder, resp []byte, fc byte) (mbap.Response, bool) {
	return f.judgeTID(b, resp, fc, probeTID)
}

// judgeTID scores a response to a request with transaction tid and
// function fc.
func (f *Fingerprinter) judgeTID(b *fpx.Builder, resp []byte, fc byte, tid uint16) (mbap.Response, bool) {
	r, err := mbap.Parse(resp)
	if err != nil {
		if len(resp) >= mbap.HeaderLen && resp[2] == 0 && resp[3] == 0 {
			b.Score(core.ConfidenceLow, "MBAP protocol identifier 0, but "+err.Error())
		}
		return r, false
	}
	b.Evidence("MBAP header valid (protocol 0, length consistent)")
	if err := r.Check(tid, fc); err != nil {
		b.Score(core.ConfidenceLow, "MBAP framing, but "+err.Error())
		return r, false
	}
	b.Sig("fc", fmt.Sprintf("0x%02x", fc))
	if r.IsException() {
		b.Sig("exc", fmt.Sprintf("0x%02x", r.Exception))
		b.Score(core.ConfidenceCertain, fmt.Sprintf("transaction ID echoed, exception %s to FC 0x%02x", mbap.ExceptionName(r.Exception), fc))
	} else {
		b.Sig("resp", "normal")
		b.Score(core.ConfidenceCertain, fmt.Sprintf("transaction ID echoed, normal response to FC 0x%02x", fc))
	}
	if r.Unit != f.unit {
		b.Evidence(fmt.Sprintf("unit %d answered for unit %d", r.Unit, f.unit))
	}
	b.Sig("unit", fmt.Sprint(r.Unit))
	b.Meta("unitId", fmt.Sprint(r.Unit))
	return r, true
}

func (f *Fingerprinter) finish(b *fpx.Builder, trace []core.Exchange) core.Result {
	details := "no Modbus TCP response"
	if b.Confidence() >= core.MatchThreshold {
		details = "Modbus TCP"
	}
	r := b.Result("modbus.fc43", details, nil)
	return r.WithExchanges(trace)
}

func deviceIDRequest(unit, code, object byte) []byte {
	return mbap.Request(probeTID, unit, mbap.FCEncapsulated, mbap.MEIReadDeviceID, code, object)
}

// deviceID is a parsed Read Device Identification response.
type deviceID struct {
	conformity byte
	more       bool
	next       byte
	objects    map[byte]string
}

func parseDeviceID(data []byte) (deviceID, error) {
	// MEI, code, conformity, more, next, count, objects...
	if len(data) < 6 {
		return deviceID{}, fmt.Errorf("device identification of %d bytes", len(data))
	}
	if data[0] != mbap.MEIReadDeviceID {
		return deviceID{}, fmt.Errorf("MEI type 0x%02x, want 0x0e", data[0])
	}
	d := deviceID{conformity: data[2], more: data[3] == 0xFF, next: data[4], objects: map[byte]string{}}
	n := int(data[5])
	p := data[6:]
	for i := 0; i < n; i++ {
		if len(p) < 2 || len(p) < 2+int(p[1]) {
			return d, fmt.Errorf("object %d overruns the response", i)
		}
		d.objects[p[0]] = string(p[2 : 2+int(p[1])])
		p = p[2+int(p[1]):]
	}
	return d, nil
}

func (f *Fingerprinter) identify(ctx context.Context, b *fpx.Builder, s *wire.Session, r mbap.Response, code byte) {
	d, err := parseDeviceID(r.Data)
	if err != nil {
		b.Evidence("device identification malformed: " + err.Error())
		return
	}
	b.Sig("conf", fmt.Sprintf("0x%02x", d.conformity))
	b.Meta("conformityLevel", fmt.Sprintf("0x%02x", d.conformity))
	objs := d.objects
	for page := 1; d.more && page < maxPages && ctx.Err() == nil; page++ {
		resp, err := s.RoundTrip(fmt.Sprintf("fc43-page%d", page), deviceIDRequest(f.unit, code, d.next), mbap.Framer, mbap.MaxADU)
		if err != nil {
			break
		}
		r2, err := mbap.Parse(resp)
		if err != nil || r2.Check(probeTID, mbap.FCEncapsulated) != nil || r2.IsException() {
			break
		}
		if d, err = parseDeviceID(r2.Data); err != nil {
			break
		}
		for k, v := range d.objects {
			objs[k] = v
		}
	}
	fillIdentity(b.Identity(), objs)
	b.Evidence(fmt.Sprintf("device identification: %d objects", len(objs)))
}

func (f *Fingerprinter) basicAfterRegular(ctx context.Context, b *fpx.Builder, s *wire.Session) {
	resp, err := s.RoundTrip("fc43-basic", deviceIDRequest(f.unit, readBasic, objVendorName), mbap.Framer, mbap.MaxADU)
	if err != nil {
		return
	}
	r, err := mbap.Parse(resp)
	if err != nil || r.Check(probeTID, mbap.FCEncapsulated) != nil || r.IsException() {
		return
	}
	f.identify(ctx, b, s, r, readBasic)
}

func fillIdentity(id *core.Identity, objs map[byte]string) {
	id.Vendor = fpx.Clean(objs[objVendorName])
	id.Version = fpx.Clean(objs[objRevision])
	id.Product = fpx.Clean(objs[objProductName])
	id.Model = fpx.Clean(objs[objModelName])
	code := fpx.Clean(objs[objProductCode])
	if id.Product == "" {
		id.Product = code
	} else {
		id.Set("productCode", code)
	}
	id.Set("vendorUrl", fpx.Clean(objs[objVendorURL]))
	id.Set("userApplicationName", fpx.Clean(objs[objUserAppName]))
	for k, v := range objs {
		if k > objUserAppName {
			if c := fpx.Clean(v); c != "" {
				id.Set(fmt.Sprintf("object0x%02x", k), c)
			} else {
				id.Set(fmt.Sprintf("object0x%02x", k), hex.EncodeToString([]byte(v)))
			}
		}
	}
}
