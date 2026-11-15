// SPDX-License-Identifier: MIT

// Package bacnet fingerprints BACnet/IP (ASHRAE 135 Annex J) over UDP.
//
// Detection sends a confirmed ReadProperty for the Object_Identifier of the
// wildcard device object (instance 4194303), which a BACnet device answers
// with a unicast ComplexACK carrying its real device object identifier — an
// answer that reaches a probing socket directly, unlike the broadcast I-Am
// that Who-Is draws. A Who-Is is sent as a fallback. Any BVLC/NPDU/APDU the
// device returns — ComplexACK, Error, Reject, Abort, I-Am or a BVLC-Result —
// identifies BACnet, since no other protocol frames an Annex J message.
//
// In identify mode the device object's identity properties are read:
// object name, vendor name and identifier, model name, firmware revision
// and application software version.
package bacnet

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolBACnet

// BVLC, NPDU and APDU constants.
const (
	bvlcType          = 0x81
	bvlcUnicastNPDU   = 0x0A
	bvlcBroadcastNPDU = 0x0B
	bvlcResult        = 0x00

	npduVersion = 0x01

	apduConfirmedReq   = 0x00
	apduUnconfirmedReq = 0x10
	apduSimpleACK      = 0x20
	apduComplexACK     = 0x30
	apduError          = 0x50
	apduReject         = 0x60
	apduAbort          = 0x70

	svcReadProperty = 12
	svcWhoIs        = 0x08

	objectDevice     = 8
	wildcardInstance = 0x3FFFFF
	maxUDP           = 1500
)

// Property identifiers.
const (
	propObjectIdentifier = 75
	propObjectName       = 77
	propModelName        = 70
	propFirmwareRevision = 44
	propAppSoftwareVer   = 12
	propVendorName       = 121
	propVendorIdentifier = 120
)

// Fingerprinter detects BACnet/IP.
type Fingerprinter struct{}

// New returns a BACnet/IP fingerprinter.
func New() *Fingerprinter { return &Fingerprinter{} }

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.UDP,
		Ports:         []int{47808, 47809, 47810, 47811, 47812, 47813, 47814, 47815},
		Priority:      75,
		Intrusiveness: core.Passive,
		Description:   "confirmed ReadProperty of the wildcard device Object_Identifier, then Who-Is; device identity properties in identify mode",
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

	instance := uint32(wildcardInstance)
	resp, err := s.RoundTripDatagram("read-object-id", readProperty(1, wildcardInstance, propObjectIdentifier), maxUDP, answers(1))
	if err == nil {
		if a, ok := f.judge(b, resp); ok {
			if a.kind == apduComplexACK {
				if inst, ok2 := readPropertyDeviceInstance(a); ok2 {
					instance = inst
					b.Meta("deviceInstance", fmt.Sprint(inst))
					b.Identity().Set("deviceInstance", fmt.Sprint(inst))
				}
			}
		}
	}
	// Fall back to a Who-Is when the wildcard read drew nothing.
	if b.Confidence() < core.MatchThreshold {
		resp, err = s.RoundTripDatagram("who-is", whoIs(), maxUDP, answersWhoIs)
		if err == nil {
			if a, ok := f.judge(b, resp); ok && a.kind == apduUnconfirmedReq {
				if inst, vendor, ok2 := parseIAm(a.apdu); ok2 {
					instance = inst
					b.Meta("deviceInstance", fmt.Sprint(inst))
					b.Identity().Set("vendorId", fmt.Sprint(vendor))
				}
			}
		} else if b.Confidence() == 0 {
			return b.Result("bacnet.readproperty", "no BACnet/IP response", s), err
		}
	}
	if b.Confidence() < core.MatchThreshold {
		return b.Result("bacnet.readproperty", "no BACnet/IP response", s), nil
	}
	if opts.Mode == core.ModeIdentify && instance != wildcardInstance {
		f.identify(ctx, b, s, instance)
	}
	return b.Result("bacnet.readproperty", "BACnet/IP device", s), nil
}

type apdu struct {
	kind     byte
	service  byte
	invoke   byte
	apdu     []byte // the APDU bytes after the type octet
	body     []byte // service-specific bytes (after the ack/request header)
	isResult bool   // a BVLC-Result rather than an APDU
}

// judge decodes one datagram and scores it.
func (f *Fingerprinter) judge(b *fpx.Builder, dg []byte) (apdu, bool) {
	a, err := parse(dg)
	if err != nil {
		if len(dg) > 0 && dg[0] == bvlcType {
			b.Score(core.ConfidenceLow, "BVLC type 0x81, but "+err.Error())
		}
		return a, false
	}
	switch a.kind {
	case apduComplexACK:
		b.Score(core.ConfidenceCertain, "ReadProperty ComplexACK from the device object")
		b.Sig("apdu", "complex-ack")
	case apduError, apduReject, apduAbort:
		b.Score(core.ConfidenceHigh, fmt.Sprintf("BACnet %s to ReadProperty", apduName(a.kind)))
		b.Sig("apdu", apduName(a.kind))
	case apduUnconfirmedReq:
		if a.service == svcWhoIs {
			return a, false // our own echo via a broadcast loop: ignore
		}
		b.Score(core.ConfidenceCertain, "BACnet I-Am")
		b.Sig("apdu", "i-am")
	case apduSimpleACK:
		b.Score(core.ConfidenceHigh, "BACnet SimpleACK")
	default:
		if a.isResult {
			b.Score(core.ConfidenceHigh, "BVLC-Result")
			b.Sig("apdu", "bvlc-result")
			return a, true // BVLC-Result
		}
		b.Score(core.ConfidenceMedium, "valid BACnet/IP frame")
	}
	return a, true
}

func (f *Fingerprinter) identify(ctx context.Context, b *fpx.Builder, s *wire.Session, instance uint32) {
	id := b.Identity()
	invoke := byte(1)
	read := func(label string, prop uint32) (byte, []byte, bool) {
		if ctx.Err() != nil {
			return 0, nil, false
		}
		// A distinct invoke ID per request, and an answer accepted only
		// for it and for the property asked: a late or duplicated answer
		// to an earlier read must not be taken for this one.
		invoke++
		resp, err := s.RoundTripDatagram(label, readProperty(invoke, instance, prop), maxUDP, answers(invoke))
		if err != nil {
			return 0, nil, false
		}
		a, err := parse(resp)
		if err != nil || a.kind != apduComplexACK || a.invoke != invoke || propertyOf(a) != prop {
			return 0, nil, false
		}
		return readPropertyValue(a)
	}
	str := func(label string, prop uint32) string {
		if tn, v, ok := read(label, prop); ok && tn == tagCharString {
			return fpx.Clean(charString(v))
		}
		return ""
	}
	id.Name = str("object-name", propObjectName)
	id.Vendor = str("vendor-name", propVendorName)
	if tn, v, ok := read("vendor-id", propVendorIdentifier); ok && tn == tagUnsigned {
		if n, ok := unsignedTag(v); ok {
			id.VendorID = fmt.Sprint(n)
		}
	}
	id.Model = str("model-name", propModelName)
	id.Version = str("firmware", propFirmwareRevision)
	if v := str("app-software", propAppSoftwareVer); v != "" {
		id.Set("applicationSoftwareVersion", v)
	}
	if !id.IsZero() {
		b.Evidence("device identity properties read")
	}
}

// answers returns a datagram filter for a confirmed request with the given
// invoke ID: BACnet replies to other invoke IDs (late or duplicate answers
// to earlier requests) and unsolicited I-Ams are discarded; anything that
// is not a BACnet reply is kept, for the caller to judge.
func answers(invoke byte) func([]byte) wire.Verdict {
	return func(dg []byte) wire.Verdict {
		a, err := parse(dg)
		if err != nil {
			return wire.Foreign
		}
		if a.isResult {
			return wire.Answer
		}
		switch a.kind {
		case apduComplexACK, apduSimpleACK, apduError, apduReject, apduAbort:
			if a.invoke == invoke {
				return wire.Answer
			}
		}
		return wire.Discard
	}
}

// answersWhoIs accepts an I-Am (and a BVLC-Result); a datagram that is not
// BACnet/IP is foreign.
func answersWhoIs(dg []byte) wire.Verdict {
	a, err := parse(dg)
	switch {
	case err != nil:
		return wire.Foreign
	case a.isResult, a.kind == apduUnconfirmedReq && a.service == 0x00:
		return wire.Answer
	}
	return wire.Discard
}

func propertyOf(a apdu) uint32 {
	_, val, _, ok := firstContextTag(a.body, 1)
	if !ok || len(val) == 0 || len(val) > 4 {
		return 0xFFFFFFFF
	}
	var v uint32
	for _, c := range val {
		v = v<<8 | uint32(c)
	}
	return v
}

// ---- encoders ----

func bvlc(fn byte, npdu []byte) []byte {
	b := []byte{bvlcType, fn, 0, 0}
	b = append(b, npdu...)
	binary.BigEndian.PutUint16(b[2:4], wire.Len16(len(b)))
	return b
}

func readProperty(invoke byte, instance, prop uint32) []byte {
	objID := uint32(objectDevice)<<22 | instance&0x3FFFFF
	apdu := []byte{apduConfirmedReq, 0x05, invoke, svcReadProperty}
	apdu = append(apdu, 0x0C) // context tag 0, object identifier, length 4
	apdu = binary.BigEndian.AppendUint32(apdu, objID)
	apdu = append(apdu, contextUnsigned(1, prop)...)
	return bvlc(bvlcUnicastNPDU, append([]byte{npduVersion, 0x04}, apdu...))
}

func whoIs() []byte {
	return bvlc(bvlcUnicastNPDU, []byte{npduVersion, 0x00, apduUnconfirmedReq, svcWhoIs})
}

// contextUnsigned encodes a context-tagged unsigned value with the minimum
// octets.
func contextUnsigned(tag byte, v uint32) []byte {
	val := binary.BigEndian.AppendUint32(nil, v)
	for len(val) > 1 && val[0] == 0 {
		val = val[1:]
	}
	return append([]byte{tag<<4 | 0x08 | wire.Len8(len(val))}, val...)
}

// ---- decoders ----

func parse(dg []byte) (apdu, error) {
	if len(dg) < 4 || dg[0] != bvlcType {
		return apdu{}, fmt.Errorf("not a BVLC frame")
	}
	fn := dg[1]
	n := int(binary.BigEndian.Uint16(dg[2:4]))
	if n != len(dg) {
		return apdu{}, fmt.Errorf("BVLC length %d does not match %d octets", n, len(dg))
	}
	switch fn {
	case bvlcUnicastNPDU, bvlcBroadcastNPDU:
	case bvlcResult:
		return apdu{isResult: true}, nil
	case 0x04: // Forwarded-NPDU carries a 6-octet originating address.
		if len(dg) < 10 {
			return apdu{}, fmt.Errorf("short Forwarded-NPDU")
		}
		return parseNPDU(dg[10:])
	default:
		return apdu{}, fmt.Errorf("BVLC function 0x%02x is not NPDU-bearing", fn)
	}
	return parseNPDU(dg[4:])
}

func parseNPDU(p []byte) (apdu, error) {
	if len(p) < 2 || p[0] != npduVersion {
		return apdu{}, fmt.Errorf("NPDU version is not 1")
	}
	control := p[1]
	p = p[2:]
	if control&0x80 != 0 {
		return apdu{}, fmt.Errorf("network-layer message, not an APDU")
	}
	// Destination (DNET/DLEN/DADR), source (SNET/SLEN/SADR), hop count.
	if control&0x20 != 0 {
		var ok bool
		if p, ok = skipAddr(p); !ok {
			return apdu{}, fmt.Errorf("truncated DADR")
		}
		if len(p) < 1 {
			return apdu{}, fmt.Errorf("missing hop count")
		}
		p = p[1:]
	}
	if control&0x08 != 0 {
		var ok bool
		if p, ok = skipAddr(p); !ok {
			return apdu{}, fmt.Errorf("truncated SADR")
		}
	}
	if len(p) < 1 {
		return apdu{}, fmt.Errorf("empty APDU")
	}
	return parseAPDU(p)
}

func skipAddr(p []byte) ([]byte, bool) {
	if len(p) < 3 {
		return nil, false
	}
	dlen := int(p[2])
	if len(p) < 3+dlen {
		return nil, false
	}
	return p[3+dlen:], true
}

func parseAPDU(p []byte) (apdu, error) {
	a := apdu{kind: p[0] & 0xF0, apdu: p}
	switch a.kind {
	case apduComplexACK:
		// type(1) invoke(1) service(1) [service data].
		if len(p) < 3 {
			return a, fmt.Errorf("short ComplexACK")
		}
		a.invoke, a.service, a.body = p[1], p[2], p[3:]
	case apduUnconfirmedReq:
		if len(p) < 2 {
			return a, fmt.Errorf("short unconfirmed request")
		}
		a.service, a.body = p[1], p[2:]
	case apduError, apduReject, apduAbort:
		if len(p) < 2 {
			return a, fmt.Errorf("short %s", apduName(a.kind))
		}
		a.invoke = p[1]
	case apduSimpleACK:
		// type(1) invoke(1) service(1).
		if len(p) < 3 {
			return a, fmt.Errorf("short SimpleACK")
		}
		a.invoke, a.service = p[1], p[2]
	default:
		return a, fmt.Errorf("APDU type 0x%02x is not a reply", a.kind)
	}
	return a, nil
}

// readPropertyDeviceInstance reads the object identifier echoed in a
// ReadProperty ComplexACK (context tag 0).
func readPropertyDeviceInstance(a apdu) (uint32, bool) {
	tag, val, _, ok := firstContextTag(a.body, 0)
	if !ok || tag != 0 || len(val) != 4 {
		return 0, false
	}
	objID := binary.BigEndian.Uint32(val)
	return objID & 0x3FFFFF, true
}

// Application tag numbers used in device identity properties.
const (
	tagUnsigned   = 2
	tagEnumerated = 9
	tagCharString = 7
)

// readPropertyValue returns the application tag number and value bytes of
// the single primitive inside the opening tag 3 of a ReadProperty
// ComplexACK.
func readPropertyValue(a apdu) (byte, []byte, bool) {
	// Skip context tags 0 (object id), 1 (property id) and optional 2
	// (array index), then read the first application tag inside tag 3.
	p := a.body
	for len(p) > 0 {
		h, ok := parseTag(p)
		if !ok {
			return 0, nil, false
		}
		if h.opening && h.number == 3 {
			return appTag(p[h.size:])
		}
		p = p[h.size+h.length:]
	}
	return 0, nil, false
}

// tagHeader is a decoded BACnet tag (ASHRAE 135 clause 20.2.1): the initial
// octet carries the tag number (15 announces a tag number octet), the class
// and the length/value/type field; 5 in that field announces a length
// octet, whose values 254 and 255 announce a length of two and of four
// octets.
type tagHeader struct {
	number  byte // the tag number, 0..254
	context bool // context-specific class (else application)
	// opening and closing mark the tags that bracket constructed data;
	// they have no contents of their own.
	opening, closing bool
	size             int // octets of the tag itself
	length           int // octets of contents that follow it; within the input
}

// parseTag decodes the tag at the start of p. It reports false for an
// empty input, the reserved tag number 255, a tag cut short, and a length
// that is larger than what follows the tag: every length is compared with
// the remaining input before it is used.
func parseTag(p []byte) (tagHeader, bool) {
	if len(p) == 0 {
		return tagHeader{}, false
	}
	h := tagHeader{number: p[0] >> 4, context: p[0]&0x08 != 0, size: 1}
	lvt := p[0] & 0x07
	if h.number == 0x0F { // extended tag number
		if len(p) < 2 || p[1] == 0xFF {
			return tagHeader{}, false
		}
		h.number, h.size = p[1], 2
	}
	if h.context && lvt >= 6 {
		h.opening, h.closing = lvt == 6, lvt == 7
		return h, true
	}
	length := uint32(lvt)
	if lvt == 5 { // extended length
		if len(p) < h.size+1 {
			return tagHeader{}, false
		}
		ext := p[h.size]
		h.size++
		switch ext {
		case 254:
			if len(p) < h.size+2 {
				return tagHeader{}, false
			}
			length = uint32(binary.BigEndian.Uint16(p[h.size:]))
			h.size += 2
		case 255:
			if len(p) < h.size+4 {
				return tagHeader{}, false
			}
			length = binary.BigEndian.Uint32(p[h.size:])
			h.size += 4
		default:
			length = uint32(ext)
		}
	}
	if uint64(length) > uint64(len(p)-h.size) {
		return tagHeader{}, false
	}
	h.length = int(length)
	return h, true
}

// appTag decodes one application-tagged primitive and returns its tag
// number and value octets.
func appTag(p []byte) (byte, []byte, bool) {
	h, ok := parseTag(p)
	if !ok || h.context {
		return 0, nil, false
	}
	return h.number, p[h.size : h.size+h.length], true
}

// firstContextTag returns the first context tag with the given tag number
// among the primitive context tags at the start of p; it stops at an
// application tag and at an opening or closing tag.
func firstContextTag(p []byte, want byte) (tag byte, val, rest []byte, ok bool) {
	for len(p) > 0 {
		h, ok := parseTag(p)
		if !ok || !h.context || h.opening || h.closing {
			return 0, nil, nil, false
		}
		end := h.size + h.length
		if h.number == want {
			return h.number, p[h.size:end], p[end:], true
		}
		p = p[end:]
	}
	return 0, nil, nil, false
}

// tagLen returns the octets the tag at p occupies, contents included.
func tagLen(p []byte) (int, bool) {
	h, ok := parseTag(p)
	if !ok {
		return 0, false
	}
	return h.size + h.length, true
}

// charString decodes a BACnet CharacterString application value (tag 7):
// an encoding octet then the text.
func charString(v []byte) string {
	// v is the value bytes of an application tag 7; the first octet is the
	// character set.
	if len(v) < 2 {
		return ""
	}
	return string(v[1:])
}

// unsignedTag decodes a BACnet Unsigned application value (tag 2).
func unsignedTag(v []byte) (uint64, bool) {
	if len(v) == 0 || len(v) > 8 {
		return 0, false
	}
	var x uint64
	for _, c := range v {
		x = x<<8 | uint64(c)
	}
	return x, true
}

// parseIAm decodes an I-Am: device object id, max APDU, segmentation,
// vendor id.
func parseIAm(apduBytes []byte) (instance uint32, vendor uint32, ok bool) {
	if len(apduBytes) < 2 || apduBytes[0]&0xF0 != apduUnconfirmedReq || apduBytes[1] != 0x00 {
		return 0, 0, false
	}
	p := apduBytes[2:]
	// application tag 12 (object identifier), length 4.
	if len(p) < 5 || p[0] != 0xC4 {
		return 0, 0, false
	}
	instance = binary.BigEndian.Uint32(p[1:5]) & 0x3FFFFF
	p = p[5:]
	// max APDU (unsigned), segmentation (enumerated), vendor id (unsigned).
	for i := 0; i < 2 && len(p) > 0; i++ { // skip two values
		n, good := tagLen(p)
		if !good {
			return instance, 0, true
		}
		p = p[n:]
	}
	if _, val, good := appTag(p); good {
		// A value wider than 32 bits is not a vendor identifier
		// (an Unsigned16); do not report it truncated.
		if v, good := unsignedTag(val); good && v <= math.MaxUint32 {
			vendor = uint32(v)
		}
	}
	return instance, vendor, true
}

func apduName(kind byte) string {
	switch kind {
	case apduComplexACK:
		return "ComplexACK"
	case apduError:
		return "Error"
	case apduReject:
		return "Reject"
	case apduAbort:
		return "Abort"
	case apduSimpleACK:
		return "SimpleACK"
	}
	return fmt.Sprintf("APDU 0x%02x", kind)
}
