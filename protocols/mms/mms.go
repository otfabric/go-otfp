// SPDX-License-Identifier: MIT

// Package mms fingerprints IEC 61850 / ISO 9506 MMS over ISO-on-TCP.
//
// A COTP connection confirm alone does not identify MMS: Siemens S7 and
// every other ISO-on-TCP stack confirm too. Detection therefore completes
// an association: COTP CR (TSEL 0x0001), then one data TPDU carrying an
// ISO 8327 session CONNECT, an ISO 8823 presentation CP, an ACSE AARQ for
// the MMS application context (1.0.9506.2.3) and an MMS Initiate-Request,
// as IEC 61850 clients send it. A session ACCEPT carrying an AARE and an
// MMS Initiate-Response proves MMS; a refusal at the ACSE or MMS level
// still identifies an MMS stack.
//
// In identify mode the MMS Identify service is called (vendor, model,
// revision). The association is concluded before closing.
package mms

import (
	"context"
	"errors"
	"fmt"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/iso"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolMMS

const maxFrame = 8192

// initiate is the user data of the association request: session CONNECT
// (SI 13), presentation CP-type (BER/MMS and ACSE contexts), ACSE AARQ
// with application context 1.0.9506.2.3 and an MMS Initiate-Request
// proposing a 65000-octet PDU, 5 outstanding requests each way, nesting
// level 10, version 1 and the IEC 61850 parameter CBB and services.
var initiate = []byte{
	0x0d, 0x81, 0x05, 0x06, 0x13, 0x01, 0x00, 0x16, 0x01, 0x02, 0x14, 0x02, 0x00, 0x02,
	0xc1, 0x73, 0x31, 0x71, 0xa0, 0x03, 0x80, 0x01, 0x01, 0xa2, 0x6a, 0xa4, 0x23, 0x30,
	0x0f, 0x02, 0x01, 0x01, 0x06, 0x04, 0x52, 0x01, 0x00, 0x01, 0x30, 0x04, 0x06, 0x02,
	0x51, 0x01, 0x30, 0x10, 0x02, 0x01, 0x03, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x01,
	0x30, 0x04, 0x06, 0x02, 0x51, 0x01, 0x61, 0x43, 0x30, 0x41, 0x02, 0x01, 0x01, 0xa0,
	0x3c, 0x60, 0x3a, 0xa1, 0x07, 0x06, 0x05, 0x28, 0xca, 0x22, 0x02, 0x03, 0xbe, 0x2f,
	0x28, 0x2d, 0x02, 0x01, 0x03, 0xa0, 0x28, 0xa8, 0x26, 0x80, 0x03, 0x00, 0xfd, 0xe8,
	0x81, 0x01, 0x05, 0x82, 0x01, 0x05, 0x83, 0x01, 0x0a, 0xa4, 0x16, 0x80, 0x01, 0x01,
	0x81, 0x03, 0x05, 0xf1, 0x00, 0x82, 0x0c, 0x03, 0xee, 0x1c, 0x00, 0x00, 0x04, 0x08,
	0x00, 0x00, 0x79, 0xef, 0x18,
}

// Session data SPDU (give tokens + data transfer) and the presentation
// fully-encoded user data header up to the MMS PDU, context 3.
var dataHeader = []byte{0x01, 0x00, 0x01, 0x00}

func presentationData(mms []byte) []byte {
	pdv := tlv(0x30, append([]byte{0x02, 0x01, 0x03}, tlv(0xa0, mms)...))
	return append(append([]byte{}, dataHeader...), tlv(0x61, pdv)...)
}

var (
	// Confirmed-Request invoke ID 1, Identify.
	identifyRequest = tlv(0xa0, []byte{0x02, 0x01, 0x01, 0x82, 0x00})
	// Conclude-Request.
	concludeRequest = []byte{0x8b, 0x00}
)

// MMS PDU tags.
const (
	tagConfirmedResponse = 0xa1
	tagConfirmedError    = 0xa2
	tagInitiateResponse  = 0xa9
	tagInitiateError     = 0xaa
	tagIdentifyResponse  = 0xa2
)

// Session SPDU identifiers.
const (
	spduAccept = 0x0e
	spduRefuse = 0x0c
	spduAbort  = 0x19
)

// Config configures the fingerprinter.
type Config struct {
	// CallingTSEL and CalledTSEL are the transport selectors of the COTP
	// CR; nil means 0x0001, the IEC 61850 default.
	CallingTSEL, CalledTSEL []byte
}

// Fingerprinter detects MMS.
type Fingerprinter struct {
	calling, called []byte
}

// New returns an MMS fingerprinter.
func New() *Fingerprinter { return NewWithConfig(Config{}) }

// NewWithConfig returns a fingerprinter with the given configuration.
func NewWithConfig(c Config) *Fingerprinter {
	f := &Fingerprinter{calling: c.CallingTSEL, called: c.CalledTSEL}
	if f.calling == nil {
		f.calling = []byte{0x00, 0x01}
	}
	if f.called == nil {
		f.called = []byte{0x00, 0x01}
	}
	return f
}

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{102, 3782},
		Priority:      10,
		Intrusiveness: core.Passive,
		Description:   "TPKT/COTP CR (TSEL 0x0001), session CONNECT + ACSE AARQ + MMS Initiate; MMS Identify in identify mode",
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

	cc, err := s.RoundTrip("cotp-cr", iso.ConnectRequest(0x0001, f.calling, f.called, 0x0a), iso.Framer, maxFrame)
	if err != nil {
		if errors.Is(err, wire.ErrClosed) {
			return b.Result("mms.initiate", "connection closed on COTP CR", s), nil
		}
		return b.Result("mms.initiate", "no COTP response", s), err
	}
	switch iso.TPDUType(cc) {
	case iso.TPDUConnectConfirm:
		if _, err := iso.ParseConfirm(cc); err != nil {
			b.Evidence("COTP CC malformed: " + err.Error())
			return b.Result("mms.initiate", "malformed COTP CC", s), nil
		}
		b.Score(core.ConfidenceLow, "COTP connection confirmed (ISO-on-TCP)")
	case iso.TPDUDisconnectRequest, iso.TPDUError:
		b.Evidence("COTP connection refused for TSEL 0x0001 (ISO-on-TCP, not an IEC 61850 server)")
		return b.Result("mms.initiate", "COTP refused", s), nil
	default:
		return b.Result("mms.initiate", "not ISO-on-TCP", s), nil
	}

	resp, err := s.RoundTrip("initiate", iso.Data(initiate), iso.Framer, maxFrame)
	if err != nil {
		b.Evidence("no answer to the association request")
		return b.Result("mms.initiate", "ISO-on-TCP without MMS", s), nil
	}
	user, ok := iso.Payload(resp)
	if !ok || len(user) == 0 {
		b.Evidence("no session data in the answer")
		return b.Result("mms.initiate", "ISO-on-TCP without MMS", s), nil
	}
	associated := f.judgeAssociation(b, user)
	if associated && opts.Mode == core.ModeIdentify {
		f.identify(b, s)
	}
	if associated {
		_, _ = s.RoundTrip("conclude", iso.Data(presentationData(concludeRequest)), iso.Framer, maxFrame)
	}
	details := "ISO-on-TCP without MMS"
	if b.Confidence() >= core.MatchThreshold {
		details = "MMS server"
	}
	return b.Result("mms.initiate", details, s), nil
}

// judgeAssociation scores the session-level answer to the association
// request; it reports whether the association was accepted.
func (f *Fingerprinter) judgeAssociation(b *fpx.Builder, user []byte) bool {
	switch user[0] {
	case spduRefuse:
		b.Score(core.ConfidenceMedium, "ISO session refused the connection")
		b.Sig("session", "refuse")
		return false
	case spduAbort:
		b.Score(core.ConfidenceMedium, "ISO session aborted the connection")
		b.Sig("session", "abort")
		return false
	case spduAccept:
	default:
		if user[0] == 0x32 || user[0] == 0x72 {
			b.Evidence("S7 PDU in the answer: a Siemens S7 endpoint")
		}
		return false
	}
	b.Score(core.ConfidenceMedium, "ISO session ACCEPT")
	b.Sig("session", "accept")
	// The AARE and the MMS PDU sit inside the presentation CPA, in the
	// session user data; find them by tag rather than decoding every
	// presentation layer field.
	pres, ok := sessionUserData(user)
	if !ok {
		b.Evidence("session ACCEPT without user data")
		return false
	}
	aare, ok := find(pres, 0x61)
	if !ok {
		return false
	}
	if res, ok := find(aare, 0xa2); ok && len(res) >= 3 && res[0] == 0x02 && res[2] != 0 {
		b.Score(core.ConfidenceHigh, fmt.Sprintf("ACSE AARE rejected the association (result %d)", res[2]))
		b.Sig("aare", "reject")
		return false
	}
	b.Score(core.ConfidenceHigh, "ACSE AARE accepted the MMS application context")
	if ir, ok := find(aare, tagInitiateResponse); ok {
		b.Score(core.ConfidenceCertain, "MMS Initiate-Response")
		b.Sig("initiate", "response")
		if v, ok := find(ir, 0x80); ok {
			b.Meta("localDetailCalled", fmt.Sprint(uintOf(v)))
		}
		if v, ok := find(ir, 0x81); ok {
			b.Meta("maxServOutstandingCalling", fmt.Sprint(uintOf(v)))
		}
		if v, ok := find(ir, 0x82); ok {
			b.Meta("maxServOutstandingCalled", fmt.Sprint(uintOf(v)))
		}
		if d, ok := find(ir, 0xa4); ok {
			if v, ok := find(d, 0x80); ok {
				b.Meta("version", fmt.Sprint(uintOf(v)))
				b.Sig("v", fmt.Sprint(uintOf(v)))
			}
		}
		return true
	}
	if _, ok := find(aare, tagInitiateError); ok {
		b.Score(core.ConfidenceHigh, "MMS Initiate-Error")
		b.Sig("initiate", "error")
	}
	return false
}

func (f *Fingerprinter) identify(b *fpx.Builder, s *wire.Session) {
	resp, err := s.RoundTrip("identify", iso.Data(presentationData(identifyRequest)), iso.Framer, maxFrame)
	if err != nil {
		b.Evidence("no answer to Identify")
		return
	}
	user, ok := iso.Payload(resp)
	if !ok {
		return
	}
	pdu, ok := find(user, 0x61, 0x30, 0xa0)
	if !ok {
		return
	}
	cr, ok := find(pdu, tagConfirmedResponse)
	if !ok {
		if _, isErr := find(pdu, tagConfirmedError); isErr {
			b.Evidence("Identify refused")
		}
		return
	}
	idr, ok := find(cr, tagIdentifyResponse)
	if !ok {
		return
	}
	id := b.Identity()
	if v, ok := find(idr, 0x80); ok {
		id.Vendor = fpx.Clean(string(v))
	}
	if v, ok := find(idr, 0x81); ok {
		id.Model = fpx.Clean(string(v))
	}
	if v, ok := find(idr, 0x82); ok {
		id.Version = fpx.Clean(string(v))
	}
	b.Evidence("MMS Identify answered")
}

// sessionUserData returns the User Data parameter (PGI 0xC1) of an ISO
// 8327 SPDU.
func sessionUserData(spdu []byte) ([]byte, bool) {
	params, ok := spduParams(spdu)
	for ok && len(params) >= 2 {
		var code byte
		var val []byte
		code, val, params, ok = spduParam(params)
		if ok && code == 0xc1 {
			return val, true
		}
	}
	return nil, false
}

func spduParams(spdu []byte) ([]byte, bool) {
	_, val, _, ok := spduParam(spdu)
	return val, ok
}

// spduParam splits an SI/PI/PGI unit: code, length (one octet, or 0xFF
// and two octets), value.
func spduParam(b []byte) (code byte, val, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	code, l, p := b[0], int(b[1]), 2
	if l == 0xff {
		if len(b) < 4 {
			return 0, nil, nil, false
		}
		l, p = int(b[2])<<8|int(b[3]), 4
	}
	if p+l > len(b) {
		return 0, nil, nil, false
	}
	return code, b[p : p+l], b[p+l:], true
}

// tlv encodes a BER TLV with a one-octet tag.
func tlv(tag byte, v []byte) []byte {
	out := []byte{tag}
	switch n := len(v); {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, v...)
}

// next splits the first BER TLV off b. Tags are one octet (the protocols
// probed here use no high tag numbers that matter); the indefinite length
// is not supported.
func next(b []byte) (tag byte, val, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	tag, l := b[0], int(b[1])
	p := 2
	if tag&0x1f == 0x1f { // high tag number: skip its octets
		for p-1 < len(b) && b[p-1]&0x80 != 0 {
			p++
		}
		if p >= len(b) {
			return 0, nil, nil, false
		}
		l = int(b[p])
		p++
	}
	if l&0x80 != 0 {
		n := l & 0x7f
		if n == 0 || n > 3 || p+n > len(b) {
			return 0, nil, nil, false
		}
		l = 0
		for _, x := range b[p : p+n] {
			l = l<<8 | int(x)
		}
		p += n
	}
	if p+l > len(b) {
		return 0, nil, nil, false
	}
	return tag, b[p : p+l], b[p+l:], true
}

// find searches b depth-first for a TLV with the first tag of path, then
// within it for the next, and so on, and returns the innermost value.
func find(b []byte, path ...byte) ([]byte, bool) {
	return findDepth(b, path, 0)
}

func findDepth(b []byte, path []byte, depth int) ([]byte, bool) {
	if depth > 16 {
		return nil, false
	}
	for len(b) > 0 {
		tag, val, rest, ok := next(b)
		if !ok {
			// Not BER at this offset (e.g. session parameters): skip.
			b = b[1:]
			continue
		}
		if tag == path[0] {
			if len(path) == 1 {
				return val, true
			}
			if v, ok := findDepth(val, path[1:], depth+1); ok {
				return v, true
			}
		}
		if tag&0x20 != 0 {
			if v, ok := findDepth(val, path, depth+1); ok {
				return v, true
			}
		}
		b = rest
	}
	return nil, false
}

func uintOf(b []byte) uint64 {
	var x uint64
	for _, c := range b {
		x = x<<8 | uint64(c)
	}
	return x
}
