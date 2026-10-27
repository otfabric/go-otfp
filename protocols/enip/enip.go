// SPDX-License-Identifier: MIT

// Package enip fingerprints EtherNet/IP (the CIP encapsulation of ODVA) over
// TCP and UDP.
//
// Detection sends a ListIdentity command (0x0063), which needs no session
// and which every EtherNet/IP target answers with its CIP Identity object:
// vendor, device type, product code, revision, serial number and product
// name. Over UDP it is a single datagram; over TCP the encapsulation header
// is validated and the CPF identity item decoded. The command identifier is
// echoed, the status must be success and the sender context must match, so
// unrelated services do not match.
//
// ListIdentity already carries the full identity, so detect and identify
// modes send the same probe; identify mode adds the vendor and device-type
// names and, over TCP, a RegisterSession to confirm the session layer.
package enip

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolENIP

// Encapsulation constants.
const (
	headerLen = 24
	maxFrame  = 65535

	cmdListServices    = 0x0004
	cmdListIdentity    = 0x0063
	cmdRegisterSession = 0x0065

	statusSuccess = 0x0000

	itemCIPIdentity = 0x000C
)

// Fingerprinter detects EtherNet/IP.
type Fingerprinter struct {
	network core.Network
}

// New returns an EtherNet/IP fingerprinter over TCP.
func New() *Fingerprinter { return &Fingerprinter{network: core.TCP} }

// NewUDP returns an EtherNet/IP fingerprinter over UDP, which probes the
// connectionless ListIdentity service.
func NewUDP() *Fingerprinter { return &Fingerprinter{network: core.UDP} }

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       f.network,
		Ports:         []int{44818, 2222},
		Priority:      70,
		Intrusiveness: core.Passive,
		Description:   "encapsulation ListIdentity (0x0063); RegisterSession over TCP in identify mode",
	}
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	if target.Network != f.network {
		return core.NoMatch(proto), nil
	}
	b := fpx.New(proto)
	s, err := wire.Dial(ctx, proto, target, opts)
	if err != nil {
		return core.NoMatch(proto), err
	}
	defer s.Close() //nolint:errcheck

	var ctxTag [8]byte
	_, _ = rand.Read(ctxTag[:])
	probe := encap(cmdListIdentity, 0, ctxTag, nil)
	var resp []byte
	if f.network == core.UDP {
		// Over UDP, discard encapsulation replies carrying another sender
		// context (answers to other scanners, or late duplicates).
		resp, err = s.RoundTripUDP("list-identity", probe, maxFrame, func(dg []byte) bool {
			h, _, perr := parseEncap(dg)
			return perr != nil || h.context == ctxTag
		})
	} else {
		resp, err = s.RoundTrip("list-identity", probe, framer, maxFrame)
	}
	if err != nil {
		if errors.Is(err, wire.ErrClosed) {
			return b.Result("enip.listidentity", "connection closed", s), nil
		}
		return b.Result("enip.listidentity", "no EtherNet/IP response", s), err
	}
	h, body, perr := parseEncap(resp)
	if perr != nil {
		if len(resp) >= 2 && binary.LittleEndian.Uint16(resp) == cmdListIdentity {
			b.Score(core.ConfidenceLow, "ListIdentity command echoed, but "+perr.Error())
		}
		return b.Result("enip.listidentity", "not EtherNet/IP", s), nil
	}
	if h.command != cmdListIdentity {
		b.Score(core.ConfidenceLow, fmt.Sprintf("encapsulation reply, but command 0x%04x", h.command))
		return b.Result("enip.listidentity", "unexpected EtherNet/IP command", s), nil
	}
	if h.context != ctxTag {
		b.Evidence("sender context not echoed")
	}
	if h.status != statusSuccess {
		b.Score(core.ConfidenceHigh, fmt.Sprintf("ListIdentity returned status 0x%08x", h.status))
		return b.Result("enip.listidentity", "EtherNet/IP error", s), nil
	}
	id, derr := parseIdentityItem(body)
	if derr != nil {
		b.Score(core.ConfidenceHigh, "valid ListIdentity encapsulation, but "+derr.Error())
		return b.Result("enip.listidentity", "EtherNet/IP", s), nil
	}
	b.Score(core.ConfidenceCertain, fmt.Sprintf("ListIdentity: %s, product %q", vendorName(id.vendorID), id.productName))
	f.fill(b, id)

	if opts.Mode == core.ModeIdentify && f.network == core.TCP {
		f.registerSession(b, s)
	}
	return b.Result("enip.listidentity", "EtherNet/IP device", s), nil
}

func (f *Fingerprinter) fill(b *fpx.Builder, id identity) {
	b.Sig("vendor", fmt.Sprint(id.vendorID))
	b.Sig("devtype", fmt.Sprintf("0x%02x", id.deviceType))
	b.Sig("product", fmt.Sprint(id.productCode))
	b.Sig("rev", fmt.Sprintf("%d.%d", id.majorRev, id.minorRev))
	i := b.Identity()
	i.Product = fpx.Clean(id.productName)
	i.Vendor = vendorName(id.vendorID)
	i.VendorID = fmt.Sprint(id.vendorID)
	i.Version = fmt.Sprintf("%d.%d", id.majorRev&0x7f, id.minorRev)
	if id.serial != 0 {
		i.Serial = fmt.Sprintf("0x%08X", id.serial)
	}
	i.Set("deviceType", deviceTypeName(id.deviceType))
	i.Set("productCode", fmt.Sprint(id.productCode))
	if id.majorRev&0x80 != 0 {
		i.Set("revisionCompatibility", "set")
	}
	if id.status != 0 {
		i.Set("status", fmt.Sprintf("0x%04x", id.status))
	}
	b.Meta("vendorId", fmt.Sprint(id.vendorID))
	b.Meta("deviceType", fmt.Sprint(id.deviceType))
}

func (f *Fingerprinter) registerSession(b *fpx.Builder, s *wire.Session) {
	var tag [8]byte
	resp, err := s.RoundTrip("register-session", encap(cmdRegisterSession, 0, tag, []byte{0x01, 0x00, 0x00, 0x00}), framer, maxFrame)
	if err != nil {
		return
	}
	h, _, perr := parseEncap(resp)
	if perr == nil && h.command == cmdRegisterSession && h.status == statusSuccess && h.session != 0 {
		b.Evidence(fmt.Sprintf("session registered (handle 0x%08x)", h.session))
		b.Sig("session", "ok")
	}
}

type header struct {
	command uint16
	length  uint16
	session uint32
	status  uint32
	context [8]byte
	options uint32
}

// encap builds an encapsulation message.
func encap(command uint16, session uint32, ctx [8]byte, data []byte) []byte {
	b := make([]byte, headerLen+len(data))
	binary.LittleEndian.PutUint16(b[0:], command)
	binary.LittleEndian.PutUint16(b[2:], uint16(len(data)))
	binary.LittleEndian.PutUint32(b[4:], session)
	copy(b[12:20], ctx[:])
	copy(b[24:], data)
	return b
}

var framer = wire.FixedHeader(headerLen, func(h []byte) int {
	n := int(binary.LittleEndian.Uint16(h[2:4]))
	if n > maxFrame-headerLen {
		return -1
	}
	return headerLen + n
})

func parseEncap(b []byte) (header, []byte, error) {
	if len(b) < headerLen {
		return header{}, nil, fmt.Errorf("%d octets is shorter than an encapsulation header", len(b))
	}
	h := header{
		command: binary.LittleEndian.Uint16(b[0:]),
		length:  binary.LittleEndian.Uint16(b[2:]),
		session: binary.LittleEndian.Uint32(b[4:]),
		status:  binary.LittleEndian.Uint32(b[8:]),
		options: binary.LittleEndian.Uint32(b[20:]),
	}
	copy(h.context[:], b[12:20])
	if int(h.length)+headerLen != len(b) {
		return h, nil, fmt.Errorf("length %d does not match %d octets", h.length, len(b))
	}
	return h, b[headerLen:], nil
}

type identity struct {
	vendorID           uint16
	deviceType         uint16
	productCode        uint16
	majorRev, minorRev uint8
	status             uint16
	serial             uint32
	productName        string
}

// parseIdentityItem decodes the CPF of a ListIdentity reply and the CIP
// Identity item it carries.
func parseIdentityItem(body []byte) (identity, error) {
	if len(body) < 2 {
		return identity{}, fmt.Errorf("no CPF item count")
	}
	count := binary.LittleEndian.Uint16(body)
	if count == 0 {
		return identity{}, fmt.Errorf("ListIdentity reported no devices")
	}
	p := body[2:]
	if len(p) < 4 {
		return identity{}, fmt.Errorf("truncated CPF item")
	}
	typ := binary.LittleEndian.Uint16(p)
	length := int(binary.LittleEndian.Uint16(p[2:]))
	p = p[4:]
	if typ != itemCIPIdentity {
		return identity{}, fmt.Errorf("first CPF item is type 0x%04x, not CIP identity", typ)
	}
	if length > len(p) {
		return identity{}, fmt.Errorf("CPF item length %d overruns %d octets", length, len(p))
	}
	item := p[:length]
	// protocol version (2) + sockaddr_in (16) + identity.
	if len(item) < 2+16+15 {
		return identity{}, fmt.Errorf("identity item truncated")
	}
	q := item[18:]
	id := identity{
		vendorID:    binary.LittleEndian.Uint16(q[0:]),
		deviceType:  binary.LittleEndian.Uint16(q[2:]),
		productCode: binary.LittleEndian.Uint16(q[4:]),
		majorRev:    q[6],
		minorRev:    q[7],
		status:      binary.LittleEndian.Uint16(q[8:]),
		serial:      binary.LittleEndian.Uint32(q[10:]),
	}
	nameLen := int(q[14])
	if 15+nameLen > len(q) {
		return id, fmt.Errorf("product name overruns the item")
	}
	id.productName = string(q[15 : 15+nameLen])
	return id, nil
}
