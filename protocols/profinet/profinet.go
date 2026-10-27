// SPDX-License-Identifier: MIT

// Package profinet fingerprints PROFINET IO over its DCE/RPC endpoint
// (connectionless RPC version 4, UDP 34964).
//
// PROFINET IO is an Industrial Ethernet protocol: cyclic data runs over
// raw Ethernet, and acyclic reads, writes and connection management run
// over connectionless DCE/RPC on UDP 34964. Detection sends a ReadImplicit
// (opnum 5) for the I&M0 identification record to the PNIO device
// interface. A DCE/RPC v4 reply that echoes the request's activity UUID —
// a response, a fault, a reject or a nocall — identifies PROFINET, since
// the activity UUID cannot be guessed by an unrelated service.
//
// ReadImplicit needs no connection and no application relationship, so the
// same probe serves detect and identify: when the device returns the I&M0
// record, its vendor ID, order ID (article number), serial number and
// hardware and software revisions are decoded.
//
// DCP device discovery (Identify-All) runs over raw Layer 2 Ethernet and
// needs elevated privileges and a local interface; it is out of scope for
// an IP-endpoint fingerprinter.
package profinet

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolPROFINET

// DCE/RPC constants.
const (
	rpcVersion = 4
	headerLen  = 80

	typeRequest  = 0
	typePing     = 1
	typeResponse = 2
	typeFault    = 3
	typeNoCall   = 5
	typeReject   = 6

	flagIdempotent = 0x20
	drepLittle     = 0x10

	opReadImplicit = 5
	ifaceVersion   = 1

	ndrHeaderLen = 20
	blockIM0     = 0x0020
	indexIM0     = 0xAFF0

	maxUDP = 1500
)

// deviceInterface is the PNIO IO-Device interface UUID.
var deviceInterface = uuid("dea00001-6c97-11d1-8271-00a02442df7d")

// Fingerprinter detects PROFINET IO.
type Fingerprinter struct{}

// New returns a PROFINET fingerprinter.
func New() *Fingerprinter { return &Fingerprinter{} }

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.UDP,
		Ports:         []int{34964},
		Priority:      85,
		Intrusiveness: core.Passive,
		Description:   "DCE/RPC v4 ReadImplicit (opnum 5) of I&M0 on the PNIO device interface",
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

	var activity uuidT
	_, _ = rand.Read(activity[:])
	probe := readImplicit(activity, indexIM0)
	// Discard DCE/RPC replies for other activities (late answers, other
	// clients); keep anything else for judging.
	resp, err := s.RoundTripUDP("read-implicit", probe, maxUDP, func(dg []byte) bool {
		h, _, perr := parseHeader(dg)
		return perr != nil || h.activity == activity
	})
	if err != nil {
		if b.Confidence() == 0 {
			return b.Result("profinet.rpc", "no PROFINET response", s), err
		}
		return b.Result("profinet.rpc", "no PROFINET response", s), nil
	}
	h, body, perr := parseHeader(resp)
	if perr != nil {
		if len(resp) > 0 && resp[0] == rpcVersion {
			b.Score(core.ConfidenceLow, "RPC version 4, but "+perr.Error())
		}
		return b.Result("profinet.rpc", "not PROFINET", s), nil
	}
	if h.activity != activity {
		b.Score(core.ConfidenceLow, "DCE/RPC v4 reply, but the activity UUID was not echoed")
		return b.Result("profinet.rpc", "unrelated DCE/RPC", s), nil
	}
	b.Meta("rpcType", rpcTypeName(h.typ))
	b.Sig("type", rpcTypeName(h.typ))
	switch h.typ {
	case typeResponse:
		b.Score(core.ConfidenceCertain, "ReadImplicit response on the PNIO device interface")
		if opts.Mode == core.ModeIdentify {
			f.identify(b, body)
		}
	case typeFault, typeReject:
		b.Score(core.ConfidenceCertain, fmt.Sprintf("DCE/RPC %s echoing the activity UUID on UDP 34964", rpcTypeName(h.typ)))
	case typeNoCall:
		b.Score(core.ConfidenceHigh, "DCE/RPC nocall echoing the activity UUID")
	default:
		b.Score(core.ConfidenceHigh, fmt.Sprintf("DCE/RPC %s echoing the activity UUID", rpcTypeName(h.typ)))
	}
	return b.Result("profinet.rpc", "PROFINET IO device", s), nil
}

func (f *Fingerprinter) identify(b *fpx.Builder, body []byte) {
	blocks, err := ndrBlocks(body)
	if err != nil {
		b.Evidence("ReadImplicit response not decodable: " + err.Error())
		return
	}
	im, ok := findIM0(blocks)
	if !ok {
		b.Evidence("no I&M0 block in the response")
		return
	}
	id := b.Identity()
	id.VendorID = fmt.Sprintf("0x%04X", im.vendorID)
	id.Product = im.orderID
	id.Serial = im.serial
	id.Version = im.software
	id.Set("orderId", im.orderID)
	id.Set("hardwareRevision", fmt.Sprint(im.hardware))
	if im.profileID != 0 {
		id.Set("profileId", fmt.Sprintf("0x%04X", im.profileID))
	}
	b.Evidence("I&M0 identification read")
}

// ---- RPC framing ----

type uuidT [16]byte

type header struct {
	typ      byte
	activity uuidT
	opnum    uint16
	bodyLen  uint16
}

// readImplicit builds a ReadImplicit request for the given record index.
func readImplicit(activity uuidT, index uint16) []byte {
	blocks := readReqBlock(index)
	body := appendNDRRequest(nil, blocks)

	b := make([]byte, headerLen)
	b[0] = rpcVersion
	b[1] = typeRequest
	b[2] = flagIdempotent
	b[3] = 0
	b[4] = drepLittle
	// drep[1], drep[2] stay 0.
	// object UUID (b[8:24]) stays nil: go-profinet accepts a nil object
	// for an implicit read.
	copy(b[24:40], encodeUUIDLE(deviceInterface))
	copy(b[40:56], activity[:])
	// server boot (b[56:60]) 0.
	binary.LittleEndian.PutUint32(b[60:64], ifaceVersion)
	binary.LittleEndian.PutUint32(b[64:68], 0) // sequence number
	binary.LittleEndian.PutUint16(b[68:70], opReadImplicit)
	binary.LittleEndian.PutUint16(b[70:72], 0xFFFF) // interface hint
	binary.LittleEndian.PutUint16(b[72:74], 0xFFFF) // activity hint
	binary.LittleEndian.PutUint16(b[74:76], uint16(len(body)))
	binary.LittleEndian.PutUint16(b[76:78], 0) // fragment number
	b[78] = 0                                  // auth protocol
	b[79] = 0                                  // serial low
	return append(b, body...)
}

func appendNDRRequest(b, blocks []byte) []byte {
	const argsMax = 16696
	b = binary.LittleEndian.AppendUint32(b, argsMax)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(blocks)))
	b = binary.LittleEndian.AppendUint32(b, argsMax)
	b = binary.LittleEndian.AppendUint32(b, 0)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(blocks)))
	return append(b, blocks...)
}

// readReqBlock builds the IODReadReqHeader block (big-endian, as PNIO
// blocks are).
func readReqBlock(index uint16) []byte {
	var b []byte
	b = append(b, 0x00, 0x09)             // BlockType IODReadReqHeader
	b = append(b, 0x00, 0x00)             // length, filled below
	b = append(b, 0x01, 0x00)             // version 1.0
	b = append(b, 0x00, 0x00)             // seqNumber
	b = append(b, make([]byte, 16)...)    // ARUUID (nil)
	b = append(b, 0x00, 0x00, 0x00, 0x00) // API
	b = append(b, 0x00, 0x00)             // slot
	b = append(b, 0x00, 0x01)             // subslot
	b = append(b, 0x00, 0x00)             // padding
	b = append(b, byte(index>>8), byte(index))
	b = append(b, 0x00, 0x00, 0x10, 0x00) // record data length (4096)
	b = append(b, make([]byte, 16)...)    // target ARUUID (nil)
	b = append(b, make([]byte, 8)...)     // reserved
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)-4))
	return b
}

func parseHeader(b []byte) (header, []byte, error) {
	if len(b) < headerLen {
		return header{}, nil, fmt.Errorf("%d octets is shorter than a DCE/RPC header", len(b))
	}
	if b[0] != rpcVersion {
		return header{}, nil, fmt.Errorf("RPC version %d, want 4", b[0])
	}
	o := order(b[4])
	h := header{typ: b[1], bodyLen: o.Uint16(b[74:76])}
	copy(h.activity[:], b[40:56])
	h.opnum = o.Uint16(b[68:70])
	body := b[headerLen:]
	if int(h.bodyLen) > len(body) {
		return h, nil, fmt.Errorf("body length %d exceeds %d octets", h.bodyLen, len(body))
	}
	return h, body[:h.bodyLen], nil
}

// ---- NDR and I&M0 ----

// ndrBlocks returns the PNIO blocks of a ReadImplicit response NDR body
// (little-endian NDR header, then big-endian blocks).
func ndrBlocks(body []byte) ([]byte, error) {
	// Response NDR header (20 octets): PNIOStatus, ArgsLength,
	// ArgsMaximum, Offset, ActualCount; then the PNIO blocks.
	if len(body) < ndrHeaderLen {
		return nil, fmt.Errorf("short NDR response")
	}
	status := binary.LittleEndian.Uint32(body)
	if status != 0 {
		return nil, fmt.Errorf("PNIO status 0x%08x", status)
	}
	actual := binary.LittleEndian.Uint32(body[16:])
	rest := body[ndrHeaderLen:]
	if int64(actual) > int64(len(rest)) {
		actual = uint32(len(rest))
	}
	return rest[:actual], nil
}

type im0 struct {
	vendorID  uint16
	orderID   string
	serial    string
	hardware  uint16
	software  string
	profileID uint16
}

// findIM0 walks the PNIO blocks (big-endian) and decodes the first I&M0.
func findIM0(blocks []byte) (im0, bool) {
	p := blocks
	for len(p) >= 4 {
		typ := binary.BigEndian.Uint16(p)
		length := int(binary.BigEndian.Uint16(p[2:]))
		if length+4 > len(p) {
			return im0{}, false
		}
		block := p[4 : 4+length]
		if typ == blockIM0 {
			return decodeIM0(block)
		}
		p = p[4+length:]
	}
	return im0{}, false
}

// decodeIM0 decodes an I&M0 block body (after the 4-octet block header,
// starting at the version octets).
func decodeIM0(b []byte) (im0, bool) {
	// version(2) vendorID(2) orderID(20) serial(16) hardware(2)
	// software(4) revisionCounter(2) profileID(2) profileType(2)
	// version major/minor(2) supported(2).
	if len(b) < 2+2+20+16+2+4+2+2 {
		return im0{}, false
	}
	p := b[2:] // skip block version
	m := im0{vendorID: binary.BigEndian.Uint16(p)}
	p = p[2:]
	m.orderID = fpx.Clean(string(p[:20]))
	p = p[20:]
	m.serial = fpx.Clean(string(p[:16]))
	p = p[16:]
	m.hardware = binary.BigEndian.Uint16(p)
	p = p[2:]
	prefix := p[0]
	if prefix < 0x20 {
		prefix = 'V'
	}
	m.software = fmt.Sprintf("%c%d.%d.%d", prefix, p[1], p[2], p[3])
	p = p[4:]
	p = p[2:] // revision counter
	m.profileID = binary.BigEndian.Uint16(p)
	return m, true
}

// ---- UUID ----

type byteOrder struct{ little bool }

func order(drep byte) byteOrder { return byteOrder{little: drep == drepLittle} }

func (o byteOrder) Uint16(b []byte) uint16 {
	if o.little {
		return binary.LittleEndian.Uint16(b)
	}
	return binary.BigEndian.Uint16(b)
}

// encodeUUIDLE encodes a UUID in little-endian DCE representation: the
// first three fields byte-swapped, the rest kept.
func encodeUUIDLE(u uuidT) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:], binary.BigEndian.Uint32(u[0:4]))
	binary.LittleEndian.PutUint16(b[4:], binary.BigEndian.Uint16(u[4:6]))
	binary.LittleEndian.PutUint16(b[6:], binary.BigEndian.Uint16(u[6:8]))
	copy(b[8:], u[8:])
	return b
}

// uuid parses a canonical UUID string (big-endian layout).
func uuid(s string) uuidT {
	var u uuidT
	i := 0
	for j := 0; j < len(s) && i < 16; j++ {
		if s[j] == '-' {
			continue
		}
		hi := fromHex(s[j])
		j++
		u[i] = hi<<4 | fromHex(s[j])
		i++
	}
	return u
}

func fromHex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func rpcTypeName(t byte) string {
	switch t {
	case typeRequest:
		return "request"
	case typePing:
		return "ping"
	case typeResponse:
		return "response"
	case typeFault:
		return "fault"
	case typeNoCall:
		return "nocall"
	case typeReject:
		return "reject"
	}
	return fmt.Sprintf("type %d", t)
}
