// SPDX-License-Identifier: MIT

// Package knx fingerprints KNXnet/IP (KNX Standard 03.08.02 Core and
// 03.08.03 Device Management) over UDP and TCP.
//
// Detection sends one DESCRIPTION_REQUEST (0x0203) to the control endpoint.
// Its HPAI is the "route back" address 0.0.0.0:0, which tells the server to
// answer the address the request came from, so the answer survives NAT; over
// UDP a second request with the HPAI of the local socket follows when the
// first draws nothing (servers that do not implement route back, reached
// without NAT). Over TCP route back is the only form the standard allows.
//
// Only a strict DESCRIPTION_RESPONSE (0x0204) matches: header length 6,
// protocol version 0x10, a total length equal to the datagram or frame, a
// DEVICE_INFO DIB of 54 octets, a SUPP_SVC_FAMILIES DIB of family/version
// pairs, and further DIBs that exactly fill the body. An echo of the request
// is a DESCRIPTION_REQUEST, not a response, and does not match.
//
// The response carries the full identity, so detect and identify modes send
// the same request: KNX medium, individual address, project/installation
// ID, serial number, routing multicast address, MAC address, friendly name,
// the supported service families and their versions, KNXnet/IP Secure and
// Tunnelling v2 presence. Nothing that opens a connection or changes state
// (CONNECT_REQUEST, tunnelling, group writes) is ever sent.
package knx

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolKNX

// Header and service constants (03.08.02 §2, §7).
const (
	headerLen  = 0x06
	version10  = 0x10
	maxFrame   = 4096
	hpaiLen    = 0x08
	hostUDP    = 0x01
	hostTCP    = 0x02
	svcDescReq = 0x0203
	svcDescRes = 0x0204
)

// DIB types.
const (
	dibDeviceInfo   = 0x01
	dibSuppSvc      = 0x02
	dibIPConfig     = 0x03
	dibIPCurConfig  = 0x04
	dibKNXAddresses = 0x05
	dibSecuredSvc   = 0x06
	dibTunnelInfo   = 0x07
	dibExtDevInfo   = 0x08
	dibMfrData      = 0xFE

	deviceInfoLen = 0x36
)

// Service family identifiers.
const (
	famCore       = 0x02
	famDevMgmt    = 0x03
	famTunnelling = 0x04
	famRouting    = 0x05
	famRemoteLog  = 0x06
	famRemoteConf = 0x07
	famObjServer  = 0x08
	famSecurity   = 0x09
)

// Fingerprinter detects KNXnet/IP.
type Fingerprinter struct {
	network core.Network
}

// New returns a KNXnet/IP fingerprinter over UDP, the transport every
// KNXnet/IP server implements.
func New() *Fingerprinter { return &Fingerprinter{network: core.UDP} }

// NewTCP returns a KNXnet/IP fingerprinter over TCP, which KNXnet/IP
// Secure and Core v2 servers offer beside UDP.
func NewTCP() *Fingerprinter { return &Fingerprinter{network: core.TCP} }

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       f.network,
		Ports:         []int{3671},
		Priority:      90,
		Intrusiveness: core.Passive,
		Description:   "KNXnet/IP DESCRIPTION_REQUEST (0x0203) with a route-back HPAI; device information and service families from the DESCRIPTION_RESPONSE",
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

	var resp []byte
	if f.network == core.UDP {
		resp, err = s.RoundTripDatagram("description-routeback", descriptionRequest(hostUDP, nil, 0), maxFrame, answers)
		var te *core.TimeoutError
		if errors.As(err, &te) && ctx.Err() == nil {
			if ip, port, ok := localHPAI(s.Conn().LocalAddr()); ok {
				var err2 error
				resp, err2 = s.RoundTripDatagram("description", descriptionRequest(hostUDP, ip, port), maxFrame, answers)
				if err2 == nil {
					err = nil
					b.Evidence("answered the HPAI of the local socket, not route back")
				}
			}
		}
	} else {
		resp, err = s.RoundTrip("description-routeback", descriptionRequest(hostTCP, nil, 0), framer, maxFrame)
	}
	if err != nil {
		if errors.Is(err, wire.ErrClosed) {
			return b.Result("knx.description", "connection closed", s), nil
		}
		return b.Result("knx.description", "no KNXnet/IP response", s), err
	}
	d, perr := parse(resp)
	if perr != nil {
		if errors.Is(perr, errEcho) {
			b.Evidence("the request was echoed: not a KNXnet/IP server")
		} else if errors.Is(perr, errHint) {
			b.Score(core.ConfidenceLow, perr.Error())
		}
		return b.Result("knx.description", "not KNXnet/IP", s), nil
	}
	f.judge(b, d)
	return b.Result("knx.description", "KNXnet/IP device", s), nil
}

// judge scores a decoded DESCRIPTION_RESPONSE and fills the identity.
func (f *Fingerprinter) judge(b *fpx.Builder, d description) {
	if d.family(famCore) > 0 {
		b.Score(core.ConfidenceCertain, fmt.Sprintf("DESCRIPTION_RESPONSE with device information and service families (%s)", d.familyList()))
	} else {
		b.Score(core.ConfidenceHigh, "DESCRIPTION_RESPONSE with device information, but the core service family is not listed")
	}
	b.Sig("svc", "description")
	b.Sig("medium", mediumName(d.medium))
	b.Sig("families", d.familySig())

	id := b.Identity()
	id.Name = d.name
	if d.serial != [6]byte{} {
		id.Serial = fmt.Sprintf("%02X%02X:%02X%02X%02X%02X", d.serial[0], d.serial[1], d.serial[2], d.serial[3], d.serial[4], d.serial[5])
	}
	if d.mfr != 0 {
		id.VendorID = fmt.Sprint(d.mfr)
	} else if mfr := binary.BigEndian.Uint16(d.serial[:2]); mfr != 0 {
		id.VendorID = fmt.Sprint(mfr)
	}
	addr := individual(d.address)
	id.Set("medium", mediumName(d.medium))
	id.Set("individualAddress", addr)
	if d.project != 0 {
		id.Set("projectInstallationId", fmt.Sprintf("%d.%d", d.project>>4, d.project&0x0F))
	}
	if d.multicast != [4]byte{} {
		id.Set("multicastAddress", net.IP(d.multicast[:]).String())
	}
	if d.mac != [6]byte{} {
		id.Set("mac", net.HardwareAddr(d.mac[:]).String())
	}
	if d.status&0x01 != 0 {
		id.Set("programmingMode", "on")
	}
	id.Set("serviceFamilies", d.familyList())
	if len(d.secured) > 0 {
		id.Set("securedServiceFamilies", familyList(d.secured))
	}
	if d.secure() {
		id.Set("secure", "true")
	}
	if d.family(famTunnelling) >= 2 {
		id.Set("tunnellingV2", "true")
	}
	if len(d.addresses) > 0 {
		id.Set("additionalAddresses", strings.Join(d.addresses, ","))
	}
	if d.tunnelSlots > 0 {
		id.Set("tunnellingSlots", fmt.Sprint(d.tunnelSlots))
	}
	if d.mask != 0 {
		id.Set("maskVersion", fmt.Sprintf("0x%04X", d.mask))
	}
	if d.maxAPDU != 0 {
		id.Set("maxApduLength", fmt.Sprint(d.maxAPDU))
	}
	if d.ipAddress != "" {
		id.Set("ipAddress", d.ipAddress)
	}
	b.Meta("individualAddress", addr)
	b.Meta("medium", mediumName(d.medium))
	if v := d.variant(); v != "" {
		b.Variant(v)
	}
	b.Evidence(fmt.Sprintf("device %s on %s, friendly name %q", addr, mediumName(d.medium), d.name))
}

// ---- encoders ----

// descriptionRequest builds a DESCRIPTION_REQUEST whose control endpoint
// HPAI is ip:port, or the route-back address 0.0.0.0:0 when ip is nil.
func descriptionRequest(host byte, ip net.IP, port uint16) []byte {
	b := []byte{headerLen, version10, svcDescReq >> 8, svcDescReq & 0xFF, 0, headerLen + hpaiLen,
		hpaiLen, host, 0, 0, 0, 0, 0, 0}
	if v4 := ip.To4(); v4 != nil {
		copy(b[8:12], v4)
	}
	binary.BigEndian.PutUint16(b[12:14], port)
	return b
}

// localHPAI returns the IPv4 address and port of the local UDP socket, for
// an explicit HPAI.
func localHPAI(a net.Addr) (net.IP, uint16, bool) {
	ua, ok := a.(*net.UDPAddr)
	if !ok {
		return nil, 0, false
	}
	v4 := ua.IP.To4()
	p := ua.Port
	if v4 == nil || v4.IsUnspecified() || p <= 0 || p > 0xFFFF {
		return nil, 0, false
	}
	return v4, uint16(p), true
}

// framer frames KNXnet/IP over TCP: a 6-octet header whose last two octets
// are the total length.
var framer = wire.FixedHeader(headerLen, func(h []byte) int {
	if h[0] != headerLen || h[1] != version10 {
		return -1
	}
	n := int(binary.BigEndian.Uint16(h[4:6]))
	if n > maxFrame {
		return -1
	}
	return n
})

// answers keeps every datagram except well-formed KNXnet/IP routing frames
// (ROUTING_INDICATION, ROUTING_LOST_MESSAGE, ROUTING_BUSY: service family
// 0x05), which are bus traffic and never an answer to a request. Anything
// else is judged by parse, including the request's own echo.
func answers(dg []byte) wire.Verdict {
	h, ok := header(dg)
	switch {
	case !ok:
		return wire.Foreign
	case h>>8 == famRouting:
		return wire.Discard
	}
	return wire.Answer
}

// ---- decoders ----

var (
	// errEcho marks our own DESCRIPTION_REQUEST coming back.
	errEcho = errors.New("echo of the DESCRIPTION_REQUEST")
	// errHint marks a KNXnet/IP-shaped frame that is not a valid response.
	errHint = errors.New("KNXnet/IP header")
	// errNot marks bytes that are not KNXnet/IP at all.
	errNot = errors.New("not a KNXnet/IP frame")
)

// header validates the KNXnet/IP header of b and returns its service type.
func header(b []byte) (uint16, bool) {
	n := len(b)
	if n < headerLen || b[0] != headerLen || b[1] != version10 {
		return 0, false
	}
	if int(binary.BigEndian.Uint16(b[4:6])) != n {
		return 0, false
	}
	return binary.BigEndian.Uint16(b[2:4]), true
}

// description is a decoded DESCRIPTION_RESPONSE.
type description struct {
	medium      byte
	status      byte
	address     uint16
	project     uint16
	serial      [6]byte
	multicast   [4]byte
	mac         [6]byte
	name        string
	families    []family
	secured     []family
	addresses   []string
	tunnelSlots int
	mask        uint16
	maxAPDU     uint16
	mfr         uint16
	ipAddress   string
}

type family struct{ id, version byte }

func (d description) family(id byte) byte {
	for _, f := range d.families {
		if f.id == id {
			return f.version
		}
	}
	return 0
}

func (d description) secure() bool { return len(d.secured) > 0 || d.family(famSecurity) > 0 }

func (d description) familyList() string { return familyList(d.families) }

func familyList(fs []family) string {
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, fmt.Sprintf("%s v%d", familyName(f.id), f.version))
	}
	return strings.Join(parts, ", ")
}

func (d description) familySig() string {
	parts := make([]string, 0, len(d.families))
	for _, f := range d.families {
		parts = append(parts, fmt.Sprintf("%02x%d", f.id, f.version))
	}
	return strings.Join(parts, ",")
}

// variant names the server's role: secure, tunnelling (v2) and routing.
func (d description) variant() string {
	var parts []string
	if d.secure() {
		parts = append(parts, "secure")
	}
	switch v := d.family(famTunnelling); {
	case v >= 2:
		parts = append(parts, "tunnelling-v2")
	case v == 1:
		parts = append(parts, "tunnelling")
	}
	if d.family(famRouting) > 0 {
		parts = append(parts, "routing")
	}
	return strings.Join(parts, "+")
}

// parse decodes a DESCRIPTION_RESPONSE strictly.
func parse(b []byte) (description, error) {
	n := len(b)
	if n < headerLen || b[0] != headerLen {
		return description{}, errNot
	}
	if b[1] != version10 {
		return description{}, fmt.Errorf("%w with protocol version 0x%02x", errHint, b[1])
	}
	if total := int(binary.BigEndian.Uint16(b[4:6])); total != n {
		return description{}, fmt.Errorf("%w, but total length %d does not match %d octets", errHint, total, n)
	}
	switch svc := binary.BigEndian.Uint16(b[2:4]); svc {
	case svcDescRes:
	case svcDescReq:
		return description{}, errEcho
	default:
		return description{}, fmt.Errorf("%w, but service 0x%04x is not DESCRIPTION_RESPONSE", errHint, svc)
	}
	d, err := parseDIBs(b[headerLen:])
	if err != nil {
		return d, fmt.Errorf("%w with a DESCRIPTION_RESPONSE service, but %v", errHint, err)
	}
	return d, nil
}

// parseDIBs decodes the DIBs of a description: DEVICE_INFO first, then
// SUPP_SVC_FAMILIES, then optional DIBs that must exactly fill p.
func parseDIBs(p []byte) (description, error) {
	var d description
	for i := 0; len(p) > 0; i++ {
		if len(p) < 2 {
			return d, fmt.Errorf("truncated DIB header")
		}
		l, typ := int(p[0]), p[1]
		if l < 2 {
			return d, fmt.Errorf("DIB length %d", l)
		}
		if l > len(p) {
			return d, fmt.Errorf("DIB 0x%02x length %d overruns %d octets", typ, l, len(p))
		}
		body := p[2:l]
		p = p[l:]
		switch {
		case i == 0 && typ != dibDeviceInfo:
			return d, fmt.Errorf("first DIB is 0x%02x, not DEVICE_INFO", typ)
		case i == 1 && typ != dibSuppSvc:
			return d, fmt.Errorf("second DIB is 0x%02x, not SUPP_SVC_FAMILIES", typ)
		}
		if err := d.dib(i, typ, l, body); err != nil {
			return d, err
		}
	}
	if d.families == nil {
		return d, fmt.Errorf("missing SUPP_SVC_FAMILIES DIB")
	}
	return d, nil
}

// dib decodes one DIB body into d.
func (d *description) dib(i int, typ byte, l int, body []byte) error {
	switch typ {
	case dibDeviceInfo:
		if i != 0 || l != deviceInfoLen {
			return fmt.Errorf("DEVICE_INFO DIB length %d, want %d", l, deviceInfoLen)
		}
		d.medium, d.status = body[0], body[1]
		d.address = binary.BigEndian.Uint16(body[2:4])
		d.project = binary.BigEndian.Uint16(body[4:6])
		copy(d.serial[:], body[6:12])
		copy(d.multicast[:], body[12:16])
		copy(d.mac[:], body[16:22])
		d.name = friendlyName(body[22:52])
	case dibSuppSvc, dibSecuredSvc:
		if typ == dibSuppSvc && d.families != nil {
			return fmt.Errorf("repeated SUPP_SVC_FAMILIES DIB")
		}
		fs, err := families(body)
		if err != nil {
			return err
		}
		if typ == dibSuppSvc {
			d.families = fs
		} else {
			d.secured = fs
		}
	case dibIPConfig, dibIPCurConfig:
		if len(body) >= 4 {
			d.ipAddress = net.IP(body[0:4]).String()
		}
	case dibKNXAddresses:
		for j := 0; j+2 <= len(body) && len(d.addresses) < 16; j += 2 {
			d.addresses = append(d.addresses, individual(binary.BigEndian.Uint16(body[j:])))
		}
	case dibTunnelInfo:
		// max APDU (2), then slots of address (2) + status (2).
		if len(body) >= 2 {
			d.tunnelSlots = (len(body) - 2) / 4
		}
	case dibExtDevInfo:
		// medium status (1), reserved (1), max APDU (2), mask (2).
		if len(body) >= 6 {
			d.maxAPDU = binary.BigEndian.Uint16(body[2:4])
			d.mask = binary.BigEndian.Uint16(body[4:6])
		}
	case dibMfrData:
		if len(body) >= 2 {
			d.mfr = binary.BigEndian.Uint16(body[0:2])
		}
	}
	return nil
}

// families decodes family/version pairs; a family must not repeat.
func families(body []byte) ([]family, error) {
	n := len(body)
	if n%2 != 0 {
		return nil, fmt.Errorf("service family DIB of odd length %d", n+2)
	}
	fs := make([]family, 0, n/2)
	seen := map[byte]bool{}
	for j := 0; j+1 < n; j += 2 {
		id, v := body[j], body[j+1]
		if id == 0 || v == 0 || seen[id] {
			return nil, fmt.Errorf("invalid service family 0x%02x version %d", id, v)
		}
		seen[id] = true
		fs = append(fs, family{id: id, version: v})
	}
	return fs, nil
}

// friendlyName decodes the 30-octet ISO 8859-1 friendly name: up to the
// first NUL, each octet the code point of the same value, with control
// characters (C0 and C1) dropped.
func friendlyName(raw []byte) string {
	var sb strings.Builder
	for _, c := range raw {
		if c == 0 {
			break
		}
		if c < 0x20 || (c >= 0x7F && c <= 0x9F) {
			continue
		}
		sb.WriteRune(rune(c))
	}
	return fpx.Clean(sb.String())
}

// individual formats an individual address as area.line.device.
func individual(a uint16) string {
	return fmt.Sprintf("%d.%d.%d", a>>12, a>>8&0x0F, a&0xFF)
}

func mediumName(m byte) string {
	switch m {
	case 0x02:
		return "TP1"
	case 0x04:
		return "PL110"
	case 0x10:
		return "RF"
	case 0x20:
		return "IP"
	}
	return fmt.Sprintf("0x%02x", m)
}

func familyName(id byte) string {
	switch id {
	case famCore:
		return "core"
	case famDevMgmt:
		return "device-management"
	case famTunnelling:
		return "tunnelling"
	case famRouting:
		return "routing"
	case famRemoteLog:
		return "remote-logging"
	case famRemoteConf:
		return "remote-configuration"
	case famObjServer:
		return "object-server"
	case famSecurity:
		return "security"
	}
	return fmt.Sprintf("0x%02x", id)
}
