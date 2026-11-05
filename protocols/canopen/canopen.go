// SPDX-License-Identifier: MIT

// Package canopen fingerprints CANopen gateways that expose a CANopen
// network through the CiA 309-3 ASCII command interface over TCP, such as
// CANopenNode's canopend ("-c tcp-<port>") and CANopen-Ethernet gateways.
//
// CiA 309-3 commands are text lines "[<sequence>] [[<net>] <node>]
// <command>" answered by "[<sequence>] OK", "[<sequence>] <value>" or
// "[<sequence>] ERROR:<code>", where the code is a gateway error (100..999)
// or a 32-bit SDO abort code (0xhhhhhhhh).
//
// Detection sends the gateway management service "info version" (Get
// version) with a random sequence number. The gateway answers it itself,
// without any CAN traffic: with its version record (vendor-ID, product
// code, revision, serial number, gateway class, protocol version,
// implementation class), or with "ERROR:100" (request not supported) as
// CANopenNode does. Only a strict 309-3 response line that echoes the
// sequence number is accepted; banners of HTTP, SSH, SMTP and other text
// services, echoes of the probe and binary data are rejected.
//
// Identify mode, when the scan allows read-only probes, additionally reads
// the identity of one CANopen node through the gateway's SDO client: the
// device type (0x1000), the manufacturer device name (0x1008), the software
// version (0x100A) and the identity object (0x1018 sub 1..4). These are SDO
// uploads on the CAN bus. They go to the gateway's default node, or to the
// node named in Config.Node. Nothing is ever written.
package canopen

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolCANopen

const (
	// maxLine bounds one response line, terminator included.
	maxLine = 256
	// maxLines bounds the lines read for one command: responses to
	// commands an earlier client left in the gateway's buffer may precede
	// ours.
	maxLines = 6
	// maxString bounds a decoded visible string.
	maxString = 64
	// maxNode is the highest CANopen node-ID.
	maxNode = 127
)

// Config configures the fingerprinter.
type Config struct {
	// Node is the CANopen node-ID (1..127) whose identity identify mode
	// reads through the gateway. Zero, or a value out of range, uses the
	// gateway's default node ("set node"), which a gateway may not have:
	// identify then reports the gateway only.
	Node int
}

// Fingerprinter detects CiA 309-3 CANopen gateways.
type Fingerprinter struct {
	node int
}

// New returns a CANopen gateway fingerprinter.
func New() *Fingerprinter { return NewWithConfig(Config{}) }

// NewWithConfig returns a fingerprinter with the given configuration.
func NewWithConfig(c Config) *Fingerprinter {
	n := c.Node
	if n < 1 || n > maxNode {
		n = 0
	}
	return &Fingerprinter{node: n}
}

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{60000},
		Priority:      145,
		Intrusiveness: core.Passive,
		Description:   "CiA 309-3 \"info version\" with a random sequence number; identify reads 0x1000/0x1008/0x100A/0x1018 by SDO when read-only probes are allowed",
	}
}

// kind is the form of a response.
type kind uint8

const (
	kindOK kind = iota + 1
	kindError
	kindValue
)

// response is one parsed CiA 309-3 response line.
type response struct {
	seq   uint32
	kind  kind
	code  string // ERROR code as sent: "100" or "0x05040000"
	value string // the value, for kindValue
}

// lineFramer completes a line at LF; a line longer than maxLine is not a
// 309-3 response.
func lineFramer(b []byte) int {
	for i, c := range b {
		if c == '\n' {
			return i + 1
		}
	}
	if len(b) >= maxLine {
		return -1
	}
	return 0
}

// newSeq returns a random-looking sequence number in 1000..2^31-1 (CANopenNode
// prints the sequence as a signed 32-bit integer).
func newSeq() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	v := binary.BigEndian.Uint32(b[:]) & 0x7FFFFFFF
	if v < 1000 {
		v += 1000
	}
	return v
}

// errNotGateway marks a line that is not a CiA 309-3 response.
var errNotGateway = errors.New("not a CiA 309-3 response")

// exchange sends cmd with sequence seq and returns the response that echoes
// seq, skipping empty lines and well-formed responses to other sequence
// numbers (left over from an earlier client). It returns errNotGateway for
// anything else, and the read error for a transport failure; stale reports
// how many foreign responses were skipped.
func exchange(s *wire.Session, label string, cmd []byte, seq uint32) (resp response, stale int, err error) {
	for i := range maxLines {
		var line []byte
		if i == 0 {
			line, err = s.RoundTrip(label, cmd, lineFramer, maxLine)
		} else {
			line, err = s.Next(label, lineFramer, maxLine)
		}
		if err != nil {
			return response{}, stale, err
		}
		body, ok := trimLine(line)
		if !ok {
			return response{}, stale, errNotGateway
		}
		if len(body) == 0 {
			continue // the answer to an empty line
		}
		r, ok := parseResponse(body)
		if !ok {
			return response{}, stale, errNotGateway
		}
		if r.seq != seq {
			stale++
			continue
		}
		return r, stale, nil
	}
	return response{}, stale, errNotGateway
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	s, err := wire.Dial(ctx, proto, target, opts)
	if err != nil {
		return core.NoMatch(proto), err
	}
	defer s.Close() //nolint:errcheck

	seq := newSeq()
	// The leading LF terminates a partial command an earlier client may
	// have left in the gateway's buffer, so that ours is parsed on its own.
	probe := []byte("\n[" + strconv.FormatUint(uint64(seq), 10) + "] info version\r\n")
	r, stale, err := exchange(s, "info-version", probe, seq)
	if stale > 0 {
		b.Evidence(fmt.Sprintf("%d CiA 309-3 response(s) to an earlier client's commands", stale))
	}
	if err != nil {
		if stale > 0 {
			// Well-formed 309-3 lines, but none for us: a hint only.
			b.Score(core.ConfidenceLow, "CiA 309-3 response lines, but our sequence number was not echoed")
		} else if wire.IsTransport(err) {
			return b.Result("canopen.309-3", "no response", s), err
		}
		return b.Result("canopen.309-3", "not a CANopen gateway", s), nil
	}

	switch r.kind {
	case kindError:
		b.Score(core.ConfidenceHigh, "CiA 309-3 ERROR:"+r.code+" echoing sequence number "+strconv.FormatUint(uint64(seq), 10))
		b.Sig("info", "ERROR:"+r.code)
	case kindOK:
		b.Score(core.ConfidenceHigh, "CiA 309-3 OK echoing sequence number "+strconv.FormatUint(uint64(seq), 10))
		b.Sig("info", "OK")
	case kindValue:
		v, ok := parseVersion(r.value)
		if !ok {
			b.Evidence("response echoes the sequence number but is not a 309-3 version record")
			return b.Result("canopen.309-3", "not a CANopen gateway", s), nil
		}
		b.Score(core.ConfidenceCertain, "CiA 309-3 version record echoing sequence number "+strconv.FormatUint(uint64(seq), 10))
		b.Sig("vendor", hex32(v[0]))
		b.Sig("product", hex32(v[1]))
		b.Sig("revision", hex32(v[2]))
		if opts.Mode == core.ModeIdentify {
			id := b.Identity()
			id.VendorID = hex32(v[0])
			id.Serial = hex32(v[3])
			id.Version = hex32(v[2])
			id.Set("gatewayProductCode", hex32(v[1]))
			id.Set("gatewayClass", strconv.FormatUint(uint64(v[4]), 10))
			id.Set("protocolVersion", strconv.FormatUint(uint64(v[5]), 10))
			id.Set("implementationClass", strconv.FormatUint(uint64(v[6]), 10))
		}
	}

	if opts.Mode == core.ModeIdentify {
		if opts.MaxIntrusiveness >= core.ReadOnly {
			f.identify(s, b, seq)
		} else {
			b.Evidence("node identity not read: SDO uploads need read-only probes")
		}
	}
	return b.Result("canopen.309-3", "CANopen CiA 309-3 gateway", s), nil
}

// object is one identity entry read by SDO upload.
type object struct {
	index    uint16
	sub      uint8
	datatype string // "u32" or "vs"
	key      string
}

// identityObjects are read in this order; the first one decides whether a
// node answers at all.
var identityObjects = []object{
	{0x1018, 1, "u32", "vendorId"},
	{0x1018, 2, "u32", "productCode"},
	{0x1018, 3, "u32", "revision"},
	{0x1018, 4, "u32", "serial"},
	{0x1000, 0, "u32", "deviceType"},
	{0x1008, 0, "vs", "deviceName"},
	{0x100A, 0, "vs", "softwareVersion"},
}

// identify reads the node's identity through the gateway's SDO client.
func (f *Fingerprinter) identify(s *wire.Session, b *fpx.Builder, seq uint32) {
	node, nodeAttr, nodeName := "", "default", "default node"
	if f.node > 0 {
		node = strconv.Itoa(f.node) + " "
		nodeAttr = strconv.Itoa(f.node)
		nodeName = "node " + nodeAttr
	}
	id := b.Identity()
	read := 0
	for i, o := range identityObjects {
		seq = nextSeq(seq)
		cmd := fmt.Sprintf("[%d] %sr 0x%04X %d %s\r\n", seq, node, o.index, o.sub, o.datatype)
		r, _, err := exchange(s, "sdo-upload-"+o.key, []byte(cmd), seq)
		if err != nil {
			b.Evidence("identity read stopped: no 309-3 response to the SDO upload of " + o.key)
			break
		}
		if r.kind == kindError {
			if gatewayError(r.code) {
				// 1xx: the request itself was refused (no default node,
				// unsupported node or net): no later read can succeed.
				b.Evidence(nodeName + " identity not read: gateway ERROR:" + r.code)
				break
			}
			if i == 0 {
				b.Evidence(nodeName + " identity not read: SDO abort " + r.code)
				break
			}
			continue // the object is optional
		}
		if r.kind != kindValue {
			continue
		}
		if o.datatype == "vs" {
			str, ok := parseVisibleString(r.value)
			if !ok {
				continue
			}
			read++
			if o.key == "deviceName" {
				id.Product = str
			} else {
				id.Version = str
			}
			continue
		}
		v, ok := parseU32(r.value)
		if !ok {
			continue
		}
		read++
		switch o.key {
		case "vendorId":
			id.VendorID = hex32(v)
		case "serial":
			id.Serial = hex32(v)
		case "deviceType":
			id.Set("deviceType", hex32(v))
			if p := v & 0xFFFF; p != 0 {
				id.Set("profile", "CiA "+strconv.FormatUint(uint64(p), 10))
			}
		default:
			id.Set(o.key, hex32(v))
		}
	}
	if read > 0 {
		id.Set("node", nodeAttr)
		b.Evidence(fmt.Sprintf("read %d identity object(s) of the %s by SDO upload", read, nodeName))
	}
}

// nextSeq returns the sequence number after seq, staying in 1..2^31-1.
func nextSeq(seq uint32) uint32 {
	if seq >= math.MaxInt32 {
		return 1000
	}
	return seq + 1
}

// gatewayError reports whether code is a gateway error (decimal) rather
// than an SDO abort code (hexadecimal).
func gatewayError(code string) bool { return !strings.HasPrefix(code, "0x") }

// trimLine strips the LF (and an optional CR) of a response line and
// checks that the rest is printable ASCII.
func trimLine(line []byte) ([]byte, bool) {
	n := len(line)
	if n == 0 || line[n-1] != '\n' {
		return nil, false // incomplete or oversized
	}
	line = line[:n-1]
	if m := len(line); m > 0 && line[m-1] == '\r' {
		line = line[:m-1]
	}
	for _, c := range line {
		if (c < 0x20 && c != '\t') || c > 0x7E {
			return nil, false
		}
	}
	return line, true
}

// parseResponse parses "[<seq>] OK", "[<seq>] ERROR:<code>[ #<text>]" or
// "[<seq>] <value>".
func parseResponse(line []byte) (response, bool) {
	s := string(line)
	if len(s) < 4 || s[0] != '[' {
		return response{}, false
	}
	end := strings.IndexByte(s, ']')
	if end < 2 || end > 11 {
		return response{}, false
	}
	seq, ok := parseDecimal(s[1:end])
	if !ok {
		return response{}, false
	}
	rest := s[end+1:]
	if rest == "" || (rest[0] != ' ' && rest[0] != '\t') {
		return response{}, false
	}
	rest = strings.TrimSpace(rest)
	if rest == "" {
		return response{}, false
	}
	switch {
	case rest == "OK":
		return response{seq: seq, kind: kindOK}, true
	case strings.HasPrefix(rest, "ERROR:"):
		code, ok := parseErrorCode(rest[len("ERROR:"):])
		if !ok {
			return response{}, false
		}
		return response{seq: seq, kind: kindError, code: code}, true
	}
	return response{seq: seq, kind: kindValue, value: rest}, true
}

// parseErrorCode validates "<code>[ #<text>]": a three-digit gateway error
// (100..999) or an eight-digit hexadecimal SDO abort code.
func parseErrorCode(s string) (string, bool) {
	code := s
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		code = s[:i]
		if c := strings.TrimSpace(s[i:]); c != "" && c[0] != '#' {
			return "", false
		}
	}
	switch {
	case len(code) == 3:
		v, ok := parseDecimal(code)
		if !ok || v < 100 {
			return "", false
		}
		return code, true
	case len(code) == 10 && (code[:2] == "0x" || code[:2] == "0X"):
		v, err := strconv.ParseUint(code[2:], 16, 32)
		if err != nil || v > math.MaxUint32 {
			return "", false
		}
		return hex32(uint32(v)), true
	}
	return "", false
}

// parseDecimal parses 1..10 ASCII digits into a uint32.
func parseDecimal(s string) (uint32, bool) {
	n := len(s)
	if n == 0 || n > 10 {
		return 0, false
	}
	for i := range n {
		if s[i] < '0' || s[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 10, 32)
	if err != nil || v > math.MaxUint32 {
		return 0, false
	}
	return uint32(v), true
}

// parseNumber parses a decimal or 0x-prefixed hexadecimal UNSIGNED32.
func parseNumber(s string) (uint32, bool) {
	if len(s) > 2 && (s[:2] == "0x" || s[:2] == "0X") {
		h := s[2:]
		if len(h) > 8 {
			return 0, false
		}
		for i := range len(h) {
			if !isHex(h[i]) {
				return 0, false
			}
		}
		v, err := strconv.ParseUint(h, 16, 32)
		if err != nil || v > math.MaxUint32 {
			return 0, false
		}
		return uint32(v), true
	}
	return parseDecimal(s)
}

// parseU32 parses an SDO-uploaded UNSIGNED32 as CANopenNode prints it:
// decimal ("u32"), 0x-hexadecimal ("x32"), or, when the object's size is
// not four octets, its octets as space-separated hexadecimal pairs in
// transfer (little-endian) order.
func parseU32(s string) (uint32, bool) {
	if v, ok := parseNumber(s); ok {
		return v, true
	}
	fields := strings.Fields(s)
	n := len(fields)
	if n == 0 || n > 4 {
		return 0, false
	}
	var v, shift uint32
	for _, f := range fields {
		if len(f) != 2 || !isHex(f[0]) || !isHex(f[1]) {
			return 0, false
		}
		octet := (hexVal(f[0])<<4 | hexVal(f[1])) & 0xFF
		v |= octet << shift
		shift += 8
	}
	return v, true
}

// parseVersion parses the "info version" record: vendor-ID, product code,
// revision number, serial number, gateway class, protocol version and
// implementation class.
func parseVersion(s string) ([7]uint32, bool) {
	var out [7]uint32
	fields := strings.Fields(s)
	if len(fields) != len(out) {
		return out, false
	}
	for i, f := range fields {
		v, ok := parseNumber(f)
		if !ok {
			return out, false
		}
		out[i] = v
	}
	return out, true
}

// parseVisibleString decodes a quoted 309-3 visible string ("" escapes a
// quote) and sanitises it; an unquoted single word is accepted as is.
func parseVisibleString(s string) (string, bool) {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = strings.ReplaceAll(s[1:len(s)-1], `""`, `"`)
	} else if strings.ContainsAny(s, "\" \t") {
		return "", false
	}
	s = fpx.Clean(s)
	if len(s) > maxString {
		s = s[:maxString]
	}
	return s, s != ""
}

func hex32(v uint32) string { return fmt.Sprintf("0x%08X", v) }

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) uint32 {
	switch {
	case c >= '0' && c <= '9':
		return uint32(c - '0')
	case c >= 'a' && c <= 'f':
		return uint32(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return uint32(c-'A') + 10
	}
	return 0
}
