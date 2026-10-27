// SPDX-License-Identifier: MIT

// Package opcua fingerprints OPC UA over its binary transport (opc.tcp).
//
// Detection performs the UACP hello handshake: a HEL message carrying the
// endpoint URL opc.tcp://host:port, to which an OPC UA server replies with
// ACK (the negotiated buffer sizes) or, when the URL does not match its
// configured endpoint, with ERR and a UA status code — both identify OPC
// UA, since no other protocol frames a "HELF"/"ACKF"/"ERRF" message.
//
// In identify mode an anonymous secure channel is opened with security
// policy None and GetEndpoints is called, returning the server's
// application description (name, application and product URIs) and the
// security policies on offer. No session is created and nothing is read.
package opcua

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolOPCUA

// Message types and chunk markers.
const (
	msgHELLO = "HEL"
	msgACK   = "ACK"
	msgERR   = "ERR"
	msgOPN   = "OPN"
	msgMSG   = "MSG"
	chunkF   = 'F'

	policyNone = "http://opcfoundation.org/UA/SecurityPolicy#None"

	idGetEndpointsRequest  = 428
	idGetEndpointsResponse = 431
	idOpenChannelResponse  = 449
	idServiceFault         = 397

	maxFrame = 1 << 20
)

// Fingerprinter detects OPC UA binary.
type Fingerprinter struct{}

// New returns an OPC UA fingerprinter.
func New() *Fingerprinter { return &Fingerprinter{} }

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{4840, 4843, 48010, 62541},
		Priority:      55,
		Intrusiveness: core.Passive,
		Description:   "UACP HEL/ACK handshake; OpenSecureChannel (None) and GetEndpoints in identify mode",
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

	endpoint := fmt.Sprintf("opc.tcp://%s:%d", target.Host, target.Port)
	resp, err := s.RoundTrip("hello", hello(endpoint), framer, maxFrame)
	if err != nil {
		if errors.Is(err, wire.ErrClosed) {
			return b.Result("opcua.hel", "connection closed on HEL", s), nil
		}
		return b.Result("opcua.hel", "no OPC UA response", s), err
	}
	typ, chunk, body, perr := parseMessage(resp)
	if perr != nil {
		return b.Result("opcua.hel", "not OPC UA", s), nil
	}
	switch typ {
	case msgACK:
		if len(body) < 20 || chunk != chunkF {
			b.Score(core.ConfidenceHigh, "OPC UA ACK, but malformed body")
			return b.Result("opcua.hel", "OPC UA", s), nil
		}
		b.Score(core.ConfidenceCertain, "UACP hello acknowledged")
		b.Variant("opc.tcp")
		b.Sig("ack", "1")
		b.Sig("recvbuf", fmt.Sprint(binary.LittleEndian.Uint32(body[4:])))
		b.Sig("sendbuf", fmt.Sprint(binary.LittleEndian.Uint32(body[8:])))
		b.Meta("maxMessageSize", fmt.Sprint(binary.LittleEndian.Uint32(body[12:])))
		b.Meta("maxChunkCount", fmt.Sprint(binary.LittleEndian.Uint32(body[16:])))
	case msgERR:
		code, reason := parseError(body)
		b.Score(core.ConfidenceCertain, fmt.Sprintf("UACP ERR 0x%08x (%s): an OPC UA server rejecting the endpoint URL", code, reason))
		b.Variant("opc.tcp")
		b.Sig("err", fmt.Sprintf("0x%08x", code))
		return b.Result("opcua.hel", "OPC UA server (endpoint URL mismatch)", s), nil
	default:
		b.Score(core.ConfidenceHigh, fmt.Sprintf("OPC UA %s message where ACK was expected", typ))
		return b.Result("opcua.hel", "OPC UA", s), nil
	}

	if opts.Mode == core.ModeIdentify {
		f.identify(b, s, endpoint)
	}
	return b.Result("opcua.hel", "OPC UA server", s), nil
}

func (f *Fingerprinter) identify(b *fpx.Builder, s *wire.Session, endpoint string) {
	resp, err := s.RoundTrip("open-channel", openChannel(), framer, maxFrame)
	if err != nil {
		b.Evidence("OpenSecureChannel not answered")
		return
	}
	channelID, tokenID, ok := openChannelResult(resp)
	if !ok {
		b.Evidence("OpenSecureChannel refused")
		return
	}
	b.Evidence("secure channel opened (policy None)")
	resp, err = s.RoundTrip("get-endpoints", getEndpoints(channelID, tokenID, endpoint), framer, maxFrame)
	if err != nil {
		return
	}
	eps, derr := parseEndpoints(resp)
	if derr != nil {
		b.Evidence("GetEndpoints: " + derr.Error())
		return
	}
	id := b.Identity()
	var policies []string
	seen := map[string]bool{}
	for _, e := range eps {
		if e.appName != "" && id.Name == "" {
			id.Name = fpx.Clean(e.appName)
		}
		if e.appURI != "" {
			id.Set("applicationUri", fpx.Clean(e.appURI))
		}
		if e.productURI != "" {
			id.Set("productUri", fpx.Clean(e.productURI))
		}
		if p := shortPolicy(e.policyURI); p != "" && !seen[p] {
			seen[p] = true
			policies = append(policies, p)
		}
	}
	if len(policies) > 0 {
		id.Set("securityPolicies", join(policies))
		b.Sig("policies", join(policies))
	}
	b.Evidence(fmt.Sprintf("GetEndpoints: %d endpoints", len(eps)))
}

// ---- UACP framing ----

func message(typ string, body []byte) []byte {
	b := make([]byte, 8+len(body))
	copy(b, typ)
	b[3] = chunkF
	binary.LittleEndian.PutUint32(b[4:], uint32(len(b)))
	copy(b[8:], body)
	return b
}

func hello(endpoint string) []byte {
	var body []byte
	body = le32(body, 0)       // protocol version
	body = le32(body, 65535)   // receive buffer size
	body = le32(body, 65535)   // send buffer size
	body = le32(body, 1<<20)   // max message size
	body = le32(body, 0)       // max chunk count
	body = str(body, endpoint) // endpoint URL
	return message(msgHELLO, body)
}

var framer = wire.FixedHeader(8, func(h []byte) int {
	switch string(h[:3]) {
	case msgACK, msgERR, msgHELLO, msgOPN, msgMSG:
	default:
		return -1
	}
	if h[3] != chunkF && h[3] != 'C' && h[3] != 'A' {
		return -1
	}
	n := int(binary.LittleEndian.Uint32(h[4:8]))
	if n < 8 || n > maxFrame {
		return -1
	}
	return n
})

func parseMessage(b []byte) (typ string, chunk byte, body []byte, err error) {
	if len(b) < 8 {
		return "", 0, nil, fmt.Errorf("short message")
	}
	switch string(b[:3]) {
	case msgACK, msgERR, msgHELLO, msgOPN, msgMSG:
	default:
		return "", 0, nil, fmt.Errorf("not a UACP message type")
	}
	n := int(binary.LittleEndian.Uint32(b[4:8]))
	if n != len(b) {
		return "", 0, nil, fmt.Errorf("message size %d does not match %d octets", n, len(b))
	}
	return string(b[:3]), b[3], b[8:], nil
}

func parseError(body []byte) (uint32, string) {
	if len(body) < 4 {
		return 0, ""
	}
	code := binary.LittleEndian.Uint32(body)
	reason, _, _ := getString(body[4:])
	return code, reason
}

// ---- encoders ----

func le32(b []byte, v uint32) []byte { return binary.LittleEndian.AppendUint32(b, v) }

func str(b []byte, s string) []byte {
	if s == "" {
		return le32(b, 0xFFFFFFFF)
	}
	b = le32(b, uint32(len(s)))
	return append(b, s...)
}

// fourByteNodeID encodes a numeric node identifier in namespace 0.
func fourByteNodeID(id uint16) []byte { return []byte{0x01, 0x00, byte(id), byte(id >> 8)} }

// requestHeader encodes a minimal RequestHeader with a null authentication
// token and the given timeout.
func requestHeader(handle uint32, timeout uint32) []byte {
	var b []byte
	b = append(b, 0x00, 0x00)                  // authentication token: two-byte null NodeId
	b = binary.LittleEndian.AppendUint64(b, 0) // timestamp
	b = le32(b, handle)                        // request handle
	b = le32(b, 0)                             // return diagnostics
	b = str(b, "")                             // audit entry id
	b = le32(b, timeout)                       // timeout hint
	b = append(b, 0x00, 0x00, 0x00)            // additional header: null NodeId + encoding 0
	return b
}

// openChannel builds an OPN message requesting an anonymous channel with
// security policy None.
func openChannel() []byte {
	var sb []byte
	sb = le32(sb, 0)         // secure channel id
	sb = str(sb, policyNone) // security policy URI
	sb = str(sb, "")         // sender certificate (null)
	sb = str(sb, "")         // receiver certificate thumbprint (null)
	sb = le32(sb, 1)         // sequence number
	sb = le32(sb, 1)         // request id

	sb = append(sb, fourByteNodeID(446)...) // OpenSecureChannelRequest
	sb = append(sb, requestHeader(1, 10000)...)
	sb = le32(sb, 0) // client protocol version
	sb = le32(sb, 0) // request type: Issue
	sb = le32(sb, 1) // security mode: None
	sb = str(sb, "") // client nonce (null)
	sb = le32(sb, 3600000)
	return message(msgOPN, sb)
}

// getEndpoints builds a GetEndpoints request on an open channel.
func getEndpoints(channelID, tokenID uint32, endpoint string) []byte {
	var sb []byte
	sb = le32(sb, channelID)
	sb = le32(sb, tokenID)
	sb = le32(sb, 2) // sequence number
	sb = le32(sb, 2) // request id

	sb = append(sb, fourByteNodeID(idGetEndpointsRequest)...)
	sb = append(sb, requestHeader(2, 10000)...)
	sb = str(sb, endpoint) // endpoint URL
	sb = le32(sb, 0)       // locale ids: array length 0
	sb = le32(sb, 0)       // profile uris: array length 0
	return message(msgMSG, sb)
}

func stripSecurityHeader(typ string, body []byte) ([]byte, bool) {
	// OPN: SecureChannelId u32 + security policy string + sender cert +
	// receiver thumbprint + sequence header (8). MSG: channel + token +
	// sequence header (8).
	switch typ {
	case msgOPN:
		p := body
		if len(p) < 4 {
			return nil, false
		}
		p = p[4:]
		for i := 0; i < 3; i++ {
			_, rest, ok := getBytes(p)
			if !ok {
				return nil, false
			}
			p = rest
		}
		if len(p) < 8 {
			return nil, false
		}
		return p[8:], true
	case msgMSG:
		if len(body) < 16 {
			return nil, false
		}
		return body[16:], true
	}
	return nil, false
}

// serviceID returns the numeric node id of the service response in b (after
// the security and sequence headers).
func serviceID(b []byte) (uint16, []byte, bool) {
	if len(b) < 4 || b[0] != 0x01 {
		return 0, nil, false
	}
	return binary.LittleEndian.Uint16(b[2:4]), b[4:], true
}

func openChannelResult(resp []byte) (channelID, tokenID uint32, ok bool) {
	typ, _, body, err := parseMessage(resp)
	if err != nil || typ != msgOPN {
		return 0, 0, false
	}
	payload, ok := stripSecurityHeader(typ, body)
	if !ok {
		return 0, 0, false
	}
	id, rest, ok := serviceID(payload)
	if !ok || id != idOpenChannelResponse {
		return 0, 0, false
	}
	// ResponseHeader: timestamp(8) requestHandle(4) serviceResult(4)
	// serviceDiagnostics(1 mask) stringTable(array len 4) additionalHeader(3).
	p := skipResponseHeader(rest)
	if p == nil || len(p) < 4 {
		return 0, 0, false
	}
	p = p[4:] // ServerProtocolVersion
	// SecurityToken: ChannelId u32, TokenId u32, ...
	if len(p) < 8 {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint32(p), binary.LittleEndian.Uint32(p[4:]), true
}

func skipResponseHeader(b []byte) []byte {
	if len(b) < 8+4+4+1 {
		return nil
	}
	p := b[8+4+4:]
	// service diagnostics: info mask byte (0 means nothing follows).
	if p[0] != 0 {
		return nil // diagnostics present: too complex to skip safely
	}
	p = p[1:]
	// string table: array of strings.
	if len(p) < 4 {
		return nil
	}
	n := int32(binary.LittleEndian.Uint32(p))
	p = p[4:]
	if n > 0 {
		for i := int32(0); i < n; i++ {
			_, rest, ok := getBytes(p)
			if !ok {
				return nil
			}
			p = rest
		}
	}
	// additional header: NodeId(2 null) + encoding(1).
	if len(p) < 3 {
		return nil
	}
	return p[3:]
}

type endpoint struct {
	appURI, productURI, appName, policyURI string
}

func parseEndpoints(resp []byte) ([]endpoint, error) {
	typ, _, body, err := parseMessage(resp)
	if err != nil {
		return nil, err
	}
	payload, ok := stripSecurityHeader(typ, body)
	if !ok {
		return nil, fmt.Errorf("short frame")
	}
	id, rest, ok := serviceID(payload)
	if !ok {
		return nil, fmt.Errorf("no service id")
	}
	if id == idServiceFault {
		return nil, fmt.Errorf("service fault")
	}
	if id != idGetEndpointsResponse {
		return nil, fmt.Errorf("unexpected service 0x%04x", id)
	}
	p := skipResponseHeader(rest)
	if p == nil {
		return nil, fmt.Errorf("response header not decodable")
	}
	if len(p) < 4 {
		return nil, fmt.Errorf("no endpoint array")
	}
	n := int32(binary.LittleEndian.Uint32(p))
	p = p[4:]
	if n < 0 || n > 64 {
		return nil, fmt.Errorf("endpoint count %d", n)
	}
	var out []endpoint
	for i := int32(0); i < n; i++ {
		var e endpoint
		if p, e, ok = decodeEndpoint(p); !ok {
			if len(out) > 0 {
				break
			}
			return nil, fmt.Errorf("endpoint %d truncated", i)
		}
		out = append(out, e)
	}
	return out, nil
}

// decodeEndpoint decodes one EndpointDescription, keeping the fields of
// interest.
func decodeEndpoint(p []byte) ([]byte, endpoint, bool) {
	var e endpoint
	var ok bool
	if _, p, ok = getBytes(p); !ok { // endpointUrl
		return nil, e, false
	}
	// ApplicationDescription: applicationUri, productUri, applicationName
	// (LocalizedText), applicationType(enum), gatewayServerUri,
	// discoveryProfileUri, discoveryUrls(array).
	if e.appURI, p, ok = getString(p); !ok {
		return nil, e, false
	}
	if e.productURI, p, ok = getString(p); !ok {
		return nil, e, false
	}
	if e.appName, p, ok = getLocalizedText(p); !ok {
		return nil, e, false
	}
	if len(p) < 4 {
		return nil, e, false
	}
	p = p[4:]                         // application type
	if _, p, ok = getString(p); !ok { // gateway server uri
		return nil, e, false
	}
	if _, p, ok = getString(p); !ok { // discovery profile uri
		return nil, e, false
	}
	if p, ok = skipStringArray(p); !ok { // discovery urls
		return nil, e, false
	}
	// serverCertificate(ByteString), securityMode(enum),
	// securityPolicyUri(String).
	if _, p, ok = getBytes(p); !ok {
		return nil, e, false
	}
	if len(p) < 4 {
		return nil, e, false
	}
	p = p[4:] // security mode
	if e.policyURI, p, ok = getString(p); !ok {
		return nil, e, false
	}
	// userIdentityTokens(array of struct), transportProfileUri(String),
	// securityLevel(byte). We only need to walk past them to the next
	// endpoint, but the token struct is variable; stop decoding further
	// fields of this endpoint and resynchronise is not possible, so skip
	// them precisely.
	if p, ok = skipUserTokenPolicies(p); !ok {
		return nil, e, false
	}
	if _, p, ok = getString(p); !ok { // transport profile uri
		return nil, e, false
	}
	if len(p) < 1 {
		return nil, e, false
	}
	p = p[1:] // security level
	return p, e, true
}

func skipUserTokenPolicies(p []byte) ([]byte, bool) {
	if len(p) < 4 {
		return nil, false
	}
	n := int32(binary.LittleEndian.Uint32(p))
	p = p[4:]
	if n < 0 {
		return p, true
	}
	for i := int32(0); i < n; i++ {
		// policyId(String), tokenType(enum), issuedTokenType(String),
		// issuerEndpointUrl(String), securityPolicyUri(String).
		var ok bool
		if _, p, ok = getString(p); !ok {
			return nil, false
		}
		if len(p) < 4 {
			return nil, false
		}
		p = p[4:]
		for j := 0; j < 3; j++ {
			if _, p, ok = getString(p); !ok {
				return nil, false
			}
		}
	}
	return p, true
}

func skipStringArray(p []byte) ([]byte, bool) {
	if len(p) < 4 {
		return nil, false
	}
	n := int32(binary.LittleEndian.Uint32(p))
	p = p[4:]
	if n < 0 {
		return p, true
	}
	for i := int32(0); i < n; i++ {
		var ok bool
		if _, p, ok = getBytes(p); !ok {
			return nil, false
		}
	}
	return p, true
}

func getBytes(p []byte) ([]byte, []byte, bool) {
	if len(p) < 4 {
		return nil, nil, false
	}
	n := int32(binary.LittleEndian.Uint32(p))
	p = p[4:]
	if n < 0 { // null
		return nil, p, true
	}
	if int(n) > len(p) {
		return nil, nil, false
	}
	return p[:n], p[n:], true
}

func getString(p []byte) (string, []byte, bool) {
	v, rest, ok := getBytes(p)
	return string(v), rest, ok
}

// getLocalizedText decodes a LocalizedText and returns its text.
func getLocalizedText(p []byte) (string, []byte, bool) {
	if len(p) < 1 {
		return "", nil, false
	}
	mask := p[0]
	p = p[1:]
	var ok bool
	if mask&0x01 != 0 { // locale
		if _, p, ok = getString(p); !ok {
			return "", nil, false
		}
	}
	if mask&0x02 != 0 { // text
		var text string
		if text, p, ok = getString(p); !ok {
			return "", nil, false
		}
		return text, p, true
	}
	return "", p, true
}

func shortPolicy(uri string) string {
	if i := lastHash(uri); i >= 0 {
		return uri[i+1:]
	}
	return uri
}

func lastHash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '#' {
			return i
		}
	}
	return -1
}

func join(v []string) string {
	s := ""
	for i, x := range v {
		if i > 0 {
			s += ","
		}
		s += x
	}
	return s
}
