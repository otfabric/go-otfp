// SPDX-License-Identifier: MIT

// Package s7 fingerprints Siemens S7comm (S7-300/400/1200/1500, LOGO!,
// soft PLCs and Snap7-based servers) over ISO-on-TCP.
//
// Detection opens COTP with the calling TSAP of a programming device
// (0x0100) and a called TSAP for rack 0 and the CPU slots 2, 1 and 3 in
// turn, then sends S7 Setup Communication. An Ack-Data with the S7 protocol
// identifier 0x32 proves S7comm and gives the negotiated PDU size; a 0x72
// protocol identifier identifies S7comm-plus.
//
// In identify mode the system status lists 0x0011 (module identification:
// order number, hardware and firmware version) and 0x001C (component
// identification: PLC and module names, plant ID, serial number, module
// type) are read. Both are read-only diagnostics that engineering tools and
// HMIs query routinely.
package s7

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/iso"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolS7

// S7 constants.
const (
	protoS7     = 0x32
	protoS7Plus = 0x72

	rosctrJob      = 0x01
	rosctrAck      = 0x02
	rosctrAckData  = 0x03
	rosctrUserData = 0x07

	fnSetupComm = 0xF0

	szlModuleID    = 0x0011
	szlComponentID = 0x001C

	maxFrame = 4096
)

// Config configures the fingerprinter.
type Config struct {
	// CalledTSAPs are tried in order until one is confirmed; nil means
	// 0x0102, 0x0101 and 0x0103 (rack 0, slots 2, 1 and 3).
	CalledTSAPs []uint16
	// CallingTSAP is the local TSAP; zero means 0x0100.
	CallingTSAP uint16
}

// Fingerprinter detects S7comm.
type Fingerprinter struct {
	called  []uint16
	calling uint16
}

// New returns an S7comm fingerprinter.
func New() *Fingerprinter { return NewWithConfig(Config{}) }

// NewWithConfig returns a fingerprinter with the given configuration.
func NewWithConfig(c Config) *Fingerprinter {
	f := &Fingerprinter{called: c.CalledTSAPs, calling: c.CallingTSAP}
	if len(f.called) == 0 {
		f.called = []uint16{0x0102, 0x0101, 0x0103}
	}
	if f.calling == 0 {
		f.calling = 0x0100
	}
	return f
}

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{102},
		Priority:      20,
		Intrusiveness: core.Passive,
		Description:   "TPKT/COTP CR (TSAP 0x0100 to 0x0102/0x0101/0x0103), S7 Setup Communication; SZL 0x0011 and 0x001C in identify mode",
	}
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	var trace []core.Exchange
	finish := func(details string, s *wire.Session) core.Result {
		if s != nil {
			trace = append(trace, s.Exchanges()...)
		}
		return b.Result("s7comm.setup", details, nil).WithExchanges(trace)
	}

	var s *wire.Session
	var tsap uint16
	refused := false
	for _, called := range f.called {
		if ctx.Err() != nil {
			return finish("cancelled", nil), ctx.Err()
		}
		var err error
		s, err = wire.Dial(ctx, proto, target, opts)
		if err != nil {
			return finish("no connection", nil), err
		}
		cc, err := s.RoundTrip(fmt.Sprintf("cotp-cr-%04x", called), iso.ConnectRequest(0x0001, u16(f.calling), u16(called), 0x0a), iso.Framer, maxFrame)
		if err != nil {
			trace = append(trace, s.Exchanges()...)
			_ = s.Close()
			if errors.Is(err, wire.ErrClosed) {
				continue // a refused TSAP, often as a plain close
			}
			return finish("no COTP response", nil), err
		}
		switch iso.TPDUType(cc) {
		case iso.TPDUConnectConfirm:
			if _, err := iso.ParseConfirm(cc); err == nil {
				tsap = called
			}
		case iso.TPDUDisconnectRequest, iso.TPDUError:
			b.Evidence(fmt.Sprintf("COTP refused TSAP 0x%04x", called))
			refused = true
		default:
			trace = append(trace, s.Exchanges()...)
			_ = s.Close()
			return finish("not ISO-on-TCP", nil), nil
		}
		if tsap != 0 {
			break
		}
		trace = append(trace, s.Exchanges()...)
		_ = s.Close()
		s = nil
	}
	if s == nil {
		if refused {
			b.Score(core.ConfidenceLow, "ISO-on-TCP endpoint refusing the S7 TSAPs")
		}
		return finish("no S7 TSAP accepted", nil), nil
	}
	defer s.Close() //nolint:errcheck
	b.Score(core.ConfidenceLow, fmt.Sprintf("COTP connection confirmed for TSAP 0x%04x", tsap))
	b.Meta("tsap", fmt.Sprintf("0x%04x", tsap))

	resp, err := s.RoundTrip("s7-setup", iso.Data(setupComm(1, 480)), iso.Framer, maxFrame)
	if err != nil {
		b.Evidence("no answer to S7 Setup Communication")
		return finish("ISO-on-TCP without S7", s), nil
	}
	pdu, ok := iso.Payload(resp)
	if !ok || len(pdu) == 0 {
		b.Evidence("answer to Setup Communication is not COTP data")
		return finish("ISO-on-TCP without S7", s), nil
	}
	if pdu[0] == protoS7Plus {
		b.Score(core.ConfidenceHigh, "S7comm-plus PDU (protocol 0x72) in answer to Setup Communication")
		b.Variant("S7comm-plus")
		b.Sig("proto", "0x72")
		return finish("Siemens S7comm-plus", s), nil
	}
	setup, err := parseSetupAck(pdu)
	if err != nil {
		if pdu[0] == protoS7 {
			b.Score(core.ConfidenceMedium, "S7 PDU, but "+err.Error())
		}
		return finish("ISO-on-TCP without S7", s), nil
	}
	b.Score(core.ConfidenceCertain, fmt.Sprintf("S7 Setup Communication acknowledged, PDU %d", setup.pdu))
	b.Sig("tsap", fmt.Sprintf("0x%04x", tsap))
	b.Sig("pdu", fmt.Sprint(setup.pdu))
	b.Sig("amq", fmt.Sprintf("%d/%d", setup.amqCalling, setup.amqCalled))
	b.Meta("pduSize", fmt.Sprint(setup.pdu))
	b.Meta("rack", fmt.Sprint(tsap>>5&0x07))
	b.Meta("slot", fmt.Sprint(tsap&0x1F))

	if opts.Mode == core.ModeIdentify {
		f.identify(b, s)
	}
	return finish("Siemens S7comm", s), nil
}

func u16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

// header builds an S7 Job or Userdata header.
func header(rosctr byte, ref uint16, params, data []byte) []byte {
	h := []byte{protoS7, rosctr, 0, 0, byte(ref >> 8), byte(ref), 0, 0, 0, 0}
	binary.BigEndian.PutUint16(h[6:], uint16(len(params)))
	binary.BigEndian.PutUint16(h[8:], uint16(len(data)))
	return append(append(h, params...), data...)
}

func setupComm(ref, pdu uint16) []byte {
	return header(rosctrJob, ref, []byte{fnSetupComm, 0x00, 0x00, 0x01, 0x00, 0x01, byte(pdu >> 8), byte(pdu)}, nil)
}

func szlRead(ref, id, index uint16) []byte {
	params := []byte{0x00, 0x01, 0x12, 0x04, 0x11, 0x44, 0x01, 0x00}
	data := []byte{0xFF, 0x09, 0x00, 0x04, byte(id >> 8), byte(id), byte(index >> 8), byte(index)}
	return header(rosctrUserData, ref, params, data)
}

type setupAck struct {
	pdu, amqCalling, amqCalled uint16
}

// parseSetupAck validates an Ack-Data to Setup Communication.
func parseSetupAck(p []byte) (setupAck, error) {
	if len(p) < 12 || p[0] != protoS7 {
		return setupAck{}, fmt.Errorf("not an S7 PDU")
	}
	if p[1] != rosctrAckData && p[1] != rosctrAck {
		return setupAck{}, fmt.Errorf("ROSCTR 0x%02x is not an acknowledgement", p[1])
	}
	plen := int(binary.BigEndian.Uint16(p[6:]))
	dlen := int(binary.BigEndian.Uint16(p[8:]))
	if 12+plen+dlen != len(p) {
		return setupAck{}, fmt.Errorf("S7 lengths %d+%d do not match %d octets", plen, dlen, len(p))
	}
	if p[10] != 0 || p[11] != 0 {
		return setupAck{}, fmt.Errorf("Setup Communication refused, error 0x%02x%02x", p[10], p[11])
	}
	if plen != 8 || p[12] != fnSetupComm {
		return setupAck{}, fmt.Errorf("not a Setup Communication acknowledgement")
	}
	q := p[12:]
	return setupAck{
		amqCalling: binary.BigEndian.Uint16(q[2:]),
		amqCalled:  binary.BigEndian.Uint16(q[4:]),
		pdu:        binary.BigEndian.Uint16(q[6:]),
	}, nil
}

// parseSZL returns the records of a Userdata SZL-read response.
func parseSZL(p []byte) (id uint16, recLen int, records [][]byte, err error) {
	if len(p) < 10 || p[0] != protoS7 || p[1] != rosctrUserData {
		return 0, 0, nil, fmt.Errorf("not an S7 Userdata PDU")
	}
	plen := int(binary.BigEndian.Uint16(p[6:]))
	dlen := int(binary.BigEndian.Uint16(p[8:]))
	if 10+plen+dlen > len(p) || plen < 8 {
		return 0, 0, nil, fmt.Errorf("S7 lengths overrun the PDU")
	}
	params := p[10 : 10+plen]
	if plen >= 12 && (params[10] != 0 || params[11] != 0) {
		return 0, 0, nil, fmt.Errorf("SZL read refused, error 0x%02x%02x", params[10], params[11])
	}
	d := p[10+plen : 10+plen+dlen]
	if len(d) < 4 || d[0] != 0xFF {
		code := byte(0)
		if len(d) > 0 {
			code = d[0]
		}
		return 0, 0, nil, fmt.Errorf("SZL read returned 0x%02x", code)
	}
	n := int(binary.BigEndian.Uint16(d[2:]))
	d = d[4:]
	if n > len(d) {
		n = len(d) // partial list: keep what arrived
	}
	d = d[:n]
	if len(d) < 8 {
		return 0, 0, nil, fmt.Errorf("SZL header truncated")
	}
	id = binary.BigEndian.Uint16(d)
	recLen = int(binary.BigEndian.Uint16(d[4:]))
	count := int(binary.BigEndian.Uint16(d[6:]))
	d = d[8:]
	for i := 0; i < count && recLen > 0 && len(d) >= recLen; i++ {
		records = append(records, d[:recLen])
		d = d[recLen:]
	}
	return id, recLen, records, nil
}

func (f *Fingerprinter) identify(b *fpx.Builder, s *wire.Session) {
	id := b.Identity()
	read := func(szl uint16, ref uint16) [][]byte {
		resp, err := s.RoundTrip(fmt.Sprintf("szl-0x%04x", szl), iso.Data(szlRead(ref, szl, 0)), iso.Framer, maxFrame)
		if err != nil {
			return nil
		}
		p, ok := iso.Payload(resp)
		if !ok {
			return nil
		}
		got, _, recs, err := parseSZL(p)
		if err != nil {
			b.Evidence(fmt.Sprintf("SZL 0x%04x: %v", szl, err))
			return nil
		}
		if got != szl {
			b.Evidence(fmt.Sprintf("SZL 0x%04x answered with 0x%04x", szl, got))
		}
		return recs
	}
	for _, r := range read(szlModuleID, 2) {
		if len(r) < 28 {
			continue
		}
		index := binary.BigEndian.Uint16(r)
		order := fpx.Clean(string(r[2:22]))
		switch index {
		case 0x0001: // module
			id.Product = order
		case 0x0006: // basic hardware
			id.Set("hardware", order)
			if v := version(r[22:28]); v != "" {
				id.Set("hardwareVersion", v)
			}
		case 0x0007: // basic firmware
			if v := version(r[22:28]); v != "" {
				id.Version = v
			}
		}
	}
	for _, r := range read(szlComponentID, 3) {
		if len(r) < 4 {
			continue
		}
		index := binary.BigEndian.Uint16(r)
		text := fpx.Clean(string(r[2:min(len(r), 34)]))
		switch index {
		case 0x0001:
			id.Name = text
		case 0x0002:
			id.Set("moduleName", text)
		case 0x0003:
			id.Set("plantId", text)
		case 0x0004:
			id.Set("copyright", text)
			if strings.Contains(strings.ToLower(text), "siemens") {
				id.Vendor = "Siemens"
			}
		case 0x0005:
			id.Serial = text
		case 0x0007:
			id.Model = text
		case 0x0008:
			id.Set("memoryCardSerial", text)
		case 0x000B:
			id.Set("location", text)
		}
	}
	if fam := family(id.Product + " " + id.Model); fam != "" {
		id.Set("family", fam)
	}
	if !id.IsZero() {
		b.Evidence("system status lists read")
	}
}

// version decodes the BGTyp/Ausbg/Ausbe octets of an SZL 0x0011 record:
// "V" followed by three version octets (firmware, "V2.6.1"), or a plain
// version number in Ausbe (hardware, "5").
func version(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	if b[2] == 'V' {
		return fmt.Sprintf("%d.%d.%d", b[3], b[4], b[5])
	}
	if b[2] == 0 && b[3] == 0 {
		if v := binary.BigEndian.Uint16(b[4:]); v != 0 {
			return fmt.Sprint(v)
		}
	}
	return ""
}

// family infers the controller family from the order number and module
// type, as engineering tools do.
func family(s string) string {
	s = strings.ToUpper(s)
	switch {
	case strings.Contains(s, "6ES7 5"), strings.Contains(s, "1500"):
		return "S7-1500"
	case strings.Contains(s, "6ES7 21"), strings.Contains(s, "1200"):
		return "S7-1200"
	case strings.Contains(s, "6ES7 4"), strings.Contains(s, "CPU 41"):
		return "S7-400"
	case strings.Contains(s, "6ES7 3"), strings.Contains(s, "CPU 31"):
		return "S7-300"
	case strings.Contains(s, "6ED1"):
		return "LOGO!"
	}
	return ""
}
