// SPDX-License-Identifier: MIT

// Package can fingerprints CAN-over-TCP gateways that expose a Controller
// Area Network bus through an SLCAN (Lawicel) ASCII serial interface over a
// TCP socket — CAN-Ethernet bridges and SocketCAN-over-TCP daemons.
//
// Detection sends the SLCAN version command ("V\r") and, when needed, the
// serial command ("N\r"), and accepts only a strict SLCAN reply: the
// command's echo letter followed by the fixed-width hexadecimal field and a
// carriage return, or a bare CR acknowledgement to a second command. ASCII
// banners of HTTP, SSH, SMTP, line protocols and the like are rejected, so
// a chatty text service does not read as a CAN gateway.
//
// In identify mode the firmware version and serial number reported by the
// gateway are recorded.
package can

import (
	"context"
	"strings"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/fpx"
	"github.com/otfabric/go-otfp/internal/wire"
)

const proto = core.ProtocolCAN

const (
	cr      = '\r'
	bell    = '\a'
	maxResp = 64
)

// SLCAN commands.
var (
	probeVersion = []byte{'V', cr}
	probeSerial  = []byte{'N', cr}
)

// Fingerprinter detects CAN-over-TCP SLCAN gateways.
type Fingerprinter struct{}

// New returns a CAN gateway fingerprinter.
func New() *Fingerprinter { return &Fingerprinter{} }

// Info describes the fingerprinter.
func (f *Fingerprinter) Info() core.Info {
	return core.Info{
		Protocol:      proto,
		Network:       core.TCP,
		Ports:         []int{20000, 29536, 3000, 2000, 19228},
		Priority:      140,
		Intrusiveness: core.Passive,
		Description:   "SLCAN version (\"V\") and serial (\"N\") commands; strict SLCAN reply validation",
	}
}

// lineFramer completes an SLCAN line at the first CR or BEL.
func lineFramer(b []byte) int {
	for i, c := range b {
		if c == cr || c == bell {
			return i + 1
		}
	}
	if len(b) >= maxResp {
		return -1
	}
	return 0
}

// Detect probes target.
func (f *Fingerprinter) Detect(ctx context.Context, target core.Target, opts core.Options) (core.Result, error) {
	b := fpx.New(proto)
	s, err := wire.Dial(ctx, proto, target, opts)
	if err != nil {
		return core.NoMatch(proto), err
	}
	defer s.Close() //nolint:errcheck

	vResp, err := s.RoundTrip("slcan-version", probeVersion, lineFramer, maxResp)
	if err != nil {
		if b.Confidence() == 0 {
			return b.Result("can.slcan", "no response", s), err
		}
		return b.Result("can.slcan", "no SLCAN response", s), nil
	}
	if looksLikeText(vResp) {
		b.Evidence("response looks like a text banner, not SLCAN")
		return b.Result("can.slcan", "not a CAN gateway", s), nil
	}

	version, versionOK := slcanField(vResp, 'V')
	if versionOK {
		b.Score(core.ConfidenceHigh, "SLCAN version reply "+version)
		b.Sig("version", version)
		if opts.Mode == core.ModeIdentify {
			b.Identity().Set("slcanVersion", version)
			b.Identity().Version = version
		}
	} else if !isBareAck(vResp) {
		return b.Result("can.slcan", "not SLCAN", s), nil
	}

	sResp, err := s.RoundTrip("slcan-serial", probeSerial, lineFramer, maxResp)
	if err == nil {
		if serial, ok := slcanField(sResp, 'N'); ok {
			b.Score(core.ConfidenceCertain, "SLCAN version and serial replies")
			b.Sig("serial", serial)
			if opts.Mode == core.ModeIdentify {
				b.Identity().Serial = serial
			}
		} else if isBareAck(sResp) && versionOK {
			b.Score(core.ConfidenceCertain, "SLCAN version reply and a bare-CR acknowledgement")
		} else if isBareAck(sResp) {
			b.Score(core.ConfidenceLow, "two bare-CR acknowledgements (too weak to confirm SLCAN)")
		}
	}

	details := "not a CAN gateway"
	if b.Confidence() >= core.MatchThreshold {
		details = "CAN-over-TCP (SLCAN) gateway"
	}
	return b.Result("can.slcan", details, s), nil
}

// slcanField validates a reply to command letter cmd: the echoed letter (or
// nothing, for versionless firmware) followed by printable hexadecimal
// characters and a terminating CR, and returns the field.
func slcanField(resp []byte, cmd byte) (string, bool) {
	line := trimTerminator(resp)
	if len(line) == 0 {
		return "", false
	}
	// The Lawicel V reply is "Vhhhh"; N is "Nxxxx"; some firmwares omit
	// the echo and answer just the digits.
	body := line
	if line[0] == cmd {
		body = line[1:]
	}
	if len(body) < 2 || len(body) > 8 {
		return "", false
	}
	for _, c := range body {
		if !isHex(c) {
			return "", false
		}
	}
	return string(line), true
}

func trimTerminator(resp []byte) []byte {
	for len(resp) > 0 && (resp[len(resp)-1] == cr || resp[len(resp)-1] == bell || resp[len(resp)-1] == '\n') {
		resp = resp[:len(resp)-1]
	}
	return resp
}

// isBareAck reports whether resp is a lone CR (SLCAN's OK acknowledgement).
func isBareAck(resp []byte) bool {
	return len(resp) == 1 && resp[0] == cr
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// looksLikeText rejects common ASCII banners that are not SLCAN.
func looksLikeText(resp []byte) bool {
	s := strings.TrimSpace(string(resp))
	if s == "" {
		return false
	}
	upper := strings.ToUpper(s)
	for _, p := range []string{"HTTP/", "SSH-", "<!DOCTYPE", "<HTML", "{", "220 ", "* OK", "+OK"} {
		if strings.HasPrefix(upper, strings.ToUpper(p)) {
			return true
		}
	}
	// A reply with a space or several words is prose, not an SLCAN field.
	if strings.ContainsAny(s, " \t") {
		return true
	}
	return false
}
