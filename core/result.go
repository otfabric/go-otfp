// SPDX-License-Identifier: MIT

package core

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Confidence is a detection certainty between 0.0 and 1.0.
//
// The built-in fingerprinters use a shared scale (see FINGERPRINTS.md):
//
//	1.00  ConfidenceCertain  a response no other protocol produces, cross-checked
//	                         (echoed identifiers, CRCs, decoded identity)
//	0.90  ConfidenceHigh     the protocol's framing and handshake, fully valid
//	0.60  ConfidenceMedium   valid framing, but a check could not be made
//	0.30  ConfidenceLow      a hint: shape matches, nothing cross-checked
type Confidence float64

// Confidence levels shared by the built-in fingerprinters.
const (
	ConfidenceNone    Confidence = 0.0
	ConfidenceLow     Confidence = 0.3
	ConfidenceMedium  Confidence = 0.6
	ConfidenceHigh    Confidence = 0.9
	ConfidenceCertain Confidence = 1.0
)

// MatchThreshold is the lowest confidence a fingerprinter reports as
// Matched. Below it a result is a hint: Matched is false and Confidence
// says how close it came.
const MatchThreshold Confidence = 0.5

// Valid reports whether c is within [0.0, 1.0].
func (c Confidence) Valid() bool { return c >= 0.0 && c <= 1.0 }

// IsHigh reports whether c is at least threshold.
func (c Confidence) IsHigh(threshold Confidence) bool { return c >= threshold }

// Clamp returns c limited to [0.0, 1.0].
func (c Confidence) Clamp() Confidence {
	switch {
	case c < 0:
		return 0
	case c > 1:
		return 1
	}
	return c
}

// Identity is what a fingerprinter learnt about the device or software
// behind the endpoint, from safe read-only requests (Modbus Read Device
// Identification, the CIP Identity object, S7 SZL, MMS Identify, the BACnet
// Device object, OPC UA BuildInfo, HTTP Server headers ...). Every field is
// optional; Attributes holds what does not fit the common ones.
type Identity struct {
	Vendor   string `json:"vendor,omitempty"`
	VendorID string `json:"vendorId,omitempty"`
	Product  string `json:"product,omitempty"`
	Model    string `json:"model,omitempty"`
	Version  string `json:"version,omitempty"`
	Serial   string `json:"serial,omitempty"`
	// Name is the instance name: S7 module/plant name, BACnet object name,
	// PROFINET station name, OPC UA application name.
	Name string `json:"name,omitempty"`
	// Attributes are further protocol-specific facts, e.g. "deviceType",
	// "productCode", "applicationUri", "deviceInstance".
	Attributes map[string]string `json:"attributes,omitempty"`
}

// IsZero reports whether no field is set.
func (id *Identity) IsZero() bool {
	return id == nil || (id.Vendor == "" && id.VendorID == "" && id.Product == "" &&
		id.Model == "" && id.Version == "" && id.Serial == "" && id.Name == "" &&
		len(id.Attributes) == 0)
}

// Set records an attribute; empty values are ignored.
func (id *Identity) Set(key, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if id.Attributes == nil {
		id.Attributes = make(map[string]string)
	}
	id.Attributes[key] = value
}

// String returns a compact one-line summary such as
// "Schneider Electric BMX P34 2020 v2.70 (serial 1234)".
func (id *Identity) String() string {
	if id.IsZero() {
		return ""
	}
	var parts []string
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			parts = append(parts, s)
		}
	}
	add(id.Vendor)
	if id.Vendor == "" && id.VendorID != "" {
		add("vendor " + id.VendorID)
	}
	add(id.Product)
	if id.Model != id.Product {
		add(id.Model)
	}
	if id.Version != "" {
		add("v" + strings.TrimPrefix(id.Version, "v"))
	}
	if id.Name != "" {
		add("\"" + id.Name + "\"")
	}
	if id.Serial != "" {
		add("(serial " + id.Serial + ")")
	}
	if len(parts) == 0 {
		keys := make([]string, 0, len(id.Attributes))
		for k := range id.Attributes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			add(k + "=" + id.Attributes[k])
		}
	}
	return strings.Join(parts, " ")
}

// Fingerprint is a stable, machine-readable signature of the endpoint's
// behaviour, for asset inventories and SIEMs.
type Fingerprint struct {
	// ID names the probe that produced it, e.g. "modbus.fc43",
	// "s7comm.szl", "ocpp.ws".
	ID string `json:"id"`
	// Signature is a compact, deterministic string of the observations,
	// e.g. "pid=0;tid=echo;fc=0x2b;mei=0x0e;conf=0x81".
	Signature string `json:"signature"`
	// Metadata holds protocol-specific key-value observations.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// String returns "ID:Signature".
func (f *Fingerprint) String() string {
	if f == nil {
		return ""
	}
	return f.ID + ":" + f.Signature
}

// Exchange is one probe and the response it got, recorded when
// Options.Trace is set.
type Exchange struct {
	// Label names the step, e.g. "cotp-cr", "s7-setup", "szl-0x0011".
	Label string `json:"label"`
	// Probe is what was sent.
	Probe []byte `json:"probe"`
	// Response is what was received; empty when nothing came back.
	Response []byte `json:"response"`
}

// Result is the outcome of one fingerprinter on one target.
//
//	Outcome              Matched  Confidence        Error
//	identified           true     >= MatchThreshold nil
//	hint                 false    (0, threshold)    nil
//	not this protocol    false    0                 nil
//	could not tell       false    0                 *TimeoutError, *ConnectionError, ...
type Result struct {
	Protocol   Protocol   `json:"protocol"`
	Matched    bool       `json:"matched"`
	Confidence Confidence `json:"confidence"`

	// Variant refines the protocol: "S7comm-plus", "OCPP 2.0.1",
	// "OpenADR 3", "BACnet/IP (BVLC)", "opc.tcp" ...
	Variant string `json:"variant,omitempty"`

	// Details is a short human-readable explanation.
	Details string `json:"details,omitempty"`

	// Evidence lists the checks that passed, in the order made.
	Evidence []string `json:"evidence,omitempty"`

	// Identity is set when Options.Mode is ModeIdentify and the endpoint
	// answered an identity request.
	Identity *Identity `json:"identity,omitempty"`

	// Fingerprint is a stable signature of the response.
	Fingerprint *Fingerprint `json:"fingerprint,omitempty"`

	// Error records why detection could not decide, e.g. a timeout or a
	// refused connection. A non-nil Error always comes with Matched false.
	Error error `json:"-"`

	// DetectionID uniquely identifies this attempt, for audit trails.
	DetectionID string `json:"detectionId"`
	// Timestamp is when the attempt finished.
	Timestamp time.Time `json:"timestamp"`
	// Duration is how long the attempt took (set by the engine).
	Duration time.Duration `json:"duration"`

	// Exchanges are the raw probe/response pairs when Options.Trace is set.
	Exchanges []Exchange `json:"exchanges,omitempty"`
}

// String returns a one-line summary of the result.
func (r Result) String() string {
	var b strings.Builder
	b.WriteString(r.Protocol.String())
	if r.Variant != "" {
		b.WriteString(" (" + r.Variant + ")")
	}
	switch {
	case r.Matched:
		fmt.Fprintf(&b, ": matched, confidence %.2f", r.Confidence)
	case r.Error != nil:
		fmt.Fprintf(&b, ": error: %v", r.Error)
	case r.Confidence > 0:
		fmt.Fprintf(&b, ": hint, confidence %.2f", r.Confidence)
	default:
		b.WriteString(": no match")
	}
	if r.Details != "" {
		b.WriteString(" - " + r.Details)
	}
	if s := r.Identity.String(); s != "" {
		b.WriteString(" [" + s + "]")
	}
	return b.String()
}

// ErrorString returns Error's message, or "" when Error is nil. It is what
// the JSON encoding carries as "error".
func (r Result) ErrorString() string {
	if r.Error == nil {
		return ""
	}
	return r.Error.Error()
}

func newDetectionID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func newResult(p Protocol) Result {
	return Result{Protocol: p, DetectionID: newDetectionID(), Timestamp: time.Now()}
}

// NoMatch returns a result saying the endpoint does not speak p.
func NoMatch(p Protocol) Result { return newResult(p) }

// Match returns a result for p with the given confidence. Matched is set
// when confidence reaches MatchThreshold; below it the result is a hint.
func Match(p Protocol, c Confidence, details string) Result {
	r := newResult(p)
	r.Confidence = c.Clamp()
	r.Matched = r.Confidence >= MatchThreshold
	r.Details = details
	return r
}

// ErrorResult returns a result recording that detection of p failed with
// err.
func ErrorResult(p Protocol, err error) Result {
	r := newResult(p)
	r.Error = err
	return r
}

// WithEvidence returns r with the observations appended to Evidence.
func (r Result) WithEvidence(e ...string) Result {
	r.Evidence = append(r.Evidence, e...)
	return r
}

// WithIdentity returns r with Identity set, unless id holds nothing.
func (r Result) WithIdentity(id *Identity) Result {
	if !id.IsZero() {
		r.Identity = id
	}
	return r
}

// WithFingerprint returns r with Fingerprint set.
func (r Result) WithFingerprint(fp *Fingerprint) Result {
	r.Fingerprint = fp
	return r
}

// WithExchanges returns r with the exchanges appended.
func (r Result) WithExchanges(x []Exchange) Result {
	r.Exchanges = append(r.Exchanges, x...)
	return r
}
