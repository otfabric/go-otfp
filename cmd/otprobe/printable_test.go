// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/testsrv"
)

// nonText holds characters that are not text for a terminal: C0 controls,
// DEL, C1 controls, format characters, the line and paragraph separators
// and an octet that is not UTF-8.
const nonText = "\x1b\a\r\n\t\x7f\U00000085\U0000009b\U0000202e\U0000200b\U0000feff\U00002028\U00002029\xff"

// checkTerminalText fails when out holds anything but graphic characters
// and line feeds.
func checkTerminalText(t *testing.T, out string) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Errorf("the output is not UTF-8: %q", out)
	}
	for _, r := range out {
		if r != '\n' && !unicode.IsGraphic(r) {
			t.Errorf("%U in the output:\n%q", r, out)
			return
		}
	}
}

func TestPrintable(t *testing.T) {
	for in, want := range map[string]string{
		"":                 "",
		"Acme PLC":         "Acme PLC",
		"Größe 東京":         "Größe 東京",
		"a\x1b[2Jb":        `a\x1b[2Jb`,
		"a\nDetected: x":   `a\nDetected: x`,
		"a\tb\rc":          `a\tb\rc`,
		"a\x7fb":           `a\x7fb`,
		"a\U00000085b":     `a\u0085b`,
		"a\U0000009bb":     `a\u009bb`,
		"a\U0000202eb":     "a\\u202eb",
		"a\U0000200bb":     "a\\u200bb",
		"a\U00002028b":     "a\\u2028b",
		"a\U000e0001b":     `a\U000e0001b`,
		"a\xffb\xc3":       `a\xffb\xc3`,
		"back\\slash kept": "back\\slash kept",
	} {
		if got := printable(in); got != want {
			t.Errorf("printable(%q) = %q, want %q", in, got, want)
		}
		checkTerminalText(t, printable(in))
	}
	var buf bytes.Buffer
	n, err := printableWriter{&buf}.Write([]byte("line 1\nline\x1b2\n"))
	if err != nil || n != 14 || buf.String() != "line 1\nline\\x1b2\n" {
		t.Errorf("printableWriter: %d, %v, %q", n, err, buf.String())
	}
	failing := printableWriter{&stickyWriter{err: errors.New("closed")}}
	if _, err := failing.Write([]byte("x")); err == nil {
		t.Error("printableWriter did not return the write error")
	}
}

// A result built outside the library's fingerprinters can hold anything:
// the text and table formats print it as text, and no value starts a line
// of its own.
func TestTextAndTableOutputAreTerminalText(t *testing.T) {
	res := core.Result{
		Protocol: core.ProtocolModbus, Matched: true, Confidence: 1,
		Variant:  "variant" + nonText,
		Details:  "details" + nonText + "\nDetected: forged",
		Evidence: []string{"evidence" + nonText, "second\nDetected: forged"},
		Identity: &core.Identity{
			Vendor: "vendor" + nonText, VendorID: "1" + nonText, Product: "product" + nonText, Model: "model" + nonText,
			Version: "1.0" + nonText, Serial: "serial" + nonText, Name: "name" + nonText,
			Attributes: map[string]string{"key" + nonText: "value" + nonText},
		},
		Fingerprint: &core.Fingerprint{ID: "id" + nonText, Signature: "sig" + nonText},
		Exchanges:   []core.Exchange{{Label: "label" + nonText, Probe: []byte{0x1b}, Response: []byte{0x9b}}},
	}
	failed := core.ErrorResult(core.ProtocolS7, errors.New("failed"+nonText))
	target := core.Target{Host: "host" + nonText, Port: 502}
	rep := core.Report{Target: target, Results: []core.Result{res, failed}, Best: res, Duration: time.Millisecond}
	for _, format := range []string{"text", "table"} {
		var out bytes.Buffer
		if err := writeScans(&out, []scan{{target, rep}}, detectFlags{format: format, trace: true}); err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		checkTerminalText(t, out.String())
		if n := strings.Count(out.String(), "\nDetected: ") + strings.Count(out.String(), "\n  Detected: "); format == "text" && n != 1 {
			t.Errorf("text: %d lines start with Detected:, want 1\n%s", n, out.String())
		}
		for _, want := range []string{`variant\x1b`, `details\x1b`} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s: %q is missing in\n%s", format, want, out.String())
			}
		}
		if lines := strings.Count(out.String(), "\n"); format == "table" && lines != 3 {
			t.Errorf("table: %d lines, want the header and one per result\n%s", lines, out.String())
		}
	}
	var dbg bytes.Buffer
	o := debugObserver{&dbg}
	o.OnStart(core.ProtocolModbus, target)
	o.OnResult(res)
	checkTerminalText(t, dbg.String())
	if strings.Count(dbg.String(), "\n") != 2 {
		t.Errorf("--debug: want two lines, got\n%s", dbg.String())
	}
}

// What an endpoint sends reaches the terminal as text: an OPC UA server
// that rejects the endpoint URL with a reason of its own choice.
func TestDetectPrintsEndpointTextAsText(t *testing.T) {
	reason := "wrong" + nonText + " endpoint"
	body := binary.LittleEndian.AppendUint32(nil, 0x80830000)
	body = binary.LittleEndian.AppendUint32(body, uint32(len(reason)))
	body = append(body, reason...)
	frame := append([]byte("ERRF\x00\x00\x00\x00"), body...)
	binary.LittleEndian.PutUint32(frame[4:], uint32(len(frame)))
	srv := testsrv.TCP(t, testsrv.Script(frame, frame))
	for _, format := range []string{"text", "table"} {
		code, out, errw := exec("detect", addr(srv), "--protocol", "opcua", "--format", format, "--debug")
		if code != exitOK {
			t.Fatalf("%s: exit %d\nstdout: %s\nstderr: %s", format, code, out, errw)
		}
		checkTerminalText(t, out)
		checkTerminalText(t, errw)
		if !strings.Contains(out, "OPC UA") {
			t.Errorf("%s: no OPC UA match in\n%s", format, out)
		}
	}
}
