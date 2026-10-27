// SPDX-License-Identifier: MIT

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/otfabric/go-otfp/core"
)

// schemaVersion is the version of the JSON document (docs/json-output.md).
const schemaVersion = 1

func writeScans(w io.Writer, scans []scan, f detectFlags) error {
	switch f.format {
	case "json":
		return writeJSON(w, scans, f.trace)
	case "table":
		return writeTable(w, scans)
	}
	return writeText(w, scans, f.trace)
}

// ---- text (default) ----

func writeText(w io.Writer, scans []scan, trace bool) error {
	sweep := len(scans) > 1
	var closed, silent []string
	shown := 0
	for _, s := range scans {
		if sweep && !answered(s.report) {
			if refused(s.report) {
				closed = append(closed, fmt.Sprint(s.target.Port))
			} else {
				silent = append(silent, fmt.Sprint(s.target.Port))
			}
			continue
		}
		if shown > 0 {
			fmt.Fprintln(w)
		}
		shown++
		writeTextScan(w, s, trace)
	}
	if sweep {
		if shown > 0 {
			fmt.Fprintln(w)
		}
		if len(closed) > 0 {
			fmt.Fprintf(w, "Closed:   %s\n", strings.Join(closed, ", "))
		}
		if len(silent) > 0 {
			fmt.Fprintf(w, "Silent:   %s\n", strings.Join(silent, ", "))
		}
	}
	return nil
}

func writeTextScan(w io.Writer, s scan, trace bool) {
	r := s.report
	fmt.Fprintf(w, "Target:   %s\n", r.Target)
	if r.Best.Matched {
		fmt.Fprintf(w, "Detected: %s", r.Best.Protocol)
		if r.Best.Variant != "" {
			fmt.Fprintf(w, " (%s)", r.Best.Variant)
		}
		fmt.Fprintf(w, ", confidence %.2f\n", r.Best.Confidence)
	} else {
		fmt.Fprintf(w, "Detected: none (%s)\n", why(r))
	}
	for _, res := range r.Matches() {
		fmt.Fprintf(w, "\n  %s  %.2f  %s\n", label(res), res.Confidence, res.Details)
		for _, e := range res.Evidence {
			fmt.Fprintf(w, "    - %s\n", e)
		}
		width := 11 // len("fingerprint")
		if res.Identity != nil {
			for k := range res.Identity.Attributes {
				width = max(width, len(k))
			}
			writeIdentity(w, res.Identity, width)
		}
		if res.Fingerprint != nil {
			fmt.Fprintf(w, "    %-*s  %s\n", width, "fingerprint", res.Fingerprint)
		}
	}
	fmt.Fprintf(w, "\n  %s in %s\n", plural(len(r.Results), "probe"), r.Duration.Round(time.Millisecond))
	if trace {
		writeTrace(w, r)
	}
}

// why summarises a scan without a match.
func why(r core.Report) string {
	switch {
	case refused(r):
		return "connection refused"
	case answered(r):
		return "no protocol matched"
	}
	return "no answer"
}

func writeIdentity(w io.Writer, id *core.Identity, width int) {
	field := func(name, v string) {
		if v != "" {
			fmt.Fprintf(w, "    %-*s  %s\n", width, name, v)
		}
	}
	field("vendor", id.Vendor)
	field("vendor id", id.VendorID)
	field("product", id.Product)
	field("model", id.Model)
	field("version", id.Version)
	field("serial", id.Serial)
	field("name", id.Name)
	for _, k := range sortedKeys(id.Attributes) {
		field(k, id.Attributes[k])
	}
}

func writeTrace(w io.Writer, r core.Report) {
	for _, res := range r.Results {
		if len(res.Exchanges) == 0 {
			continue
		}
		fmt.Fprintf(w, "\n  trace %s\n", res.Protocol.Slug())
		for _, x := range res.Exchanges {
			fmt.Fprintf(w, "    %s\n", x.Label)
			if len(x.Probe) > 0 {
				fmt.Fprintf(w, "      > %s\n", hex.EncodeToString(x.Probe))
			}
			if len(x.Response) > 0 {
				fmt.Fprintf(w, "      < %s\n", hex.EncodeToString(x.Response))
			}
		}
	}
}

// ---- table ----

func writeTable(w io.Writer, scans []scan) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TARGET\tPROTOCOL\tMATCH\tCONF\tVARIANT\tDETAILS")
	for _, s := range scans {
		for _, res := range s.report.Results {
			match := "no"
			switch {
			case res.Matched:
				match = "yes"
			case res.Error != nil:
				match = "error"
			case res.Confidence > 0:
				match = "hint"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%.2f\t%s\t%s\n", s.target, res.Protocol.Slug(), match, res.Confidence, dash(res.Variant), detail(res))
		}
	}
	return tw.Flush()
}

// ---- json (opt-in, for machines) ----

type jsonExchange struct {
	Label    string `json:"label"`
	Probe    string `json:"probe,omitempty"`
	Response string `json:"response,omitempty"`
}

type jsonError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type jsonResult struct {
	Protocol    string            `json:"protocol"`
	Name        string            `json:"name"`
	Matched     bool              `json:"matched"`
	Confidence  float64           `json:"confidence"`
	Variant     string            `json:"variant,omitempty"`
	Details     string            `json:"details,omitempty"`
	Evidence    []string          `json:"evidence,omitempty"`
	Identity    *core.Identity    `json:"identity,omitempty"`
	Fingerprint *core.Fingerprint `json:"fingerprint,omitempty"`
	Error       *jsonError        `json:"error,omitempty"`
	DurationMS  int64             `json:"durationMs"`
	Exchanges   []jsonExchange    `json:"exchanges,omitempty"`
}

type jsonScan struct {
	Target     string       `json:"target"`
	Host       string       `json:"host"`
	Port       int          `json:"port"`
	Network    string       `json:"network"`
	TLS        bool         `json:"tls"`
	StartedAt  time.Time    `json:"startedAt"`
	DurationMS int64        `json:"durationMs"`
	Detected   *jsonResult  `json:"detected"`
	Results    []jsonResult `json:"results"`
}

func writeJSON(w io.Writer, scans []scan, trace bool) error {
	doc := struct {
		SchemaVersion int        `json:"schemaVersion"`
		Scans         []jsonScan `json:"scans"`
	}{SchemaVersion: schemaVersion, Scans: []jsonScan{}}
	for _, s := range scans {
		r := s.report
		js := jsonScan{
			Target: r.Target.String(), Host: r.Target.Host, Port: r.Target.Port,
			Network: r.Target.Network.String(), TLS: r.Target.TLS != nil,
			StartedAt: r.StartedAt.UTC(), DurationMS: r.Duration.Milliseconds(),
			Results: []jsonResult{},
		}
		if r.Best.Matched {
			b := toJSON(r.Best, trace)
			js.Detected = &b
		}
		for _, res := range r.Results {
			js.Results = append(js.Results, toJSON(res, trace))
		}
		doc.Scans = append(doc.Scans, js)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func toJSON(res core.Result, trace bool) jsonResult {
	out := jsonResult{
		Protocol: res.Protocol.Slug(), Name: res.Protocol.String(), Matched: res.Matched,
		Confidence: float64(res.Confidence), Variant: res.Variant, Details: res.Details,
		Evidence: res.Evidence, Identity: res.Identity, Fingerprint: res.Fingerprint,
		DurationMS: res.Duration.Milliseconds(),
	}
	if res.Error != nil {
		out.Error = &jsonError{Kind: errorKind(res.Error), Message: res.Error.Error()}
	}
	if trace {
		for _, x := range res.Exchanges {
			out.Exchanges = append(out.Exchanges, jsonExchange{x.Label, hex.EncodeToString(x.Probe), hex.EncodeToString(x.Response)})
		}
	}
	return out
}

// errorKind names a per-probe error for JSON consumers.
func errorKind(err error) string {
	var ce *core.ConnectionError
	var te *core.TimeoutError
	switch {
	case errors.As(err, &ce) && ce.Refused():
		return "refused"
	case errors.As(err, &ce):
		return "unreachable"
	case errors.As(err, &te):
		return "timeout"
	}
	return "io"
}

// ---- helpers ----

func answered(r core.Report) bool {
	for _, res := range r.Results {
		if res.Error == nil {
			return true
		}
	}
	return false
}

func refused(r core.Report) bool {
	for _, res := range r.Results {
		var ce *core.ConnectionError
		if errors.As(res.Error, &ce) && ce.Refused() {
			return true
		}
	}
	return false
}

func label(r core.Result) string {
	if r.Variant != "" {
		return r.Protocol.String() + " / " + r.Variant
	}
	return r.Protocol.String()
}

func detail(r core.Result) string {
	if r.Error != nil {
		return r.Error.Error()
	}
	return r.Details
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
