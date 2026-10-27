// SPDX-License-Identifier: MIT

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/otfabric/go-otfp/core"
)

func writeReport(w io.Writer, r core.Report, f detectFlags) error {
	switch f.format {
	case "json":
		return writeJSON(w, r, f.trace)
	case "table":
		return writeTable(w, r)
	case "text", "":
		return writeText(w, r, f.trace)
	}
	return fmt.Errorf("unknown format %q (want text, json or table)", f.format)
}

func writeText(w io.Writer, r core.Report, trace bool) error {
	fmt.Fprintf(w, "Target:   %s\n", r.Target)
	fmt.Fprintf(w, "Duration: %s\n", r.Duration.Round(1e6))
	if r.Best.Matched {
		fmt.Fprintf(w, "Detected: %s", r.Best.Protocol)
		if r.Best.Variant != "" {
			fmt.Fprintf(w, " (%s)", r.Best.Variant)
		}
		fmt.Fprintf(w, " — confidence %.2f\n", r.Best.Confidence)
		if id := r.Best.Identity.String(); id != "" {
			fmt.Fprintf(w, "Identity: %s\n", id)
		}
	} else {
		fmt.Fprintln(w, "Detected: none")
	}
	matches := r.Matches()
	if len(matches) > 0 {
		fmt.Fprintln(w, "\nMatches:")
		for _, res := range matches {
			fmt.Fprintf(w, "  %-18s %.2f  %s\n", label(res), res.Confidence, res.Details)
			for _, e := range res.Evidence {
				fmt.Fprintf(w, "      · %s\n", e)
			}
			if res.Identity != nil {
				writeIdentity(w, res.Identity)
			}
		}
	}
	if trace {
		writeTrace(w, r)
	}
	return nil
}

func writeIdentity(w io.Writer, id *core.Identity) {
	field := func(name, v string) {
		if v != "" {
			fmt.Fprintf(w, "      %-12s %s\n", name+":", v)
		}
	}
	field("vendor", id.Vendor)
	field("product", id.Product)
	field("model", id.Model)
	field("version", id.Version)
	field("serial", id.Serial)
	field("name", id.Name)
	keys := make([]string, 0, len(id.Attributes))
	for k := range id.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		field(k, id.Attributes[k])
	}
}

func writeTrace(w io.Writer, r core.Report) {
	for _, res := range r.Results {
		if len(res.Exchanges) == 0 {
			continue
		}
		fmt.Fprintf(w, "\nTrace %s:\n", res.Protocol.Slug())
		for _, x := range res.Exchanges {
			fmt.Fprintf(w, "  %s\n", x.Label)
			if len(x.Probe) > 0 {
				fmt.Fprintf(w, "    > %s\n", hex.EncodeToString(x.Probe))
			}
			if len(x.Response) > 0 {
				fmt.Fprintf(w, "    < %s\n", hex.EncodeToString(x.Response))
			}
		}
	}
}

func writeTable(w io.Writer, r core.Report) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PROTOCOL\tMATCH\tCONF\tDETAILS")
	for _, res := range r.Results {
		match := "no"
		if res.Matched {
			match = "yes"
		} else if res.Error != nil {
			match = "err"
		}
		fmt.Fprintf(tw, "%s\t%s\t%.2f\t%s\n", res.Protocol.Slug(), match, res.Confidence, detail(res))
	}
	return tw.Flush()
}

func writeJSON(w io.Writer, r core.Report, trace bool) error {
	type exchange struct {
		Label    string `json:"label"`
		Probe    string `json:"probe,omitempty"`
		Response string `json:"response,omitempty"`
	}
	type result struct {
		Protocol    string            `json:"protocol"`
		Matched     bool              `json:"matched"`
		Confidence  core.Confidence   `json:"confidence"`
		Variant     string            `json:"variant,omitempty"`
		Details     string            `json:"details,omitempty"`
		Evidence    []string          `json:"evidence,omitempty"`
		Identity    *core.Identity    `json:"identity,omitempty"`
		Fingerprint *core.Fingerprint `json:"fingerprint,omitempty"`
		Error       string            `json:"error,omitempty"`
		DurationMS  float64           `json:"durationMs"`
		Exchanges   []exchange        `json:"exchanges,omitempty"`
	}
	conv := func(res core.Result) result {
		out := result{
			Protocol: res.Protocol.Slug(), Matched: res.Matched, Confidence: res.Confidence,
			Variant: res.Variant, Details: res.Details, Evidence: res.Evidence,
			Identity: res.Identity, Fingerprint: res.Fingerprint, Error: res.ErrorString(),
			DurationMS: float64(res.Duration) / 1e6,
		}
		if trace {
			for _, x := range res.Exchanges {
				out.Exchanges = append(out.Exchanges, exchange{x.Label, hex.EncodeToString(x.Probe), hex.EncodeToString(x.Response)})
			}
		}
		return out
	}
	doc := struct {
		Target     string   `json:"target"`
		DurationMS float64  `json:"durationMs"`
		Best       result   `json:"best"`
		Results    []result `json:"results"`
	}{Target: r.Target.String(), DurationMS: float64(r.Duration) / 1e6, Best: conv(r.Best)}
	for _, res := range r.Results {
		doc.Results = append(doc.Results, conv(res))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func label(r core.Result) string {
	if r.Variant != "" {
		return r.Protocol.Slug() + "/" + strings.ReplaceAll(strings.ToLower(r.Variant), " ", "-")
	}
	return r.Protocol.Slug()
}

func detail(r core.Result) string {
	if r.Error != nil {
		return r.Error.Error()
	}
	return r.Details
}
