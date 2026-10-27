// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	otfp "github.com/otfabric/go-otfp"
	"github.com/spf13/cobra"
)

var listFormats = []string{"text", "json", "table"}

func listCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the supported protocols and their probes",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := checkFormat(format, listFormats...); err != nil {
				return err
			}
			if err := writeList(stdout, format); err != nil {
				return fail(kindOutput, codeOutputFailed, "write output: %v", err)
			}
			return nil
		},
	}
	formatFlag(cmd, &format, listFormats...)
	return cmd
}

type listEntry struct {
	Protocol      string `json:"protocol"`
	Name          string `json:"name"`
	Network       string `json:"network"`
	Ports         []int  `json:"ports"`
	Intrusiveness string `json:"intrusiveness"`
	Refines       string `json:"refines,omitempty"`
	Probe         string `json:"probe"`
}

func writeList(w io.Writer, format string) error {
	var entries []listEntry
	for _, fp := range otfp.DefaultRegistry().All() {
		i := fp.Info()
		e := listEntry{
			Protocol: i.Protocol.Slug(), Name: i.Protocol.String(), Network: i.Network.String(),
			Ports: i.Ports, Intrusiveness: i.Intrusiveness.String(), Probe: i.Description,
		}
		if i.Refines.IsValid() {
			e.Refines = i.Refines.Slug()
		}
		entries = append(entries, e)
	}
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(map[string]any{"protocols": entries})
	case "table":
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		fmt.Fprintln(tw, "PROTOCOL\tNETWORK\tPORTS\tINTRUSIVENESS\tNAME")
		for _, e := range entries {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", e.Protocol, e.Network, ports(e.Ports), e.Intrusiveness, e.Name)
		}
		return tw.Flush()
	}
	for _, e := range entries {
		fmt.Fprintf(w, "%-10s %-4s %-26s %s\n", e.Protocol, e.Network, ports(e.Ports), e.Name)
		fmt.Fprintf(w, "           %s\n", e.Probe)
	}
	return nil
}

func ports(p []int) string {
	s := make([]string, len(p))
	for i, x := range p {
		s[i] = fmt.Sprint(x)
	}
	return strings.Join(s, ",")
}
