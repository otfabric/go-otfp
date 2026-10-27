// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"io"
	"text/tabwriter"

	otfp "github.com/otfabric/go-otfp"
	"github.com/spf13/cobra"
)

func listCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the supported protocols and their probes",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "PROTOCOL\tTRANSPORT\tPORTS\tPROBE")
			for _, fp := range otfp.DefaultRegistry().All() {
				i := fp.Info()
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", i.Protocol.Slug(), i.Network, ports(i.Ports), i.Description)
			}
			return tw.Flush()
		},
	}
}

func ports(p []int) string {
	s := ""
	for i, x := range p {
		if i > 0 {
			s += ","
		}
		s += fmt.Sprint(x)
	}
	return s
}
