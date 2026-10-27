// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"io"
	"runtime"

	"github.com/spf13/cobra"
)

func versionCommand(stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			v := version
			if tag != "" {
				v = tag
			}
			fmt.Fprintf(stdout, "otprobe %s (commit %s, built %s, %s %s/%s)\n",
				v, commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			return nil
		},
	}
}
