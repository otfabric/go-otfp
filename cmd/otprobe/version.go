// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"runtime"

	"github.com/spf13/cobra"
)

var versionFormats = []string{"text", "json"}

func versionCommand(stdout io.Writer) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := checkFormat(format, versionFormats...); err != nil {
				return err
			}
			v := version
			if tag != "" {
				v = tag
			}
			var err error
			if format == "json" {
				enc := json.NewEncoder(stdout)
				enc.SetIndent("", "  ")
				err = enc.Encode(map[string]string{
					"version": v, "commit": commit, "buildDate": buildDate,
					"go": runtime.Version(), "platform": runtime.GOOS + "/" + runtime.GOARCH,
				})
			} else {
				_, err = fmt.Fprintf(stdout, "otprobe %s (commit %s, built %s, %s %s/%s)\n",
					v, commit, buildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
			}
			if err != nil {
				return fail(kindOutput, codeOutputFailed, "write output: %v", err)
			}
			return nil
		},
	}
	formatFlag(cmd, &format, versionFormats...)
	return cmd
}
