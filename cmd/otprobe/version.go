// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
)

// versionFormats: table prints the text line, so that OTPROBE_OUTPUT_FORMAT
// set for the other commands applies here too.
var versionFormats = []string{"text", "json", "table"}

func versionCommand(stdout io.Writer) *cobra.Command {
	var format string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long: `Print the version, release tag, commit, build date, Go version and platform
on one line, or as one line of JSON with --json (or --format json).`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if err := checkFormat(format, versionFormats...); err != nil {
				return err
			}
			info := currentBuildInfo()
			line := info.Text()
			if asJSON || format == "json" {
				line = info.JSON()
			}
			if _, err := fmt.Fprintln(stdout, line); err != nil {
				return fail(kindOutput, codeOutputFailed, "write output: %v", err)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the version information as one line of JSON")
	formatFlag(cmd, &format, versionFormats...)
	return cmd
}
