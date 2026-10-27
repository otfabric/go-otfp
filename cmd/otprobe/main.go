// SPDX-License-Identifier: MIT

// Command otprobe fingerprints OT protocols on a network endpoint using the
// safe, connection-level probes of the go-otfp library.
package main

import (
	"errors"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// Build-time variables injected via ldflags.
var (
	version   = "dev"
	tag       = ""
	commit    = "unknown"
	buildDate = "unknown"
)

// formatEnv sets the default --format of every command that has one.
const formatEnv = "OTPROBE_OUTPUT_FORMAT"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// run executes the command line and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	root := &cobra.Command{
		Use:   "otprobe",
		Short: "Fingerprint OT protocols on a network endpoint",
		Long: `otprobe identifies which industrial protocol an endpoint speaks — Modbus,
SunSpec, IEC 61850 MMS, S7comm, OPC UA, EtherNet/IP, BACnet/IP, PROFINET,
DNP3, IEC 60870-5-104, OCPP, IEEE 2030.5, OpenADR or an SLCAN CAN gateway —
with each protocol's standard handshake or one harmless request. With
--identify it also reads the device's identity over the protocol's own
read-only service. It never writes, controls or reconfigures a device.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return fail(kindUsage, codeInvalidInput, "%v", err)
	})
	root.AddCommand(detectCommand(stdout, stderr), listCommand(stdout), versionCommand(stdout), completionCommand(root, stdout))
	root.CompletionOptions.DisableDefaultCmd = true // replaced by completionCommand

	err := root.Execute()
	if err == nil {
		return exitDetected
	}
	var st *exitStatus
	if errors.As(err, &st) {
		return st.code
	}
	return render(err, wantsJSON(args), stdout, stderr)
}

// wantsJSON reports whether the command line asks for JSON output, read
// directly from the arguments so that even a command line that does not
// parse renders its usage error in the requested format.
func wantsJSON(args []string) bool {
	format := os.Getenv(formatEnv)
	for i, a := range args {
		switch {
		case a == "--":
			return format == "json"
		case (a == "--format" || a == "-o") && i+1 < len(args):
			format = args[i+1]
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		case strings.HasPrefix(a, "-o="):
			format = strings.TrimPrefix(a, "-o=")
		case strings.HasPrefix(a, "-o") && !strings.HasPrefix(a, "--"):
			format = strings.TrimPrefix(a, "-o")
		}
	}
	return format == "json"
}

// formatFlag adds --format with the given choices, defaulting to text (or
// OTPROBE_OUTPUT_FORMAT), with shell completion of the values.
func formatFlag(cmd *cobra.Command, dst *string, choices ...string) {
	def := "text"
	if v := os.Getenv(formatEnv); v != "" {
		def = v
	}
	cmd.Flags().StringVarP(dst, "format", "o", def, "output format: "+strings.Join(choices, ", ")+" (env "+formatEnv+")")
	_ = cmd.RegisterFlagCompletionFunc("format", fixedCompletion(choices...))
}

func checkFormat(format string, choices ...string) error {
	for _, c := range choices {
		if format == c {
			return nil
		}
	}
	return fail(kindInvalidInput, codeInvalidFormat, "unknown --format %q (want %s)", format, strings.Join(choices, ", "))
}
