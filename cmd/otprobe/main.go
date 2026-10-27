// SPDX-License-Identifier: MIT

// Command otprobe fingerprints OT protocols on a network endpoint using the
// safe, connection-level probes of the go-otfp library.
package main

import (
	"io"
	"os"

	"github.com/spf13/cobra"
)

// Build-time variables injected via ldflags.
var (
	version   = "dev"
	tag       = ""
	commit    = "unknown"
	buildDate = "unknown"
)

// Exit codes.
const (
	exitDetected  = 0 // a protocol was identified at high confidence
	exitNoMatch   = 1 // nothing matched
	exitConnError = 2 // the target could not be reached
	exitBadParams = 3 // invalid arguments
	exitPartial   = 4 // matched, but below the high-confidence threshold
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) (code int) {
	root := &cobra.Command{
		Use:           "otprobe",
		Short:         "OT protocol fingerprinting",
		Long:          "otprobe detects industrial protocols on a network endpoint with safe, connection-level probes.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(detectCommand(stdout, stderr, &code), listCommand(stdout), versionCommand(stdout))

	if err := root.Execute(); err != nil {
		var se *silentExit
		if as(err, &se) {
			return se.code
		}
		return exitBadParams
	}
	return code
}

// silentExit carries an exit code out of a command without cobra printing
// it as an error.
type silentExit struct{ code int }

func (e *silentExit) Error() string { return "" }

func as(err error, target **silentExit) bool {
	for err != nil {
		if se, ok := err.(*silentExit); ok {
			*target = se
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
