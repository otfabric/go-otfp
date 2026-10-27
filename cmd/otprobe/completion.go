// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/spf13/cobra"
)

func completionCommand(root *cobra.Command, stdout io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "completion bash|zsh|fish|powershell",
		Short: "Generate the shell completion script",
		Long: `Generate the completion script for your shell. It completes commands, flags
and flag values: protocol names for --protocol and --exclude, formats,
networks, well-known ports, and target schemes.

  bash:        source <(otprobe completion bash)
               (permanently: otprobe completion bash > /etc/bash_completion.d/otprobe)
  zsh:         otprobe completion zsh > "${fpath[1]}/_otprobe"   (then restart the shell)
  fish:        otprobe completion fish > ~/.config/fish/completions/otprobe.fish
  powershell:  otprobe completion powershell | Out-String | Invoke-Expression`,
		Args:                  cobra.ExactArgs(1),
		ValidArgs:             []string{"bash", "zsh", "fish", "powershell"},
		DisableFlagsInUseLine: true,
		RunE: func(_ *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return root.GenBashCompletionV2(stdout, true)
			case "zsh":
				return root.GenZshCompletion(stdout)
			case "fish":
				return root.GenFishCompletion(stdout, true)
			case "powershell":
				return root.GenPowerShellCompletionWithDesc(stdout)
			}
			return fail(kindUsage, codeInvalidInput, "unknown shell %q (want bash, zsh, fish or powershell)", args[0])
		},
	}
}

// fixedCompletion completes one of the given values ("value\tdescription").
func fixedCompletion(values ...string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return values, cobra.ShellCompDirectiveNoFileComp
	}
}

// protocolCompletion completes protocol slugs, with their names as
// descriptions, for a comma-separated list: values already given are kept
// as a prefix and not offered again.
func protocolCompletion(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	prefix, given := "", map[string]bool{}
	if i := strings.LastIndex(toComplete, ","); i >= 0 {
		prefix = toComplete[:i+1]
		for _, v := range strings.Split(toComplete[:i], ",") {
			given[v] = true
		}
	}
	var out []string
	for _, p := range core.AllProtocols() {
		if !given[p.Slug()] {
			out = append(out, prefix+p.Slug()+"\t"+p.String())
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
}

// portCompletion completes the well-known ports, described by the protocols
// that use them.
func portCompletion(_ *cobra.Command, _ []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	prefix := ""
	if i := strings.LastIndex(toComplete, ","); i >= 0 {
		prefix = toComplete[:i+1]
	}
	users := map[int][]string{}
	for _, fp := range otfp.DefaultRegistry().All() {
		i := fp.Info()
		for _, p := range i.Ports {
			users[p] = appendUnique(users[p], i.Protocol.Slug())
		}
	}
	ports := make([]int, 0, len(users))
	for p := range users {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, fmt.Sprintf("%s%d\t%s", prefix, p, strings.Join(users[p], ", ")))
	}
	return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
}

// targetCompletion offers the target schemes; hosts are the user's to type.
func targetCompletion(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 || strings.Contains(toComplete, "://") {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return []string{"tcp://\tTCP", "udp://\tUDP (BACnet, PROFINET, EtherNet/IP)", "tls://\tTCP over TLS"},
		cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
