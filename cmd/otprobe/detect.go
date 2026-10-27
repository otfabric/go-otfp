// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"os/signal"
	"syscall"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/core"
	"github.com/spf13/cobra"
)

type detectFlags struct {
	port      int
	network   string
	useTLS    bool
	timeout   time.Duration
	overall   time.Duration
	protocols []string
	exclude   []string
	identify  bool
	safe      bool
	parallel  bool
	maxConc   int
	minGap    time.Duration
	allProbes bool
	format    string
	trace     bool
	debug     bool
}

func detectCommand(stdout, stderr io.Writer, code *int) *cobra.Command {
	var f detectFlags
	cmd := &cobra.Command{
		Use:   "detect <host>",
		Short: "Detect OT protocols on a target endpoint",
		Long: `Detect OT protocols on a target by sending each protocol's standard
handshake or a single harmless request and analysing the reply.

The host may be a bare address, or carry a port and scheme:
  otprobe detect 10.0.0.5                 scan the default TCP ports
  otprobe detect 10.0.0.5:502             scan one TCP port
  otprobe detect udp://10.0.0.5:47808     scan a UDP port (BACnet, PROFINET)
  otprobe detect tls://10.0.0.5:802        scan a TLS port (Modbus Security)

Exit codes: 0 detected, 1 no match, 2 connection error, 3 bad arguments,
4 matched below the high-confidence threshold.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c := runDetect(f, args[0], stdout, stderr)
			*code = c
			if c != exitDetected {
				return &silentExit{code: c}
			}
			return nil
		},
	}
	fl := cmd.Flags()
	fl.IntVar(&f.port, "port", 0, "target port (overrides a port in the host, defaults per protocol)")
	fl.StringVar(&f.network, "network", "", "transport: tcp or udp (default from the host scheme, else tcp)")
	fl.BoolVar(&f.useTLS, "tls", false, "probe over TLS (identify only; certificates are not verified)")
	fl.DurationVar(&f.timeout, "timeout", core.DefaultTimeout, "per-probe timeout")
	fl.DurationVar(&f.overall, "deadline", 0, "overall deadline for the scan (0 = none)")
	fl.StringSliceVar(&f.protocols, "protocol", nil, "restrict to these protocols (repeatable; e.g. modbus,s7comm)")
	fl.StringSliceVar(&f.exclude, "exclude", nil, "skip these protocols")
	fl.BoolVar(&f.identify, "identify", false, "read device identity (vendor, model, version) where supported")
	fl.BoolVar(&f.safe, "safe", false, "OT-safe scan: passive probes only, likely protocols first, 250ms between probes")
	fl.BoolVar(&f.parallel, "parallel", false, "probe protocols concurrently (off by default: many devices allow one connection)")
	fl.IntVar(&f.maxConc, "max-concurrency", 0, "limit concurrent probes when --parallel (0 = unbounded)")
	fl.DurationVar(&f.minGap, "min-interval", 0, "minimum delay between probes")
	fl.BoolVar(&f.allProbes, "all", false, "run every applicable probe instead of stopping at the first confident match")
	fl.StringVar(&f.format, "format", "text", "output format: text, json or table")
	fl.BoolVar(&f.trace, "trace", false, "include raw probe/response bytes (text/json)")
	fl.BoolVar(&f.debug, "debug", false, "log each probe to stderr")
	return cmd
}

func runDetect(f detectFlags, host string, stdout, stderr io.Writer) int {
	target, err := parseTarget(host, f)
	if err != nil {
		fmt.Fprintln(stderr, "otprobe:", err)
		return exitBadParams
	}
	cfg, err := engineConfig(f, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "otprobe:", err)
		return exitBadParams
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if f.overall > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.overall)
		defer cancel()
	}

	engine := otfp.NewEngine(cfg)
	report, err := engine.Scan(ctx, target)
	if err != nil {
		fmt.Fprintln(stderr, "otprobe:", err)
		return exitBadParams
	}
	if err := writeReport(stdout, report, f); err != nil {
		fmt.Fprintln(stderr, "otprobe:", err)
		return exitBadParams
	}
	return exitCode(report)
}

func parseTarget(host string, f detectFlags) (core.Target, error) {
	t := core.Target{Timeout: f.timeout}
	if hasScheme(host) || hasPort(host) {
		parsed, err := core.ParseTarget(host)
		if err != nil {
			return t, err
		}
		t.Host, t.Port, t.Network, t.TLS = parsed.Host, parsed.Port, parsed.Network, parsed.TLS
	} else {
		t.Host = host
	}
	if f.port != 0 {
		t.Port = f.port
	}
	if f.network != "" {
		n, err := core.ParseNetwork(f.network)
		if err != nil {
			return t, err
		}
		t.Network = n
	}
	if f.useTLS && t.TLS == nil {
		t.TLS = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // fingerprinting identifies, it does not trust
	}
	if t.Port == 0 {
		return t, fmt.Errorf("no port: give host:port, a scheme, or --port")
	}
	return t, nil
}

func engineConfig(f detectFlags, stderr io.Writer) (core.EngineConfig, error) {
	cfg := core.DefaultEngineConfig()
	if f.safe {
		cfg = core.SafeEngineConfig()
	}
	if f.identify {
		cfg.Mode = core.ModeIdentify
	}
	cfg.Trace = f.trace
	cfg.Parallel = f.parallel
	if f.maxConc > 0 {
		cfg.MaxConcurrency = f.maxConc
	}
	if f.minGap > 0 {
		cfg.MinInterval = f.minGap
	}
	if f.allProbes {
		cfg.EarlyStop = false
	}
	for _, name := range f.protocols {
		p, err := core.ParseProtocol(name)
		if err != nil {
			return cfg, err
		}
		cfg.Protocols = append(cfg.Protocols, p)
	}
	for _, name := range f.exclude {
		p, err := core.ParseProtocol(name)
		if err != nil {
			return cfg, err
		}
		cfg.Exclude = append(cfg.Exclude, p)
	}
	if f.debug {
		cfg.Logger = core.NewSlogLogger(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
		cfg.Observer = debugObserver{stderr}
	}
	return cfg, nil
}

func exitCode(r core.Report) int {
	switch {
	case r.Best.Matched && r.Best.Confidence >= core.ConfidenceHigh:
		return exitDetected
	case r.Best.Matched:
		return exitPartial
	}
	for _, res := range r.Results {
		var ce *core.ConnectionError
		var te *core.TimeoutError
		if asErr(res.Error, &ce) || asErr(res.Error, &te) {
			return exitConnError
		}
	}
	return exitNoMatch
}

func hasScheme(s string) bool {
	for i := 0; i+2 < len(s); i++ {
		switch s[i] {
		case ':':
			return s[i+1] == '/' && s[i+2] == '/'
		case '/', '[':
			return false
		}
	}
	return false
}

func hasPort(s string) bool {
	// A bracketed IPv6 literal, or a single colon with digits after it.
	if len(s) > 0 && s[0] == '[' {
		return true
	}
	colons, lastColon := 0, -1
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			colons++
			lastColon = i
		}
	}
	return colons == 1 && lastColon < len(s)-1
}

type debugObserver struct{ w io.Writer }

func (d debugObserver) OnStart(p core.Protocol, t core.Target) {
	fmt.Fprintf(d.w, "probe %s %s\n", p.Slug(), t)
}
func (d debugObserver) OnResult(r core.Result) {
	fmt.Fprintf(d.w, "  -> %s (%.0fms)\n", r, float64(r.Duration)/float64(time.Millisecond))
}

func asErr[T error](err error, target *T) bool {
	for err != nil {
		if t, ok := err.(T); ok {
			*target = t
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
