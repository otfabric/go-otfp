// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	otfp "github.com/otfabric/go-otfp"
	"github.com/otfabric/go-otfp/cmd/otprobe/internal/netdial"
	"github.com/otfabric/go-otfp/core"
	"github.com/otfabric/go-otfp/internal/tlsx"
	"github.com/otfabric/go-otfp/protocols/canopen"
	"github.com/spf13/cobra"
)

type detectFlags struct {
	port      int
	ports     []string
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
	path      string
	// canopenNode is the CANopen node identified through a CiA 309-3
	// gateway; 0 means the gateway's default node.
	canopenNode int
	trace       bool
	debug       bool
	// sourceAddr and proxy build the dialer of every probe (netdial).
	sourceAddr string
	proxy      string
}

var detectFormats = []string{"text", "json", "table"}

func detectCommand(stdout, stderr io.Writer) *cobra.Command {
	var f detectFlags
	cmd := &cobra.Command{
		Use:   "detect <host>[:port] | <scheme>://<host>:<port>",
		Short: "Detect the OT protocols a target speaks",
		Long: `Detect which OT protocol a target speaks by sending each protocol's standard
handshake or one harmless request and judging the reply.

The target is a host with an optional port and scheme:

  otprobe detect 10.0.0.5:502               one TCP port
  otprobe detect udp://10.0.0.5:47808       one UDP port (BACnet, PROFINET, EtherNet/IP)
  otprobe detect tls://10.0.0.5:802         TCP over TLS (Modbus Security, wss://, https://)
  otprobe detect 10.0.0.5                   sweep the protocols' well-known ports
  otprobe detect 10.0.0.5 --ports 502,102   sweep these ports

A sweep tries, on each port, only the protocols registered for it; a
single port tries every protocol of its transport, that port's first.

Exit codes: 0 detected, 1 no match (findings), 2 usage, 3 invalid input,
4 transport (refused, unreachable, TLS), 5 timeout, 7 matched below high
confidence (partial), 10 output or internal error, 130 interrupted. See
docs/exitcodes.md.`,
		Example: `  otprobe detect 10.0.0.5:502 --identify
  otprobe detect 10.0.0.5:102 --protocol s7comm --format json
  otprobe detect udp://10.0.0.5:47808 --identify --trace
  otprobe detect 10.0.0.5 --safe --format table`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: targetCompletion,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDetect(cmd.Context(), f, args[0], stdout, stderr)
		},
	}
	fl := cmd.Flags()
	fl.IntVarP(&f.port, "port", "p", 0, "target port (overrides a port in the target)")
	fl.StringSliceVar(&f.ports, "ports", nil, "sweep these ports, e.g. 502,102,44818 (default: each protocol's well-known ports)")
	fl.StringVar(&f.network, "network", "", "transport: tcp or udp (default: from the scheme, else tcp)")
	fl.BoolVar(&f.useTLS, "tls", false, "probe over TLS (server certificates are not verified)")
	fl.DurationVarP(&f.timeout, "timeout", "t", core.DefaultTimeout, "per-operation timeout (dial, write, read)")
	fl.DurationVar(&f.overall, "deadline", 0, "deadline for the whole scan (0 = none)")
	fl.StringSliceVar(&f.protocols, "protocol", nil, "probe only these protocols (repeatable or comma-separated)")
	fl.StringSliceVar(&f.exclude, "exclude", nil, "skip these protocols")
	fl.BoolVarP(&f.identify, "identify", "i", false, "read the device identity (vendor, model, version, serial) where supported")
	fl.BoolVar(&f.safe, "safe", false, "OT-safe scan: passive probes only, likely protocols only, 250ms between probes")
	fl.BoolVar(&f.parallel, "parallel", false, "probe protocols concurrently (many field devices accept one connection: off by default)")
	fl.IntVar(&f.maxConc, "max-concurrency", 0, "limit concurrent probes with --parallel (0 = unbounded)")
	fl.DurationVar(&f.minGap, "min-interval", 0, "minimum delay between probes")
	fl.BoolVar(&f.allProbes, "all", false, "run every applicable probe instead of stopping at the first confident match")
	formatFlag(cmd, &f.format, detectFormats...)
	fl.StringVar(&f.path, "path", "", "WebSocket path OCPP tries first (e.g. the station id)")
	fl.IntVar(&f.canopenNode, "canopen-node", 0, "CANopen node (1-127) to identify through a CiA 309-3 gateway (default: the gateway's default node)")
	fl.BoolVar(&f.trace, "trace", false, "include the raw probe and response bytes")
	fl.BoolVar(&f.debug, "debug", false, "log every probe to stderr")
	fl.StringVar(&f.sourceAddr, "source-addr", "", "bind every probe to this local IP address (an interface's address)")
	fl.StringVar(&f.proxy, "proxy", "", "probe through a SOCKS5 proxy: socks5://host:port, or socks5h:// to resolve host names at the proxy (TCP only)")

	_ = cmd.RegisterFlagCompletionFunc("protocol", protocolCompletion)
	_ = cmd.RegisterFlagCompletionFunc("exclude", protocolCompletion)
	_ = cmd.RegisterFlagCompletionFunc("network", fixedCompletion("tcp\tTCP (with --tls: TLS)", "udp\tUDP datagrams"))
	_ = cmd.RegisterFlagCompletionFunc("ports", portCompletion)
	for _, name := range []string{"port", "timeout", "deadline", "max-concurrency", "min-interval", "path", "canopen-node", "source-addr", "proxy"} {
		_ = cmd.RegisterFlagCompletionFunc(name, cobra.NoFileCompletions)
	}
	return cmd
}

// scan is one scanned target and its report.
type scan struct {
	target core.Target
	report core.Report
}

func runDetect(parent context.Context, f detectFlags, arg string, stdout, stderr io.Writer) error {
	if err := checkFormat(f.format, detectFormats...); err != nil {
		return err
	}
	targets, sweep, err := parseTargets(arg, f)
	if err != nil {
		return err
	}
	cfg, err := engineConfig(f, sweep, stderr)
	if err != nil {
		return err
	}

	ctx := parent
	if f.overall > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, f.overall)
		defer cancel()
	}

	engine := core.NewEngine(registry(f), cfg)
	var scans []scan
	for _, t := range targets {
		rep, err := engine.Scan(ctx, t)
		if errors.Is(err, core.ErrNoFingerprinters) {
			if sweep {
				continue // no selected protocol uses this port
			}
			return fail(kindInvalidInput, codeNoFingerprinters, "no selected protocol runs over %s", t.Network)
		}
		if err != nil {
			return fail(kindInvalidInput, codeInvalidTarget, "%v", err)
		}
		scans = append(scans, scan{t, rep})
		if ctx.Err() != nil {
			break
		}
	}
	if parent.Err() != nil {
		return fail(kindInterrupted, codeContextCanceled, "interrupted")
	}
	if len(scans) == 0 {
		return fail(kindInvalidInput, codeNoFingerprinters, "no selected protocol has a well-known port to sweep; give a port")
	}
	if err := writeScans(stdout, scans, f); err != nil {
		return fail(kindOutput, codeOutputFailed, "write output: %v", err)
	}
	code := outcome(scans)
	if code == exitFindings && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		// --deadline cut the scan short: "nothing matched" is not a
		// completed finding.
		code = exitTimeout
	}
	if code != exitOK {
		return &exitStatus{code}
	}
	return nil
}

// parseTargets resolves the argument and flags into one target, or into one
// target per port for a sweep.
func parseTargets(arg string, f detectFlags) ([]core.Target, bool, error) {
	t := core.Target{Timeout: f.timeout, Path: f.path}
	if f.timeout <= 0 {
		return nil, false, fail(kindInvalidInput, codeInvalidInput, "--timeout must be positive")
	}
	if hasScheme(arg) || hasPort(arg) {
		parsed, err := core.ParseTarget(arg)
		if err != nil {
			return nil, false, fail(kindInvalidInput, codeInvalidTarget, "%v", err)
		}
		t.Host, t.Port, t.Network, t.TLS = parsed.Host, parsed.Port, parsed.Network, parsed.TLS
	} else {
		t.Host = strings.Trim(arg, "[]")
	}
	if f.network != "" {
		n, err := core.ParseNetwork(f.network)
		if err != nil {
			return nil, false, fail(kindInvalidInput, codeInvalidInput, "%v", err)
		}
		t.Network = n
	}
	if f.useTLS && t.TLS == nil {
		t.TLS = tlsx.Fingerprint()
	}
	if t.TLS != nil && t.Network == core.UDP {
		return nil, false, fail(kindInvalidInput, codeInvalidFlags, "TLS is not available over UDP")
	}
	if f.proxy != "" && t.Network == core.UDP {
		return nil, false, fail(kindInvalidInput, codeInvalidFlags, "--proxy carries TCP only; UDP probes cannot go through it")
	}
	if f.port != 0 && len(f.ports) > 0 {
		return nil, false, fail(kindInvalidInput, codeInvalidFlags, "--port and --ports are exclusive")
	}
	if f.port != 0 {
		t.Port = f.port
	}
	if t.Port != 0 {
		if len(f.ports) > 0 {
			return nil, false, fail(kindInvalidInput, codeInvalidFlags, "the target has a port; --ports sweeps a bare host")
		}
		if err := t.Validate(); err != nil {
			return nil, false, fail(kindInvalidInput, codeInvalidTarget, "%v", err)
		}
		return []core.Target{t}, false, nil
	}

	// A sweep.
	ports, err := sweepPorts(f, t.Network)
	if err != nil {
		return nil, false, err
	}
	var out []core.Target
	for _, p := range ports {
		pt := t
		pt.Port = p
		if err := pt.Validate(); err != nil {
			return nil, false, fail(kindInvalidInput, codeInvalidTarget, "%v", err)
		}
		out = append(out, pt)
	}
	return out, true, nil
}

func sweepPorts(f detectFlags, n core.Network) ([]int, error) {
	if len(f.ports) > 0 {
		var out []int
		for _, s := range f.ports {
			p, err := strconv.Atoi(strings.TrimSpace(s))
			if err != nil || p < 1 || p > 65535 {
				return nil, fail(kindInvalidInput, codeInvalidInput, "--ports: %q is not a port", s)
			}
			out = append(out, p)
		}
		return out, nil
	}
	selected, err := selectedProtocols(f)
	if err != nil {
		return nil, err
	}
	seen := map[int]bool{}
	var out []int
	for _, fp := range otfp.DefaultRegistry().All() {
		info := fp.Info()
		if info.Network != n || (selected != nil && !selected[info.Protocol]) {
			continue
		}
		for _, p := range info.Ports {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	sort.Ints(out)
	return out, nil
}

// selectedProtocols returns the --protocol set, or nil for all.
func selectedProtocols(f detectFlags) (map[core.Protocol]bool, error) {
	if len(f.protocols) == 0 {
		return nil, nil
	}
	m := map[core.Protocol]bool{}
	for _, name := range f.protocols {
		p, err := core.ParseProtocol(name)
		if err != nil {
			return nil, fail(kindInvalidInput, codeInvalidProtocol, "%v (see otprobe list)", err)
		}
		m[p] = true
	}
	return m, nil
}

// registry is the default registry, with the CANopen fingerprinter set to
// --canopen-node when given.
func registry(f detectFlags) *core.Registry {
	fps := otfp.Fingerprinters()
	if f.canopenNode != 0 {
		for i, fp := range fps {
			if fp.Info().Protocol == core.ProtocolCANopen {
				fps[i] = canopen.NewWithConfig(canopen.Config{Node: f.canopenNode})
			}
		}
	}
	return core.NewRegistry().MustRegister(fps...)
}

func engineConfig(f detectFlags, sweep bool, stderr io.Writer) (core.EngineConfig, error) {
	if f.canopenNode < 0 || f.canopenNode > 127 {
		return core.EngineConfig{}, fail(kindInvalidInput, codeInvalidFlags, "--canopen-node %d: a CANopen node is 1 to 127", f.canopenNode)
	}
	cfg := core.DefaultEngineConfig()
	if f.safe {
		cfg = core.SafeEngineConfig()
	}
	// A sweep probes, on each port, that port's protocols only.
	cfg.LikelyOnly = cfg.LikelyOnly || sweep
	if f.identify {
		cfg.Mode = core.ModeIdentify
	}
	cfg.Trace = f.trace
	cfg.Parallel = f.parallel
	if f.maxConc < 0 {
		return cfg, fail(kindInvalidInput, codeInvalidInput, "--max-concurrency must not be negative")
	}
	if f.maxConc > 0 && !f.parallel {
		return cfg, fail(kindInvalidInput, codeInvalidFlags, "--max-concurrency needs --parallel")
	}
	cfg.MaxConcurrency = f.maxConc
	if f.minGap > 0 {
		cfg.MinInterval = f.minGap
	}
	if f.allProbes {
		cfg.EarlyStop = false
	}
	sel, err := selectedProtocols(f)
	if err != nil {
		return cfg, err
	}
	for p := range sel {
		cfg.Protocols = append(cfg.Protocols, p)
	}
	for _, name := range f.exclude {
		p, err := core.ParseProtocol(name)
		if err != nil {
			return cfg, fail(kindInvalidInput, codeInvalidProtocol, "%v (see otprobe list)", err)
		}
		cfg.Exclude = append(cfg.Exclude, p)
	}
	dial, err := netdial.New(f.sourceAddr, f.proxy)
	if err != nil {
		return cfg, fail(kindInvalidInput, codeInvalidInput, "%v", err)
	}
	cfg.Dialer = dial
	if f.debug {
		cfg.Logger = core.NewSlogLogger(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
		cfg.Observer = debugObserver{stderr}
	}
	return cfg, nil
}

// outcome maps the scans to the exit code: detected, partial, no match
// (findings), or, when nothing answered at all, transport, timeout or
// internal (a fingerprinter failed).
func outcome(scans []scan) int {
	var detected, partial, answered, transport, timedOut, internal bool
	for _, s := range scans {
		for _, r := range s.report.Results {
			switch {
			case r.Matched && r.Confidence >= core.ConfidenceHigh:
				detected = true
			case r.Matched:
				partial = true
			case r.Error == nil:
				answered = true
			default:
				switch resultKind(r.Error) {
				case kindTransport:
					transport = true
				case kindTimeout:
					timedOut = true
				case kindInternal:
					internal = true
				}
			}
		}
	}
	switch {
	case detected:
		return exitOK
	case partial:
		return exitPartial
	case answered:
		return exitFindings
	case transport:
		return exitTransport
	case timedOut:
		return exitTimeout
	case internal:
		return exitInternal
	}
	return exitFindings
}

// resultKind classifies the error of one probe result by the library's
// typed errors: a dial or I/O failure (refused, unreachable, reset, TLS
// handshake) is transport, a deadline is timeout, and a fingerprinter that
// failed by itself (the engine reports a panic as a DetectError of op
// "detect") is internal. Anything else is left to the other results.
func resultKind(err error) kind {
	if te, ok := errors.AsType[*core.TimeoutError](err); ok && te != nil {
		return kindTimeout
	}
	if ce, ok := errors.AsType[*core.ConnectionError](err); ok && ce != nil {
		return kindTransport
	}
	if de, ok := errors.AsType[*core.DetectError](err); ok && de != nil {
		if de.Op == "detect" {
			return kindInternal
		}
		return kindTransport
	}
	if core.IsTimeout(err) {
		return kindTimeout
	}
	return ""
}

func hasScheme(s string) bool { return strings.Contains(s, "://") }

// hasPort reports whether s ends in a port: "host:502", "[::1]:502". A bare
// IPv6 address ("::1", "[::1]") has none.
func hasPort(s string) bool {
	if strings.HasPrefix(s, "[") {
		i := strings.LastIndex(s, "]")
		return i >= 0 && i+1 < len(s) && s[i+1] == ':'
	}
	return strings.Count(s, ":") == 1
}

type debugObserver struct{ w io.Writer }

func (d debugObserver) OnStart(p core.Protocol, t core.Target) {
	fmt.Fprintf(d.w, "probe %s %s\n", p.Slug(), t)
}

func (d debugObserver) OnResult(r core.Result) {
	fmt.Fprintf(d.w, "  -> %s (%s)\n", r, r.Duration.Round(time.Millisecond))
}
