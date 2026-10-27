# API reference — `github.com/otfabric/go-otfp`

> Go ≥ 1.23 · standard-library core · the CLI adds [cobra](https://github.com/spf13/cobra).

Complete reference for the exported API. The authoritative, always-current
reference is [pkg.go.dev](https://pkg.go.dev/github.com/otfabric/go-otfp).

## Package `otfp` (root)

```go
import otfp "github.com/otfabric/go-otfp"
```

| Function | Signature | Description |
|---|---|---|
| `Fingerprinters` | `() []core.Fingerprinter` | A fresh instance of every built-in fingerprinter (EtherNet/IP over both TCP and UDP). |
| `DefaultRegistry` | `() *core.Registry` | A registry pre-loaded with every built-in fingerprinter. |
| `NewEngine` | `(core.EngineConfig) *core.Engine` | An engine over `DefaultRegistry`. |
| `DefaultEngine` | `() *core.Engine` | `NewEngine(core.DefaultEngineConfig())`. |

## Package `core`

```go
import "github.com/otfabric/go-otfp/core"
```

### Protocol & Network

```go
type Protocol uint8   // ProtocolModbus, ProtocolMMS, … ProtocolOpenADR
type Network  uint8   // TCP, UDP
```

`Protocol`: `String()` (human name), `Slug()` (stable machine id, e.g.
`"modbus"`), `IsValid()`, `MarshalText`/`UnmarshalText`. `ParseProtocol(s)`
accepts a slug, a name or a common alias (`"s7"`, `"ethernetip"`,
`"2030.5"`, …), case-insensitively. `AllProtocols()` returns every known
protocol. `Network`: `String()`, text marshalling, `ParseNetwork`.

### Target

```go
type Target struct {
	Host    string       // IP or host name
	Port    int          // 1..65535
	Network Network       // zero value TCP
	Timeout time.Duration // per-operation; zero → DefaultTimeout (3s)
	TLS     *tls.Config  // non-nil runs TCP probes over TLS
	Path    string       // overrides the first HTTP/WebSocket path
}
```

`Addr()`, `String()` (`tcp://host:port`, `+tls`), `EffectiveTimeout()`,
`Validate()`. `ParseTarget("[scheme://]host:port")` accepts the schemes
`tcp`, `udp` and `tls`.

### Confidence, Identity, Fingerprint, Result

```go
type Confidence float64 // ConfidenceNone/Low/Medium/High/Certain; MatchThreshold = 0.5
```
`Valid()`, `IsHigh(threshold)`, `Clamp()`.

```go
type Identity struct {
	Vendor, VendorID, Product, Model, Version, Serial, Name string
	Attributes map[string]string
}
```
`IsZero()`, `Set(key, value)` (ignores empty values), `String()` (one-line
summary).

```go
type Fingerprint struct { ID, Signature string; Metadata map[string]string }
type Exchange   struct { Label string; Probe, Response []byte }

type Result struct {
	Protocol    Protocol
	Matched     bool
	Confidence  Confidence
	Variant     string        // "S7comm-plus", "OCPP 2.0.1", …
	Details     string
	Evidence    []string      // checks that passed, in order
	Identity    *Identity     // identify mode
	Fingerprint *Fingerprint
	Error       error         // why detection could not decide
	DetectionID string
	Timestamp   time.Time
	Duration    time.Duration
	Exchanges   []Exchange    // raw probe/response pairs when tracing
}
```
`String()`, `ErrorString()`. Constructors `NoMatch`, `Match`, `ErrorResult`
and the chainable `WithEvidence`, `WithIdentity`, `WithFingerprint`,
`WithExchanges` are used by fingerprinter implementations.

### Fingerprinter

```go
type Mode uint8            // ModeDetect, ModeIdentify
type Intrusiveness uint8   // Passive, ReadOnly
type Options struct { Mode Mode; Trace bool; Logger Logger; MaxIntrusiveness Intrusiveness }

type Info struct {
	Protocol      Protocol
	Network       Network
	Ports         []int
	Priority      int
	Intrusiveness Intrusiveness
	Refines       Protocol  // e.g. SunSpec refines Modbus
	Description   string
}

type Fingerprinter interface {
	Info() Info
	Detect(ctx context.Context, target Target, opts Options) (Result, error)
}
```

A `Detect` returns a non-nil error only when detection could not decide (the
endpoint was unreachable or timed out); a reply that is merely *not this
protocol* is a `NoMatch` result with a nil error. Implementations must be
safe for concurrent use and must never panic (the engine recovers panics
anyway).

### Registry

```go
func NewRegistry() *Registry
func (*Registry) Register(Fingerprinter) error
func (*Registry) MustRegister(...Fingerprinter) *Registry
func (*Registry) Get(Protocol, Network) Fingerprinter
func (*Registry) All() []Fingerprinter
func (*Registry) Protocols() []Protocol
func (*Registry) Plan(Target) []Fingerprinter   // port-ordered
```

### Engine

```go
type EngineConfig struct {
	Mode                    Mode
	Trace                   bool
	Protocols, Exclude      []Protocol
	MaxIntrusiveness        Intrusiveness
	LikelyOnly              bool
	EarlyStop               bool
	HighConfidenceThreshold Confidence
	StopOnRefused           bool
	Parallel                bool
	MaxConcurrency          int
	MinInterval             time.Duration
	Observer                Observer
	Logger                  Logger
}
func DefaultEngineConfig() EngineConfig  // early stop, stop on refused, read-only
func SafeEngineConfig() EngineConfig     // + passive only, likely-first, 250ms pacing

type Engine struct{ /* … */ }
func NewEngine(*Registry, EngineConfig) *Engine
func (*Engine) Scan(ctx, Target) (Report, error)
func (*Engine) Detect(ctx, Target, Protocol) (Result, error)
func (*Engine) Config() EngineConfig

type Report struct {
	Target     Target
	StartedAt, FinishedAt time.Time
	Duration   time.Duration
	Results    []Result
	Best       Result
}
func (Report) Matches() []Result
```

`Scan` returns an error only for an invalid target or when no fingerprinter
applies (`ErrNoFingerprinters`); per-protocol failures are in `Results`.

### Observer, Logger, errors

```go
type Observer interface { OnStart(Protocol, Target); OnResult(Result) }
type Logger   interface { Debugf, Infof, Warnf, Errorf(string, ...any) }
func NopLogger() Logger
func NewSlogLogger(slog.Handler) Logger
```

Typed errors: `DetectError`, `TimeoutError`, `ConnectionError`
(`Refused()`), `InvalidResponseError`, `ProtocolNotFoundError`, and the
sentinel `ErrNoFingerprinters`. `ClassifyDial` and `ClassifyIO` map transport
failures to them; `IsTimeout(err)` reports deadline errors. See
[ERRORS.md](ERRORS.md).

## Protocol packages

Each `protocols/<name>` package exports `New() *Fingerprinter` (and, for
EtherNet/IP, `NewUDP()`); several expose a `Config` and `NewWithConfig` for
tuning addresses, TSAPs, unit IDs or paths. See the package docs on
pkg.go.dev and [FINGERPRINTS.md](FINGERPRINTS.md).

## CLI — `otprobe`

`otprobe detect <target>` (a `host:port`, a `tcp://`/`udp://`/`tls://` URL, or
a bare host to sweep its well-known ports), `otprobe list`, `otprobe version`
and `otprobe completion bash|zsh|fish|powershell`. Text is the default output;
`-o table` and `-o json` are available on every command. Exit codes: 0
detected, 1 no match, 2 usage, 3 invalid input, 4 unreachable, 5 timeout, 7
partial, 10 interrupted or internal. See [docs/cli.md](docs/cli.md),
[docs/exitcodes.md](docs/exitcodes.md) and
[docs/json-output.md](docs/json-output.md).
