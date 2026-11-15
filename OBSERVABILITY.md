# Observability

go-otfp is silent by default. Three hooks expose what a scan is doing. They
take no part in detection: a hook that returns normally changes no result.

## Logger

`core.Logger` (`Debugf`/`Infof`/`Warnf`/`Errorf`) receives diagnostic output.
Set `EngineConfig.Logger` (or `Options.Logger` for a lone fingerprinter).
`NopLogger()` discards everything; `NewSlogLogger(handler)` adapts a
`log/slog` handler and only formats messages the handler is enabled for. At
debug level the engine logs each probe and its result, and sessions log the
bytes they send and receive. Of the datagrams a UDP round trip discards, the
first four are logged with their bytes and the rest as one count. A `Logger`
is called synchronously, from several goroutines with `Parallel`; a method
that does not return normally is recovered and becomes the error of that
probe's result, and that probe's connection is closed.

```go
cfg := core.DefaultEngineConfig()
cfg.Logger = core.NewSlogLogger(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
```

The `otprobe --debug` flag wires this to stderr and adds a progress observer.

## Observer

`core.Observer` is a scan-progress and audit hook, not a request-latency
metric: `OnStart(protocol, target)` fires before each fingerprinter and
`OnResult(result)` after. Implementations must be non-blocking, and
concurrency-safe when `Parallel` is set. Use it for progress bars, audit
trails or counters.

A callback runs on the goroutine of its probe, with no lock of the engine
held: it may call the engine (`Config`, `Detect`), and it may cancel the
scan's context to end the scan. A slow callback delays its own probe only.
A callback that does not return normally is recovered, in sequential and in
parallel scans, and becomes the error of that probe's result (a
`*core.DetectError` of operation `observer`); the scan goes on. When
`OnStart` does not return normally the fingerprinter is not run, so an
audit trail that records every probe before it is sent never misses one.

## Tracing

Set `EngineConfig.Trace` (or `Options.Trace`, or `otprobe --trace`) to record
every probe and response as `core.Exchange{Label, Probe, Response}` on each
`Result`. Tracing is how the fingerprinters were validated against the
reference servers, and it is the first tool for diagnosing why a device was
or was not detected.

A trace is bounded: per connection of a fingerprinter at most 256 exchanges
and 4 MiB of probes and responses. What does not fit is counted, and the
trace then ends with one entry without bytes whose label says how many
exchanges and octets were left out.

## Result as a record

Every `Result` is self-describing for offline analysis: a unique
`DetectionID`, a `Timestamp`, the `Duration`, the ordered `Evidence`, the
stable `Fingerprint` signature and, in identify mode, the `Identity`. The
`otprobe --format json` output serialises all of it (add `--trace` for the
raw bytes), ready for a SIEM or an asset-inventory pipeline.
