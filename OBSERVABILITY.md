# Observability

go-otfp is silent by default. Three hooks expose what a scan is doing, none
of which affects the results.

## Logger

`core.Logger` (`Debugf`/`Infof`/`Warnf`/`Errorf`) receives diagnostic output.
Set `EngineConfig.Logger` (or `Options.Logger` for a lone fingerprinter).
`NopLogger()` discards everything; `NewSlogLogger(handler)` adapts a
`log/slog` handler and only formats messages the handler is enabled for. At
debug level the engine logs each probe and its result, and sessions log the
bytes they send and receive.

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

## Tracing

Set `EngineConfig.Trace` (or `Options.Trace`, or `otprobe --trace`) to record
every probe and response as `core.Exchange{Label, Probe, Response}` on each
`Result`. Tracing is how the fingerprinters were validated against the
reference servers, and it is the first tool for diagnosing why a device was
or was not detected.

## Result as a record

Every `Result` is self-describing for offline analysis: a unique
`DetectionID`, a `Timestamp`, the `Duration`, the ordered `Evidence`, the
stable `Fingerprint` signature and, in identify mode, the `Identity`. The
`otprobe --format json` output serialises all of it (add `--trace` for the
raw bytes), ready for a SIEM or an asset-inventory pipeline.
