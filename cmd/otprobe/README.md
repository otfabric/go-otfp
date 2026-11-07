# otprobe

`otprobe` fingerprints OT protocols on a network endpoint with the safe,
connection-level probes of the [go-otfp](../../README.md) library. It never
writes, controls or reconfigures a device.

This directory is its own Go module (`github.com/otfabric/go-otfp/cmd/otprobe`).
Installation, release binaries and shell completion are described in the
[repository README](../../README.md#install-otprobe).

| Document | Contents |
|---|---|
| [docs/cli.md](docs/cli.md) | Commands, flags and real output for every protocol |
| [docs/exitcodes.md](docs/exitcodes.md) | Process exit codes and the JSON error object |
| [docs/json-output.md](docs/json-output.md) | The `--format json` schema |
