# Contributing

Thanks for helping improve go-otfp.

## Before a pull request

Run the full gate, which CI mirrors:

```bash
make check     # fmt, lint (staticcheck + golangci-lint), vet, govulncheck, race tests, coverage
```

- Format with the gofmt of the Go version in `go.mod` (`make fmt`); CI checks
  both that gofmt and the local one.
- Keep the library dependency-free (standard library only). The CLI, a nested
  module in `cmd/otprobe`, may use cobra. Never import a `go-<protocol>` library or an `*-interop` package
  from library or CLI code — they are for validation only.
- Add tests for new behaviour, and a `Fuzz` target for any new parser. Keep
  library-package coverage at or above the codecov target.

## Adding a protocol

1. Create `protocols/<name>` with a `Fingerprinter` implementing
   `core.Info` and `core.Detect`, built on `internal/wire` and scored with
   `internal/fpx`. Follow an existing package (`protocols/modbus` is a good
   template).
2. Register it in `otfp.Fingerprinters()` and add a `core.Protocol` constant
   (append — never renumber existing values).
3. Validate the probe bytes against the protocol's reference implementation:
   the sibling `go-<protocol>` library's server where one exists, otherwise a
   pinned `*-interop` image. Add an adapter to `interop/harness_test.go`.
4. Document it in `README.md` and `FINGERPRINTS.md`.
5. Respect the safety contract: detection sends a handshake or one harmless
   request; identify uses the protocol's own read-only identity service.
   Never write, control or reconfigure a device.

## Generated code

`protocols/enip/catalog.go` is generated from `go-ethernetip` by `make
generate`; do not edit it by hand. `make generate-check` (with a local
`go-ethernetip` checkout) verifies it is current.

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do not open a public issue for
vulnerabilities.
