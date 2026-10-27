# Interoperability

The fingerprinters are validated against the otfabric reference
implementations, so a probe is known to match what real stacks send — not
only what a specification says.

## Two sources of truth

1. **The `go-<protocol>` libraries.** Each sibling library ships an
   in-process server (or, for S7, a reference Docker server). The probe bytes
   and decoders here were developed and checked against them: `go-modbus`,
   `go-sunspec`, `go-dnp3`, `go-iec104`, `go-mms`, `go-opcua`,
   `go-ethernetip`, `go-profinet`, `go-bacnet`'s codecs, `go-ocpp`,
   `go-openadr` and `go-ieee20305`.
2. **The `*-interop` container suites.** Each protocol has a suite of
   independent third-party stacks packaged as reference servers (for example
   `modbus-interop` bundles libmodbus, pymodbus, digitalpetri, NModbus and
   tokio-modbus). The published, multi-arch images are the same ones the
   sibling libraries qualify against.

go-otfp depends on none of these at runtime — it is a zero-dependency
library. They are tools for validation only.

## The interop suite

`interop/` holds Docker-gated tests (build tag `interop`) that start the
pinned reference servers and assert that `otfp` detects each as the right
protocol, with the expected identity:

```bash
make interop                                  # all adapters (needs Docker)
OTFP_INTEROP_ADAPTERS=modbus-pymodbus,bacnet-stack make interop
```

The images are pinned by digest in `interop/harness_test.go`, taken from
each sibling library's own interop harness, and overridable per adapter with
an `OTFP_<PROTOCOL>_IMAGE` environment variable.

## What is out of scope

- **Unpublished GPL reference stacks** — the DNP3 Step Function I/O server
  and the PROFINET p-net device are not redistributable, so the suite uses
  the published adapters (opendnp3, pnio-rs) instead.
- **Host Layer-2 access** — PROFINET DCP Identify runs over raw Ethernet and
  needs privileges and a local interface; go-otfp fingerprints the UDP
  DCE/RPC endpoint, which the suite covers.
The suite covers 11 reference servers: pymodbus (Modbus), opendnp3 (DNP3),
lib60870 (IEC 104), Snap7 (S7comm), open62541 (OPC UA), OpENer
(EtherNet/IP), bacnet-stack (BACnet/IP), The Mobility House ocpp (OCPP),
OpenLEADR (OpenADR 3), and GridAPPS-D and Envoy (IEEE 2030.5). Detection and,
where the server provides it, identity are asserted. The images that need
fixtures or a PKI (Snap7, open62541, the IEEE 2030.5 servers) use the
sibling `*-interop` repositories' own fixtures and PKI helper, and are
skipped when those are not checked out beside go-otfp.
