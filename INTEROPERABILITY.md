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
- **Kernel CAN** — the CANopen gateway test needs a Docker host whose
  kernel has vcan (Linux with `can`, `can-raw`, `vcan` loaded). Docker
  Desktop has no CAN support, so the test skips there (fails with
  `OTFP_REQUIRE_INTEROP=1`); the nightly job loads the modules.
- **Unpublished KNX adapters** — the knx-interop knxd and calimero adapters
  are built locally (knxd is GPL); the suite uses the official
  calimero-server image with a config in `interop/testdata/knx`.

## Coverage

The suite covers 18 reference servers and setups:

| Protocol | Server | Image |
|---|---|---|
| Modbus | pymodbus | modbus-interop v0.3.3 |
| DNP3 | opendnp3 | dnp3-interop v0.11.2 |
| IEC 104 | lib60870 | iec104-interop v0.5.0 |
| S7comm | Snap7 | snap7-interop v0.4.2 |
| OPC UA | open62541 | opcua-interop v0.19.0 |
| EtherNet/IP | OpENer | ethernetip-interop v0.6.1 |
| BACnet/IP | bacnet-stack | bacnet-interop v0.11.3 |
| OCPP | The Mobility House ocpp | ocpp-interop v0.5.3 |
| IEEE 2030.5 | GridAPPS-D, Envoy | ieee20305-interop v0.3.1 |
| OpenADR 3 | OpenLEADR | openadr-interop v0.6.3 |
| KNXnet/IP (UDP, TCP) | calimero-server 3.0-M1 | `calimeroproject/knxserver` (knx-interop versions.yaml) |
| MQTT | Eclipse Mosquitto 2.1.2, HiveMQ CE 2026.5 | as pinned by go-sparkplugb |
| Sparkplug B | sparkplughost host + srad edge on Mosquitto and on HiveMQ CE | sparkplugb-interop v0.3.1 |
| CANopen (CiA 309-3) | CANopenNode v4.1 canopend gateway + canopend-device node 32 on vcan | canopen-interop v0.3.1 (Linux hosts only) |

Detection and, where the server provides it, identity are asserted. The
images that need fixtures or a PKI (Snap7, open62541, the IEEE 2030.5
servers) use the sibling `*-interop` repositories' own fixtures and PKI
helper, and are skipped when those are not checked out beside go-otfp.

### Additional manual validation (2026-11-05)

Checked once by hand, not in the suite:

- **KNXnet/IP**: knxd 0.14.73 (knx-interop knxd adapter, built locally;
  UDP only, knxd has no TCP server), plain and `-R` routing; calimero-server
  in `--secure --routing` mode; go-knx v0.7.0's in-process server (plain,
  TCP, Secure: reported `secure+tunnelling-v2`). knxd answers route-back
  HPAIs only; calimero closes a TCP connection on an explicit HPAI.
- **MQTT**: Mosquitto with `allow_anonymous false` (high, return code 5,
  Sparkplug B not checked) and a Mosquitto TLS listener on 8883 (certain;
  identify reads `$SYS/broker/version`).
- **Sparkplug B**: an Eclipse Tahu edge (sparkplugb-interop) on Mosquitto:
  NBIRTH/DBIRTH/NDATA/DDATA decoded.
- **CANopen**: the default-node path (ERROR:105 until a node is set), an
  absent node (stops on SDO abort 0x05040000), and detection after a stale
  SLCAN `V\r` left by the CAN probe. The version-record form of
  `info version` is checked by unit tests only (CANopenNode does not
  implement it).
