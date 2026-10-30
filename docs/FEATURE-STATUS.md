# Support and feature matrix

What go-otfp fingerprints, and against what each fingerprinter has been run. Status: v0.2.0. How each one works: [FINGERPRINTS.md](../FINGERPRINTS.md). Limits: [LIMITATIONS.md](../LIMITATIONS.md).

None of this is a conformance claim: nothing is certified, a match says how a peer answered and not what it is, and no fingerprinter has been recorded against physical devices.

## 1. Versions

| go-otfp | Go | Supported |
|---|---|---|
| **v0.2.0** | 1.23 or later (CI: 1.23 to 1.26) | **yes** |

## 2. Platforms

The library has no dependencies. CI tests on Linux amd64. Linux arm64 and arm, macOS arm64 and Windows amd64 are built by `make cross`, not tested.

## 3. Feature support

**Cross matrix**: a scripted speaker in `TestCrossProtocolMatrix`. **Independent**: a third-party reference server in `interop/harness_test.go`, run on demand with `make interop`, not in CI; a dash means none.

| Protocol | Slug | Transport | Cross matrix | Independent |
|---|---|---|:---:|---|
| Modbus TCP | `modbus` | TCP | ✅ | pymodbus |
| SunSpec | `sunspec` | TCP, read-only, refines Modbus | — | — |
| IEC 61850 MMS | `mms` | TCP | — | — |
| Siemens S7comm, S7comm-plus | `s7comm` | TCP | ✅ | Snap7 ¹ |
| OPC UA | `opcua` | TCP | ✅ | open62541 ¹ |
| EtherNet/IP | `enip` | TCP and UDP | ✅ | OpENer |
| BACnet/IP | `bacnet` | UDP | — (TCP only) | bacnet-stack |
| PROFINET IO | `profinet` | UDP | — (TCP only) | — |
| DNP3 | `dnp3` | TCP | ✅ | opendnp3 |
| IEC 60870-5-104 | `iec104` | TCP | ✅ | lib60870 |
| OCPP | `ocpp` | TCP, WebSocket | ✅ | The Mobility House ocpp |
| IEEE 2030.5 | `ieee2030.5` | TCP, TLS | — | GridAPPS-D, Envoy ¹ |
| OpenADR | `openadr` | TCP | — | OpenLEADR |
| CAN over TCP | `can` | TCP | ✅ | — |

¹ Skipped unless the sibling `*-interop` repository, with its fixtures or PKI, is checked out beside go-otfp.
