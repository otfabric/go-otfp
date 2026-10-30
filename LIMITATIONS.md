# Limitations

What go-otfp does not do, or does with restrictions.

## Certification and evidence

- **Nothing here is certified**, and a match is no conformance statement.
- **Results are hints, not proof.** A result says how a peer answered, not
  what it is: any host can imitate the expected response. Do not base access
  decisions on a match ([SECURITY.md](SECURITY.md)).
- Fingerprinters were checked against reference implementations and
  container images ([INTEROPERABILITY.md](INTEROPERABILITY.md)), not recorded
  against physical devices.
- Interop images that need fixtures or a PKI (Snap7, open62541, the IEEE
  2030.5 servers) are skipped when the sibling `*-interop` repositories are
  not checked out beside go-otfp.
- The interop suite uses published adapters only: not the DNP3 Step Function
  I/O server nor the PROFINET p-net device.

## Scope of the probes

- **PROFINET**: the UDP DCE/RPC endpoint is fingerprinted. DCP Identify runs
  over raw Ethernet and is not used: it needs privileges and a local
  interface.
- **CAN**: only SLCAN (Lawicel) ASCII gateways exposed over TCP.
- **IEEE 2030.5**: Go's TLS has no `TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8`, so
  detection reads the server's plaintext flight without completing a
  handshake. Without a device certificate the data model cannot be read; a
  server that chooses CCM_8 is detected but GET /dcap is not read.
- **Below `MatchThreshold`** (0.50) a result is a hint, not a match.

## Effect on the target

Probing is active network traffic: probes may raise alerts in OT intrusion
detection systems, and some open protocol state before the connection is
closed (S7 Setup Communication, STARTDT in IEC 104 identify mode, the OCPP
WebSocket upgrade). See [SECURITY.md](SECURITY.md) for `--safe` and the
pacing options.
