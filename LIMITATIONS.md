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
- **CANopen**: only CiA 309-3 ASCII gateways over TCP, not raw CAN or
  CANopen over SLCAN. Identify reads one node (the gateway's default node, or
  `canopen.Config.Node`); CANopenNode has no default node until a client sets
  one, so identify then reports the gateway only. Node identity reads are
  SDO uploads on the bus and need read-only probes. The version-record form of
  `info version` is checked against the specification only: CANopenNode
  answers ERROR:100. canopend serves one TCP client at a time; concurrent
  probes queue.
- **KNXnet/IP**: Secure is recognised only when the server advertises it in
  the description (security family 0x09 or DIB 0x06); calimero-server 3.0-M1
  in secure mode does neither and is reported as `tunnelling-v2+routing`.
  Finding Secure otherwise would take a SESSION_REQUEST, which is out of
  scope. Multicast search (224.0.23.12) is not used. A silent UDP port costs
  two timeouts: route back, then the explicit HPAI.
- **MQTT**: a broker that requires credentials is detected from its CONNACK
  refusal, but not identified further (no credentials are sent). `$SYS`
  topics are broker-specific: HiveMQ CE publishes none, so it is identified
  by its MQTT 5 CONNACK properties only. A broker that closes on both MQTT
  3.1.1 and 5 (MQTT 3.1 only, or one that drops unknown clients) is not
  detected.
- **Sparkplug B**: detection is passive observation of the broker. Edge-node
  births are not retained, so an infrastructure whose host application
  publishes no STATE and whose edge nodes are idle during the window (two
  seconds) is reported as no match. A broker whose ACLs refuse the
  subscriptions is reported as no match. Each scan of an MQTT broker without
  Sparkplug traffic waits the whole window.
- **IEEE 2030.5**: Go's TLS has no `TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8`, so
  detection reads the server's plaintext flight without completing a
  handshake. Without a device certificate the data model cannot be read; a
  server that chooses CCM_8 is detected but GET /dcap is not read.
- **Below `MatchThreshold`** (0.50) a result is a hint, not a match.

## Effect on the target

Probing is active network traffic: probes may raise alerts in OT intrusion
detection systems, and some open protocol state before the connection is
closed (S7 Setup Communication, STARTDT in IEC 104 identify mode, the OCPP
WebSocket upgrade, the MQTT CONNECT and, for Sparkplug B and MQTT identify,
QoS 0 subscriptions in a clean session the broker discards on DISCONNECT;
CANopen identify sends SDO uploads on the bus). See [SECURITY.md](SECURITY.md) for `--safe` and the
pacing options.
