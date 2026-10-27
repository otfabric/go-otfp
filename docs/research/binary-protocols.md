# Research notes: binary OT protocols

Facts from the OT Fabric sibling repositories behind the binary
fingerprinters. Library versions: go-modbus v1.7.1, go-sunspec v0.6.0,
go-dnp3 v1.4.1, go-iec104 v0.0.2, go-opcua v1.25.0, go-bacnet v0.4.0 (client
only), go-profinet v0.1.2.

## Modbus TCP
- Positive: normal reply or exceptions 02/03/04/05/06/08 (go-modbus internal/protocol/detect.go);
  any well-formed exception FC|0x80 code 0x01-0x0B proves Modbus.
- Liveness: FC03 addr 0 qty 1 `00 01 00 00 00 06 01 03 00 00 00 01`.
- Identity: FC43/14 basic stream `.. 01 2B 0E 01 00`; reply `2B 0E 01 <conf> <more> <next> <n> {id len value}`;
  page while more=0xFF using next id.
- Unknown FC: digitalpetri/NModbus close, libmodbus delays, go-modbus answers exception 01.
  Wrong unit: libmodbus serves, pymodbus exc 4, digitalpetri/NModbus silent, go-sunspec exc 0x0B.
  One probe per connection; reconnect after RST. FC17 breaks NModbus/tokio-modbus: never send.
- Interop modbus-interop v0.2.0: libmodbus, pymodbus, digitalpetri, nmodbus, tokiomodbus;
  digests go-modbus/interop/harness.go:39-45; `server --fixture /fixtures/baseline/fixture.json` port 1502.
  Only pymodbus/tokiomodbus serve FC43. Fixture identity "otfabric" / "MBI-BASELINE" / "1.0".

## SunSpec
- Marker "SunS" (0x5375 0x6E53) via FC03 qty 2 at 40000, 0, 50000 (+ off-by-one variants);
  some devices use FC04 instead.
- Model 1 at base+2: ID 1, L 66 (or 65). Offsets from base: Mn +4 (16 regs), Md +20 (16), Opt +36 (8),
  Vr +44 (8), SN +52 (16), DA +68 (1). One read: FC03 base+2 qty 68.
- In-process: sunspec.NewServer(&ServerOptions{UnitID:1, BaseAddress:40000}, ServerModel{ID:1, Values:...}) is a
  modbus.RequestHandler; modbus.NewServer(&ServerConfig{URL:"tcp://addr"}, h).Start()/Stop() (URL only, pick port).

## DNP3
- REQUEST_LINK_STATUS (ctrl 0xC9). To outstation 10 from master 1: `05 64 05 C9 0A 00 01 00 FE DA`;
  to self address 0xFFFC: `05 64 05 C9 FC FF 01 00 8C 0E`. Reply LINK_STATUS ctrl 0x0B (or 0x1B DFC):
  `05 64 05 0B 01 00 0A 00 6D ED`; outstation address = Src (bytes 6-7 LE). Verify header CRC.
- Identity: READ g0v254 qualifier 06, unconfirmed user data ctrl 0xC4:
  `05 64 0B C4 0A 00 01 00 AC D1 C0 C0 01 00 FE 06 5D B9`; response FC 0x81, objects
  [var][type][len][data], visible string type 1. Variations: 242 sw version, 243 hw version,
  247 user name, 248 serial, 250 product/model, 252 manufacturer.
- Broadcast 0xFFFD-F gets no reply. Outstations answer only configured masters (interop: outstation
  1024, master 1). dnp3ctl discover bursts link status to candidate addresses 10, 65532; reads up to 8 frames.
- Interop dnp3-interop v0.5.1 opendnp3/dscsystems/dnp3py pinned in go-dnp3/interop/harness.go; stepfunc unpublished.
- In-process: server.New(WithAddress(10), WithSelfAddress(true), WithAttributes(map[uint8]app.Attribute{...})); Serve(ln); Close().

## IEC 60870-5-104
- TESTFR act `68 04 43 00 00 00` -> con `68 04 83 00 00 00` (answered in any state; must be 0x83, not echo).
  STARTDT act 07 -> con 0B; STOPDT act 13 -> con 23.
- I-frame before STARTDT closes the connection. Station may send TESTFR act on idle links (t3).
- Identity weak: CA via GI `68 0E 00 00 00 00 64 01 06 00 FF FF 00 00 00 14` (heavy: whole process image).
- Interop iec104-interop v0.2.0 lib60870/openmuc/wendy512, digests go-iec104/interop/harness.go:35-40, port 2404, CA 1.
- In-process: server.New(server.NewMux(), WithCommonAddrs(1)); Serve(ln); Close().

## OPC UA
- HEL must carry an EndpointUrl `opc.tcp://host:port[/path]`; go-opcua answers ERR BadTcpEndpointUrlInvalid
  (0x80830000) to a null URL. ERR body {u32 code, String reason}. ACK 28 bytes.
- Validate MessageSize == len and chunk type 'F'.
- Identity: OPN SecurityPolicy None + GetEndpoints (NodeId 428 req / 431 resp; FindServers 422/425;
  ServiceFault 397; OPN req 446 resp 449) -> ApplicationDescription (ApplicationUri, ProductUri, ApplicationName).
- Interop opcua-interop v0.16.0 open62541/milo/async-opcua/dotnet/node-opcua/asyncua; digests in
  go-opcua/interop/*harness_test.go; `server --fixture /fixtures/baseline.json`, path /opcua-interop.
- In-process: server.New(ListenOn("127.0.0.1:0"), EndPoint("127.0.0.1",0), EnableSecurity("None", ua.MessageSecurityModeNone),
  EnableAuthMode(ua.UserTokenTypeAnonymous), ServerName, ManufacturerName, ProductName, SoftwareVersion); Start(ctx); Port(); Close().

## BACnet/IP (UDP 47808)
- Unicast Who-Is `81 0A 00 08 01 00 10 08` (NPDU control 0x00). I-Am:
  `81 0A 00 14 01 00 10 00 C4 02 00 04 D2 22 05 C4 91 03 21 0F` (device 1234, vendor 15).
- Devices often broadcast I-Am to port 47808, never reaching an ephemeral socket: prefer confirmed
  ReadProperty of wildcard device 4194303 Object_Identifier `81 0A 00 11 01 04 00 05 01 0C 0C 02 3F FF FF 19 4B`
  (BACpypes3 rejects wildcard -> fall back to Who-Is). Then RPM vendor-name 121, vendor-id 120, model-name 70,
  firmware-revision 44, application-software-version 12, object-name 77.
- Require NPDU version 0x01 and APDU type I-Am/ComplexACK/Error/Reject/Abort; BVLC-Result `81 00 00 06 xx xx` valid.
- go-bacnet has no server. Interop bacnet-interop v0.10.0 images pinned in go-bacnet/interop/bacnet-interop-pin.json;
  vendor-id 999, device 1234 "InteropDevice".

## PROFINET (UDP 34964, DCE/RPC CL v4)
- CL header 80 bytes: 04 | ptype | flags1 | flags2 | drep 10 00 00 | serial_hi | object | interface | activity |
  boot | ifver | seq | opnum | ihint FFFF | ahint FFFF | len | fragnum | auth 0 | serial_lo.
  ptypes: 0 request, 1 ping, 2 response, 3 fault, 5 nocall, 6 reject.
- PNIO device interface DEA00001-6C97-11D1-8271-00A02442DF7D; EPM e1af8308-5d1f-11c9-91a4-08002b14a0fa.
  go-profinet answers PING with NOCALL, EPM with REJECT nca_unk_if 0x1C010003.
- Identity: ReadImplicit opnum 5, object nil (go-profinet) or DEA00000-6C97-11D1-8271-{instance}{device}{vendor}
  (real devices); IODReadReqHeader block 0x0009 index 0xAFF0 -> I&M0 block 0x0020 (VendorID, OrderID[20], Serial[16], HW, SW).
- Match on ptype in {2,3,5,6} + echoed activity UUID. Never send Connect/Write/Control.
- DCP Identify is Layer 2, needs privileges: out of scope.
- In-process: device.New(device.Config{Model, Mux: l2.NewMux(vnet endpoint), StationName, ListenPacket: lp, DisableLLDP, NoResponseDelay});
  RPCAddr(); Close(). Interop images local-only (pnet GPL; pnio-rs published).

## IEC 61850 MMS (TCP 102)
- CC alone is not MMS (S7 and any ISO-on-TCP stack confirm too): complete Session CONNECT
  (SI 0x0D) / Presentation CP / ACSE AARQ (MMS app context 1.0.9506.2.3) / MMS Initiate (0xA8).
  Identify: confirmed request service tag 0x82 empty; response 0xA2 {vendor, model, revision}.
- go-mms v1.0.7: mms.NewServer(ServerOptions{}); HandleIdentify(fn); iso.Listen("127.0.0.1:0");
  ListenAndServe(ctx, ln). go-cotp accepts any called TSAP unless WithCalledTSelector.
- mms-interop v0.1.4: ghcr.io/otfabric/mms-interop-libiec61850 (GPL) / -iec61850bean, no pinned digests;
  `IMAGE --fixture /fixtures/mms/interop.json --port 1102`; vendor "OTFabric".

## Siemens S7comm (TCP 102)
- go-s7comm v0.7.5 has no server: only snap7-interop images (native Snap7 / python-snap7, rack 0 slot 2,
  PDU 480): native @sha256:66e3826813005bfacb8510ce5de33119315499325b35bf616dcf61de0506a342,
  python @sha256:a53c81d7b6acb042a010fc1c9932f1f92b8c337e2555e3200938f4b0b46e3d54;
  env SNAP_INTEROP_FIXTURE=/fixtures/basic-db.compiled.json SNAP_INTEROP_LISTEN_ADDRESS=0.0.0.0 SNAP_INTEROP_PORT=102.
- TSAPs: calling 0x0100 (PG), called 0x03xx (rack<<5|slot; S7 basic), old otfp used 0x0102. CR fixture
  `11 e0 ... c1 02 01 00 c2 02 03 01 c0 01 0a`.
- Setup Communication: header 0x32 ROSCTR 0x01, param f0 00 amq amq pdu; ACK ROSCTR 0x03.
- SZL read (Userdata 0x07): param `00 01 12 04 11 44 01 00`, data `FF 09 00 04 <id> <index>`;
  0x0011 module ID (order number bytes [2:22]), 0x001C component ID (module name [2:26], plant [26:34]).
- S7comm-plus (S7-1200/1500) uses protocol id 0x72; not implemented anywhere in the repos.
- s7commctl outcome taxonomy: TCP-only / COTP accepted / S7 setup accepted.

## EtherNet/IP (TCP+UDP 44818)
- Header 24 bytes LE: command, length, session, status, context[8], options. ListIdentity 0x0063
  (no session), ListServices 0x0004, RegisterSession 0x0065 (version 1, options 0; options != 0 discarded).
- ListIdentity CPF item 0x000C: protocol version u16, sockaddr 16 (BE), vendor u16, device type u16,
  product code u16, revision maj/min, status u16, serial u32, product name (short string), state u8.
- go-ethernetip v0.3.2: server.New(server.WithIdentity(cip.Identity{...}), server.WithIOAddress("127.0.0.1:0"));
  Listen("127.0.0.1:0"); go Serve(); Addr()/UDPAddr(); Close().
- ethernetip-interop v0.5.0 servers opener, cpppo, libplctag (TCP only), gologix (TCP only); digests in
  go-ethernetip/interop/harness_test.go:47-59; `server [--fixture] [--port]`.
