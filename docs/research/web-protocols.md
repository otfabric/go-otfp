# Research notes: OCPP, IEEE 2030.5, OpenADR

Facts gathered from the OT Fabric sibling repositories (go-ocpp v0.1.3,
go-ieee20305 v0.5.2 + tlsccm v0.3.0, go-openadr v0.4.0 and their -interop
repos) that the web-protocol fingerprinters rely on.

## OCPP (WebSocket)
- Subprotocol tokens: ocpp1.6, ocpp2.0.1, ocpp2.1 (exact, case-sensitive).
- Station id = last path segment; empty -> 404. Auth before subprotocol: unknown id 404,
  bad creds 401 `WWW-Authenticate: Basic realm="OCPP"`. No supported subprotocol -> 101
  without Sec-WebSocket-Protocol then close 1008. Otherwise 101 with first offered token.
- Probe: upgrade to /ocpp/<random id ≤48 chars [A-Za-z0-9*-_=+|@.]> offering
  "ocpp2.1, ocpp2.0.1, ocpp1.6"; 101 + echoed token = certain; close immediately.
- chargetime: every refusal 404; its 1.6 server accepts no subprotocol. lorenzodonini: 401 only.
- Interop: ocpp-interop v0.4.1; servers mobilityhouse (1.6/2.0.1/2.1), chargetime, lorenzodonini
  (1.6/2.0.1), citrineos (slow). Digests in go-ocpp/interop/harness.go:37-41.
  `docker run -p 127.0.0.1:P:9000 IMG server --version 1.6|2.0.1|2.1`; known station OT-FABRIC-TEST-001.
- In-process: server.New(WithHandler(ocpp.V16, ocpp16.CentralSystem(ocpp16.UnimplementedCentralSystemHandler{})), ..., WithoutAuthentication()); Serve(ln); Shutdown(ctx).

## IEEE 2030.5
- Namespace urn:ieee:std:2030.5:ns, media type application/sep+xml.
- Proper servers require client certs (RequireAnyClientCert); without cert -> TLS alert
  (1.3 certificate_required) or 403 empty body at HTTP level; 406 when Accept lacks XML.
- GET /dcap -> <DeviceCapability xmlns="urn:ieee:std:2030.5:ns" href="/dcap" pollRate=...>.
- GridAPPS-D offers only TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 (crypto/tls can't); Envoy (HAProxy) CCM_8 + GCM.
- Unauthenticated evidence: ServerHello selecting CCM_8 to a raw ClientHello, ECDSA cert,
  CertificateRequest; mDNS _smartenergy._tcp.
- Interop: ieee20305-interop v0.2.0; servers gridappsd, envoy; digests go-ieee20305/interop/images.go:12-21;
  `docker run -p 127.0.0.1::443 -v DIR:/tls:ro IMG server --version 2018 --tls-dir /tls/server`.
- In-process: server.New(server.Config{}) is an http.Handler; security.TestCA/TestServerCert/ServerTLSConfig.

## OpenADR
- go-openadr implements OpenADR 3.1.0 only; 2.0b exists nowhere in the repos (spec knowledge only).
- OpenADR 3: GET /auth/server unauthenticated -> {"tokenURL": ...} (501 if unset).
  GET /programs no token -> 401 `WWW-Authenticate: Bearer` + JSON problem {"title","status","detail"};
  AllowAnonymous -> 200 JSON array. OpenLEADR: 401 without token, 403 forged.
- 2.0b: POST /OpenADR2/Simple/2.0b/EiRegisterParty oadrQueryRegistration -> oadrCreatedPartyRegistration;
  ns http://openadr.org/oadr-2.0b/2012/07.
- Interop: openadr-interop v0.4.0 server openleadr
  ghcr.io/otfabric/openadr-interop-openleadr@sha256:b8221b89983a5b7cdc69cea92443e05416336ad1ddcd843250770d65950b4fb2
  `server --fixture /fixtures/baseline/fixture.json --public-url http://127.0.0.1:P`, port 8080.
- In-process: server.New(server.Config{Store: storage.NewMemory(), Validator: ..., TokenURL: ...}) http.Handler.
