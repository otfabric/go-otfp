// SPDX-License-Identifier: MIT

// Package mbap frames Modbus TCP application data units (MBAP header plus
// PDU), shared by the Modbus and SunSpec fingerprinters.
package mbap

import (
	"encoding/binary"
	"fmt"

	"github.com/otfabric/go-otfp/internal/wire"
)

// HeaderLen is the MBAP header length: transaction ID, protocol ID, length,
// unit ID.
const HeaderLen = 7

// MaxADU is the largest Modbus TCP ADU.
const MaxADU = 260

// Function codes and the exception flag.
const (
	FCReadHoldingRegisters = 0x03
	FCReadInputRegisters   = 0x04
	FCEncapsulated         = 0x2B
	MEIReadDeviceID        = 0x0E
	ExceptionFlag          = 0x80
)

// Request returns an ADU.
func Request(tid uint16, unit byte, pdu ...byte) []byte {
	b := make([]byte, HeaderLen+len(pdu))
	binary.BigEndian.PutUint16(b[0:2], tid)
	binary.BigEndian.PutUint16(b[4:6], uint16(1+len(pdu)))
	b[6] = unit
	copy(b[7:], pdu)
	return b
}

// ReadRegisters returns an FC03 or FC04 request ADU.
func ReadRegisters(tid uint16, unit, fc byte, addr, qty uint16) []byte {
	return Request(tid, unit, fc, byte(addr>>8), byte(addr), byte(qty>>8), byte(qty))
}

// Framer reads one ADU.
var Framer = wire.FixedHeader(HeaderLen, func(h []byte) int {
	if h[2] != 0 || h[3] != 0 {
		return -1
	}
	n := int(binary.BigEndian.Uint16(h[4:6]))
	if n < 2 || n > MaxADU-6 {
		return -1
	}
	return 6 + n
})

// Response is a parsed response ADU.
type Response struct {
	TID  uint16
	Unit byte
	FC   byte
	// Exception is the exception code when FC has ExceptionFlag set.
	Exception byte
	// Data is the PDU after the function code.
	Data []byte
}

// IsException reports whether the response is an exception.
func (r Response) IsException() bool { return r.FC&ExceptionFlag != 0 }

// Parse validates the MBAP header of b and returns the response. It does
// not check the transaction ID or function code against a request; see
// Check.
func Parse(b []byte) (Response, error) {
	if len(b) < HeaderLen+1 {
		return Response{}, fmt.Errorf("%d bytes is shorter than an MBAP header and function code", len(b))
	}
	if pid := binary.BigEndian.Uint16(b[2:4]); pid != 0 {
		return Response{}, fmt.Errorf("protocol identifier 0x%04x, want 0", pid)
	}
	n := int(binary.BigEndian.Uint16(b[4:6]))
	if n < 2 || 6+n != len(b) {
		return Response{}, fmt.Errorf("MBAP length %d does not match %d bytes", n, len(b))
	}
	r := Response{
		TID:  binary.BigEndian.Uint16(b[0:2]),
		Unit: b[6],
		FC:   b[7],
		Data: b[8:],
	}
	if r.IsException() {
		if len(r.Data) != 1 {
			return r, fmt.Errorf("exception response with %d data bytes", len(r.Data))
		}
		r.Exception = r.Data[0]
	}
	return r, nil
}

// Check reports whether r answers a request with this transaction ID and
// function code: the IDs match, and the function code is the request's,
// possibly with ExceptionFlag carrying a standard exception code
// (0x01..0x0B).
func (r Response) Check(tid uint16, fc byte) error {
	if r.TID != tid {
		return fmt.Errorf("transaction ID 0x%04x, want 0x%04x", r.TID, tid)
	}
	switch r.FC {
	case fc:
		return nil
	case fc | ExceptionFlag:
		if r.Exception < 0x01 || r.Exception > 0x0B {
			return fmt.Errorf("exception code 0x%02x is not a Modbus exception", r.Exception)
		}
		return nil
	}
	return fmt.Errorf("function code 0x%02x does not answer 0x%02x", r.FC, fc)
}

// ExceptionName names the standard exception codes.
func ExceptionName(code byte) string {
	switch code {
	case 0x01:
		return "illegal function"
	case 0x02:
		return "illegal data address"
	case 0x03:
		return "illegal data value"
	case 0x04:
		return "server device failure"
	case 0x05:
		return "acknowledge"
	case 0x06:
		return "server device busy"
	case 0x08:
		return "memory parity error"
	case 0x0A:
		return "gateway path unavailable"
	case 0x0B:
		return "gateway target device failed to respond"
	}
	return fmt.Sprintf("exception 0x%02x", code)
}

// Registers decodes an FC03/FC04 response payload holding qty registers.
func Registers(data []byte, qty int) ([]uint16, error) {
	if len(data) < 1 || int(data[0]) != 2*qty || len(data) != 1+2*qty {
		return nil, fmt.Errorf("register response of %d bytes, want %d registers", len(data), qty)
	}
	out := make([]uint16, qty)
	for i := range out {
		out[i] = binary.BigEndian.Uint16(data[1+2*i:])
	}
	return out, nil
}
