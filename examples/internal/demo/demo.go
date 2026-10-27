// SPDX-License-Identifier: MIT

// Package demo runs small loopback devices for the examples, so that every
// example works offline. They implement just enough of each protocol to be
// fingerprinted; point the examples at a real device to probe it instead.
package demo

import (
	"encoding/binary"
	"net"
)

// Modbus starts a Modbus TCP device on 127.0.0.1 that answers Read Device
// Identification (vendor "OT Fabric", product code "DEMO-1", revision
// "1.2.0", product name "Demo PLC", model "D-100") and refuses every other
// function with "illegal function". It returns the device's address.
func Modbus() (string, func()) {
	objects := []string{"OT Fabric", "DEMO-1", "1.2.0", "https://otfabric.io", "Demo PLC", "D-100"}
	return serve(func(req []byte) []byte {
		if len(req) < 8 || req[2] != 0 || req[3] != 0 {
			return nil
		}
		tid, unit, fc := req[:2], req[6], req[7]
		pdu := []byte{fc | 0x80, 0x01}
		if fc == 0x2B && len(req) >= 11 && req[8] == 0x0E {
			pdu = []byte{0x2B, 0x0E, req[9], 0x82, 0x00, 0x00, byte(len(objects))}
			for i, v := range objects {
				pdu = append(pdu, byte(i), byte(len(v)))
				pdu = append(pdu, v...)
			}
		}
		resp := append([]byte{tid[0], tid[1], 0, 0, 0, 0, unit}, pdu...)
		binary.BigEndian.PutUint16(resp[4:], uint16(1+len(pdu)))
		return resp
	})
}

// IEC104 starts an IEC 60870-5-104 controlled station on 127.0.0.1 that
// confirms TESTFR, STARTDT and STOPDT.
func IEC104() (string, func()) {
	return serve(func(req []byte) []byte {
		if len(req) != 6 || req[0] != 0x68 || req[1] != 4 {
			return nil
		}
		// TESTFR, STARTDT and STOPDT act -> con.
		con := map[byte]byte{0x43: 0x83, 0x07: 0x0B, 0x13: 0x23}[req[2]]
		if con == 0 {
			return nil
		}
		return []byte{0x68, 0x04, con, 0, 0, 0}
	})
}

// serve answers each request on a loopback listener with answer(req); a nil
// answer closes the connection.
func serve(answer func([]byte) []byte) (string, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close() //nolint:errcheck
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					out := answer(buf[:n])
					if out == nil {
						return
					}
					if _, err := c.Write(out); err != nil {
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}
