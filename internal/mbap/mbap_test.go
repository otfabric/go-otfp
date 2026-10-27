// SPDX-License-Identifier: MIT

package mbap

import "testing"

func TestRequestParseCheck(t *testing.T) {
	req := ReadRegisters(0x1234, 1, FCReadHoldingRegisters, 0, 2)
	if len(req) != HeaderLen+5 {
		t.Fatalf("len %d", len(req))
	}
	// A matching normal response.
	resp := Request(0x1234, 1, FCReadHoldingRegisters, 4, 0, 1, 0, 2)
	r, err := Parse(resp)
	if err != nil || r.Check(0x1234, FCReadHoldingRegisters) != nil {
		t.Fatalf("%+v %v", r, err)
	}
	regs, err := Registers(r.Data, 2)
	if err != nil || regs[0] != 1 || regs[1] != 2 {
		t.Fatalf("regs %v %v", regs, err)
	}
}

func TestException(t *testing.T) {
	resp := Request(0x1234, 1, FCReadHoldingRegisters|ExceptionFlag, 0x02)
	r, _ := Parse(resp)
	if !r.IsException() || r.Check(0x1234, FCReadHoldingRegisters) != nil || r.Exception != 0x02 {
		t.Fatalf("%+v", r)
	}
	if ExceptionName(0x02) == "" || ExceptionName(0x99) == "" {
		t.Fatal("name")
	}
	bad := Request(0x1234, 1, FCReadHoldingRegisters|ExceptionFlag, 0x55)
	rb, _ := Parse(bad)
	if rb.Check(0x1234, FCReadHoldingRegisters) == nil {
		t.Fatal("0x55 is not a Modbus exception code")
	}
}

func TestParseErrors(t *testing.T) {
	for _, b := range [][]byte{
		nil,
		{0, 0, 0, 1, 0, 2, 1, 3}, // protocol id != 0
		{0, 0, 0, 0, 0, 9, 1, 3}, // length mismatch
	} {
		if _, err := Parse(b); err == nil {
			t.Fatalf("% x accepted", b)
		}
	}
}

func TestFramer(t *testing.T) {
	resp := Request(1, 1, 3, 2, 0, 1)
	if Framer(resp) != len(resp) {
		t.Fatal("framer")
	}
	if Framer([]byte{0, 0, 0, 1, 0, 2, 1}) != -1 {
		t.Fatal("protocol id != 0 should be rejected")
	}
}

func FuzzParse(f *testing.F) {
	f.Add(Request(1, 1, 3, 4, 0, 1, 0, 2))
	f.Fuzz(func(t *testing.T, b []byte) {
		if r, err := Parse(b); err == nil {
			_ = r.Check(r.TID, r.FC)
			_, _ = Registers(r.Data, 1)
		}
	})
}

func TestNamesAndChecks(t *testing.T) {
	for code := byte(1); code <= 0x0B; code++ {
		if ExceptionName(code) == "" {
			t.Errorf("code %d", code)
		}
	}
	r, _ := Parse(Request(7, 1, 0x03, 2, 0, 1))
	if r.Check(8, 0x03) == nil || r.Check(7, 0x04) == nil {
		t.Fatal("TID and function mismatches")
	}
	if _, err := Parse(Request(7, 1, 0x83, 1, 2)); err == nil {
		t.Fatal("exception with two data bytes")
	}
	if Framer([]byte{0, 0, 0, 0, 0x01, 0x10, 1}) != -1 {
		t.Fatal("length beyond the largest ADU")
	}
	if _, err := Registers([]byte{4, 0, 1}, 2); err == nil {
		t.Fatal("short register payload")
	}
}
