// SPDX-License-Identifier: MIT

package httpx

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

const (
	chunkedHead = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
	lengthHead  = "HTTP/1.1 200 OK\r\nContent-Length: %s\r\n\r\n"
)

// The sizes a response declares are compared with what was read, never
// added to an offset first: the outcome is the same where int has 32 bits
// (linux/386 and linux/arm, the nightly test-386 job) and where it has 64.
// A size that is not a number, or does not fit the field, is not a frame; a
// size larger than what arrived is a frame that is not complete.
func TestFramerDeclaredSizes(t *testing.T) {
	const maxInt32 = math.MaxInt32
	chunk := func(size string, data string) string { return chunkedHead + size + "\r\n" + data }
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"chunk of 0", chunk("0", "\r\n"), len(chunk("0", "\r\n"))},
		{"chunk of 1, complete", chunk("1", "a\r\n0\r\n\r\n"), len(chunk("1", "a\r\n0\r\n\r\n"))},
		{"chunk of 1, data missing", chunk("1", ""), 0},
		{"chunk of 1, CRLF missing", chunk("1", "a"), 0},
		{"chunk one larger than what arrived", chunk("4", "abc\r\n"), 0},
		{"chunk of 2^31-2", chunk(strconv.FormatInt(maxInt32-1, 16), "abc"), 0},
		{"chunk of 2^31-1", chunk(strconv.FormatInt(maxInt32, 16), "abc"), 0},
		{"chunk of 2^31-1 after a complete chunk", chunk("3", "abc\r\n"+strconv.FormatInt(maxInt32, 16)+"\r\nabc"), 0},
		{"chunk of 2^31", chunk(strconv.FormatInt(maxInt32+1, 16), "abc"), -1},
		{"chunk of 2^32", chunk("100000000", "abc"), -1},
		{"chunk of 2^63-1", chunk("7fffffffffffffff", "abc"), -1},
		{"chunk of 2^64", chunk("10000000000000000", "abc"), -1},
		{"negative chunk", chunk("-1", "abc"), -1},
		{"chunk size that is not hexadecimal", chunk("xyz", "abc"), -1},
		{"content length 0", fmt.Sprintf(lengthHead, "0"), len(fmt.Sprintf(lengthHead, "0"))},
		{"content length 1", fmt.Sprintf(lengthHead, "1") + "a", len(fmt.Sprintf(lengthHead, "1")) + 1},
		{"content length 2^31-1", fmt.Sprintf(lengthHead, strconv.Itoa(maxInt32)), -2}, // see below
		{"content length of the largest int", fmt.Sprintf(lengthHead, strconv.Itoa(math.MaxInt)), -1},
		{"content length one above the largest int", fmt.Sprintf(lengthHead, strconv.FormatUint(uint64(math.MaxInt)+1, 10)), 0},
		{"negative content length", fmt.Sprintf(lengthHead, "-1"), 0},
	}
	for _, tc := range cases {
		got := Framer([]byte(tc.in))
		want := tc.want
		if want == -2 {
			// The header plus 2^31-1 octets: a length that fits an int of
			// 64 bits, and is no frame where int has 32.
			want = -1
			if strconv.IntSize == 64 {
				want = len(tc.in) + maxInt32
			}
		}
		if got != want {
			t.Errorf("%s: Framer = %d, want %d", tc.name, got, want)
		}
	}
}

// Framer is given every prefix of the responses above while they arrive: no
// prefix makes it return a length beyond what the complete response has.
func TestFramerNeverRunsPastTheResponse(t *testing.T) {
	for _, full := range []string{
		chunkedHead + "5\r\nhello\r\n6;x=1\r\n world\r\n0\r\nT: 1\r\n\r\n",
		chunkedHead + strconv.FormatInt(math.MaxInt32, 16) + "\r\n" + strings.Repeat("a", 64),
		fmt.Sprintf(lengthHead, "5") + "hello",
	} {
		for i := 0; i <= len(full); i++ {
			if n := Framer([]byte(full[:i])); n > len(full) {
				t.Fatalf("prefix of %d octets of %q: Framer = %d", i, full, n)
			}
		}
	}
}

func FuzzFramer(f *testing.F) {
	f.Add([]byte(chunkedHead + "5\r\nhello\r\n0\r\n\r\n"))
	f.Add([]byte(chunkedHead + "7fffffff\r\nabc"))
	f.Add([]byte(fmt.Sprintf(lengthHead, "2") + "ok"))
	f.Add([]byte("HTTP/1.1 101 Switching Protocols\r\n\r\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		n := Framer(b)
		// A complete chunked or 1xx/204/304 message ends within what was
		// read; only a Content-Length may announce more than arrived.
		if n < -1 {
			t.Fatalf("Framer = %d", n)
		}
		if n > len(b) && !strings.Contains(strings.ToLower(string(b)), "content-length") {
			t.Fatalf("Framer = %d for %d octets without a Content-Length", n, len(b))
		}
	})
}
