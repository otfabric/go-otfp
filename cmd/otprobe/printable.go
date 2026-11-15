// SPDX-License-Identifier: MIT

package main

import (
	"io"
	"strconv"
	"unicode"
	"unicode/utf8"
)

// The text and table formats are read on a terminal, so everything they
// print is text: a character that is not graphic (a control or format
// character, a line or paragraph separator) and an octet that is not UTF-8
// are written as Go escapes (\x1b, \n, \u009b, \u202e, \xff). The library's
// own fingerprinters deliver text only; this covers a result from a
// fingerprinter outside it, and what an error message quotes.

// printable returns s with every character that is not graphic escaped. A
// value printed from a result goes through it: a line feed inside a value
// is escaped too, so a value cannot start a line of the output.
func printable(s string) string {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || !unicode.IsGraphic(r) {
			return string(appendPrintable(make([]byte, 0, len(s)+8), []byte(s), false))
		}
		i += size
	}
	return s
}

// appendPrintable appends src to dst with the escapes; lf lets a line feed
// through.
func appendPrintable(dst, src []byte, lf bool) []byte {
	for len(src) > 0 {
		r, size := utf8.DecodeRune(src)
		switch {
		case r == utf8.RuneError && size == 1:
			dst = append(dst, '\\', 'x', hexDigits[src[0]>>4], hexDigits[src[0]&0x0F])
		case unicode.IsGraphic(r), lf && r == '\n':
			dst = append(dst, src[:size]...)
		default:
			q := strconv.AppendQuoteRuneToASCII(nil, r) // '\x1b', '\u202e'
			dst = append(dst, q[1:len(q)-1]...)
		}
		src = src[size:]
	}
	return dst
}

const hexDigits = "0123456789abcdef"

// printableWriter is the last step before the terminal: it writes what it
// is given with the escapes, line feeds apart, so that an output line that
// did not pass its values through printable still reaches the terminal as
// text. Every Write is taken as whole characters, which is how fmt and
// text/tabwriter write.
type printableWriter struct{ w io.Writer }

func (p printableWriter) Write(b []byte) (int, error) {
	if _, err := p.w.Write(appendPrintable(make([]byte, 0, len(b)), b, true)); err != nil {
		return 0, err
	}
	return len(b), nil
}
