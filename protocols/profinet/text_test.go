// SPDX-License-Identifier: MIT

package profinet

import "testing"

// The software revision prefix of I&M0 is one visible ASCII character; any
// other octet is shown as 'V'.
func TestSoftwareRevisionPrefix(t *testing.T) {
	for prefix, want := range map[byte]string{
		0x00: "V1.2.3", 0x1F: "V1.2.3", 0x20: " 1.2.3", 'V': "V1.2.3", 'R': "R1.2.3", 0x7E: "~1.2.3",
		0x7F: "V1.2.3", 0x80: "V1.2.3", 0x9B: "V1.2.3", 0xFF: "V1.2.3",
	} {
		body := []byte{0x01, 0x00, 0xF0, 0x00}
		body = append(body, make([]byte, 36)...)
		body = append(body, 0, 1, prefix, 1, 2, 3, 0, 0, 0, 0)
		im, ok := decodeIM0(body)
		if !ok || im.software != want {
			t.Errorf("prefix 0x%02X: software %q (%v), want %q", prefix, im.software, ok, want)
		}
	}
}
