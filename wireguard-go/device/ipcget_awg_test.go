/* SPDX-License-Identifier: MIT
 *
 * The AmneziaWG get path: IpcGet must report every obfuscation parameter it
 * accepted, including i1..i5 and the AmneziaWG 3.x keys.
 */

package device

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

func TestIpcGetReportsAWGParams(t *testing.T) {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}

	bind, _ := newChanBindPair()
	dev := NewDevice(context.Background(), newChanTun(), bind, NewLogger(LogLevelError, "dev: "), 1)
	t.Cleanup(dev.Close)

	hpKey := strings.Repeat("ab", HeaderCipherKeySize)

	set := strings.Join([]string{
		"private_key=" + hex.EncodeToString(sk[:]),
		"jc=4", "jmin=40", "jmax=70",
		"s1=15", "s2=20", "s3=25", "s4=30",
		"h1=1", "h2=2", "h3=3", "h4=100-200",
		"i1=<b 0xf6a1>", "i3=<r 8>", "i5=<t>",
		"header_protection_key=" + hpKey,
		"content_padding_addition=10-100",
		"rekey_after_time=100-120", "rekey_timeout=3-7", "reject_after_time=150-180",
		"keepalive_timeout=5-15", "max_handshake_attempts=15-20",
		"random_trailers=1", "disable_cookies=1",
		"",
	}, "\n")
	if err := dev.IpcSet(set); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}

	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}

	for _, want := range []string{
		"jc=4\n", "jmin=40\n", "jmax=70\n",
		"s1=15\n", "s2=20\n", "s3=25\n", "s4=30\n",
		"h1=1\n", "h2=2\n", "h3=3\n", "h4=100-200\n",
		"i1=<b 0xf6a1>\n", "i3=<r 8>\n", "i5=<t>\n",
		"header_protection_key=" + hpKey + "\n",
		"content_padding_addition=10-100\n",
		"rekey_after_time=100-120\n", "rekey_timeout=3-7\n", "reject_after_time=150-180\n",
		"keepalive_timeout=5-15\n", "max_handshake_attempts=15-20\n",
		"random_trailers=1\n", "disable_cookies=1\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("IpcGet missing %q:\n%s", want, got)
		}
	}

	// Unset I-slots must stay absent, not surface as empty values.
	for _, absent := range []string{"i2=", "i4="} {
		if strings.Contains(got, absent) {
			t.Errorf("IpcGet reported unset %q", absent)
		}
	}
}

// A plain WireGuard device reports none of the unset AmneziaWG keys. As in
// amneziawg-go, h1..h4 always hold a value (the WireGuard message types are
// their default) and the two booleans are always reported.
func TestIpcGetPlainWireGuard(t *testing.T) {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}

	bind, _ := newChanBindPair()
	dev := NewDevice(context.Background(), newChanTun(), bind, NewLogger(LogLevelError, "dev: "), 1)
	t.Cleanup(dev.Close)

	if err := dev.IpcSet("private_key=" + hex.EncodeToString(sk[:]) + "\n"); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	got, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	for _, absent := range []string{
		"jc=", "jmin=", "jmax=", "s1=", "s2=", "s3=", "s4=", "i1=",
		"header_protection_key=", "content_padding_addition=", "rekey_after_time=", "rekey_timeout=",
		"reject_after_time=", "keepalive_timeout=", "max_handshake_attempts=",
	} {
		if strings.Contains(got, absent) {
			t.Errorf("plain WireGuard IpcGet reported %q:\n%s", absent, got)
		}
	}
	for _, want := range []string{"h1=1\n", "h2=2\n", "h3=3\n", "h4=4\n", "random_trailers=0\n", "disable_cookies=0\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("plain WireGuard IpcGet lost the default %q:\n%s", want, got)
		}
	}
}
