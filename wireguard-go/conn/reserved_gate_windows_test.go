/* SPDX-License-Identifier: MIT
 *
 * Coverage for the WinRingBind hasReserved gate; see reserved_gate_test.go.
 */

package conn

import (
	"net/netip"
	"testing"
)

func TestWinRingBindHasReserved(t *testing.T) {
	bind, ok := NewWinRingBind(nil).(*WinRingBind)
	if !ok {
		t.Skip("registered I/O unavailable, NewWinRingBind fell back to StdNetBind")
	}
	if bind.hasReserved() {
		t.Fatal("fresh bind must report no reserved value")
	}

	ep := netip.MustParseAddrPort("127.0.0.1:51820")
	bind.SetReservedForEndpoint(ep, [3]byte{0, 0, 0})
	if bind.hasReserved() {
		t.Fatal("all-zero reserved must not count as reserved")
	}

	bind.SetReservedForEndpoint(ep, [3]byte{0x12, 0, 0})
	if !bind.hasReserved() {
		t.Fatal("non-zero reserved must count as reserved")
	}

	bind.SetReservedForEndpoint(ep, [3]byte{0, 0, 0})
	if bind.hasReserved() {
		t.Fatal("reserved reset to zero must disarm the clear")
	}
}
