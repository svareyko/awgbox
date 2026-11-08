/* SPDX-License-Identifier: MIT
 *
 * Coverage for the hasReserved gate in front of the receive-side clear of
 * bytes 1-3 (the Cloudflare WARP "reserved" field). With AmneziaWG the first
 * four bytes of a datagram are a little-endian magic header (H1-H4) or random
 * S1-S4 padding, so the receive paths may clear bytes 1-3 only when a
 * non-zero reserved value is configured for some endpoint.
 */

package conn

import (
	"bytes"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

func stdNetBindForTest(t *testing.T) *StdNetBind {
	t.Helper()
	b, ok := NewStdNetBind(nil).(*StdNetBind)
	if !ok {
		t.Fatalf("NewStdNetBind did not return *StdNetBind")
	}
	return b
}

func TestStdNetBindHasReserved(t *testing.T) {
	b := stdNetBindForTest(t)
	if b.hasReserved() {
		t.Fatal("fresh bind must report no reserved value")
	}

	ep := netip.MustParseAddrPort("127.0.0.1:51820")

	// An all-zero reserved value is indistinguishable from "unset" and must
	// not arm the clear.
	b.SetReservedForEndpoint(ep, [3]byte{0, 0, 0})
	if b.hasReserved() {
		t.Fatal("all-zero reserved must not count as reserved")
	}

	// Any non-zero byte arms the clear.
	b.SetReservedForEndpoint(ep, [3]byte{0, 0, 1})
	if !b.hasReserved() {
		t.Fatal("non-zero reserved (byte 3) must count as reserved")
	}

	// Resetting the only non-zero value to zero disarms it again.
	b.SetReservedForEndpoint(ep, [3]byte{0, 0, 0})
	if b.hasReserved() {
		t.Fatal("reserved reset to zero must disarm the clear")
	}

	// A second endpoint's non-zero value must also be seen.
	b2 := stdNetBindForTest(t)
	ep2 := netip.MustParseAddrPort("192.0.2.1:2408")
	b2.SetReservedForEndpoint(ep, [3]byte{0, 0, 0})
	b2.SetReservedForEndpoint(ep2, [3]byte{0xAB, 0, 0})
	if !b2.hasReserved() {
		t.Fatal("non-zero reserved on any endpoint must count as reserved")
	}
}

// TestStdNetBindReceiveKeepsBytes1to3 drives the real StdNetBind receive path
// over a loopback socket: an AmneziaWG-style datagram whose magic header
// occupies bytes 0-3 must arrive untouched while no reserved value is set,
// and bytes 1-3 must be cleared once one is.
func TestStdNetBindReceiveKeepsBytes1to3(t *testing.T) {
	b := stdNetBindForTest(t)

	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen rx: %v", err)
	}
	defer rx.Close()
	tx, err := net.DialUDP("udp4", nil, rx.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial tx: %v", err)
	}
	defer tx.Close()

	var pc *ipv4.PacketConn
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		pc = ipv4.NewPacketConn(rx)
	}
	receive := b.makeReceiveIPv4(pc, rx, false)

	// magic header 0x1A2B3C4D (little-endian) followed by some payload
	datagram := []byte{0x4D, 0x3C, 0x2B, 0x1A, 0xDE, 0xAD, 0xBE, 0xEF}

	recvOne := func() []byte {
		t.Helper()
		if _, err := tx.Write(datagram); err != nil {
			t.Fatalf("write: %v", err)
		}
		if err := rx.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("deadline: %v", err)
		}
		bufs := make([][]byte, IdealBatchSize)
		for i := range bufs {
			bufs[i] = make([]byte, 2048)
		}
		sizes := make([]int, IdealBatchSize)
		eps := make([]Endpoint, IdealBatchSize)
		n, err := receive(bufs, sizes, eps)
		if err != nil {
			t.Fatalf("receive: %v", err)
		}
		if n != 1 {
			t.Fatalf("received %d datagrams, want 1", n)
		}
		return bufs[0][:sizes[0]]
	}

	if got := recvOne(); !bytes.Equal(got, datagram) {
		t.Fatalf("datagram altered without a reserved value: got %x, want %x", got, datagram)
	}

	b.SetReservedForEndpoint(netip.MustParseAddrPort("192.0.2.1:2408"), [3]byte{1, 2, 3})
	want := append([]byte(nil), datagram...)
	want[1], want[2], want[3] = 0, 0, 0
	if got := recvOne(); !bytes.Equal(got, want) {
		t.Fatalf("reserved bytes not cleared with a reserved value set: got %x, want %x", got, want)
	}
}
