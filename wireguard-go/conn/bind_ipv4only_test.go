/* SPDX-License-Identifier: MIT
 *
 * The bind keeps its IPv4 socket when the IPv6 one cannot be opened. On
 * Windows, pinning a socket to an interface whose IPv6 is disabled fails with
 * WSAEINVAL ("An invalid argument was supplied"), which is not EAFNOSUPPORT;
 * the bind used to close IPv4 as well and was left with no socket.
 */

package conn

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
)

var errFakeIPv6Control = errors.New("An invalid argument was supplied.")

func failIPv6Control(network, address string, conn syscall.RawConn) error {
	if network == "udp6" {
		return errFakeIPv6Control
	}
	return nil
}

func TestStdNetBindKeepsIPv4WhenIPv6Fails(t *testing.T) {
	bind := NewStdNetBind(failIPv6Control).(*StdNetBind)
	var warnings []string
	bind.SetWarnFunc(func(format string, args ...any) {
		warnings = append(warnings, fmt.Sprintf(format, args...))
	})

	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peerAddr := peer.LocalAddr().(*net.UDPAddr).AddrPort()

	for round, destination := range []netip.AddrPort{
		peerAddr,
		// The rebind path, and a v4-mapped destination, which must leave
		// through the IPv4 socket when there is no IPv6 one.
		netip.AddrPortFrom(netip.AddrFrom16(peerAddr.Addr().As16()), peerAddr.Port()),
	} {
		fns, port, err := bind.Open(0)
		if err != nil {
			t.Fatalf("round %d: Open: %v", round, err)
		}
		if port == 0 {
			t.Fatalf("round %d: Open returned port 0", round)
		}
		if len(fns) != 1 {
			t.Fatalf("round %d: %d receive functions, want 1 (IPv4 only)", round, len(fns))
		}
		bind.mu.Lock()
		hasV4, hasV6 := bind.ipv4 != nil, bind.ipv6 != nil
		bind.mu.Unlock()
		if !hasV4 || hasV6 {
			t.Fatalf("round %d: ipv4 open %v, ipv6 open %v; want true, false", round, hasV4, hasV6)
		}

		payload := []byte(fmt.Sprintf("awgbox round %d", round))
		if err := bind.Send([][]byte{payload}, &StdNetEndpoint{AddrPort: destination}, 0); err != nil {
			t.Fatalf("round %d: Send to %v: %v", round, destination, err)
		}
		_ = peer.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 1500)
		n, from, err := peer.ReadFromUDPAddrPort(buf)
		if err != nil {
			t.Fatalf("round %d: peer read: %v", round, err)
		}
		if !bytes.Equal(buf[:n], payload) {
			t.Fatalf("round %d: peer got %q, want %q", round, buf[:n], payload)
		}
		if from.Port() != port {
			t.Fatalf("round %d: datagram came from port %d, bind reported %d", round, from.Port(), port)
		}

		if err := bind.Send([][]byte{payload}, &StdNetEndpoint{AddrPort: netip.MustParseAddrPort("[2001:db8::1]:51820")}, 0); !errors.Is(err, syscall.EAFNOSUPPORT) {
			t.Fatalf("round %d: Send to IPv6 without an IPv6 socket: %v, want EAFNOSUPPORT", round, err)
		}
		if err := bind.Close(); err != nil {
			t.Fatalf("round %d: Close: %v", round, err)
		}
	}

	if len(warnings) != 1 {
		t.Fatalf("warnings %q, want exactly one", warnings)
	}
	if !strings.HasPrefix(warnings[0], "IPv6 bind failed: ") ||
		!strings.HasSuffix(warnings[0], errFakeIPv6Control.Error()+"; running IPv4 only") {
		t.Fatalf("warning %q, want \"IPv6 bind failed: <err>; running IPv4 only\"", warnings[0])
	}
}

func TestStdNetBindFailsWhenNoFamilyOpens(t *testing.T) {
	errV4 := errors.New("fake IPv4 failure")
	bind := NewStdNetBind(func(network, address string, conn syscall.RawConn) error {
		if network == "udp4" {
			return errV4
		}
		return errFakeIPv6Control
	}).(*StdNetBind)
	if _, _, err := bind.Open(0); !errors.Is(err, errV4) {
		t.Fatalf("Open: %v, want the IPv4 error", err)
	}
	bind.mu.Lock()
	defer bind.mu.Unlock()
	if bind.ipv4 != nil || bind.ipv6 != nil {
		t.Fatal("a failed Open left a socket behind")
	}
}
