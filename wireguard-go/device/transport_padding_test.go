/* SPDX-License-Identifier: MIT
 *
 * Transport padding (uapi "s4") over every outbound path: the tun read loop
 * (MaxMessageSize buffers) and the injection paths InputPacket/InputPackets,
 * whose buffers are allocated by packet size and must still leave room for
 * the S4 padding in front of the transport header.
 */

package device

import (
	"fmt"
	"testing"
)

const testTransportPadding = 60

func newPaddedDevicePair(t *testing.T) *devicePair {
	t.Helper()
	pair := newDevicePair(t, pairOptions{deviceLines: fmt.Sprintf("s4=%d\n", testTransportPadding)})
	if got := pair.devA.paddings.transport.Load(); got != testTransportPadding {
		t.Fatalf("s4 not applied: paddings.transport = %d", got)
	}
	return pair
}

func TestTransportPaddingInputPacket(t *testing.T) {
	pair := newPaddedDevicePair(t)

	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	dst := testIPB.AsSlice()

	send := func() { pair.devA.InputPacket(dst, [][]byte{pkt}) }
	send()
	awaitPacket(t, pair.tunB, pkt, send)
}

func TestTransportPaddingInputPackets(t *testing.T) {
	pair := newPaddedDevicePair(t)

	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	refs := []*InputPacketRef{{
		Destination:  testIPB.AsSlice(),
		PacketSlices: [][]byte{pkt[:12], pkt[12:]}, // multi-slice on purpose
	}}

	send := func() {
		if unmatched := pair.devA.InputPackets(refs); len(unmatched) != 0 {
			t.Fatalf("InputPackets returned %d unmatched refs", len(unmatched))
		}
	}
	send()
	awaitPacket(t, pair.tunB, pkt, send)
}

func TestTransportPaddingTunPath(t *testing.T) {
	pair := newPaddedDevicePair(t)

	pkt := buildIPv4Packet(testIPA, testIPB, 8)

	send := func() { pair.tunA.toDevice <- append([]byte(nil), pkt...) }
	send()
	awaitPacket(t, pair.tunB, pkt, send)
}
