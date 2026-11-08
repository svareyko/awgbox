/* SPDX-License-Identifier: MIT
 *
 * With no S1-S4 padding the H1-H4 magic header occupies bytes 0-3 of every
 * datagram, where plain WireGuard has its type byte and the three reserved
 * bytes Cloudflare WARP uses. The H1-H4 ranges here lie entirely above
 * 0x10000000, so any value has a non-zero byte among bytes 1-3: a bind or a
 * device that touched those bytes would make every datagram unclassifiable.
 * The bind-level gate itself is covered in conn (reserved_gate_test.go).
 */

package device

import (
	"encoding/binary"
	"fmt"
	"testing"
)

const (
	magicH1Lo, magicH1Hi = 268500000, 268600000 // init
	magicH2Lo, magicH2Hi = 300000000, 300100000 // response
	magicH3Lo, magicH3Hi = 400000000, 400100000 // cookie
	magicH4Lo, magicH4Hi = 500000000, 500100000 // transport
)

func magicHeaderLines() string {
	return fmt.Sprintf("jc=3\njmin=8\njmax=16\nh1=%d-%d\nh2=%d-%d\nh3=%d-%d\nh4=%d-%d\n",
		magicH1Lo, magicH1Hi, magicH2Lo, magicH2Hi, magicH3Lo, magicH3Hi, magicH4Lo, magicH4Hi)
}

// Over real loopback sockets.
func TestAWGZeroPaddingMagicHeadersLoopback(t *testing.T) {
	pair := newDevicePair(t, pairOptions{loopback: true, deviceLines: magicHeaderLines()})
	pingBothWays(t, pair)
}

// Over the channel bind, checking the magic header on the wire.
func TestAWGZeroPaddingMagicHeadersOnWire(t *testing.T) {
	tap := &wireTap{}
	pair := newDevicePair(t, pairOptions{deviceLines: magicHeaderLines(), tapA: tap})
	pingBothWays(t, pair)

	var sawInit, sawTransport bool
	for _, dg := range tap.snapshot() {
		if len(dg) < 4 {
			continue
		}
		magic := binary.LittleEndian.Uint32(dg[:4])
		switch {
		case len(dg) == MessageInitiationSize && magic >= magicH1Lo && magic <= magicH1Hi:
			sawInit = true
		case len(dg) >= MessageTransportSize && magic >= magicH4Lo && magic <= magicH4Hi:
			sawTransport = true
		}
	}
	if !sawInit {
		t.Error("no initiation with an H1 magic header in bytes 0-3 seen on the wire")
	}
	if !sawTransport {
		t.Error("no transport datagram with an H4 magic header in bytes 0-3 seen on the wire")
	}
}
