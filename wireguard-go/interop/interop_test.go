/* SPDX-License-Identifier: MIT
 *
 * Wire interoperability between the fork (github.com/sagernet/wireguard-go
 * with AmneziaWG 3.1 grafted in) and the official amneziawg-go v3.1.20260828:
 * two userspace devices in one process, real UDP on 127.0.0.1, ping both ways.
 */

package interop

import (
	"testing"
	"time"
)

// fullShared is the part of the AmneziaWG 3.1 parameter set that must match
// on both sides. random_trailers belongs here: a receiver accepts a datagram
// longer than S+message size only when its own random_trailers is set (the
// same check in both implementations' receive.go), so an initiator alone with
// random_trailers=1 is dropped as "unknown type" by either responder.
func fullShared(headerKey string) string {
	return lines(
		"s1", "68",
		"s2", "149",
		"s3", "32",
		"s4", "16",
		"h1", "1000000-1999999",
		"h2", "2000000-2999999",
		"h3", "3000000-3999999",
		"h4", "4000000-4999999",
		"header_protection_key", headerKey,
		"random_trailers", "1",
	)
}

// fullClient is the client-only part: junk, I1, content padding, disabled
// cookies and the five timing ranges.
var fullClient = lines(
	"jc", "3",
	"jmin", "40",
	"jmax", "70",
	"i1", "<b 0x16030100><r 32>",
	"content_padding_addition", "0-64",
	"disable_cookies", "1",
	"rekey_after_time", "100-120",
	"rekey_timeout", "4-6",
	"reject_after_time", "170-180",
	"keepalive_timeout", "9-11",
	"max_handshake_attempts", "16-18",
)

var fullClientPeer = lines("persistent_keepalive_interval", "5-10")

func fullSetConfig(initiatorKey, responderKey string) pairConfig {
	return pairConfig{
		initiatorDevice: fullShared(initiatorKey) + fullClient,
		responderDevice: fullShared(responderKey),
		initiatorPeer:   fullClientPeer,
	}
}

func TestForkClientToAmneziaServer_FullSet(t *testing.T) {
	log := newTestLog(t)
	initiator := newForkSide(t, log, "initiator")
	responder := newAWGSide(t, log, "responder")
	key := randomHex32(t)
	configurePair(t, initiator, responder, fullSetConfig(key, key))
	pingBothWays(t, initiator, responder)
}

func TestAmneziaClientToForkServer_FullSet(t *testing.T) {
	log := newTestLog(t)
	initiator := newAWGSide(t, log, "initiator")
	responder := newForkSide(t, log, "responder")
	key := randomHex32(t)
	configurePair(t, initiator, responder, fullSetConfig(key, key))
	pingBothWays(t, initiator, responder)
}

// The shape smart-vpn's server uses: single-value headers, S1-S4, junk on
// the initiator, no header protection, no AWG-3 extras.
func TestForkToAmnezia_SingleValues(t *testing.T) {
	log := newTestLog(t)
	initiator := newForkSide(t, log, "initiator")
	responder := newAWGSide(t, log, "responder")
	shared := lines(
		"s1", "68",
		"s2", "149",
		"s3", "32",
		"s4", "16",
		"h1", "1785263459",
		"h2", "389527153",
		"h3", "1103948204",
		"h4", "2093847211",
	)
	configurePair(t, initiator, responder, pairConfig{
		initiatorDevice: shared + lines("jc", "3", "jmin", "40", "jmax", "70"),
		responderDevice: shared,
	})
	pingBothWays(t, initiator, responder)
}

func TestPlainWireGuard_ForkToAmnezia(t *testing.T) {
	log := newTestLog(t)
	initiator := newForkSide(t, log, "initiator")
	responder := newAWGSide(t, log, "responder")
	configurePair(t, initiator, responder, pairConfig{})
	pingBothWays(t, initiator, responder)
}

// Negative control: the full set with a different header protection key on
// each side must not pass a single packet, proving the tests above really
// exercise the obfuscation.
func TestHeaderKeyMismatch(t *testing.T) {
	log := newTestLog(t)
	initiator := newForkSide(t, log, "initiator")
	responder := newAWGSide(t, log, "responder")
	configurePair(t, initiator, responder, fullSetConfig(randomHex32(t), randomHex32(t)))
	awaitNoPacket(t, initiator, responder, pingInitiatorToResponder(), 3*time.Second)
	if handshakeDone(t, responder) || handshakeDone(t, initiator) {
		t.Fatal("a handshake completed across a header key mismatch")
	}
}
