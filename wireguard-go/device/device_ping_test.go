/* SPDX-License-Identifier: MIT
 *
 * Two-device pings in the style of amneziawg-go's device_test.go
 * (TestTwoDevicePing, TestAWGDevicePing, TestAWGHandshakeDevicePing), adapted
 * to this fork's NewDevice signature and run over real UDP sockets bound to
 * 127.0.0.1 only.
 */

package device

import "testing"

// Plain WireGuard (no AmneziaWG keys) must keep working.
func TestTwoDevicePing(t *testing.T) {
	pair := newDevicePair(t, pairOptions{loopback: true})
	pingBothWays(t, pair)
}

// The parameter set of amneziawg-go's TestAWGDevicePing.
func TestAWGDevicePing(t *testing.T) {
	pair := newDevicePair(t, pairOptions{
		loopback: true,
		deviceLines: uapiLines(
			"jc", "5",
			"jmin", "500",
			"jmax", "1000",
			"s1", "15",
			"s2", "18",
			"s3", "20",
			"s4", "25",
			"h1", "123456-123500",
			"h2", "67543-67550",
			"h3", "123123-123200",
			"h4", "32345-32350",
		),
	})
	pingBothWays(t, pair)
}

// The controlled packets of amneziawg-go's (manual) TestAWGHandshakeDevicePing
// precede every initiation; here they run once, automatically. The <c> tag of
// the upstream specs is not a tag this obfuscator knows and is left out.
func TestAWGHandshakeDevicePing(t *testing.T) {
	pair := newDevicePair(t, pairOptions{
		loopback: true,
		deviceLines: uapiLines(
			"i1", "<b 0xf6ab3267fa><b 0xf6ab><t><r 10>",
			"i2", "<b 0xf6ab3267fa><b 0xf6ab><t><rc 10>",
			"i3", "<b 0xf6ab3267fa><b 0xf6ab><t><rd 10>",
			"i4", "<b 0xf6ab3267fa><r 100>",
		),
	})
	pingBothWays(t, pair)
}

// awgFullDeviceLines is a full AmneziaWG 3.1 device parameter set: junk,
// S1-S4 (all >= the 12-byte header protection nonce), ranged H1-H4, an I1
// controlled packet, header protection, content padding addition, random
// trailers, disabled cookies and the five timing ranges.
func awgFullDeviceLines(headerKeyHex string) string {
	return uapiLines(
		"jc", "4",
		"jmin", "10",
		"jmax", "50",
		"s1", "55",
		"s2", "42",
		"s3", "40",
		"s4", "12",
		"h1", "1020325451-1020325500",
		"h2", "3288052141-3288052200",
		"h3", "1766607858-1766607900",
		"h4", "2528465083-2528465100",
		"i1", "<b 0xc70000000108ce1bf31eec7d93360000449e227e4596ed7f75c4d35ce31880b4133107c822c6355b51f0d7c1bba96d5c210a48aca01885fed0871cfc37d59137d73b506dc013bb4a13c060ca5b04b7ae215af71e37d6e8ff1db235f9fe0c25cb8b492471054a7c8d0d6077d430d07f6e87a8699287f6e69f54263c7334a8e144a29851429bf2e350e519445172d36953e96085110ce1fb641e5efad42c0feb4711ece959b72cc4d6f3c1e83251adb572b921534f6ac4b10927167f41fe50040a75acef62f45bded67c0b45b9d655ce374589cad6f6b3c2712f45e01e1b0d92d36ec9e6b9e10c0a5e1d8ae1a2ac65cb26e9d6b6b8d1d9e05e1a31c0b9c55c6b1f6efc0c6e9db0a1df73d3e8f6e3e8c0b9ff2c4ee6b8f8e1e3e5d4ea7b0f><r 16><t>",
		"header_protection_key", headerKeyHex,
		"content_padding_addition", "10-100",
		"random_trailers", "1",
		"disable_cookies", "1",
		"rekey_after_time", "100-120",
		"rekey_timeout", "3-7",
		"reject_after_time", "150-180",
		"keepalive_timeout", "5-15",
		"max_handshake_attempts", "15-20",
	)
}

// The full AmneziaWG 3.1 parameter set plus a ranged persistent keepalive,
// over real loopback sockets.
func TestAWGFullParameterSetPing(t *testing.T) {
	lines := awgFullDeviceLines(newHeaderKeyHex(t))
	pair := newDevicePair(t, pairOptions{
		loopback:    true,
		deviceLines: lines,
		peerLinesA:  uapiLines("persistent_keepalive_interval", "25-35"),
	})
	pingBothWays(t, pair)
}
