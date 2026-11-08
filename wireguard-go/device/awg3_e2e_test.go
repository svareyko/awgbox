/* SPDX-License-Identifier: MIT
 *
 * AmneziaWG 3.1 end to end: two devices wired through the in-memory channel
 * bind, both configured with the full parameter set (junk, S1-S4, ranged
 * H1-H4, I1, header protection, content padding addition, random trailers,
 * disabled cookies, the five timing ranges, a ranged persistent keepalive),
 * must handshake and pass packets in both directions over every outbound
 * path (tun read and InputPacket injection). The wire is tapped to pin the
 * datagram format: S1/S4 padding in front, the type word masked by the
 * header cipher keyed with the first 12 bytes of the padding, content padding
 * growing data packets. The negative cases pin the uapi guards.
 */

package device

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20"
)

// S1 and S4 of awgFullDeviceLines.
const (
	awg3S1 = 55
	awg3S4 = 12
)

func newHeaderKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, HeaderCipherKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return key
}

func newHeaderKeyHex(t *testing.T) string {
	t.Helper()
	return hex.EncodeToString(newHeaderKey(t))
}

// unmaskType undoes the header protection on the type word at offset: the
// keystream is ChaCha20(key, nonce = datagram[:12]) from byte 0, exactly what
// the sender applied.
func unmaskType(t *testing.T, key, pkt []byte, offset int) uint32 {
	t.Helper()
	cip, err := chacha20.NewUnauthenticatedCipher(key, pkt[:HeaderCipherNonceSize])
	if err != nil {
		t.Fatalf("chacha20: %v", err)
	}
	var ks [4]byte
	cip.XORKeyStream(ks[:], ks[:])
	var word [4]byte
	for i := range word {
		word[i] = pkt[offset+i] ^ ks[i]
	}
	return binary.LittleEndian.Uint32(word[:])
}

func mustRange(t *testing.T, spec string) UintRange {
	t.Helper()
	var r UintRange
	if err := r.FromString(spec); err != nil {
		t.Fatalf("range %q: %v", spec, err)
	}
	return r
}

func newAWG3DevicePair(t *testing.T, keyA, keyB []byte, tapA *wireTap) *devicePair {
	t.Helper()
	return newDevicePair(t, pairOptions{
		deviceLines:  awgFullDeviceLines(hex.EncodeToString(keyA)),
		deviceLinesB: awgFullDeviceLines(hex.EncodeToString(keyB)),
		peerLinesA:   uapiLines("persistent_keepalive_interval", "25-35"),
		tapA:         tapA,
	})
}

func TestAWG3EndToEnd(t *testing.T) {
	key := newHeaderKey(t)
	tap := &wireTap{}
	pair := newAWG3DevicePair(t, key, key, tap)

	// A -> B over the tun read path.
	const payloadLen = 100
	pkt := buildIPv4Packet(testIPA, testIPB, payloadLen)
	sendTun := func() { pair.tunA.toDevice <- append([]byte(nil), pkt...) }
	sendTun()
	awaitPacket(t, pair.tunB, pkt, sendTun)

	// B -> A (the responder's transport path).
	pktBack := buildIPv4Packet(testIPB, testIPA, 40)
	sendBack := func() { pair.tunB.toDevice <- append([]byte(nil), pktBack...) }
	sendBack()
	awaitPacket(t, pair.tunA, pktBack, sendBack)

	// A -> B over the injection path (element allocated by packet size).
	pktInject := buildIPv4Packet(testIPA, testIPB, 8)
	sendInject := func() { pair.devA.InputPacket(testIPB.AsSlice(), [][]byte{pktInject}) }
	sendInject()
	awaitPacket(t, pair.tunB, pktInject, sendInject)

	h1 := mustRange(t, "1020325451-1020325500")
	h4 := mustRange(t, "2528465083-2528465100")

	// Wire format.
	var sawInit, sawTransport, sawPaddedData, sawI1 bool
	const dataDatagram = awg3S4 + MessageTransportSize + 20 + payloadLen // exact size without addition
	for _, dg := range tap.snapshot() {
		if len(dg) > 4 && binary.BigEndian.Uint32(dg[:4]) == 0xc7000000 {
			sawI1 = true
			continue
		}
		if len(dg) >= awg3S1+MessageInitiationSize && h1.Contains(unmaskType(t, key, dg, awg3S1)) {
			sawInit = true
			if raw := binary.LittleEndian.Uint32(dg[awg3S1:]); h1.Contains(raw) {
				t.Errorf("initiation type word is in the clear on the wire")
			}
			continue
		}
		if len(dg) >= awg3S4+MessageTransportSize && h4.Contains(unmaskType(t, key, dg, awg3S4)) {
			sawTransport = true
			if raw := binary.LittleEndian.Uint32(dg[awg3S4:]); h4.Contains(raw) {
				t.Errorf("transport type word is in the clear on the wire")
			}
			// content_padding_addition=10-100 grows the 100-byte data packet's
			// datagram by 10..100 (the UDP window of 500 leaves room)
			if len(dg) > dataDatagram && len(dg) <= dataDatagram+100 {
				sawPaddedData = true
			}
			if len(dg) == dataDatagram {
				t.Errorf("data datagram sent without content padding addition (len %d)", len(dg))
			}
		}
	}
	if !sawI1 {
		t.Errorf("no I1 controlled packet seen on the wire")
	}
	if !sawInit {
		t.Errorf("no header-protected handshake initiation seen on the wire")
	}
	if !sawTransport {
		t.Errorf("no header-protected transport datagram seen on the wire")
	}
	if !sawPaddedData {
		t.Errorf("no content-padded data datagram seen on the wire")
	}
}

// A header-key mismatch must leave both sides unable to classify each
// other's datagrams: no handshake, nothing delivered.
func TestAWG3HeaderKeyMismatch(t *testing.T) {
	pair := newAWG3DevicePair(t, newHeaderKey(t), newHeaderKey(t), nil)

	pkt := buildIPv4Packet(testIPA, testIPB, 8)
	pair.tunA.toDevice <- append([]byte(nil), pkt...)
	awaitNoPacket(t, pair.tunB, 3*time.Second)

	got, err := pair.devB.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	if !strings.Contains(got, "last_handshake_time_sec=0\n") {
		t.Fatalf("handshake completed across a header-key mismatch:\n%s", got)
	}
}

// The uapi refuses a header key unless every S1-S4 can carry the 12-byte
// nonce, also when the key is already on the device and only a padding
// shrinks (the staged set is seeded from the device).
func TestAWG3UapiRejectsShortPaddingWithHeaderKey(t *testing.T) {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	bind, _ := newChanBindPair()
	dev := NewDevice(context.Background(), newChanTun(), bind, NewLogger(LogLevelError, "dev: "), 1)
	t.Cleanup(dev.Close)

	keyHex := newHeaderKeyHex(t)
	base := "private_key=" + hex.EncodeToString(sk[:]) + "\n"
	headerKey := func() HeaderCipherKey {
		dev.headerProtection.RLock()
		defer dev.headerProtection.RUnlock()
		return dev.headerProtection.key
	}

	if err := dev.IpcSet(base + "s1=55\ns2=42\ns3=40\ns4=8\nheader_protection_key=" + keyHex + "\n"); err == nil {
		t.Fatal("s4=8 with a header key accepted")
	}
	if !headerKey().IsZero() {
		t.Fatal("rejected IpcSet left the header key on the device")
	}
	if got := dev.paddings.transport.Load(); got != 0 {
		t.Fatalf("rejected IpcSet changed s4 to %d", got)
	}

	if err := dev.IpcSet(base + "s1=55\ns2=42\ns3=40\ns4=12\nheader_protection_key=" + keyHex + "\n"); err != nil {
		t.Fatalf("valid AWG 3 set rejected: %v", err)
	}
	if headerKey().IsZero() {
		t.Fatal("header key not applied")
	}

	// partial update: only s2 shrinks, the key stays -> refused
	if err := dev.IpcSet("s2=4\n"); err == nil {
		t.Fatal("s2=4 next to an existing header key accepted")
	}
	if got := dev.paddings.response.Load(); got != 42 {
		t.Fatalf("rejected partial set changed s2 to %d", got)
	}

	// clearing the key lifts the constraint
	if err := dev.IpcSet("header_protection_key=" + strings.Repeat("00", HeaderCipherKeySize) + "\ns2=4\n"); err != nil {
		t.Fatalf("clearing the key with a short padding rejected: %v", err)
	}
	if !headerKey().IsZero() {
		t.Fatal("zero header key did not clear header protection")
	}
}

// H1-H4 must not overlap.
func TestAWG3UapiRejectsOverlappingHeaders(t *testing.T) {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	bind, _ := newChanBindPair()
	dev := NewDevice(context.Background(), newChanTun(), bind, NewLogger(LogLevelError, "dev: "), 1)
	t.Cleanup(dev.Close)

	err = dev.IpcSet("private_key=" + hex.EncodeToString(sk[:]) + "\nh1=100-200\nh2=150-250\nh3=3\nh4=4\n")
	if err == nil || !strings.Contains(err.Error(), "overlap") {
		t.Fatalf("overlapping h1/h2 accepted (err=%v)", err)
	}
}

func TestUintRangeFromString(t *testing.T) {
	cases := []struct {
		spec    string
		lo, hi  uint32
		wantErr bool
	}{
		{"5", 5, 5, false},
		{"3-7", 3, 7, false},
		{"0", 0, 0, false},
		{"4294967295", 4294967295, 4294967295, false},
		{"0-4294967295", 0, 4294967295, false},
		{"7-3", 0, 0, true},
		{"", 0, 0, true},
		{"a", 0, 0, true},
		{"1-2-3", 0, 0, true},
		{"1-4294967296", 0, 0, true},
		{"-1", 0, 0, true},
	}
	for _, c := range cases {
		var r UintRange
		err := r.FromString(c.spec)
		if c.wantErr != (err != nil) {
			t.Errorf("FromString(%q): err = %v, wantErr = %v", c.spec, err, c.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if r.Lo() != c.lo || r.Hi() != c.hi {
			t.Errorf("FromString(%q) = [%d, %d], want [%d, %d]", c.spec, r.Lo(), r.Hi(), c.lo, c.hi)
		}
		if got := r.ToString(); got != c.spec && !(c.lo == c.hi && got == fmt.Sprint(c.lo)) {
			t.Errorf("ToString(%q) = %q", c.spec, got)
		}
		for i := 0; i < 16; i++ {
			if v := r.PickOne(); !r.Contains(v) {
				t.Errorf("PickOne(%q) = %d outside range", c.spec, v)
			}
		}
	}
}

// persistent_keepalive_interval accepts the AmneziaWG "min-max" form and keeps
// the plain WireGuard number form; IpcGet reports a non-zero value back
// verbatim and omits a zero one.
func TestAWG3PersistentKeepaliveRange(t *testing.T) {
	sk, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	peerSK, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey: %v", err)
	}
	peerPK := peerSK.publicKey()
	bind, _ := newChanBindPair()
	dev := NewDevice(context.Background(), newChanTun(), bind, NewLogger(LogLevelError, "dev: "), 1)
	t.Cleanup(dev.Close)

	set := func(value string) error {
		return dev.IpcSet("private_key=" + hex.EncodeToString(sk[:]) + "\npublic_key=" + hex.EncodeToString(peerPK[:]) +
			"\npersistent_keepalive_interval=" + value + "\n")
	}
	get := func() string {
		got, err := dev.IpcGet()
		if err != nil {
			t.Fatalf("IpcGet: %v", err)
		}
		return got
	}

	for _, value := range []string{"25-35", "25"} {
		if err := set(value); err != nil {
			t.Fatalf("persistent_keepalive_interval=%s rejected: %v", value, err)
		}
		if got := get(); !strings.Contains(got, "persistent_keepalive_interval="+value+"\n") {
			t.Errorf("persistent_keepalive_interval=%s not reported:\n%s", value, got)
		}
	}
	if err := set("0"); err != nil {
		t.Fatalf("persistent_keepalive_interval=0 rejected: %v", err)
	}
	if got := get(); strings.Contains(got, "persistent_keepalive_interval=") {
		t.Errorf("persistent_keepalive_interval=0 reported:\n%s", got)
	}
	for _, bad := range []string{"35-25", "x"} {
		if err := set(bad); err == nil {
			t.Errorf("persistent_keepalive_interval=%s accepted", bad)
		}
	}
}
