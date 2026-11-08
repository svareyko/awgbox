/* SPDX-License-Identifier: MIT
 *
 * Test harness for the AmneziaWG device tests: an in-memory conn.Bind over Go
 * channels, a loopback-only UDP conn.Bind (real sockets on 127.0.0.1, never on
 * all interfaces), an in-memory tun.Device, and helpers that bring up a pair
 * of peered devices. This fork has no conn/bindtest or tun/tuntest packages.
 */

package device

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/tun"

	"golang.org/x/net/ipv4"
)

// ---------------------------------------------------------------------------
// In-memory conn.Bind over Go channels.
// ---------------------------------------------------------------------------

type chanEndpoint uint16

func (e chanEndpoint) ClearSrc()           {}
func (e chanEndpoint) SrcToString() string { return "" }
func (e chanEndpoint) DstToString() string { return fmt.Sprintf("127.0.0.1:%d", uint16(e)) }
func (e chanEndpoint) DstToBytes() []byte  { return []byte{byte(e), byte(e >> 8)} }
func (e chanEndpoint) DstIP() netip.Addr   { return netip.AddrFrom4([4]byte{127, 0, 0, 1}) }
func (e chanEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

type chanBind struct {
	rx, tx chan []byte
	source chanEndpoint // "port" this bind listens on
	target chanEndpoint // endpoint of the opposite bind

	mu          sync.Mutex
	closeSignal chan struct{} // recreated on every Open (BindUpdate closes+reopens)

	// tap, if set, sees a copy of every datagram this bind sends (wire-format
	// assertions). Set before Up; called on the sender's goroutine.
	tap func(pkt []byte)
}

// newChanBindPair returns two Binds whose Send/Receive are cross-wired.
func newChanBindPair() (*chanBind, *chanBind) {
	aToB := make(chan []byte, 1024)
	bToA := make(chan []byte, 1024)
	a := &chanBind{rx: bToA, tx: aToB, source: 1, target: 2}
	b := &chanBind{rx: aToB, tx: bToA, source: 2, target: 1}
	return a, b
}

func (b *chanBind) currentCloseSignal() chan struct{} {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closeSignal
}

func (b *chanBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	b.closeSignal = make(chan struct{})
	closeSignal := b.closeSignal
	b.mu.Unlock()
	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-closeSignal:
			// Must be net.ErrClosed: RoutineReceiveIncoming treats anything
			// else as a transient error and death-spirals before exiting.
			return 0, net.ErrClosed
		case pkt, ok := <-b.rx:
			if !ok {
				return 0, net.ErrClosed
			}
			sizes[0] = copy(packets[0], pkt)
			eps[0] = b.target
			return 1, nil
		}
	}
	return []conn.ReceiveFunc{fn}, uint16(b.source), nil
}

func (b *chanBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closeSignal != nil {
		select {
		case <-b.closeSignal:
		default:
			close(b.closeSignal)
		}
	}
	return nil
}

func (b *chanBind) SetMark(mark uint32) error { return nil }

func (b *chanBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	closeSignal := b.currentCloseSignal()
	if closeSignal == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		pkt := make([]byte, len(buf)-offset)
		copy(pkt, buf[offset:])
		if b.tap != nil {
			b.tap(pkt)
		}
		select {
		case <-closeSignal:
			return net.ErrClosed
		case b.tx <- pkt:
		}
	}
	return nil
}

func (b *chanBind) ParseEndpoint(s string) (conn.Endpoint, error) { return b.target, nil }

func (b *chanBind) BatchSize() int { return 1 }

func (b *chanBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {}

// ---------------------------------------------------------------------------
// Loopback-only UDP conn.Bind: real sockets, bound to 127.0.0.1 only.
// ---------------------------------------------------------------------------

type loopbackBind struct {
	mu   sync.Mutex
	conn *net.UDPConn
}

func (b *loopbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	b.conn = udpConn
	fn := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, addr, err := udpConn.ReadFromUDPAddrPort(packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())}
		return 1, nil
	}
	return []conn.ReceiveFunc{fn}, uint16(udpConn.LocalAddr().(*net.UDPAddr).Port), nil
}

func (b *loopbackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == nil {
		return nil
	}
	err := b.conn.Close()
	b.conn = nil
	return err
}

func (b *loopbackBind) SetMark(mark uint32) error { return nil }

func (b *loopbackBind) Send(bufs [][]byte, ep conn.Endpoint, offset int) error {
	b.mu.Lock()
	udpConn := b.conn
	b.mu.Unlock()
	if udpConn == nil {
		return net.ErrClosed
	}
	stdEndpoint, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	for _, buf := range bufs {
		if _, err := udpConn.WriteToUDPAddrPort(buf[offset:], stdEndpoint.AddrPort); err != nil {
			return err
		}
	}
	return nil
}

func (b *loopbackBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addrPort, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	if !addrPort.Addr().IsLoopback() {
		return nil, errors.New("loopbackBind: only loopback endpoints are allowed")
	}
	return &conn.StdNetEndpoint{AddrPort: addrPort}, nil
}

func (b *loopbackBind) BatchSize() int { return 1 }

func (b *loopbackBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {}

// ---------------------------------------------------------------------------
// In-memory tun.Device over Go channels.
// ---------------------------------------------------------------------------

type chanTun struct {
	toDevice   chan []byte // packets the device Reads (outbound plaintext)
	fromDevice chan []byte // packets the device Writes (inbound plaintext)
	events     chan tun.Event
	closed     chan struct{}
	closeOnce  sync.Once
}

func newChanTun() *chanTun {
	return &chanTun{
		toDevice:   make(chan []byte, 1024),
		fromDevice: make(chan []byte, 1024),
		events:     make(chan tun.Event, 4),
		closed:     make(chan struct{}),
	}
}

func (t *chanTun) File() *os.File { return nil }

func (t *chanTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case pkt, ok := <-t.toDevice:
		if !ok {
			return 0, os.ErrClosed
		}
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	}
}

func (t *chanTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		pkt := make([]byte, len(buf)-offset)
		copy(pkt, buf[offset:])
		select {
		case <-t.closed:
			return 0, os.ErrClosed
		case t.fromDevice <- pkt:
		}
	}
	return len(bufs), nil
}

func (t *chanTun) MTU() (int, error)        { return DefaultMTU, nil }
func (t *chanTun) Name() (string, error)    { return "chantun", nil }
func (t *chanTun) Events() <-chan tun.Event { return t.events }
func (t *chanTun) BatchSize() int           { return 1 }

func (t *chanTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

// ---------------------------------------------------------------------------
// Wire tap.
// ---------------------------------------------------------------------------

// wireTap records every datagram a chanBind sends.
type wireTap struct {
	mu   sync.Mutex
	pkts [][]byte
}

func (w *wireTap) record(pkt []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pkts = append(w.pkts, append([]byte(nil), pkt...))
}

func (w *wireTap) snapshot() [][]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([][]byte(nil), w.pkts...)
}

// ---------------------------------------------------------------------------
// Device pair scaffolding.
// ---------------------------------------------------------------------------

var (
	testIPA = netip.AddrFrom4([4]byte{10, 0, 0, 1})
	testIPB = netip.AddrFrom4([4]byte{10, 0, 0, 2})
)

// buildIPv4Packet builds a minimal, routable IPv4/UDP packet whose header
// fields satisfy the receive-side validation in processInboundContainer
// (version, total-length field, allowed source address).
func buildIPv4Packet(src, dst netip.Addr, payloadLen int) []byte {
	total := ipv4.HeaderLen + payloadLen
	pkt := make([]byte, total)
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[IPv4offsetTotalLength:IPv4offsetTotalLength+2], uint16(total))
	pkt[8] = 64 // TTL
	pkt[9] = 17 // protocol: UDP
	copy(pkt[IPv4offsetSrc:], src.AsSlice())
	copy(pkt[IPv4offsetDst:], dst.AsSlice())
	for i := ipv4.HeaderLen; i < total; i++ {
		pkt[i] = byte(i) // deterministic payload
	}
	return pkt
}

type devicePair struct {
	devA, devB *Device
	tunA, tunB *chanTun
}

// pairOptions configures newDevicePair.
type pairOptions struct {
	// deviceLines are uapi lines (each ending in "\n") applied to both
	// devices; deviceLinesB, if non-empty, replaces them for device B.
	deviceLines  string
	deviceLinesB string
	// peerLinesA are extra uapi lines for A's peer section (B as seen by A).
	peerLinesA string
	// tapA sees A's outgoing datagrams (channel bind only).
	tapA *wireTap
	// loopback selects real UDP sockets on 127.0.0.1 instead of channels.
	loopback bool
}

// newDevicePair brings up two Up()'d devices peered with each other.
func newDevicePair(t *testing.T, opts pairOptions) *devicePair {
	t.Helper()

	skA, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey A: %v", err)
	}
	skB, err := newPrivateKey()
	if err != nil {
		t.Fatalf("newPrivateKey B: %v", err)
	}
	pkA := skA.publicKey()
	pkB := skB.publicKey()

	var bindA, bindB conn.Bind
	if opts.loopback {
		bindA, bindB = &loopbackBind{}, &loopbackBind{}
	} else {
		chanA, chanB := newChanBindPair()
		if opts.tapA != nil {
			chanA.tap = opts.tapA.record
		}
		bindA, bindB = chanA, chanB
	}
	tunA := newChanTun()
	tunB := newChanTun()

	devA := NewDevice(context.Background(), tunA, bindA, NewLogger(LogLevelError, "devA: "), 1)
	devB := NewDevice(context.Background(), tunB, bindB, NewLogger(LogLevelError, "devB: "), 1)
	t.Cleanup(devA.Close)
	t.Cleanup(devB.Close)

	linesB := opts.deviceLines
	if opts.deviceLinesB != "" {
		linesB = opts.deviceLinesB
	}
	endpointA, endpointB := "127.0.0.1:2", "127.0.0.1:1"
	if opts.loopback {
		endpointA, endpointB = "", ""
	}
	cfgA := "private_key=" + hex.EncodeToString(skA[:]) + "\n" + opts.deviceLines +
		fmt.Sprintf("replace_peers=true\npublic_key=%s\nallowed_ip=%s/32\n", hex.EncodeToString(pkB[:]), testIPB) +
		opts.peerLinesA
	cfgB := "private_key=" + hex.EncodeToString(skB[:]) + "\n" + linesB +
		fmt.Sprintf("replace_peers=true\npublic_key=%s\nallowed_ip=%s/32\n", hex.EncodeToString(pkA[:]), testIPA)
	if endpointA != "" {
		cfgA += "endpoint=" + endpointA + "\n"
		cfgB += "endpoint=" + endpointB + "\n"
	}

	if err := devA.IpcSet(cfgA); err != nil {
		t.Fatalf("IpcSet A: %v", err)
	}
	if err := devB.IpcSet(cfgB); err != nil {
		t.Fatalf("IpcSet B: %v", err)
	}
	if err := devA.Up(); err != nil {
		t.Fatalf("Up A: %v", err)
	}
	if err := devB.Up(); err != nil {
		t.Fatalf("Up B: %v", err)
	}

	if opts.loopback {
		// The ports are known only after Up.
		if err := devA.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=127.0.0.1:%d\n",
			hex.EncodeToString(pkB[:]), listenPort(t, devB))); err != nil {
			t.Fatalf("set endpoint A->B: %v", err)
		}
		if err := devB.IpcSet(fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=127.0.0.1:%d\n",
			hex.EncodeToString(pkA[:]), listenPort(t, devA))); err != nil {
			t.Fatalf("set endpoint B->A: %v", err)
		}
	}

	return &devicePair{devA: devA, devB: devB, tunA: tunA, tunB: tunB}
}

// listenPort reads listen_port from the device's IpcGet output.
func listenPort(t *testing.T, dev *Device) uint16 {
	t.Helper()
	dump, err := dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	for _, line := range strings.Split(dump, "\n") {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			port, err := strconv.ParseUint(v, 10, 16)
			if err != nil {
				t.Fatalf("parse listen_port %q: %v", v, err)
			}
			return uint16(port)
		}
	}
	t.Fatalf("listen_port not found in IpcGet output:\n%s", dump)
	return 0
}

// awaitPacket waits for want to arrive on the receiving tun, periodically
// re-sending via resend (nothing is delivered before the handshake completes).
func awaitPacket(t *testing.T, from *chanTun, want []byte, resend func()) {
	t.Helper()
	deadline := time.After(20 * time.Second)
	retry := time.NewTicker(1 * time.Second)
	defer retry.Stop()
	for {
		select {
		case got := <-from.fromDevice:
			if bytes.Equal(got, want) {
				return
			}
			t.Logf("ignoring unexpected packet, len=%d", len(got))
		case <-retry.C:
			resend()
		case <-deadline:
			t.Fatal("timed out waiting for packet on peer tun")
		}
	}
}

// awaitNoPacket asserts nothing reaches the tun within d.
func awaitNoPacket(t *testing.T, from *chanTun, d time.Duration) {
	t.Helper()
	select {
	case got := <-from.fromDevice:
		t.Fatalf("unexpected packet delivered, len=%d", len(got))
	case <-time.After(d):
	}
}

// pingBothWays passes one packet A -> B over the tun read path and one back.
func pingBothWays(t *testing.T, pair *devicePair) {
	t.Helper()
	ping := buildIPv4Packet(testIPA, testIPB, 64)
	sendPing := func() { pair.tunA.toDevice <- append([]byte(nil), ping...) }
	sendPing()
	awaitPacket(t, pair.tunB, ping, sendPing)

	pong := buildIPv4Packet(testIPB, testIPA, 64)
	sendPong := func() { pair.tunB.toDevice <- append([]byte(nil), pong...) }
	sendPong()
	awaitPacket(t, pair.tunA, pong, sendPong)
}

// uapiLines joins key=value pairs into uapi lines.
func uapiLines(kv ...string) string {
	if len(kv)%2 != 0 {
		panic("odd number of args to uapiLines")
	}
	var b strings.Builder
	for i := 0; i < len(kv); i += 2 {
		b.WriteString(kv[i])
		b.WriteByte('=')
		b.WriteString(kv[i+1])
		b.WriteByte('\n')
	}
	return b.String()
}
