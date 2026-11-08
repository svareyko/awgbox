/* SPDX-License-Identifier: MIT
 *
 * Harness for the interoperability tests: loopback-only UDP binds for both
 * implementations (real sockets on 127.0.0.1, never on all interfaces), a
 * channel-backed TUN for the fork (amneziawg-go brings tun/tuntest), and a
 * small "side" abstraction so a test can put either implementation in either
 * role.
 */

package interop

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
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

	aconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	adevice "github.com/amnezia-vpn/amneziawg-go/v3/device"
	atuntest "github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
	fconn "github.com/sagernet/wireguard-go/conn"
	fdevice "github.com/sagernet/wireguard-go/device"
	ftun "github.com/sagernet/wireguard-go/tun"
)

var (
	initiatorIP = netip.MustParseAddr("10.0.0.1")
	responderIP = netip.MustParseAddr("10.0.0.2")
)

// ---------------------------------------------------------------------------
// Loopback UDP socket shared by both bind flavours.
// ---------------------------------------------------------------------------

type loopbackSocket struct {
	mu   sync.Mutex
	conn *net.UDPConn
}

func (s *loopbackSocket) open(port uint16) (*net.UDPConn, uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return nil, 0, errors.New("bind is already open")
	}
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		return nil, 0, err
	}
	s.conn = c
	return c, uint16(c.LocalAddr().(*net.UDPAddr).Port), nil
}

func (s *loopbackSocket) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

func (s *loopbackSocket) send(bufs [][]byte, dst netip.AddrPort, offset int) error {
	s.mu.Lock()
	c := s.conn
	s.mu.Unlock()
	if c == nil {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := c.WriteToUDPAddrPort(buf[offset:], dst); err != nil {
			return err
		}
	}
	return nil
}

func parseLoopback(s string) (netip.AddrPort, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if !ap.Addr().IsLoopback() {
		return netip.AddrPort{}, fmt.Errorf("loopback bind: %s is not a loopback endpoint", s)
	}
	return ap, nil
}

func readOne(c *net.UDPConn, buf []byte) (int, netip.AddrPort, error) {
	n, addr, err := c.ReadFromUDPAddrPort(buf)
	if err != nil {
		return 0, netip.AddrPort{}, err
	}
	return n, netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port()), nil
}

// forkBind implements the fork's conn.Bind.
type forkBind struct{ sock loopbackSocket }

func (b *forkBind) Open(port uint16) ([]fconn.ReceiveFunc, uint16, error) {
	c, actual, err := b.sock.open(port)
	if err != nil {
		return nil, 0, err
	}
	fn := func(packets [][]byte, sizes []int, eps []fconn.Endpoint) (int, error) {
		n, from, err := readOne(c, packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &fconn.StdNetEndpoint{AddrPort: from}
		return 1, nil
	}
	return []fconn.ReceiveFunc{fn}, actual, nil
}

func (b *forkBind) Close() error              { return b.sock.close() }
func (b *forkBind) SetMark(mark uint32) error { return nil }
func (b *forkBind) BatchSize() int            { return 1 }

func (b *forkBind) Send(bufs [][]byte, ep fconn.Endpoint, offset int) error {
	e, ok := ep.(*fconn.StdNetEndpoint)
	if !ok {
		return fconn.ErrWrongEndpointType
	}
	return b.sock.send(bufs, e.AddrPort, offset)
}

func (b *forkBind) ParseEndpoint(s string) (fconn.Endpoint, error) {
	ap, err := parseLoopback(s)
	if err != nil {
		return nil, err
	}
	return &fconn.StdNetEndpoint{AddrPort: ap}, nil
}

func (b *forkBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {}

// awgBind implements amneziawg-go's conn.Bind.
type awgBind struct{ sock loopbackSocket }

func (b *awgBind) Open(port uint16) ([]aconn.ReceiveFunc, uint16, error) {
	c, actual, err := b.sock.open(port)
	if err != nil {
		return nil, 0, err
	}
	fn := func(packets [][]byte, sizes []int, eps []aconn.Endpoint) (int, error) {
		n, from, err := readOne(c, packets[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &aconn.StdNetEndpoint{AddrPort: from}
		return 1, nil
	}
	return []aconn.ReceiveFunc{fn}, actual, nil
}

func (b *awgBind) Close() error              { return b.sock.close() }
func (b *awgBind) SetMark(mark uint32) error { return nil }
func (b *awgBind) BatchSize() int            { return 1 }

func (b *awgBind) Send(bufs [][]byte, ep aconn.Endpoint) error {
	e, ok := ep.(*aconn.StdNetEndpoint)
	if !ok {
		return aconn.ErrWrongEndpointType
	}
	return b.sock.send(bufs, e.AddrPort, 0)
}

func (b *awgBind) ParseEndpoint(s string) (aconn.Endpoint, error) {
	ap, err := parseLoopback(s)
	if err != nil {
		return nil, err
	}
	return &aconn.StdNetEndpoint{AddrPort: ap}, nil
}

// ---------------------------------------------------------------------------
// Channel TUN for the fork (its tree has no tun/tuntest).
// ---------------------------------------------------------------------------

type forkChanTun struct {
	toDevice   chan []byte // packets the device reads (outbound plaintext)
	fromDevice chan []byte // packets the device writes (inbound plaintext)
	events     chan ftun.Event
	closed     chan struct{}
	closeOnce  sync.Once
}

func newForkChanTun() *forkChanTun {
	return &forkChanTun{
		toDevice:   make(chan []byte, 64),
		fromDevice: make(chan []byte, 64),
		events:     make(chan ftun.Event, 4),
		closed:     make(chan struct{}),
	}
}

func (t *forkChanTun) File() *os.File { return nil }

func (t *forkChanTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case <-t.closed:
		return 0, os.ErrClosed
	case pkt := <-t.toDevice:
		sizes[0] = copy(bufs[0][offset:], pkt)
		return 1, nil
	}
}

func (t *forkChanTun) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		pkt := append([]byte(nil), buf[offset:]...)
		select {
		case <-t.closed:
			return i, os.ErrClosed
		case t.fromDevice <- pkt:
		}
	}
	return len(bufs), nil
}

func (t *forkChanTun) MTU() (int, error)         { return fdevice.DefaultMTU, nil }
func (t *forkChanTun) Name() (string, error)     { return "forkchantun", nil }
func (t *forkChanTun) Events() <-chan ftun.Event { return t.events }
func (t *forkChanTun) BatchSize() int            { return 1 }

func (t *forkChanTun) Close() error {
	t.closeOnce.Do(func() {
		close(t.closed)
		close(t.events)
	})
	return nil
}

// ---------------------------------------------------------------------------
// Loggers into t.Logf, silenced once the test's devices are closed.
// ---------------------------------------------------------------------------

type testLog struct {
	t    *testing.T
	mu   sync.Mutex
	done bool
}

// newTestLog must be called before any device is created: its cleanup is
// registered first, so it runs last, after the devices are closed.
func newTestLog(t *testing.T) *testLog {
	l := &testLog{t: t}
	t.Cleanup(func() {
		l.mu.Lock()
		l.done = true
		l.mu.Unlock()
	})
	return l
}

func (l *testLog) logf(prefix string) func(string, ...any) {
	return func(format string, args ...any) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if !l.done {
			l.t.Logf(prefix+format, args...)
		}
	}
}

// ---------------------------------------------------------------------------
// Sides.
// ---------------------------------------------------------------------------

type side interface {
	name() string
	ipcSet(cfg string) error
	ipcGet() (string, error)
	up() error
	inject(pkt []byte)        // a packet the device reads from its TUN
	delivered() <-chan []byte // packets the device writes to its TUN
}

type forkSide struct {
	dev *fdevice.Device
	tun *forkChanTun
}

func newForkSide(t *testing.T, log *testLog, role string) side {
	tn := newForkChanTun()
	logger := &fdevice.Logger{
		Verbosef: log.logf("fork " + role + " DEBUG: "),
		Errorf:   log.logf("fork " + role + " ERROR: "),
	}
	dev := fdevice.NewDevice(t.Context(), tn, &forkBind{}, logger, 1)
	t.Cleanup(dev.Close)
	return &forkSide{dev: dev, tun: tn}
}

func (s *forkSide) name() string             { return "fork" }
func (s *forkSide) ipcSet(cfg string) error  { return s.dev.IpcSet(cfg) }
func (s *forkSide) ipcGet() (string, error)  { return s.dev.IpcGet() }
func (s *forkSide) up() error                { return s.dev.Up() }
func (s *forkSide) delivered() <-chan []byte { return s.tun.fromDevice }
func (s *forkSide) inject(pkt []byte) {
	select {
	case s.tun.toDevice <- append([]byte(nil), pkt...):
	case <-s.tun.closed:
	}
}

type awgSide struct {
	dev *adevice.Device
	tun *atuntest.ChannelTUN
}

func newAWGSide(t *testing.T, log *testLog, role string) side {
	tn := atuntest.NewChannelTUN()
	logger := &adevice.Logger{
		Verbosef: log.logf("amneziawg-go " + role + " DEBUG: "),
		Errorf:   log.logf("amneziawg-go " + role + " ERROR: "),
	}
	dev := adevice.NewDevice(tn.TUN(), &awgBind{}, logger)
	t.Cleanup(dev.Close)
	return &awgSide{dev: dev, tun: tn}
}

func (s *awgSide) name() string             { return "amneziawg-go" }
func (s *awgSide) ipcSet(cfg string) error  { return s.dev.IpcSet(cfg) }
func (s *awgSide) ipcGet() (string, error)  { return s.dev.IpcGet() }
func (s *awgSide) up() error                { return s.dev.Up() }
func (s *awgSide) delivered() <-chan []byte { return s.tun.Inbound }
func (s *awgSide) inject(pkt []byte) {
	// Outbound is unbuffered; the device's TUN reader drains it.
	select {
	case s.tun.Outbound <- append([]byte(nil), pkt...):
	case <-time.After(time.Second):
	}
}

// ---------------------------------------------------------------------------
// Pair setup.
// ---------------------------------------------------------------------------

type pairConfig struct {
	initiatorDevice string // device lines on the initiator
	responderDevice string // device lines on the responder
	initiatorPeer   string // peer lines on the initiator (the responder as seen by it)
}

type keyPair struct{ priv, pub string }

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("X25519: %v", err)
	}
	return keyPair{priv: hex.EncodeToString(k.Bytes()), pub: hex.EncodeToString(k.PublicKey().Bytes())}
}

func randomHex32(t *testing.T) string {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return hex.EncodeToString(b)
}

// lines joins key=value pairs into UAPI lines.
func lines(kv ...string) string {
	if len(kv)%2 != 0 {
		panic("lines: odd number of arguments")
	}
	var b strings.Builder
	for i := 0; i < len(kv); i += 2 {
		b.WriteString(kv[i] + "=" + kv[i+1] + "\n")
	}
	return b.String()
}

// configurePair configures and brings up the responder (listen_port 0, port
// read back from IpcGet), then the initiator with the responder's endpoint.
func configurePair(t *testing.T, initiator, responder side, cfg pairConfig) {
	t.Helper()
	ki, kr := newKeyPair(t), newKeyPair(t)

	respCfg := "private_key=" + kr.priv + "\nlisten_port=0\n" + cfg.responderDevice +
		lines("replace_peers", "true", "public_key", ki.pub, "allowed_ip", initiatorIP.String()+"/32")
	t.Logf("responder (%s) UAPI:\n%s", responder.name(), redact(respCfg))
	if err := responder.ipcSet(respCfg); err != nil {
		t.Fatalf("responder IpcSet: %v", err)
	}
	if err := responder.up(); err != nil {
		t.Fatalf("responder Up: %v", err)
	}
	port := listenPort(t, responder)

	initCfg := "private_key=" + ki.priv + "\n" + cfg.initiatorDevice +
		lines("replace_peers", "true", "public_key", kr.pub, "allowed_ip", responderIP.String()+"/32",
			"endpoint", fmt.Sprintf("127.0.0.1:%d", port)) + cfg.initiatorPeer
	t.Logf("initiator (%s) UAPI:\n%s", initiator.name(), redact(initCfg))
	if err := initiator.ipcSet(initCfg); err != nil {
		t.Fatalf("initiator IpcSet: %v", err)
	}
	if err := initiator.up(); err != nil {
		t.Fatalf("initiator Up: %v", err)
	}
}

func redact(cfg string) string {
	var out []string
	for _, l := range strings.Split(strings.TrimSuffix(cfg, "\n"), "\n") {
		if strings.HasPrefix(l, "private_key=") {
			l = "private_key=<redacted>"
		}
		out = append(out, "  "+l)
	}
	return strings.Join(out, "\n")
}

func listenPort(t *testing.T, s side) uint16 {
	t.Helper()
	dump, err := s.ipcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	for _, l := range strings.Split(dump, "\n") {
		if v, ok := strings.CutPrefix(l, "listen_port="); ok {
			p, err := strconv.ParseUint(v, 10, 16)
			if err != nil || p == 0 {
				t.Fatalf("bad listen_port %q", v)
			}
			return uint16(p)
		}
	}
	t.Fatalf("no listen_port in IpcGet output")
	return 0
}

// awaitPacket injects pkt on from and waits for it on to, re-injecting every
// second (nothing passes before the handshake completes).
func awaitPacket(t *testing.T, from, to side, pkt []byte, timeout time.Duration) {
	t.Helper()
	start := time.Now()
	deadline := time.After(timeout)
	retry := time.NewTicker(time.Second)
	defer retry.Stop()
	from.inject(pkt)
	for {
		select {
		case got := <-to.delivered():
			if bytes.Equal(got, pkt) {
				t.Logf("%s -> %s delivered after %v", from.name(), to.name(), time.Since(start).Round(time.Millisecond))
				return
			}
			t.Logf("ignoring unexpected packet on %s, len=%d", to.name(), len(got))
		case <-retry.C:
			from.inject(pkt)
		case <-deadline:
			t.Fatalf("%s -> %s: packet not delivered within %v", from.name(), to.name(), timeout)
		}
	}
}

// awaitNoPacket injects pkt on from every second and asserts nothing reaches to.
func awaitNoPacket(t *testing.T, from, to side, pkt []byte, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	retry := time.NewTicker(time.Second)
	defer retry.Stop()
	from.inject(pkt)
	for {
		select {
		case got := <-to.delivered():
			t.Fatalf("%s -> %s: packet delivered (len=%d) where none should pass", from.name(), to.name(), len(got))
		case <-retry.C:
			from.inject(pkt)
		case <-deadline:
			return
		}
	}
}

func pingInitiatorToResponder() []byte { return atuntest.Ping(responderIP, initiatorIP) }
func pingResponderToInitiator() []byte { return atuntest.Ping(initiatorIP, responderIP) }

func pingBothWays(t *testing.T, initiator, responder side) {
	t.Helper()
	awaitPacket(t, initiator, responder, pingInitiatorToResponder(), 10*time.Second)
	awaitPacket(t, responder, initiator, pingResponderToInitiator(), 10*time.Second)
}

func handshakeDone(t *testing.T, s side) bool {
	t.Helper()
	dump, err := s.ipcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	return !strings.Contains(dump, "last_handshake_time_sec=0\n")
}
