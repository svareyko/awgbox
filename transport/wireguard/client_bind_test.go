package wireguard

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/wireguard-go/conn"

	"github.com/stretchr/testify/require"
)

type testPacketConn struct {
	written [][]byte
	read    []byte
}

func (c *testPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	return copy(p, c.read), &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 443}, nil
}

func (c *testPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.written = append(c.written, append([]byte(nil), p...))
	return len(p), nil
}

func (c *testPacketConn) Close() error                       { return nil }
func (c *testPacketConn) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *testPacketConn) SetDeadline(t time.Time) error      { return nil }
func (c *testPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *testPacketConn) SetWriteDeadline(t time.Time) error { return nil }

func newTestClientBind(reserved [3]uint8) (*ClientBind, *testPacketConn) {
	packetConn := &testPacketConn{}
	bind := &ClientBind{
		reservedForEndpoint: make(map[netip.AddrPort][3]uint8),
		done:                make(chan struct{}),
		reserved:            reserved,
		conn:                &wireConn{PacketConn: packetConn, done: make(chan struct{})},
	}
	return bind, packetConn
}

func TestClientBindReserved(t *testing.T) {
	t.Parallel()
	destination := netip.MustParseAddrPort("192.0.2.1:443")
	// An AmneziaWG magic header uses all of bytes 0-3.
	packet := []byte{0xb8, 0x9a, 0x8c, 0x70, 0x01, 0x02, 0x03, 0x04}
	stamped := []byte{0xb8, 0x0a, 0x0b, 0x0c, 0x01, 0x02, 0x03, 0x04}
	cleared := []byte{0xb8, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04}

	receive := func(t *testing.T, bind *ClientBind, packetConn *testPacketConn, data []byte) []byte {
		packetConn.read = data
		buffers := [][]byte{make([]byte, 64)}
		sizes := make([]int, 1)
		endpoints := make([]conn.Endpoint, 1)
		count, err := bind.receive(buffers, sizes, endpoints)
		require.NoError(t, err)
		require.Equal(t, 1, count)
		return buffers[0][:sizes[0]]
	}
	send := func(t *testing.T, bind *ClientBind, packetConn *testPacketConn) []byte {
		require.NoError(t, bind.Send([][]byte{append([]byte(nil), packet...)}, remoteEndpoint(destination), 0))
		return packetConn.written[len(packetConn.written)-1]
	}

	t.Run("none", func(t *testing.T) {
		bind, packetConn := newTestClientBind([3]uint8{})
		require.False(t, bind.hasReserved())
		require.Equal(t, packet, send(t, bind, packetConn))
		require.Equal(t, packet, receive(t, bind, packetConn, packet))
	})
	t.Run("zero per endpoint", func(t *testing.T) {
		bind, packetConn := newTestClientBind([3]uint8{})
		bind.SetReservedForEndpoint(destination, [3]uint8{})
		require.False(t, bind.hasReserved())
		require.Equal(t, packet, send(t, bind, packetConn))
		require.Equal(t, packet, receive(t, bind, packetConn, packet))
	})
	t.Run("default", func(t *testing.T) {
		bind, packetConn := newTestClientBind([3]uint8{0x0a, 0x0b, 0x0c})
		require.True(t, bind.hasReserved())
		require.Equal(t, stamped, send(t, bind, packetConn))
		require.Equal(t, cleared, receive(t, bind, packetConn, stamped))
	})
	t.Run("per endpoint", func(t *testing.T) {
		bind, packetConn := newTestClientBind([3]uint8{})
		bind.SetReservedForEndpoint(destination, [3]uint8{0x0a, 0x0b, 0x0c})
		require.True(t, bind.hasReserved())
		require.Equal(t, stamped, send(t, bind, packetConn))
		require.Equal(t, cleared, receive(t, bind, packetConn, stamped))
	})
}
