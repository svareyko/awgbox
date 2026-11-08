package wireguard

import (
	"context"
	"net/netip"
	"time"

	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type EndpointOptions struct {
	Context      context.Context
	Logger       logger.ContextLogger
	System       bool
	Handler      tun.Handler
	UDPTimeout   time.Duration
	ICMPTimeout  time.Duration
	UDPMapping   tun.NATMapping
	UDPFiltering tun.NATFiltering
	UDPNATMax    uint32

	InterfaceFinder   control.InterfaceFinder
	EgressPoolOptions tun.UDPEgressPoolOptions
	Dialer            N.Dialer
	CreateDialer      func(interfaceName string) N.Dialer
	Tag               string
	Name              string
	MTU               uint32
	Address           []netip.Prefix
	PrivateKey        string
	ListenPort        uint16
	ResolvePeer       func(domain string) ([]netip.Addr, error)
	Peers             []PeerOptions
	Workers           int
	AmneziaWG         AmneziaWGOptions
}

type PeerOptions struct {
	Endpoint                    M.Socksaddr
	PublicKey                   string
	PreSharedKey                string
	AllowedIPs                  []netip.Prefix
	PersistentKeepaliveInterval uint16
	Reserved                    []uint8
}

// AmneziaWGOptions carries the AmneziaWG device parameters. Ranges are
// canonical spec strings ("N" or "N-M"), empty when unset.
type AmneziaWGOptions struct {
	Jc                     uint32
	Jmin                   uint32
	Jmax                   uint32
	S1                     uint16
	S2                     uint16
	S3                     uint16
	S4                     uint16
	H1                     string
	H2                     string
	H3                     string
	H4                     string
	I1                     string
	I2                     string
	I3                     string
	I4                     string
	I5                     string
	HeaderProtectionKey    string
	ContentPaddingAddition string
	RekeyAfterTime         string
	RekeyTimeout           string
	RejectAfterTime        string
	KeepaliveTimeout       string
	MaxHandshakeAttempts   string
	RandomTrailers         bool
	DisableCookies         bool
}
