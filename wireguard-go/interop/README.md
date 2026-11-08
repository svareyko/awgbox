# interop: the fork against the official amneziawg-go

Proves that this fork (`github.com/sagernet/wireguard-go` with AmneziaWG 3.1 grafted in) speaks the same wire protocol as `github.com/amnezia-vpn/amneziawg-go/v3` at `v3.1.20260828`: two userspace devices in one process, real UDP on 127.0.0.1 only, channel-backed TUNs, a ping both ways with the full AWG 3.1 set (both roles), single-value headers as a typical server profile, plain WireGuard, and a header-key mismatch as a negative control.

Run from this directory (its own module; `replace` points the fork at `../`):

    go test -count=1 -v ./...

The first run downloads amneziawg-go and its dependencies into the module cache (`GOMODCACHE`). No OS interfaces are created; the package finishes in about ten seconds.

Note: `random_trailers` must be set on both sides; a receiver without it drops longer datagrams as "unknown type".
