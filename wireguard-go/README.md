# wireguard-go with AmneziaWG obfuscation

**Read this when:** you work on the WireGuard engine under this sing-box tree.
**Sections:** 1 What this is · 2 Grafted files · 3 Tests · 4 How it is wired in

## 1. What this is

A copy of sagernet's fork of wireguard-go (module path
`github.com/sagernet/wireguard-go`, `go.mod` and `go.sum` unchanged) with the
AmneziaWG 3.1 obfuscation grafted onto it, and nothing else.

| Parent | Source | Revision |
|---|---|---|
| Base | `github.com/sagernet/wireguard-go` | commit `e4d85ef2ed38` (the revision sing-box v1.14.4 pins) |
| Graft | `github.com/amnezia-vpn/amneziawg-go` | tag `v3.1.20260828` (diffed against its zx2c4 merge base `12269c2761734b15625017d8565745096325392f`) |

Brought in from AmneziaWG: junk packets (Jc/Jmin/Jmax), paddings S1-S4,
magic headers H1-H4 as ranges, controlled packets I1-I5, header protection
(`header_protection_key`), `content_padding_addition`, `random_trailers`,
`disable_cookies`, the timing ranges (`rekey_after_time`, `rekey_timeout`,
`reject_after_time`, `keepalive_timeout`, `max_handshake_attempts`), the
ranged peer `persistent_keepalive_interval`, and their UAPI get/set keys.

One adaptation of sagernet's binds: they cleared bytes 1-3 of every received
datagram for the Cloudflare WARP "reserved" field. With AmneziaWG those bytes
belong to the magic header or the random padding, so `StdNetBind`,
`WinRingBind` and the darwin `recvmsg_x` path clear them only when a non-zero
reserved value is configured (`hasReserved`). The send side already stamps
them only for an endpoint whose reserved value was set.

sagernet's `MessageEncapsulatingTransportSize` headroom (8 free bytes before
every datagram passed to `conn.Bind.Send`) is kept; the AmneziaWG layout
follows it. See the comment above the message size constants in
`device/noise-protocol.go`.

`LICENSE` is sagernet's (MIT); `LICENSE.amneziawg-go` is amneziawg-go's.

## 2. Grafted files

| File | Change |
|---|---|
| `device/obf*.go` | new, verbatim from amneziawg-go: the I1-I5 tag parser and obfuscators |
| `device/noise-types.go` | `HeaderCipherKey`, `UintRange`, `AtomicUintRange` |
| `device/noise-protocol.go` | typed message types, `MessageUnknownType`, H1/H2 picked per message, `JunkPackets`, `HeaderProtectionCipher` |
| `device/device.go` | obfuscation state on `Device`, default H1-H4, keychain expiry from the timing ranges |
| `device/send.go` | padding, header protection, trailers and junk on every send path, including `InputPacket(s)` |
| `device/receive.go` | classification by size and H1-H4, header unmasking, padding removal, cookie bypass |
| `device/timers.go` | timers carry their duration; timeouts from the timing ranges |
| `device/peer.go` | ranged keepalive, UDP window, max handshake attempts |
| `device/cookie.go`, `device/constants.go` | cookie reply type from H3; `DefaultUdpWindow` |
| `device/uapi.go` | all AmneziaWG keys in `IpcSet` and `IpcGet` |
| `conn/bind_std.go`, `conn/bind_windows.go`, `conn/msgx_darwin.go` | the `hasReserved` gate |

## 3. Tests

From this directory, with the toolchain settings of the parent repository:

```
go test -skip TestEndpointResolver ./...
```

The device tests run two devices over an in-memory channel bind or over UDP
sockets bound to 127.0.0.1. sagernet's own `TestEndpointResolver*` use
`conn.NewStdNetBind`, which listens on all interfaces; on a desktop with a
firewall that asks about listening programs, skip them as above.

## 4. How it is wired in

The root `go.mod` of this repository replaces `github.com/sagernet/wireguard-go`
with this directory, so sing-box builds against it without changing imports.
