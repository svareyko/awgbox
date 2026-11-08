# sing-box with AmneziaWG

A fork of [SagerNet/sing-box](https://github.com/SagerNet/sing-box) v1.14.4 whose `wireguard`
endpoint speaks [AmneziaWG](https://github.com/amnezia-vpn/amneziawg-go) 3.1 on the client side.
Everything else is upstream sing-box, unchanged.

This is an independent fork. It is not affiliated with SagerNet or with Amnezia VPN, and it is not
supported by either of them.

| You want | Open |
|---|---|
| The AmneziaWG options of the `wireguard` endpoint, with their meaning | [docs/configuration/endpoint/wireguard.md](docs/configuration/endpoint/wireguard.md), section "AmneziaWG Fields" |
| A complete client config to start from | [examples/amneziawg-client.json](examples/amneziawg-client.json) |
| What changed in which release | [CHANGELOG.md](CHANGELOG.md) |
| How the fork is built, tested and kept in step with upstream (for maintainers and agents) | [CLAUDE.md](CLAUDE.md) |
| Everything else about sing-box | the upstream documentation, https://sing-box.sagernet.org |

## What it is

- sing-box v1.14.4 plus one feature: the `wireguard` endpoint accepts the AmneziaWG obfuscation
  parameters and runs the tunnel through a wireguard-go that implements them. The feature is always
  compiled in; there is no build tag.
- The WireGuard implementation is SagerNet's wireguard-go (the exact revision upstream v1.14.4 pins)
  with the obfuscation code of amneziawg-go v3.1.20260828 grafted into its `device` package. It lives
  in [wireguard-go/](wireguard-go/) and replaces the upstream module through `go.mod`.
- Built as a client: a `tun` inbound routed into a `wireguard` endpoint that carries the AmneziaWG
  parameters of the server's profile. The device code is symmetric; the fork is tested in both roles
  against the official amneziawg-go v3.1.20260828 in `wireguard-go/interop/`.

## What it is not

- Not a new protocol, outbound or inbound. An endpoint without AmneziaWG keys behaves exactly like
  upstream, byte for byte.
- No AmneziaWG server, no `awg-quick`, no `.conf` import: the parameters go into the sing-box JSON.
- No convenience layers from other forks (masquerade profiles, decoy generators, keepalive ranges per
  peer). The options are the ones amneziawg-go accepts over its UAPI, nothing more.
- Not a graphical client. The release is the `sing-box` binary.

## Options

All of them sit at the endpoint level, next to `private_key`, like the `[Interface]` keys of an
`awg-quick` file. Fields marked "server" must equal the server's values.

| Key | Type | Server | Meaning |
|---|---|---|---|
| `jc` | number (uint32) | | junk packets sent before each handshake initiation |
| `jmin`, `jmax` | number (uint32) | | junk packet size bounds, `jmin <= jmax` |
| `s1`, `s2`, `s3`, `s4` | number (0 to 65535) | yes | padding before handshake initiation, response, cookie reply and every transport packet |
| `h1`, `h2`, `h3`, `h4` | range | yes | magic headers of the four message kinds; must not overlap |
| `i1` to `i5` | string | | decoy packets in the AmneziaWG packet language, passed to the device as is |
| `header_protection_key` | string, base64 of 32 bytes | yes | AmneziaWG 3 header encryption; needs `s1` to `s4` of at least 12 |
| `content_padding_addition` | range | | extra padding inside transport packets |
| `rekey_after_time`, `rekey_timeout`, `reject_after_time`, `keepalive_timeout`, `max_handshake_attempts` | range | | overrides of the WireGuard timers (seconds) and of the handshake attempt limit |
| `random_trailers` | bool | yes | random tails on handshake and transport messages; a receiver accepts them only when its own flag is on, so both sides must set it |
| `disable_cookies` | bool | | never send or require cookie replies |

A range is a JSON number, or a string `"N"` or `"N-M"` with `N <= M`; the device picks a new value
from the range at every use. `0` and `""` mean unset.

`sing-box check` rejects what the device would refuse: non-numeric or out-of-range numbers,
`jmin > jmax`, overlapping headers, a bad `header_protection_key`, paddings too short for it.
The `i1` to `i5` strings are parsed by the device when the endpoint starts.

Without an explicit `mtu`, an endpoint with `s4` set uses 1280 instead of upstream's 1408.

### Example endpoint

```json
{
  "type": "wireguard",
  "tag": "awg",
  "mtu": 1280,
  "address": ["10.8.0.2/32"],
  "private_key": "SD+QN1yME7TRlKaAWVe1lGgKzSYxwrEf3z80A12J2Hs=",
  "jc": 4,
  "jmin": 40,
  "jmax": 70,
  "s1": 68,
  "s2": 149,
  "s3": 32,
  "s4": 16,
  "h1": 1785263459,
  "h2": 389527153,
  "h3": 1103948204,
  "h4": 2093847211,
  "peers": [
    {
      "address": "203.0.113.1",
      "port": 443,
      "public_key": "+MlQpO/DVfRTaWv3IaNt2GWm/AvBwWfMzfaiTUXm5ms=",
      "allowed_ips": ["0.0.0.0/0", "::/0"],
      "persistent_keepalive_interval": 25
    }
  ]
}
```

The full file with a `tun` inbound and routing is [examples/amneziawg-client.json](examples/amneziawg-client.json).

## Building

Requirements: Go 1.26.5 (the toolchain is pinned with `GOTOOLCHAIN=local`; any Go that satisfies
`go.mod` works) and git. No cgo: every target is cross-compiled with `CGO_ENABLED=0 -trimpath` and
the build tags of upstream's release (`release/DEFAULT_BUILD_TAGS_OTHERS`, darwin without `with_usbip`).

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File build\build.ps1 -Version 1.14.4-awg.1
```

```bash
make awg-release AWG_VERSION=1.14.4-awg.1
```

Both call `go run ./build/release`, which builds `darwin-arm64`, `darwin-amd64`, `windows-amd64`,
`windows-arm64` and `linux-amd64` into `dist/<version>/`:

| File | Content |
|---|---|
| `sing-box-<version>-<os>-<arch>.tar.gz` (darwin, linux) | directory `sing-box-<version>-<os>-<arch>/` with `sing-box` and `LICENSE` |
| `sing-box-<version>-<os>-<arch>.zip` (windows) | the same with `sing-box.exe` |
| `SHA256SUMS` | SHA-256 of the archives |
| `SHA256SUMS.binaries` | SHA-256 of the binaries inside them |

`sing-box version` prints the version given. Without `-Version` the scripts take the tag on `HEAD`
(`v1.14.4-awg.1` becomes `1.14.4-awg.1`). Pushing such a tag runs
[.github/workflows/awg-release.yml](.github/workflows/awg-release.yml), which builds the same five
archives and attaches them to a GitHub release.

Windows needs no `wintun.dll` next to the binary: sing-tun embeds wintun 0.14.1 in the executable,
as upstream's release does.

Only the `-Version` differs between the owner's machine and CI; see [CLAUDE.md](CLAUDE.md) for the
environment variables and the tests.

## Attribution and licence

- sing-box: Copyright SagerNet, GNU General Public License v3.0 or later ([LICENSE](LICENSE)).
  Upstream's licence adds that no derivative work may use its name or imply association without
  consent; this fork claims no association.
- wireguard-go: Copyright WireGuard LLC, MIT ([wireguard-go/LICENSE](wireguard-go/LICENSE)). The copy
  in `wireguard-go/` is SagerNet's fork at the revision sing-box v1.14.4 pins.
- amneziawg-go v3.1.20260828: Copyright Amnezia VPN, MIT
  ([wireguard-go/LICENSE.amneziawg-go](wireguard-go/LICENSE.amneziawg-go)); its obfuscation code is
  grafted into `wireguard-go/device/`.
- The adaptation of that graft to SagerNet's wireguard-go follows
  [Leadaxe/sing-box-lx](https://github.com/Leadaxe/sing-box-lx) and its `wireguard-go-awg2-lx`.

See [NOTICE](NOTICE). The fork as a whole is distributed under the GNU General Public License v3.0 or
later, like upstream.
