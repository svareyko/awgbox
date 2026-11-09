# Changelog

**Read this when:** you need to know what changed in a release of this fork, or you are adding an
entry. Grep it, do not read it. Newest first. Upstream's own changes are in its release notes.

## 1.14.4-awg.3 (2026-11-09)

The `wireguard` endpoint keeps working on a machine without IPv6 on the outgoing interface.

- `wireguard-go/conn/bind_std.go`: when the IPv4 socket opened and the IPv6 one fails with any
  error, `StdNetBind.Open` keeps IPv4, warns once per distinct cause ("IPv6 bind failed: <err>;
  running IPv4 only") and goes on; it fails only when neither family opened. Before, only
  `EAFNOSUPPORT` was tolerated: on Windows, `auto_detect_interface` pinning the IPv6 socket to a
  Wi-Fi adapter with IPv6 disabled fails with "An invalid argument was supplied", the bind closed
  IPv4 too, and every handshake then failed with "address family not supported by protocol". The
  port reported by `Open` is the IPv4 socket's when IPv6 failed; a v4-mapped destination leaves
  through the IPv4 socket when there is no IPv6 one; a rebind behaves the same. A consequence of
  the new policy: a fixed `listen_port` whose IPv6 side another program holds now runs IPv4 only
  with the same warning, where it used to fail.
- `transport/wireguard/endpoint.go`: the bind's warning goes to the endpoint's logger
  (`StdNetBind.SetWarnFunc`).
- Test: `wireguard-go/conn/bind_ipv4only_test.go`.

## 1.14.4-awg.2 (2026-11-08)

The product is named awgbox; no functional change.

- Binary `awgbox` (`awgbox.exe` on Windows), archives `awgbox-<version>-<os>-<arch>.tar.gz` and
  `.zip` with a top directory of the same name, `version` banner `awgbox version <version>`, cobra
  `Use` name `awgbox`, workflow artifact `awgbox-<version>`. The Go module path, the import paths and
  the main package `cmd/sing-box` stay upstream's.
- README, CLAUDE.md, NOTICE and the AmneziaWG docs section use the new name; "sing-box" remains
  where it names the origin of the code or a licence.

## 1.14.4-awg.1 (2026-11-08)

First release. SagerNet/sing-box v1.14.4 plus AmneziaWG 3.1 in the `wireguard` endpoint:

- `wireguard-go/`: SagerNet's wireguard-go at the revision v1.14.4 pins, with the obfuscation of
  amneziawg-go v3.1.20260828 grafted into `device/` (junk packets, paddings S1 to S4, magic headers
  H1 to H4, decoy packets I1 to I5, header protection, content padding, timer ranges, random
  trailers, cookie switch) and the UAPI keys for them; receive paths of the binds clear bytes 1 to 3
  only when a WARP reserved value is configured. Replaced into the build through `go.mod`.
- `wireguard` endpoint options `jc jmin jmax s1 s2 s3 s4 h1 h2 h3 h4 i1 i2 i3 i4 i5
  header_protection_key content_padding_addition rekey_after_time rekey_timeout reject_after_time
  keepalive_timeout max_handshake_attempts random_trailers disable_cookies`, validated so that
  `sing-box check` rejects what the device would refuse; default MTU 1280 when `s4` is set.
- `ClientBind` (the detour path) stamps and clears the reserved bytes only when a non-zero value is
  configured, so magic headers survive.
- `wireguard-go/interop/`: tests against the official amneziawg-go v3.1.20260828 over loopback, both
  roles, full AmneziaWG 3.1 set, plain WireGuard, header-key mismatch. They showed that
  `random_trailers` must be set on both sides.
- Docs page section, JSON schema, example config, release build (`build/`) for darwin-arm64,
  darwin-amd64, windows-amd64, windows-arm64, linux-amd64 with checksums, GitHub Actions for CI and
  tag releases. Upstream's docker, linux and stale workflows removed.
