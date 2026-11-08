# Changelog

**Read this when:** you need to know what changed in a release of this fork, or you are adding an
entry. Grep it, do not read it. Newest first. Upstream's own changes are in its release notes.

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
