# awgbox: map for agents

**Read this when:** you start any session in this repository.
**Not this, for:** what awgbox is and the option names → [README.md](README.md); the meaning of
each option → [docs/configuration/endpoint/wireguard.md](docs/configuration/endpoint/wireguard.md);
what changed when → [CHANGELOG.md](CHANGELOG.md) (grep it, do not read it).

awgbox is SagerNet/sing-box v1.14.4 plus AmneziaWG 3.1 in the `wireguard` endpoint, always compiled
in. Branch `awg` carries our commits on top of upstream's tag; upstream's history is kept so that a
newer release can be rebased under it. The git remote `upstream` is SagerNet/sing-box.

**Names.** The product, the binary (`awgbox`, `awgbox.exe`), the archives, the `version` banner and
the cobra `Use` are awgbox (upstream's licence forbids using its name). The module path
`github.com/sagernet/sing-box`, every import path and the main package directory `cmd/sing-box` stay
upstream's: renaming them would make every rebase a conflict in every file. Where a document means
the origin of the code or quotes a licence, "sing-box" is the right word; where it means this
product, "awgbox" is.

## Task → file

| Task | Open |
|---|---|
| Option names, JSON types, range syntax, schema | `option/wireguard_amneziawg.go`; embedded into `WireGuardEndpointOptions` in `option/wireguard.go` |
| Validation and the UAPI lines sent to the device | `transport/wireguard/amneziawg.go` (`Validate`, `IpcLines`, MTU rules) |
| Where the lines join the device config, the MTU default | `transport/wireguard/endpoint.go`, `NewEndpoint` |
| Why bytes 1 to 3 of a datagram are left alone | `transport/wireguard/client_bind.go` (`hasReserved`) and `wireguard-go/conn/bind_std.go`, `bind_windows.go`, `msgx_darwin.go` |
| Mapping option → transport struct | `protocol/wireguard/endpoint.go`, `amneziaWGOptions` |
| The WireGuard implementation with the obfuscation | `wireguard-go/` (own module, replaced in `go.mod`); its `README.md` lists the grafted files and the two parents |
| Interoperability with the official implementation | `wireguard-go/interop/` (own module, tests against amneziawg-go v3.1.20260828 over loopback UDP) |
| Tests of the option and transport side | `option/wireguard_amneziawg_test.go`, `transport/wireguard/amneziawg_test.go`, `transport/wireguard/client_bind_test.go` |
| User documentation of the fields | `docs/configuration/endpoint/wireguard.md`, section "AmneziaWG Fields" (English page only) |
| Release build, packaging, checksums | `build/release/main.go` (the implementation), `build/build.ps1` and `build/awg.mk` (wrappers) |
| CI and releases on GitHub | `.github/workflows/awg-ci.yml`, `.github/workflows/awg-release.yml` |
| Licences and origins | `NOTICE`, `LICENSE`, `wireguard-go/LICENSE`, `wireguard-go/LICENSE.amneziawg-go` |
| A complete client config | `examples/amneziawg-client.json` |

## Ours versus upstream

Ours: `wireguard-go/`, `build/`, `examples/`, `NOTICE`, `CLAUDE.md`, `CHANGELOG.md`, `README.md`
(replaced), the two `awg-*.yml` workflows, `option/wireguard_amneziawg*.go`,
`transport/wireguard/amneziawg*.go`, `transport/wireguard/client_bind_test.go`, the "AmneziaWG
Fields" section of the docs page, the `AmneziaWGRange` definition and 25 properties in
`docs/schema.json`. Upstream files we edit, kept to a few lines each: `go.mod` (the `replace`),
`test/go.mod` (the same `replace`), `option/wireguard.go`, `transport/wireguard/endpoint.go`,
`transport/wireguard/endpoint_options.go`, `transport/wireguard/client_bind.go`,
`protocol/wireguard/endpoint.go`, `cmd/sing-box/cmd.go` (the `Use` name), `cmd/sing-box/cmd_version.go`
(the banner), `Makefile` (one `include`), `.gitignore`. Removed:
`.github/workflows/docker.yml`, `linux.yml`, `stale.yml` (they fire on every published release or
nightly and need upstream's secrets). Everything else is upstream and stays so.

## Toolchain and environment

| Fact | Value |
|---|---|
| Go | 1.26.5, `GOTOOLCHAIN=local`; `go.mod` asks for 1.25.5. On the owner's workstation: `G:\TOOLS\go\bin\go.exe` |
| Flags for every go command | `GOFLAGS=-mod=mod CGO_ENABLED=0` |
| Caches | inside the repository: `GOMODCACHE=<repo>/.modcache`, `GOCACHE=<repo>/.gocache` (both ignored); never under the user profile |
| Build tags | upstream's `release/DEFAULT_BUILD_TAGS_OTHERS`; darwin without `with_usbip` (as upstream's workflow) |
| ldflags | `-X github.com/sagernet/sing-box/constant.Version=<version>` plus `release/LDFLAGS`, `-s -w -buildid=`, `-trimpath` |
| Line endings | the owner's git has `core.autocrlf=true`; write LF, `gofmt -w` normalises |

## Commands

| Do | Run (repository root, environment as above) |
|---|---|
| Build and vet everything | `go build ./...` then `go vet -unsafeptr=false ./...` (two upstream files trip the unsafeptr analyzer; upstream's golangci config never runs govet) |
| Our tests | `go test ./option/ ./transport/wireguard/` |
| The fork's own tests | `cd wireguard-go && go test ./...` (two in-process devices over loopback UDP, about 15 s). On a desktop whose firewall asks about listening programs add `-skip TestEndpointResolver`: sagernet's resolver tests listen on all interfaces |
| Interop against amneziawg-go | `cd wireguard-go/interop && go test ./...` (downloads amneziawg-go v3.1.20260828 into the module cache) |
| Check a config | `go run ./cmd/sing-box check -c examples/amneziawg-client.json` |
| Regenerate the schema after changing options | `go run -ldflags "$(cat release/LDFLAGS)" -tags "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" ./cmd/sing-box schema -o docs/schema.json` |
| Release archives | `powershell -NoProfile -ExecutionPolicy Bypass -File build\build.ps1 -Version 1.14.4-awg.3 [-Go G:\TOOLS\go\bin\go.exe]` or `make awg-release AWG_VERSION=1.14.4-awg.3`; output in `dist/<version>/`: `awgbox-<version>-<os>-<arch>.{tar.gz,zip}`, `SHA256SUMS`, `SHA256SUMS.binaries` |

Upstream's `test/` module needs Docker and is not run here. Of upstream's own tests, `common/windivert` and `common/tlsspoof` need administrator rights (they load the WinDivert driver) and the three `TestWindowsClient*TLS13` tests in `common/tls` need Schannel TLS 1.3 (Windows 11); everything else passes on Windows 10. Windows builds need no `wintun.dll`:
sing-tun embeds wintun 0.14.1 (SHA-256 of the embedded DLLs: amd64
`e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`, arm64
`f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80`).

## Versions and releases

Versions are `<upstream>-awg.<n>`: `1.14.4-awg.3`. The version is baked at build time from the tag
on `HEAD` (`v1.14.4-awg.3`) or from `-Version`; `constant/version.go` stays upstream's `unknown`.
Pushing a `v*-awg.*` tag runs `awg-release.yml`, which builds the five targets on `ubuntu-latest`
with the same script and attaches `*.tar.gz`, `*.zip`, `SHA256SUMS` and `SHA256SUMS.binaries` to a
GitHub release. Every release gets an entry in `CHANGELOG.md`.

## Taking an upstream release

1. `git fetch upstream --tags`, then `git rebase v<new> awg` (our commits are the ones after the
   old upstream tag). Expect conflicts in: the three deleted workflows (delete them again),
   `Makefile`, `.gitignore`, `option/wireguard.go`, `transport/wireguard/endpoint.go`,
   `endpoint_options.go`, `client_bind.go`, `protocol/wireguard/endpoint.go`, `cmd/sing-box/cmd.go`,
   `cmd/sing-box/cmd_version.go`, the docs page, and `docs/schema.json` (do not merge it: take
   upstream's and regenerate).
2. If upstream moved `github.com/sagernet/wireguard-go` in `go.mod`: clone sagernet/wireguard-go
   into scratch, `git diff <old revision> <new revision>` and apply it to `wireguard-go/`
   (`git apply --directory=wireguard-go -3`); resolve conflicts in the grafted files listed in
   `wireguard-go/README.md`; copy the new `go.mod`/`go.sum` of the module; run its tests and the
   interop tests.
3. `go build ./... && go vet ./...`, the three test commands, `check` on the example, regenerate the
   schema, build the archives, tag `v<new>-awg.1`, write the CHANGELOG entry.
