# awgbox release build. Usage: make awg-release [AWG_VERSION=1.14.4-awg.3]
AWG_VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null | sed 's/^v//')

.PHONY: awg-release
awg-release:
	@test -n "$(AWG_VERSION)" || { echo "HEAD is not tagged: pass AWG_VERSION=<version>"; exit 1; }
	GOTOOLCHAIN=local GOFLAGS=-mod=mod CGO_ENABLED=0 go run ./build/release -version $(AWG_VERSION)
