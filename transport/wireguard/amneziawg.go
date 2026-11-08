package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"

	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

const (
	// amneziaWGHeaderKeySize is the size of the header protection key.
	amneziaWGHeaderKeySize = 32
	// amneziaWGHeaderNonceSize is the size of the header cipher nonce, taken
	// from the first bytes of the s1-s4 padding of every message.
	amneziaWGHeaderNonceSize = 12
)

// Default message types the device keeps for an unset h1-h4.
var amneziaWGDefaultHeaders = [4]amneziaWGRange{{1, 1}, {2, 2}, {3, 3}, {4, 4}}

type amneziaWGRange struct {
	lo, hi uint32
}

func (r amneziaWGRange) String() string {
	if r.lo == r.hi {
		return F.ToString(r.lo)
	}
	return F.ToString(r.lo, "-", r.hi)
}

func (r amneziaWGRange) overlap(other amneziaWGRange) bool {
	return r.lo <= other.hi && other.lo <= r.hi
}

// parseAmneziaWGRange parses spec the way the device's UintRange.FromString
// does: "N" or "N-M", both uint32, N <= M.
func parseAmneziaWGRange(spec string) (amneziaWGRange, error) {
	parts := strings.Split(spec, "-")
	if len(parts) > 2 {
		return amneziaWGRange{}, E.New("invalid range ", strconv.Quote(spec))
	}
	lo, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return amneziaWGRange{}, E.Cause(err, "invalid range ", strconv.Quote(spec))
	}
	hi := lo
	if len(parts) == 2 {
		hi, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return amneziaWGRange{}, E.Cause(err, "invalid range ", strconv.Quote(spec))
		}
	}
	if hi < lo {
		return amneziaWGRange{}, E.New("invalid range ", strconv.Quote(spec), ": start is greater than end")
	}
	return amneziaWGRange{uint32(lo), uint32(hi)}, nil
}

type amneziaWGKeyValue struct {
	key   string
	value string
}

func (o AmneziaWGOptions) ranges() []amneziaWGKeyValue {
	return []amneziaWGKeyValue{
		{"content_padding_addition", o.ContentPaddingAddition},
		{"rekey_after_time", o.RekeyAfterTime},
		{"rekey_timeout", o.RekeyTimeout},
		{"reject_after_time", o.RejectAfterTime},
		{"keepalive_timeout", o.KeepaliveTimeout},
		{"max_handshake_attempts", o.MaxHandshakeAttempts},
	}
}

func (o AmneziaWGOptions) headers() []amneziaWGKeyValue {
	return []amneziaWGKeyValue{{"h1", o.H1}, {"h2", o.H2}, {"h3", o.H3}, {"h4", o.H4}}
}

// Validate rejects what the AmneziaWG device would refuse at IpcSet, or
// would break on later, so that the error surfaces in `awgbox check`.
func (o AmneziaWGOptions) Validate() error {
	_, err := o.validate()
	return err
}

func (o AmneziaWGOptions) validate() (headerProtectionKeyHex string, err error) {
	if o.Jmin > o.Jmax {
		return "", E.New("amneziawg: jmin (", o.Jmin, ") must not be greater than jmax (", o.Jmax, ")")
	}
	headers := amneziaWGDefaultHeaders
	for i, header := range o.headers() {
		if header.value == "" {
			continue
		}
		headers[i], err = parseAmneziaWGRange(header.value)
		if err != nil {
			return "", E.Cause(err, "amneziawg: ", header.key)
		}
	}
	for i := 0; i < len(headers); i++ {
		for j := i + 1; j < len(headers); j++ {
			if headers[i].overlap(headers[j]) {
				return "", E.New("amneziawg: headers must not overlap: h", i+1, " (", headers[i], ") and h", j+1, " (", headers[j], ")")
			}
		}
	}
	for _, knob := range o.ranges() {
		if knob.value == "" {
			continue
		}
		_, err = parseAmneziaWGRange(knob.value)
		if err != nil {
			return "", E.Cause(err, "amneziawg: ", knob.key)
		}
	}
	if o.HeaderProtectionKey == "" {
		return "", nil
	}
	key, err := base64.StdEncoding.DecodeString(o.HeaderProtectionKey)
	if err != nil {
		return "", E.Cause(err, "amneziawg: decode header_protection_key")
	}
	if len(key) != amneziaWGHeaderKeySize {
		return "", E.New("amneziawg: header_protection_key must be ", amneziaWGHeaderKeySize, " bytes, got ", len(key))
	}
	isZero := true
	for _, b := range key {
		if b != 0 {
			isZero = false
			break
		}
	}
	if isZero {
		return "", E.New("amneziawg: header_protection_key must not be all zeros")
	}
	for i, padding := range []uint16{o.S1, o.S2, o.S3, o.S4} {
		if padding < amneziaWGHeaderNonceSize {
			return "", E.New("amneziawg: s", i+1, " (", padding, ") must be at least ", amneziaWGHeaderNonceSize, " when header_protection_key is set")
		}
	}
	return hex.EncodeToString(key), nil
}

// IpcLines validates the options and renders them as UAPI device lines, one
// key per line with a leading newline and no trailing one. It returns "" when
// no AmneziaWG parameter is set.
func (o AmneziaWGOptions) IpcLines() (string, error) {
	headerProtectionKeyHex, err := o.validate()
	if err != nil {
		return "", err
	}
	var lines strings.Builder
	writeLine := func(key, value string) {
		if value == "" {
			return
		}
		lines.WriteString("\n")
		lines.WriteString(key)
		lines.WriteString("=")
		lines.WriteString(value)
	}
	writeUint := func(key string, value uint32) {
		if value != 0 {
			writeLine(key, F.ToString(value))
		}
	}
	writeBool := func(key string, value bool) {
		if value {
			writeLine(key, "1")
		}
	}
	writeUint("jc", o.Jc)
	writeUint("jmin", o.Jmin)
	writeUint("jmax", o.Jmax)
	writeUint("s1", uint32(o.S1))
	writeUint("s2", uint32(o.S2))
	writeUint("s3", uint32(o.S3))
	writeUint("s4", uint32(o.S4))
	for _, header := range o.headers() {
		writeLine(header.key, header.value)
	}
	writeLine("i1", o.I1)
	writeLine("i2", o.I2)
	writeLine("i3", o.I3)
	writeLine("i4", o.I4)
	writeLine("i5", o.I5)
	writeLine("header_protection_key", headerProtectionKeyHex)
	for _, knob := range o.ranges() {
		writeLine(knob.key, knob.value)
	}
	writeBool("random_trailers", o.RandomTrailers)
	writeBool("disable_cookies", o.DisableCookies)
	return lines.String(), nil
}

// defaultMTU is the MTU used when none is configured: s4 bytes are prepended
// to every transport datagram, so with s4 set the plain WireGuard default of
// 1408 no longer fits.
func (o AmneziaWGOptions) defaultMTU() uint32 {
	if o.S4 > 0 {
		return 1280
	}
	return 1408
}

// mtuBudget returns the largest MTU that fits a 1492-byte path after IP/UDP
// (28), the WireGuard transport header (32) and s4, and whether mtu exceeds
// it. Without s4 there is nothing to check.
func (o AmneziaWGOptions) mtuBudget(mtu uint32) (budget int, exceeded bool) {
	if o.S4 == 0 {
		return 0, false
	}
	budget = 1492 - 28 - 32 - int(o.S4)
	return budget, int(mtu) > budget
}
