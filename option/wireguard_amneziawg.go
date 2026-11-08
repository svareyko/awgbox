package option

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// AmneziaWGOptions holds the AmneziaWG obfuscation parameters of a WireGuard
// endpoint. They sit at the endpoint level, next to private_key, as in an
// awg-quick configuration file. A zero value means plain WireGuard.
type AmneziaWGOptions struct {
	Jc                     uint32         `json:"jc,omitempty"`
	Jmin                   uint32         `json:"jmin,omitempty"`
	Jmax                   uint32         `json:"jmax,omitempty"`
	S1                     uint16         `json:"s1,omitempty"`
	S2                     uint16         `json:"s2,omitempty"`
	S3                     uint16         `json:"s3,omitempty"`
	S4                     uint16         `json:"s4,omitempty"`
	H1                     AmneziaWGRange `json:"h1,omitempty"`
	H2                     AmneziaWGRange `json:"h2,omitempty"`
	H3                     AmneziaWGRange `json:"h3,omitempty"`
	H4                     AmneziaWGRange `json:"h4,omitempty"`
	I1                     string         `json:"i1,omitempty"`
	I2                     string         `json:"i2,omitempty"`
	I3                     string         `json:"i3,omitempty"`
	I4                     string         `json:"i4,omitempty"`
	I5                     string         `json:"i5,omitempty"`
	HeaderProtectionKey    string         `json:"header_protection_key,omitempty"`
	ContentPaddingAddition AmneziaWGRange `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         AmneziaWGRange `json:"rekey_after_time,omitempty"`
	RekeyTimeout           AmneziaWGRange `json:"rekey_timeout,omitempty"`
	RejectAfterTime        AmneziaWGRange `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       AmneziaWGRange `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   AmneziaWGRange `json:"max_handshake_attempts,omitempty"`
	RandomTrailers         bool           `json:"random_trailers,omitempty"`
	DisableCookies         bool           `json:"disable_cookies,omitempty"`
}

// AmneziaWGRange is an AmneziaWG "number or inclusive range" value: a uint32,
// or a string "N" or "N-M" with N <= M. It holds the canonical spec the device
// parses ("N", "N-M", or "" when unset); zero means unset.
type AmneziaWGRange string

const amneziaWGRangePattern = `^\d+(-\d+)?$`

func (r *AmneziaWGRange) UnmarshalJSON(data []byte) error {
	var spec string
	if len(data) > 0 && data[0] == '"' {
		err := json.Unmarshal(data, &spec)
		if err != nil {
			return err
		}
	} else {
		var value uint32
		err := json.Unmarshal(data, &value)
		if err != nil {
			return E.New("invalid range ", string(data), `: expected uint32 or "N-M" string`)
		}
		spec = strconv.FormatUint(uint64(value), 10)
	}
	normalized, err := normalizeAmneziaWGRange(spec)
	if err != nil {
		return err
	}
	*r = AmneziaWGRange(normalized)
	return nil
}

func (r AmneziaWGRange) MarshalJSON() ([]byte, error) {
	normalized, err := normalizeAmneziaWGRange(string(r))
	if err != nil {
		return nil, err
	}
	if normalized == "" {
		return []byte("0"), nil
	}
	if !strings.Contains(normalized, "-") {
		return []byte(normalized), nil
	}
	return json.Marshal(normalized)
}

func (r AmneziaWGRange) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("AmneziaWGRange", func() (*schema.Node, error) {
		return schema.AnyOf(
			schema.UnsignedNode(32),
			&schema.Node{Type: "string", Pattern: amneziaWGRangePattern},
		), nil
	})
}

// Spec returns the canonical spec string ("N", "N-M", or "" when unset).
// A value that does not parse is returned unchanged, so that validation in
// the transport layer reports it.
func (r AmneziaWGRange) Spec() string {
	normalized, err := normalizeAmneziaWGRange(string(r))
	if err != nil {
		return string(r)
	}
	return normalized
}

// normalizeAmneziaWGRange accepts what the device's UintRange.FromString
// accepts: "N" or "N-M", both uint32, N <= M. It returns "" for zero, "N" for
// a single value (including "N-N") and "N-M" for a range.
func normalizeAmneziaWGRange(spec string) (string, error) {
	if spec == "" {
		return "", nil
	}
	parts := strings.Split(spec, "-")
	if len(parts) > 2 {
		return "", E.New("invalid range ", strconv.Quote(spec), `: expected "N" or "N-M"`)
	}
	start, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return "", E.New("invalid range ", strconv.Quote(spec), ": parse ", strconv.Quote(parts[0]), ": ", err)
	}
	end := start
	if len(parts) == 2 {
		end, err = strconv.ParseUint(parts[1], 10, 32)
		if err != nil {
			return "", E.New("invalid range ", strconv.Quote(spec), ": parse ", strconv.Quote(parts[1]), ": ", err)
		}
	}
	if end < start {
		return "", E.New("invalid range ", strconv.Quote(spec), ": start is greater than end")
	}
	if end == 0 {
		return "", nil
	}
	if start == end {
		return strconv.FormatUint(start, 10), nil
	}
	return strconv.FormatUint(start, 10) + "-" + strconv.FormatUint(end, 10), nil
}
