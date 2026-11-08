package wireguard

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The bytes 0x01..0x20.
const testHeaderProtectionKey = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA="

func fullAmneziaWGOptions() AmneziaWGOptions {
	return AmneziaWGOptions{
		Jc:                     4,
		Jmin:                   40,
		Jmax:                   70,
		S1:                     15,
		S2:                     18,
		S3:                     20,
		S4:                     23,
		H1:                     "1000",
		H2:                     "2000-2999",
		H3:                     "3000",
		H4:                     "4000-4999",
		I1:                     "<b 0xc0ffee><r 16>",
		I2:                     "<r 32>",
		I3:                     "<t><c>",
		I4:                     "<rc 8>",
		I5:                     "<rd 4>",
		HeaderProtectionKey:    testHeaderProtectionKey,
		ContentPaddingAddition: "0-64",
		RekeyAfterTime:         "100-140",
		RekeyTimeout:           "5",
		RejectAfterTime:        "170-190",
		KeepaliveTimeout:       "8-12",
		MaxHandshakeAttempts:   "18",
		RandomTrailers:         true,
		DisableCookies:         true,
	}
}

var fullAmneziaWGLines = []string{
	"jc=4",
	"jmin=40",
	"jmax=70",
	"s1=15",
	"s2=18",
	"s3=20",
	"s4=23",
	"h1=1000",
	"h2=2000-2999",
	"h3=3000",
	"h4=4000-4999",
	"i1=<b 0xc0ffee><r 16>",
	"i2=<r 32>",
	"i3=<t><c>",
	"i4=<rc 8>",
	"i5=<rd 4>",
	"header_protection_key=0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
	"content_padding_addition=0-64",
	"rekey_after_time=100-140",
	"rekey_timeout=5",
	"reject_after_time=170-190",
	"keepalive_timeout=8-12",
	"max_handshake_attempts=18",
	"random_trailers=1",
	"disable_cookies=1",
}

func joinAmneziaWGLines(lines []string, omit ...string) string {
	var builder strings.Builder
	for _, line := range lines {
		key, _, _ := strings.Cut(line, "=")
		omitted := false
		for _, omitKey := range omit {
			if key == omitKey {
				omitted = true
			}
		}
		if !omitted {
			builder.WriteString("\n" + line)
		}
	}
	return builder.String()
}

func TestAmneziaWGIpcLinesFull(t *testing.T) {
	t.Parallel()
	lines, err := fullAmneziaWGOptions().IpcLines()
	require.NoError(t, err)
	require.Equal(t, joinAmneziaWGLines(fullAmneziaWGLines), lines)
	require.True(t, strings.HasPrefix(lines, "\n"))
	require.False(t, strings.HasSuffix(lines, "\n"))
}

func TestAmneziaWGIpcLinesEmpty(t *testing.T) {
	t.Parallel()
	lines, err := AmneziaWGOptions{}.IpcLines()
	require.NoError(t, err)
	require.Equal(t, "", lines)
}

func TestAmneziaWGIpcLinesOmitted(t *testing.T) {
	t.Parallel()
	// Each case clears one option. omit lists the keys that disappear: the
	// option itself, plus what has to go with it to stay valid (s1-s4 are
	// required by header_protection_key, jmin must not exceed jmax).
	for _, testCase := range []struct {
		omit  []string
		clear func(o *AmneziaWGOptions)
	}{
		{[]string{"jc"}, func(o *AmneziaWGOptions) { o.Jc = 0 }},
		{[]string{"jmin"}, func(o *AmneziaWGOptions) { o.Jmin = 0 }},
		{[]string{"jmax", "jmin"}, func(o *AmneziaWGOptions) { o.Jmax, o.Jmin = 0, 0 }},
		{[]string{"s1", "header_protection_key"}, func(o *AmneziaWGOptions) { o.S1, o.HeaderProtectionKey = 0, "" }},
		{[]string{"s2", "header_protection_key"}, func(o *AmneziaWGOptions) { o.S2, o.HeaderProtectionKey = 0, "" }},
		{[]string{"s3", "header_protection_key"}, func(o *AmneziaWGOptions) { o.S3, o.HeaderProtectionKey = 0, "" }},
		{[]string{"s4", "header_protection_key"}, func(o *AmneziaWGOptions) { o.S4, o.HeaderProtectionKey = 0, "" }},
		{[]string{"h1"}, func(o *AmneziaWGOptions) { o.H1 = "" }},
		{[]string{"h2"}, func(o *AmneziaWGOptions) { o.H2 = "" }},
		{[]string{"h3"}, func(o *AmneziaWGOptions) { o.H3 = "" }},
		{[]string{"h4"}, func(o *AmneziaWGOptions) { o.H4 = "" }},
		{[]string{"i1"}, func(o *AmneziaWGOptions) { o.I1 = "" }},
		{[]string{"i2"}, func(o *AmneziaWGOptions) { o.I2 = "" }},
		{[]string{"i3"}, func(o *AmneziaWGOptions) { o.I3 = "" }},
		{[]string{"i4"}, func(o *AmneziaWGOptions) { o.I4 = "" }},
		{[]string{"i5"}, func(o *AmneziaWGOptions) { o.I5 = "" }},
		{[]string{"header_protection_key"}, func(o *AmneziaWGOptions) { o.HeaderProtectionKey = "" }},
		{[]string{"content_padding_addition"}, func(o *AmneziaWGOptions) { o.ContentPaddingAddition = "" }},
		{[]string{"rekey_after_time"}, func(o *AmneziaWGOptions) { o.RekeyAfterTime = "" }},
		{[]string{"rekey_timeout"}, func(o *AmneziaWGOptions) { o.RekeyTimeout = "" }},
		{[]string{"reject_after_time"}, func(o *AmneziaWGOptions) { o.RejectAfterTime = "" }},
		{[]string{"keepalive_timeout"}, func(o *AmneziaWGOptions) { o.KeepaliveTimeout = "" }},
		{[]string{"max_handshake_attempts"}, func(o *AmneziaWGOptions) { o.MaxHandshakeAttempts = "" }},
		{[]string{"random_trailers"}, func(o *AmneziaWGOptions) { o.RandomTrailers = false }},
		{[]string{"disable_cookies"}, func(o *AmneziaWGOptions) { o.DisableCookies = false }},
	} {
		t.Run(testCase.omit[0], func(t *testing.T) {
			options := fullAmneziaWGOptions()
			testCase.clear(&options)
			lines, err := options.IpcLines()
			require.NoError(t, err)
			require.Equal(t, joinAmneziaWGLines(fullAmneziaWGLines, testCase.omit...), lines)
		})
	}
}

func TestAmneziaWGValidate(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name   string
		modify func(o *AmneziaWGOptions)
		err    string
	}{
		{"jmin greater than jmax", func(o *AmneziaWGOptions) { o.Jmin, o.Jmax = 100, 50 }, "amneziawg: jmin (100) must not be greater than jmax (50)"},
		{"headers overlap", func(o *AmneziaWGOptions) { o.H1, o.H2 = "100-200", "150-300" }, "amneziawg: headers must not overlap: h1 (100-200) and h2 (150-300)"},
		{"headers touch", func(o *AmneziaWGOptions) { o.H3, o.H4 = "3000-4000", "4000-4999" }, "amneziawg: headers must not overlap: h3 (3000-4000) and h4 (4000-4999)"},
		{"header overlaps default", func(o *AmneziaWGOptions) { *o = AmneziaWGOptions{H1: "2"} }, "amneziawg: headers must not overlap: h1 (2) and h2 (2)"},
		{"header range covers default", func(o *AmneziaWGOptions) { *o = AmneziaWGOptions{H4: "0-10"} }, "amneziawg: headers must not overlap: h1 (1) and h4 (0-10)"},
		{"bad header", func(o *AmneziaWGOptions) { o.H1 = "5-" }, "amneziawg: h1: invalid range \"5-\""},
		{"header start greater than end", func(o *AmneziaWGOptions) { o.H2 = "300-200" }, "amneziawg: h2: invalid range \"300-200\": start is greater than end"},
		{"header above uint32", func(o *AmneziaWGOptions) { o.H3 = "4294967296" }, "amneziawg: h3: invalid range \"4294967296\""},
		{"bad range", func(o *AmneziaWGOptions) { o.RekeyTimeout = "10-5" }, "amneziawg: rekey_timeout: invalid range \"10-5\""},
		{"bad range syntax", func(o *AmneziaWGOptions) { o.MaxHandshakeAttempts = "1-2-3" }, "amneziawg: max_handshake_attempts: invalid range \"1-2-3\""},
		{"bad key base64", func(o *AmneziaWGOptions) { o.HeaderProtectionKey = "not base64!" }, "amneziawg: decode header_protection_key"},
		{"short key", func(o *AmneziaWGOptions) { o.HeaderProtectionKey = "AQIDBA==" }, "amneziawg: header_protection_key must be 32 bytes, got 4"},
		{"zero key", func(o *AmneziaWGOptions) {
			o.HeaderProtectionKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		}, "amneziawg: header_protection_key must not be all zeros"},
		{"key with short s1", func(o *AmneziaWGOptions) { o.S1 = 8 }, "amneziawg: s1 (8) must be at least 12 when header_protection_key is set"},
		{"key with short s4", func(o *AmneziaWGOptions) { o.S4 = 11 }, "amneziawg: s4 (11) must be at least 12 when header_protection_key is set"},
		{"key without paddings", func(o *AmneziaWGOptions) {
			*o = AmneziaWGOptions{HeaderProtectionKey: testHeaderProtectionKey}
		}, "amneziawg: s1 (0) must be at least 12"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			options := fullAmneziaWGOptions()
			testCase.modify(&options)
			require.ErrorContains(t, options.Validate(), testCase.err)
			_, err := options.IpcLines()
			require.ErrorContains(t, err, testCase.err)
		})
	}
}

func TestAmneziaWGValidateAccepts(t *testing.T) {
	t.Parallel()
	for _, options := range []AmneziaWGOptions{
		{},
		{Jc: 0, Jmin: 10, Jmax: 10},
		{Jc: 3},
		{S1: 1, S2: 2, S3: 3, S4: 4},
		{H1: "5", H2: "6", H3: "7", H4: "8"},
		{H1: "1", H2: "2", H3: "3", H4: "4"},
		{H1: "100-199", H2: "200-299", H3: "300-399", H4: "400-499"},
		{H1: "5", H2: "6", H3: "7", H4: "8", HeaderProtectionKey: testHeaderProtectionKey, S1: 12, S2: 12, S3: 12, S4: 12},
	} {
		require.NoError(t, options.Validate(), "%+v", options)
	}
}

func TestAmneziaWGMTU(t *testing.T) {
	t.Parallel()
	require.Equal(t, uint32(1408), AmneziaWGOptions{}.defaultMTU())
	require.Equal(t, uint32(1408), AmneziaWGOptions{S1: 68, Jc: 4}.defaultMTU())
	require.Equal(t, uint32(1280), AmneziaWGOptions{S4: 16}.defaultMTU())

	_, exceeded := AmneziaWGOptions{}.mtuBudget(1500)
	require.False(t, exceeded)
	budget, exceeded := AmneziaWGOptions{S4: 16}.mtuBudget(1416)
	require.Equal(t, 1416, budget)
	require.False(t, exceeded)
	_, exceeded = AmneziaWGOptions{S4: 16}.mtuBudget(1417)
	require.True(t, exceeded)
}
