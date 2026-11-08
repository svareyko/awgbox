package option

import (
	"testing"

	"github.com/sagernet/sing/common/json"

	"github.com/stretchr/testify/require"
)

func TestAmneziaWGRangeUnmarshal(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name     string
		input    string
		expected AmneziaWGRange
	}{
		{"number", `1234567890`, "1234567890"},
		{"number max uint32", `4294967295`, "4294967295"},
		{"number zero is unset", `0`, ""},
		{"string number", `"1234567890"`, "1234567890"},
		{"string range", `"43613244-384550127"`, "43613244-384550127"},
		{"string range full uint32", `"0-4294967295"`, "0-4294967295"},
		{"string degenerate range", `"7-7"`, "7"},
		{"string leading zeros", `"007-010"`, "7-10"},
		{"string zero is unset", `"0"`, ""},
		{"string zero range is unset", `"0-0"`, ""},
		{"string empty is unset", `""`, ""},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var value AmneziaWGRange
			require.NoError(t, json.Unmarshal([]byte(testCase.input), &value))
			require.Equal(t, testCase.expected, value)
			require.Equal(t, string(testCase.expected), value.Spec())
		})
	}
}

func TestAmneziaWGRangeUnmarshalError(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name  string
		input string
	}{
		{"start greater than end", `"100-50"`},
		{"number above uint32", `4294967296`},
		{"range part above uint32", `"1-4294967296"`},
		{"negative number", `-1`},
		{"float number", `1.5`},
		{"garbage string", `"junk"`},
		{"three parts", `"123-456-789"`},
		{"missing range start", `"-5"`},
		{"missing range end", `"5-"`},
		{"spaces", `" 10 - 20 "`},
		{"bool", `true`},
		{"object", `{}`},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			var value AmneziaWGRange
			require.Error(t, json.Unmarshal([]byte(testCase.input), &value))
		})
	}
}

func TestAmneziaWGRangeMarshal(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		value    AmneziaWGRange
		expected string
	}{
		{"", `0`},
		{"1234567890", `1234567890`},
		{"10-20", `"10-20"`},
	} {
		content, err := json.Marshal(testCase.value)
		require.NoError(t, err)
		require.Equal(t, testCase.expected, string(content))
	}
}

func TestWireGuardEndpointAmneziaWGOptions(t *testing.T) {
	t.Parallel()
	const input = `{
		"private_key": "key",
		"jc": 4, "jmin": 40, "jmax": 70,
		"s1": 15, "s2": 18, "s3": 20, "s4": 23,
		"h1": 1000, "h2": "2000", "h3": "3000-3999", "h4": "4000-4000",
		"i1": "<b 0xc0ffee><r 16>",
		"header_protection_key": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		"content_padding_addition": "0-64",
		"rekey_after_time": 120,
		"random_trailers": true,
		"disable_cookies": true
	}`
	var options WireGuardEndpointOptions
	require.NoError(t, json.Unmarshal([]byte(input), &options))
	require.Equal(t, AmneziaWGOptions{
		Jc: 4, Jmin: 40, Jmax: 70,
		S1: 15, S2: 18, S3: 20, S4: 23,
		H1: "1000", H2: "2000", H3: "3000-3999", H4: "4000",
		I1:                     "<b 0xc0ffee><r 16>",
		HeaderProtectionKey:    "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=",
		ContentPaddingAddition: "0-64",
		RekeyAfterTime:         "120",
		RandomTrailers:         true,
		DisableCookies:         true,
	}, options.AmneziaWGOptions)

	content, err := json.Marshal(options)
	require.NoError(t, err)
	var roundTrip WireGuardEndpointOptions
	require.NoError(t, json.Unmarshal(content, &roundTrip))
	require.Equal(t, options.AmneziaWGOptions, roundTrip.AmneziaWGOptions)
}

func TestWireGuardEndpointAmneziaWGOptionsRejected(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		`{"jc": "abc"}`,
		`{"jc": -1}`,
		`{"s4": 70000}`,
		`{"h1": "5-"}`,
		`{"rekey_timeout": "10-5"}`,
	} {
		var options WireGuardEndpointOptions
		require.Error(t, json.Unmarshal([]byte(input), &options), input)
	}
}

func TestWireGuardEndpointWithoutAmneziaWG(t *testing.T) {
	t.Parallel()
	var options WireGuardEndpointOptions
	require.NoError(t, json.Unmarshal([]byte(`{"private_key": "key", "mtu": 1408}`), &options))
	require.Equal(t, AmneziaWGOptions{}, options.AmneziaWGOptions)
	content, err := json.Marshal(options)
	require.NoError(t, err)
	require.NotContains(t, string(content), `"h1"`)
	require.NotContains(t, string(content), `"jc"`)
}
