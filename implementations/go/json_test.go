package vhlog

import (
	"math"
	"testing"
)

func TestFormatNumber(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{0, "0"},
		{math.Copysign(0, -1), "0"},
		{1, "1"},
		{-1.5, "-1.5"},
		{1e21, "1e+21"},
		{1e20, "100000000000000000000"},
		{1e-7, "1e-7"},
		{1e-6, "0.000001"},
		{123456789012345678, "123456789012345680"},
		{896365914996807.2, "896365914996807.2"},
		{0.30000000000000004, "0.30000000000000004"},
		{5e-324, "5e-324"},
		{1.7976931348623157e308, "1.7976931348623157e+308"},
		{9.999999999999999e22, "1e+23"},
		{1.23e-18, "1.23e-18"},
		{-1e-7, "-1e-7"},
		{295147905179352830000, "295147905179352830000"},
	}
	for _, c := range cases {
		if got := FormatNumber(c.in); got != c.want {
			t.Errorf("FormatNumber(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestCanonicalizeText(t *testing.T) {
	cases := []struct{ in, want string }{
		// Keys sort by UTF-16 code units: U+1F600 (D83D DE00) sorts before U+FB33.
		{`{"\ufb33":1,"\ud83d\ude00":2,"a":3,"A":4}`, `{"A":4,"a":3,"😀":2,"דּ":1}`},
		// Duplicate keys: the last value wins.
		{`{"a":1,"a":2}`, `{"a":2}`},
		// Lone surrogates survive and are escaped, as JSON.stringify does.
		{`["\ud800","\uDC00x"]`, `["\ud800","\udc00x"]`},
		// No HTML escaping; U+2028 stays raw; control characters use \u00xx.
		{`"<&>\u2028\u001f\u007f"`, "\"<&>\u2028\\u001f\u007f\""},
		{` [ 1.0 , -0 , 1E2 ] `, `[1,0,100]`},
	}
	for _, c := range cases {
		got, err := CanonicalizeText(c.in)
		if err != nil || got != c.want {
			t.Errorf("CanonicalizeText(%s) = %s (%v), want %s", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{``, `{`, `[1,]`, `01`, `1.`, `"\x"`, "\"\x01\"", `{"a" 1}`, `nul`, `1 2`} {
		if _, err := CanonicalizeText(bad); err == nil {
			t.Errorf("CanonicalizeText(%q) succeeded", bad)
		}
	}
	if _, err := CanonicalizeText(`1e400`); err == nil {
		t.Error("non-finite number canonicalised")
	}
}

func TestStringifyRoundTrip(t *testing.T) {
	in := "{\"b\":[true,false,null],\"a\":\"\\ud83d\\ude00 \\ud800\",\"c\":{\"x\":1.5}}"
	v, err := ParseJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"b\":[true,false,null],\"a\":\"😀 \\ud800\",\"c\":{\"x\":1.5}}"
	if got := Stringify(v); got != want {
		t.Errorf("Stringify = %s, want %s", got, want)
	}
	if isSafeJSON(v) {
		t.Error("value with a lone surrogate reported as I-JSON safe")
	}
	// A raw (WTF-8) high surrogate followed by an escaped low one joins into a pair.
	joined, err := ParseJSON("\"\xed\xa0\xbd" + `\ude00"`)
	if err != nil || joined != "😀" {
		t.Errorf("surrogate pair across escape forms: %q (%v)", joined, err)
	}
}

func TestBase58AndMultihash(t *testing.T) {
	for _, data := range [][]byte{{}, {0}, {0, 0, 1}, []byte("hello world")} {
		enc := Base58btcEncode(data)
		dec, ok := Base58btcDecode(enc)
		if !ok || string(dec) != string(data) {
			t.Errorf("round trip of %x via %q gave %x", data, enc, dec)
		}
	}
	if _, ok := Base58btcDecode("0OIl"); ok {
		t.Error("decoded characters outside the alphabet")
	}
	if got := CheckSHA256Multihash(HashString("x")); got != MultihashOK {
		t.Errorf("SHA-256 multihash classified as %v", got)
	}
	if got := CheckSHA256Multihash(""); got != MultihashNotBase58 {
		t.Errorf("empty string classified as %v", got)
	}
	if got := CheckSHA256Multihash("z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"[1:]); got != MultihashUnsupported {
		t.Errorf("multikey bytes classified as %v", got)
	}
}

func TestParseVersionTime(t *testing.T) {
	valid := []string{"2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00", "0000-01-01T00:00:00Z", "2024-02-29T23:59:59Z", "2000-02-29T12:00:00Z"}
	invalid := []string{"2026-01-01T00:00:00z", "2026-01-01T00:00:00.5Z", "2026-01-01T00:00:00", "2026-01-01T00:00:00+01:00",
		"2026-02-29T00:00:00Z", "1900-02-29T00:00:00Z", "2026-01-01T24:00:00Z", "2026-06-30T23:59:60Z", "2026-13-01T00:00:00Z", "26-01-01T00:00:00Z"}
	for _, s := range valid {
		if _, ok := ParseVersionTime(s); !ok {
			t.Errorf("%s rejected", s)
		}
	}
	for _, s := range invalid {
		if _, ok := ParseVersionTime(s); ok {
			t.Errorf("%s accepted", s)
		}
	}
	a, _ := ParseVersionTime("2026-01-01T00:00:00Z")
	b, _ := ParseVersionTime("2026-01-01T00:00:00+00:00")
	if !a.Equal(b) {
		t.Error("Z and +00:00 differ")
	}
}

func TestIsWatcherURL(t *testing.T) {
	for _, u := range []string{"https://w.example", "http://w.example/x?y#z", "https://xn--bcher-kva.example"} {
		if !IsWatcherURL(u) {
			t.Errorf("%s rejected", u)
		}
	}
	for _, u := range []string{"", "ftp://w.example", "https://", "https:///path", "https://a b", "https://bücher.example", "HTTPS://w.example"} {
		if IsWatcherURL(u) {
			t.Errorf("%s accepted", u)
		}
	}
}
