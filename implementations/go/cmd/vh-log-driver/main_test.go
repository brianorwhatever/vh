package main

import (
	"bytes"
	"strings"
	"testing"

	vhlog "github.com/brianorwhatever/vh/implementations/go"
)

func TestRun(t *testing.T) {
	big := strings.Repeat("x", 200_000) // well beyond bufio.Scanner's default 64 KiB
	requests := strings.Join([]string{
		`{"id":1,"op":"jcs","input":{"text":"{\"b\":\"\u2028\",\"a\":1e21}"}}`,
		``,
		`{"id":2,"op":"hash","input":{"data":"` + big + `"}}`,
		`{"id":3,"op":"nope","input":{}}`,
		`not json`,
		`{"id":4,"op":"resolve","input":{"log":"","now":"2026-01-01T00:00:00Z"}}`,
		`{"id":5,"op":"multikey","input":{"seed":"00"}}`,
	}, "\n") // no final newline: the last request still counts
	var out bytes.Buffer
	if err := run(strings.NewReader(requests), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("got %d responses:\n%s", len(lines), out.String())
	}
	want := []string{
		`{"id":1,"ok":true,"result":{"output":"{\"a\":1e+21,\"b\":\"` + "\u2028" + `\"}"}}`,
		`{"id":2,"ok":true,"result":{"output":"` + vhlog.HashString(big) + `"}}`,
		`{"id":3,"ok":false,"error":"unknown op \"nope\""}`,
		``, // checked below
		`{"id":4,"ok":true,"result":{"valid":false,"error":{"code":"invalid-log","version":null,"message":"log is empty"}}}`,
		``, // checked below
	}
	for i, w := range want {
		if w != "" && lines[i] != w {
			t.Errorf("response %d:\n got %s\nwant %s", i+1, lines[i], w)
		}
	}
	if !strings.HasPrefix(lines[3], `{"id":null,"ok":false,`) {
		t.Errorf("malformed request: %s", lines[3])
	}
	if !strings.HasPrefix(lines[5], `{"id":5,"ok":false,`) {
		t.Errorf("short seed: %s", lines[5])
	}
}
