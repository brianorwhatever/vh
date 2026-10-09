package vhlog

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func testKey(t testing.TB, b byte) ed25519.PrivateKey {
	t.Helper()
	k, err := KeyFromSeedHex(strings.Repeat(fmt.Sprintf("%02x", b), 32))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func at(day int) string { return fmt.Sprintf("2026-01-%02dT00:00:00Z", day) }

var testNow, _ = ParseVersionTime("2026-06-01T00:00:00Z")

func mustCode(t *testing.T, err error, code ErrorCode, version int) {
	t.Helper()
	var e *VHLogError
	if !errors.As(err, &e) {
		t.Fatalf("expected %s, got %v", code, err)
	}
	if e.Code != code || e.Version != version {
		t.Fatalf("expected %s at version %d, got %s at %d (%s)", code, version, e.Code, e.Version, e.Message)
	}
}

// TestLifecycle creates a pre-rotated, witnessed log, rotates its key,
// deactivates it and resolves it in several ways.
func TestLifecycle(t *testing.T) {
	k1, k2, w1, w2 := testKey(t, 1), testKey(t, 2), testKey(t, 3), testKey(t, 4)
	witnesses := []any{ObjectOf("id", "did:key:"+Multikey(w1)), ObjectOf("id", "did:key:"+Multikey(w2))}

	created, err := CreateLog(ObjectOf("id", "example:{SCID}"),
		ObjectOf("updateKeys", []string{Multikey(k1)}, "nextKeyHashes", []string{KeyHash(Multikey(k2))},
			"witness", ObjectOf("threshold", 2, "witnesses", witnesses)),
		at(1), []ed25519.PrivateKey{k1})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.SCID, "Qm") || !strings.Contains(created.Log, "example:"+created.SCID) {
		t.Fatalf("SCID not substituted: %s", created.Log)
	}

	// Rotating to a key that was not committed is a pre-rotation violation.
	bad, err := UpdateLog(created.Log, ObjectOf("id", "x"),
		ObjectOf("updateKeys", []string{Multikey(w1)}, "nextKeyHashes", []string{}), at(2), []ed25519.PrivateKey{w1})
	if err != nil {
		t.Fatal(err)
	}
	p1, _ := WitnessProof(created.VersionID, w1, "")
	p2, _ := WitnessProof(created.VersionID, w2, "")
	genesisWitnessed := []byte(Stringify([]any{ObjectOf("versionId", created.VersionID, "proof", []any{p1, p2})}))
	if v := VerifyLog(bad.Log, genesisWitnessed, testNow); v.Failure == nil || v.Failure.Code != ErrPrerotationViolation {
		t.Fatalf("expected prerotation-violation, got %v", v.Failure)
	}

	rotated, err := UpdateLog(created.Log, ObjectOf("id", "example:"+created.SCID, "name", "rotated"),
		ObjectOf("updateKeys", []string{Multikey(k2)}, "nextKeyHashes", []string{}), at(2), []ed25519.PrivateKey{k2})
	if err != nil {
		t.Fatal(err)
	}
	deactivated, err := UpdateLog(rotated.Log, ObjectOf("id", "example:"+created.SCID),
		ObjectOf("deactivated", true), at(3), []ed25519.PrivateKey{k2})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(deactivated.VersionID, "3-") {
		t.Fatalf("versionId %s", deactivated.VersionID)
	}

	// Without witness proofs, entry 1 already fails and resolution fails.
	_, err = Resolve(ResolveInput{Log: deactivated.Log, Now: testNow})
	mustCode(t, err, ErrWitnessThresholdNotMet, 1)

	// Proofs over the last versionId cover every earlier entry.
	var proofs []any
	for _, w := range []ed25519.PrivateKey{w1, w2} {
		p, err := WitnessProof(deactivated.VersionID, w, "")
		if err != nil {
			t.Fatal(err)
		}
		proofs = append(proofs, p)
	}
	witnessFile := []byte(Stringify([]any{ObjectOf("versionId", deactivated.VersionID, "proof", proofs)}))

	res, err := Resolve(ResolveInput{Log: deactivated.Log, Witness: witnessFile, Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	m := res.Metadata
	if m.VersionNumber != 3 || !m.Deactivated || m.Witness == nil || m.Witness.Threshold != 2 || m.SCID != created.SCID ||
		m.Created != at(1) || m.Updated != at(3) || res.FirstInvalidVersion != nil {
		t.Fatalf("unexpected metadata %+v", m)
	}

	two := 2
	res, err = Resolve(ResolveInput{Log: deactivated.Log, Witness: witnessFile, Now: testNow,
		Options: ResolveOptions{VersionNumber: &two}})
	if err != nil {
		t.Fatal(err)
	}
	if get(res.State, "name") != "rotated" || res.Metadata.UpdateKeys[0] != Multikey(k2) || !res.Metadata.Deactivated {
		t.Fatalf("version 2: %s %+v", Stringify(res.State), res.Metadata)
	}

	// A clock before the last entry (minus the tolerance) rejects it. Proofs
	// over an invalid entry's versionId then count for nothing, so entry 1 is
	// unwitnessed and resolution fails.
	early, _ := ParseVersionTime(at(2))
	_, err = Resolve(ResolveInput{Log: deactivated.Log, Witness: witnessFile, Now: early})
	mustCode(t, err, ErrWitnessThresholdNotMet, 1)

	// An entry after deactivation is rejected.
	after, err := UpdateLog(deactivated.Log, ObjectOf(), nil, at(4), []ed25519.PrivateKey{k2})
	if err != nil {
		t.Fatal(err)
	}
	v := VerifyLog(after.Log, witnessFile, testNow)
	if v.Failure == nil || v.Failure.Code != ErrEntryAfterDeactivation || len(v.Entries) != 3 {
		t.Fatalf("after deactivation: %v", v.Failure)
	}
}

func TestPartialValidityAndSelection(t *testing.T) {
	k := testKey(t, 1)
	keys := []ed25519.PrivateKey{k}
	created, _ := CreateLog(ObjectOf("n", 1), ObjectOf("updateKeys", []string{Multikey(k)}), at(1), keys)
	second, _ := UpdateLog(created.Log, ObjectOf("n", 2), nil, at(2), keys)
	third, _ := UpdateLog(second.Log, ObjectOf("n", 3), nil, at(3), keys)
	lines := SplitLogLines(third.Log)
	tampered := strings.Join(lines[:2], "\n") + "\n" + strings.Replace(lines[2], `"n":3`, `"n":4`, 1) + "\n"

	res, err := Resolve(ResolveInput{Log: tampered, Now: testNow})
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata.VersionNumber != 2 || *res.FirstInvalidVersion != 3 || res.Error.Code != ErrInvalidProof ||
		len(res.Metadata.Warnings) != 1 || res.Metadata.Warnings[0].Code != WarningInvalidEntries {
		t.Fatalf("tampered log: %+v %v", res.Metadata, res.Error)
	}
	three := 3
	_, err = Resolve(ResolveInput{Log: tampered, Now: testNow, Options: ResolveOptions{VersionNumber: &three}})
	mustCode(t, err, ErrInvalidProof, 3)

	vt := at(2)
	res, err = Resolve(ResolveInput{Log: third.Log, Now: testNow, Options: ResolveOptions{VersionTime: &vt}})
	if err != nil || res.Metadata.VersionNumber != 2 {
		t.Fatalf("by time: %v %v", res, err)
	}
	unknown := "9-Qm"
	_, err = Resolve(ResolveInput{Log: third.Log, Now: testNow, Options: ResolveOptions{VersionID: &unknown}})
	mustCode(t, err, ErrNotFound, 0)
	_, err = Resolve(ResolveInput{Log: third.Log, Now: testNow, Options: ResolveOptions{VersionID: &unknown, VersionTime: &vt}})
	mustCode(t, err, ErrInvalidOption, 0)

	// Copies: a behind copy is fine; a valid diverging copy is a fork.
	res, err = Resolve(ResolveInput{Log: third.Log, Now: testNow, Copies: []CopyInput{
		{Source: "https://w1.example", Log: second.Log},
		{Source: "https://w2.example", Unavailable: true, Reason: "timeout"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Metadata.Copies; len(got) != 3 || got[0].Status != CopyCurrent || got[1].Status != CopyBehind || got[2].Status != CopyUnavailable {
		t.Fatalf("copies: %+v", got)
	}
	fork, _ := UpdateLog(second.Log, ObjectOf("n", "fork"), nil, at(3), keys)
	_, err = Resolve(ResolveInput{Log: third.Log, Now: testNow, Copies: []CopyInput{{Source: "w", Log: fork.Log}}})
	mustCode(t, err, ErrForkDetected, 3)
	_, err = Resolve(ResolveInput{Log: third.Log, Now: testNow, RetainedVersionID: &fork.VersionID})
	mustCode(t, err, ErrForkDetected, 3)
}

func TestInvalidLogLines(t *testing.T) {
	k := testKey(t, 1)
	created, _ := CreateLog(ObjectOf(), ObjectOf("updateKeys", []string{Multikey(k)}), at(1), []ed25519.PrivateKey{k})
	for name, log := range map[string]string{
		"empty":          "",
		"not JSON":       "{",
		"array":          "[]",
		"overflow":       strings.Replace(created.Log, `"state":{}`, `"state":{"x":1e400}`, 1),
		"lone surrogate": strings.Replace(created.Log, `"state":{}`, `"state":{"x":"\ud800"}`, 1),
	} {
		v := VerifyLog(log, nil, testNow)
		if v.Failure == nil || v.Failure.Code != ErrInvalidLog || len(v.Entries) != 0 {
			t.Errorf("%s: %v", name, v.Failure)
		}
	}
	if v := VerifyLog(created.Log, nil, testNow); !v.FullyValid() {
		t.Fatalf("valid log rejected: %v", v.Failure)
	}
}

func ExampleResolve() {
	key, _ := KeyFromSeedHex(strings.Repeat("01", 32))
	signers := []ed25519.PrivateKey{key}

	created, _ := CreateLog(ObjectOf("id", "example:{SCID}"),
		ObjectOf("updateKeys", []string{Multikey(key)}), "2026-01-01T00:00:00Z", signers)
	updated, _ := UpdateLog(created.Log, ObjectOf("id", "example:"+created.SCID, "name", "updated"),
		nil, "2026-01-02T00:00:00Z", signers)

	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	res, err := Resolve(ResolveInput{Log: updated.Log, Now: now})
	if err != nil {
		fmt.Println("invalid:", err)
		return
	}
	fmt.Println(res.Metadata.VersionNumber, Stringify(get(res.State, "name")))
	// Output: 2 "updated"
}
