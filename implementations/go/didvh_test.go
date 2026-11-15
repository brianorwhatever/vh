package vhlog

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// did:vh library tests: every did:vh vector, and the specialisation hook
// keeping VH-Log and did:vh logs apart.

func sameJSON(a, b any) bool {
	ca, errA := Canonicalize(a)
	cb, errB := Canonicalize(b)
	return errA == nil && errB == nil && ca == cb
}

func TestDidVhResolutionVectors(t *testing.T) {
	files, err := os.ReadDir(filepath.Join(vectorsDir, "didvh/resolution"))
	if err != nil {
		t.Skipf("vectors not available: %v", err)
	}
	names := []string{}
	for _, f := range files {
		names = append(names, f.Name())
	}
	sort.Strings(names)
	for _, file := range names {
		for _, c := range list(get(loadVectors(t, "didvh/resolution/"+file), "cases")) {
			name := file + "/" + text(get(c, "name"))
			input, expect := get(c, "input"), get(c, "expect")
			ctx := ResolverContext{}
			ctx.Remote, _ = get(input, "remote").(bool)
			if now, ok := get(input, "now").(string); ok {
				ctx.Now, _ = ParseVersionTime(now)
			}
			did, _ := get(input, "did").(string)
			got := ResolveDid(did, get(input, "options"), ctx).JSON()
			meta := get(got, "didResolutionMetadata")
			if has(expect, "error") {
				if !sameJSON(get(meta, "error"), get(expect, "error")) {
					t.Errorf("%s: error %v, want %v", name, get(meta, "error"), get(expect, "error"))
				}
				if want := get(expect, "vhLogError"); want != nil && get(meta, "problemDetails", "vhLog", "code") != want {
					t.Errorf("%s: vhLog %v, want %v", name, get(meta, "problemDetails", "vhLog", "code"), want)
				}
				continue
			}
			if has(meta, "error") {
				t.Errorf("%s: unexpected error %s", name, Stringify(meta))
				continue
			}
			for _, k := range []string{"didDocument", "didDocumentMetadata"} {
				if !sameJSON(get(got, k), get(expect, k)) {
					t.Errorf("%s: %s %s, want %s", name, k, Stringify(get(got, k)), Stringify(get(expect, k)))
				}
			}
			for _, k := range []string{"didLog", "didWitness"} {
				if !sameJSON(get(meta, k), get(expect, k)) {
					t.Errorf("%s: %s %s, want %s", name, k, Stringify(get(meta, k)), Stringify(get(expect, k)))
				}
			}
		}
	}
}

func didVhOutcome(ok *Object, err error) *Object {
	if err != nil {
		return ObjectOf("valid", false, "error", string(err.(*DidVhError).Code))
	}
	return ok
}

func TestDidVhReferenceSrcAndDidURLVectors(t *testing.T) {
	for _, c := range list(get(loadVectors(t, "didvh/ref.json"), "cases")) {
		ref, ok := get(c, "ref").(string)
		if !ok {
			ref = "\x00"
		}
		kind, err := CheckRef(ref)
		got := didVhOutcome(ObjectOf("valid", true, "kind", string(kind)), err)
		if !sameJSON(got, get(c, "expect")) {
			t.Errorf("ref/%s: got %s", text(get(c, "name")), Stringify(got))
		}
	}
	for _, c := range list(get(loadVectors(t, "didvh/src.json"), "cases")) {
		srcLog, srcWitness, err := SrcReferences(text(get(c, "src")))
		got := didVhOutcome(ObjectOf("valid", true, "srcLog", srcLog, "srcWitness", srcWitness), err)
		if !sameJSON(got, get(c, "expect")) {
			t.Errorf("src/%s: got %s", text(get(c, "name")), Stringify(got))
		}
	}
	for _, c := range list(get(loadVectors(t, "didvh/did-url.json"), "cases")) {
		didURL, ok := get(c, "didUrl").(string)
		if !ok {
			didURL = "\x00"
		}
		u, err := ParseDidURL(didURL)
		var got *Object
		if err == nil {
			got = ObjectOf("valid", true, "did", u.Did, "options", u.Options)
			if u.HasFragment {
				got.Set("fragment", u.Fragment)
			}
		}
		got = didVhOutcome(got, err)
		if !sameJSON(got, get(c, "expect")) {
			t.Errorf("did-url/%s: got %s", text(get(c, "name")), Stringify(got))
		}
	}
}

func TestDidVhCreateUpdateResolve(t *testing.T) {
	key := testKey(t, 0x11)
	params := ObjectOf("updateKeys", []any{Multikey(key)})
	created, err := CreateDid(ObjectOf("id", "did:vh:{SCID}", "controller", "did:vh:{SCID}"), params, "2026-01-01T00:00:00Z", []ed25519.PrivateKey{key})
	if err != nil {
		t.Fatal(err)
	}
	if scid, ok := ParseDidVh(created.Did); !ok || scid != created.SCID {
		t.Fatalf("DID %s does not carry SCID %s", created.Did, created.SCID)
	}
	line, _ := ParseJSON(created.Log)
	if get(line, "parameters", "method") != DidVhMethod || has(get(line, "parameters"), "logVersion") {
		t.Fatalf("genesis parameters %s", Stringify(get(line, "parameters")))
	}
	if get(line, "state", "controller") != created.Did {
		t.Fatalf("{SCID} not replaced in the document")
	}
	updated, err := UpdateDid(created.Log, ObjectOf("id", created.Did, "v", 2.0), nil, "2026-01-02T00:00:00Z", []ed25519.PrivateKey{key})
	if err != nil {
		t.Fatal(err)
	}
	r := ResolveDid(created.Did, ObjectOf("didLog", updated.Log), ResolverContext{Now: testNow})
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	if !sameJSON(r.DidDocument, ObjectOf("id", created.Did, "v", 2.0)) || r.DidDocumentMetadata.VersionID != updated.VersionID {
		t.Fatalf("resolved %s at %s", Stringify(r.DidDocument), r.DidDocumentMetadata.VersionID)
	}
}

func TestDidVhAndVHLogAreNotInterchangeable(t *testing.T) {
	key := testKey(t, 0x11)
	params := ObjectOf("updateKeys", []any{Multikey(key)})
	vh, err := CreateLog(ObjectOf("id", "did:vh:{SCID}"), params, "2026-01-01T00:00:00Z", []ed25519.PrivateKey{key})
	if err != nil {
		t.Fatal(err)
	}
	if r := ResolveDid("did:vh:"+vh.SCID, ObjectOf("didLog", vh.Log), ResolverContext{Now: testNow}); r.Error == nil || r.Error.Code != DidVhInvalidDid {
		t.Fatalf("a VH-Log log resolved as did:vh: %v", r.Error)
	}
	did, err := CreateDid(ObjectOf("id", "did:vh:{SCID}"), params, "2026-01-01T00:00:00Z", []ed25519.PrivateKey{key})
	if err != nil {
		t.Fatal(err)
	}
	_, err = Resolve(ResolveInput{Log: did.Log, Now: testNow})
	if e, ok := err.(*VHLogError); !ok || e.Code != ErrUnsupportedLogVersion {
		t.Fatalf("a did:vh log resolved as VH-Log: %v", err)
	}
}
