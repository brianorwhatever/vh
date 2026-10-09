package vhlog

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// The shared vectors live at the repository root.
const vectorsDir = "../../vectors"

func loadVectors(t *testing.T, path string) *Object {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(vectorsDir, path))
	if err != nil {
		t.Skipf("vectors not available: %v", err)
	}
	v, err := ParseJSON(string(data))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return v.(*Object)
}

func get(v any, path ...string) any {
	for _, k := range path {
		o, ok := v.(*Object)
		if !ok {
			return nil
		}
		v, _ = o.Get(k)
	}
	return v
}

func has(v any, key string) bool {
	o, ok := v.(*Object)
	return ok && o.Has(key)
}

func list(v any) []any {
	l, _ := v.([]any)
	return l
}

func text(v any) string {
	s, _ := v.(string)
	return s
}

func mustKey(t *testing.T, seed any) ed25519.PrivateKey {
	t.Helper()
	k, err := KeyFromSeedHex(text(seed))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestPrimitiveVectors(t *testing.T) {
	v := loadVectors(t, "primitives.json")
	for _, c := range list(get(v, "jcs")) {
		got, err := CanonicalizeText(text(get(c, "text")))
		if err != nil || got != text(get(c, "output")) {
			t.Errorf("jcs %q: got %q (%v), want %q", text(get(c, "text")), got, err, text(get(c, "output")))
		}
	}
	for _, c := range list(get(v, "hash")) {
		if got := HashString(text(get(c, "data"))); got != text(get(c, "output")) {
			t.Errorf("hash %q: got %s", text(get(c, "data")), got)
		}
	}
	for _, c := range list(get(v, "multikey")) {
		if got := Multikey(mustKey(t, get(c, "seed"))); got != text(get(c, "multikey")) {
			t.Errorf("multikey: got %s, want %s", got, text(get(c, "multikey")))
		}
	}
	for _, c := range list(get(v, "keyHash")) {
		if got := KeyHash(text(get(c, "multikey"))); got != text(get(c, "output")) {
			t.Errorf("keyHash: got %s", got)
		}
	}
	for _, c := range list(get(v, "scid")) {
		got, err := ComputeSCID(get(c, "entry").(*Object))
		if err != nil || got != text(get(c, "scid")) {
			t.Errorf("scid: got %s (%v)", got, err)
		}
	}
	for _, c := range list(get(v, "entryHash")) {
		got, err := ComputeEntryHash(get(c, "entry").(*Object), text(get(c, "previousVersionId")))
		if err != nil || got != text(get(c, "hash")) {
			t.Errorf("entryHash: got %s (%v), want %s", got, err, text(get(c, "hash")))
		}
	}
	for i, c := range list(get(v, "sign")) {
		document := get(c, "document")
		proof, err := CreateProof(document, mustKey(t, get(c, "seed")), ProofOptions{Created: text(get(c, "created"))})
		if err != nil || !equalJSON(proof, get(c, "proof")) {
			t.Errorf("sign[%d]: got %s (%v)", i, Stringify(proof), err)
		}
		if !VerifyProof(document, get(c, "proof")) {
			t.Errorf("verify[%d]: valid proof rejected", i)
		}
		tampered := document.(*Object).Clone()
		tampered.Set("extra", 1.0)
		if VerifyProof(tampered, get(c, "proof")) {
			t.Errorf("verify[%d]: tampered document accepted", i)
		}
	}
}

// compareResolution mirrors the harness's comparison of a resolve result with
// a vector's expectation.
func compareResolution(expect, got *Object) []string {
	var problems []string
	if get(got, "valid") != get(expect, "valid") {
		problems = append(problems, "valid differs")
	}
	gotErr := get(got, "error")
	if expErr := get(expect, "error"); expErr != nil {
		codes := []string{text(get(expErr, "code"))}
		if oneOf := list(get(expErr, "oneOf")); oneOf != nil {
			codes = codes[:0]
			for _, c := range oneOf {
				codes = append(codes, text(c))
			}
		}
		if gotErr == nil || !slices.Contains(codes, text(get(gotErr, "code"))) {
			problems = append(problems, "error.code: expected "+strings.Join(codes, "|")+", got "+Stringify(gotErr))
		}
		if has(expErr, "version") && gotErr != nil && !equalJSON(get(expErr, "version"), get(gotErr, "version")) {
			problems = append(problems, "error.version: expected "+Stringify(get(expErr, "version"))+", got "+Stringify(get(gotErr, "version")))
		}
	} else if gotErr != nil {
		problems = append(problems, "unexpected error "+Stringify(gotErr))
	}
	if get(expect, "valid") == true && get(got, "valid") == true {
		if !equalJSON(get(expect, "state"), get(got, "state")) {
			problems = append(problems, "state: got "+Stringify(get(got, "state")))
		}
		if !equalJSON(get(expect, "firstInvalidVersion"), get(got, "firstInvalidVersion")) {
			problems = append(problems, "firstInvalidVersion: got "+Stringify(get(got, "firstInvalidVersion")))
		}
		var codes []any
		for _, w := range list(get(got, "metadata", "warnings")) {
			codes = append(codes, get(w, "code"))
		}
		sort.Slice(codes, func(i, j int) bool { return text(codes[i]) < text(codes[j]) })
		want := list(get(expect, "warnings"))
		if len(codes) != len(want) || (len(want) > 0 && !equalJSON(codes, want)) {
			problems = append(problems, "warnings: got "+Stringify(codes))
		}
		if meta, ok := get(expect, "metadata").(*Object); ok {
			for _, k := range meta.Keys() {
				if !equalJSON(get(meta, k), get(got, "metadata", k)) {
					problems = append(problems, "metadata."+k+": got "+Stringify(get(got, "metadata", k)))
				}
			}
		}
	}
	return problems
}

func TestResolutionVectors(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(vectorsDir, "resolution", "*.json"))
	if err != nil || len(files) == 0 {
		t.Skip("resolution vectors not available")
	}
	for _, file := range files {
		group := strings.TrimSuffix(filepath.Base(file), ".json")
		v := loadVectors(t, filepath.Join("resolution", filepath.Base(file)))
		for _, c := range list(get(v, "cases")) {
			t.Run(group+"/"+text(get(c, "name")), func(t *testing.T) {
				got, err := ResolveRequest(get(c, "input").(*Object))
				if err != nil {
					t.Fatalf("request error: %v", err)
				}
				for _, p := range compareResolution(get(c, "expect").(*Object), got) {
					t.Error(p)
				}
			})
		}
	}
}

func TestGenerationVectors(t *testing.T) {
	v := loadVectors(t, "generation.json")
	for _, sc := range list(get(v, "scenarios")) {
		t.Run(text(get(sc, "name")), func(t *testing.T) {
			var log, scid string
			var versionIDs []string
			for i, step := range list(get(sc, "steps")) {
				input := get(step, "input").(*Object)
				if i > 0 {
					replaced, err := ParseJSON(strings.ReplaceAll(Stringify(input), SCIDPlaceholder, scid))
					if err != nil {
						t.Fatal(err)
					}
					input = replaced.(*Object)
				}
				var keys []ed25519.PrivateKey
				for _, s := range list(get(input, "signers")) {
					keys = append(keys, mustKey(t, s))
				}
				params, _ := get(input, "parameters").(*Object)
				var versionID string
				switch op := text(get(step, "op")); op {
				case "create":
					created, err := CreateLog(get(input, "state"), params, text(get(input, "versionTime")), keys)
					if err != nil {
						t.Fatal(err)
					}
					log, scid, versionID = created.Log, created.SCID, created.VersionID
					if want := text(get(step, "expect", "scid")); want != "" && scid != want {
						t.Errorf("step %d: scid %s, want %s", i+1, scid, want)
					}
				case "update":
					updated, err := UpdateLog(log, get(input, "state"), params, text(get(input, "versionTime")), keys)
					if err != nil {
						t.Fatal(err)
					}
					log, versionID = updated.Log, updated.VersionID
				default:
					t.Fatalf("unknown op %s", op)
				}
				versionIDs = append(versionIDs, versionID)
				if want := text(get(step, "expect", "versionId")); versionID != want {
					t.Errorf("step %d: versionId %s, want %s", i+1, versionID, want)
				}
				lines := SplitLogLines(log)
				if len(lines) != i+1 {
					t.Errorf("step %d: log has %d lines", i+1, len(lines))
				}
				line, err := ParseJSON(lines[len(lines)-1])
				if err != nil || !equalJSON(line, get(step, "expect", "line")) {
					t.Errorf("step %d: line %s", i+1, lines[len(lines)-1])
				}
			}
			var witnessFile []byte
			if w := list(get(sc, "witness")); w != nil {
				var records []any
				for _, item := range w {
					versionID := versionIDs[int(get(item, "step").(float64))-1]
					var proofs []any
					for _, s := range list(get(item, "seeds")) {
						p, err := WitnessProof(versionID, mustKey(t, s), "")
						if err != nil {
							t.Fatal(err)
						}
						proofs = append(proofs, p)
					}
					records = append(records, ObjectOf("versionId", versionID, "proof", proofs))
				}
				if !equalJSON(records, get(sc, "witnessFile")) {
					t.Errorf("witness file differs: %s", Stringify(records))
				}
				witnessFile = []byte(Stringify(records))
			}
			now, _ := ParseVersionTime(text(get(sc, "resolve", "now")))
			res, err := Resolve(ResolveInput{Log: log, Witness: witnessFile, Now: now})
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if res.Error != nil || !equalJSON(res.State, get(sc, "resolve", "state")) ||
				res.Metadata.VersionID != text(get(sc, "resolve", "versionId")) {
				t.Errorf("resolve: %s %s %v", res.Metadata.VersionID, Stringify(res.State), res.Error)
			}
		})
	}
}

func TestExternalVectors(t *testing.T) {
	root := filepath.Join(vectorsDir, "external")
	sources, err := os.ReadDir(root)
	if err != nil {
		t.Skip("external vectors not available")
	}
	for _, source := range sources {
		manifest := loadVectors(t, filepath.Join("external", source.Name(), "manifest.json"))
		for _, sc := range list(get(manifest, "scenarios")) {
			name := text(get(sc, "name"))
			t.Run(source.Name()+"/"+name, func(t *testing.T) {
				data, err := os.ReadFile(filepath.Join(root, source.Name(), name+".jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				var entries []*Object
				for _, line := range SplitLogLines(strings.TrimSpace(string(data))) {
					v, err := ParseJSON(line)
					if err != nil {
						t.Fatal(err)
					}
					entries = append(entries, v.(*Object))
				}
				scid := text(get(entries[0], "parameters", "scid"))
				for i, entry := range entries {
					doc := entry.without("proof")
					if i == 0 {
						prelim := doc.Clone()
						prelim.Set("versionId", SCIDPlaceholder)
						parsed, _ := ParseJSON(strings.ReplaceAll(Stringify(prelim), scid, SCIDPlaceholder))
						if got, _ := ComputeSCID(parsed.(*Object)); got != scid {
							t.Errorf("scid: got %s, want %s", got, scid)
						}
					}
					previous := scid
					if i > 0 {
						previous = text(get(entries[i-1], "versionId"))
					}
					_, hash, _ := strings.Cut(text(get(entry, "versionId")), "-")
					if got, _ := ComputeEntryHash(doc, previous); got != hash {
						t.Errorf("entry %d hash: got %s, want %s", i+1, got, hash)
					}
					for j, p := range list(get(entry, "proof")) {
						if !VerifyProof(doc, p) {
							t.Errorf("entry %d proof %d did not verify", i+1, j+1)
						}
						tampered := doc.Clone()
						tampered.Set("versionTime", "1999-01-01T00:00:00Z")
						if VerifyProof(tampered, p) {
							t.Errorf("entry %d proof %d verified tampered content", i+1, j+1)
						}
					}
					if i > 0 {
						committed, _ := asStringArray(get(entries[i-1], "parameters", "nextKeyHashes"))
						if len(committed) > 0 {
							keys, _ := asStringArray(get(entry, "parameters", "updateKeys"))
							for _, k := range keys {
								if !slices.Contains(committed, KeyHash(k)) {
									t.Errorf("entry %d: key hash of %s not committed", i+1, k)
								}
							}
						}
					}
				}
				if get(sc, "witness") == true {
					data, err := os.ReadFile(filepath.Join(root, source.Name(), name+".witness.json"))
					if err != nil {
						t.Fatal(err)
					}
					records, ok := parseWitnessFile(data)
					if !ok {
						t.Fatal("malformed witness file")
					}
					for _, r := range records {
						for _, p := range r.proofs {
							if !VerifyProof(ObjectOf("versionId", r.versionID), p) {
								t.Errorf("witness proof for %s did not verify", r.versionID)
							}
						}
					}
				}
			})
		}
	}
}

// equalJSON reports whether two parsed JSON values are structurally equal.
func equalJSON(a, b any) bool {
	return mustCanonical(a) == mustCanonical(b)
}

func mustCanonical(v any) string {
	s, err := Canonicalize(v)
	if err != nil {
		return Stringify(v)
	}
	return s
}
