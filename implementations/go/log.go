package vhlog

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// SCIDPlaceholder is replaced by the SCID when a log is created.
	SCIDPlaceholder = "{SCID}"
	// LogVersion is the log version this package implements.
	LogVersion = "vh-log:1.0"
	// LogFileName is the conventional name of a log file.
	LogFileName = "vh-log.jsonl"
	// WitnessFileName is the conventional name of a witness file.
	WitnessFileName = "vh-log-witness.json"
)

// entryFieldOrder is the member order of a serialised entry (profile §5).
var entryFieldOrder = []string{"versionId", "versionTime", "parameters", "state", "proof"}

// ComputeSCID returns the SCID of a preliminary entry: one whose placeholders
// are still in place and whose versionId is "{SCID}". Any proof is ignored.
func ComputeSCID(preliminary *Object) (string, error) {
	c, err := Canonicalize(preliminary.without("proof"))
	if err != nil {
		return "", err
	}
	return HashString(c), nil
}

// ComputeEntryHash returns an entry's hash: the entry without proof, with its
// versionId replaced by its predecessor's (the SCID for the first entry).
func ComputeEntryHash(entry *Object, previousVersionID string) (string, error) {
	doc := entry.without("proof")
	doc.Set("versionId", previousVersionID)
	c, err := Canonicalize(doc)
	if err != nil {
		return "", err
	}
	return HashString(c), nil
}

// SerializeEntry returns an entry as one compact JSON line (with the trailing
// newline), members ordered versionId, versionTime, parameters, state, proof,
// then anything else.
func SerializeEntry(entry *Object) string {
	ordered := NewObject()
	for _, k := range entryFieldOrder {
		if v, ok := entry.Get(k); ok {
			ordered.Set(k, v)
		}
	}
	for _, k := range entry.keys {
		if !ordered.Has(k) {
			ordered.Set(k, entry.values[k])
		}
	}
	return Stringify(ordered) + "\n"
}

// SplitLogLines splits a log file into lines on "\n" only, dropping the empty
// string after a final newline.
func SplitLogLines(log string) []string {
	lines := strings.Split(log, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

func signDocument(document *Object, signers []ed25519.PrivateKey) ([]any, error) {
	created, _ := document.Get("versionTime")
	createdText, _ := created.(string)
	proofs := make([]any, 0, len(signers))
	for _, key := range signers {
		p, err := CreateProof(document, key, ProofOptions{Created: createdText})
		if err != nil {
			return nil, err
		}
		proofs = append(proofs, p)
	}
	return proofs, nil
}

// CreatedLog is the result of CreateLog.
type CreatedLog struct {
	// Log is the new log file: one line, newline-terminated.
	Log string `json:"log"`
	// SCID is the log's self-certifying identifier.
	SCID string `json:"scid"`
	// VersionID is the first entry's versionId ("1-<hash>").
	VersionID string `json:"versionId"`
}

// CreateLog creates a log with its first entry. "{SCID}" anywhere in state or
// parameters is replaced by the SCID. logVersion defaults to "vh-log:1.0" and
// scid to "{SCID}". Each signer adds one proof, in order, with created set to
// versionTime.
//
// CreateLog does not validate parameters (profile §5): it signs whatever it is
// given, so verify the result with VerifyLog if the input is untrusted.
func CreateLog(state any, parameters *Object, versionTime string, signers []ed25519.PrivateKey) (*CreatedLog, error) {
	params := NewObject()
	if parameters != nil {
		params = parameters.Clone()
	}
	if !params.Has("logVersion") {
		params.Set("logVersion", LogVersion)
	}
	if !params.Has("scid") {
		params.Set("scid", SCIDPlaceholder)
	}
	preliminary := ObjectOf("versionId", SCIDPlaceholder, "versionTime", versionTime, "parameters", params, "state", state)
	scid, err := ComputeSCID(preliminary)
	if err != nil {
		return nil, err
	}
	replaced, err := ParseJSON(strings.ReplaceAll(Stringify(preliminary), SCIDPlaceholder, scid))
	if err != nil {
		return nil, err
	}
	document := replaced.(*Object)
	hash, err := ComputeEntryHash(document, scid)
	if err != nil {
		return nil, err
	}
	document.Set("versionId", "1-"+hash)
	proofs, err := signDocument(document, signers)
	if err != nil {
		return nil, err
	}
	entry := document.Clone()
	entry.Set("proof", proofs)
	return &CreatedLog{Log: SerializeEntry(entry), SCID: scid, VersionID: "1-" + hash}, nil
}

// UpdatedLog is the result of UpdateLog.
type UpdatedLog struct {
	// Log is the input log with the new line appended.
	Log string `json:"log"`
	// VersionID is the new entry's versionId.
	VersionID string `json:"versionId"`
}

// UpdateLog appends an entry with the given state and parameter changes (nil
// or empty for none; {"deactivated": true} deactivates). The hash chain
// continues from the log's last line. Like CreateLog it does not validate
// semantics.
func UpdateLog(log string, state any, parameters *Object, versionTime string, signers []ed25519.PrivateKey) (*UpdatedLog, error) {
	if log == "" {
		return nil, errors.New("cannot update an empty log")
	}
	lines := SplitLogLines(log)
	if len(lines) == 0 {
		return nil, errors.New("cannot update an empty log")
	}
	last, err := ParseJSON(lines[len(lines)-1])
	if err != nil {
		return nil, fmt.Errorf("last log line: %w", err)
	}
	previous, ok := last.(*Object)
	if !ok {
		return nil, errors.New("last log line is not a JSON object")
	}
	pv, _ := previous.Get("versionId")
	previousID, ok := pv.(string)
	if !ok {
		return nil, errors.New("last log line has no string versionId")
	}
	if parameters == nil {
		parameters = NewObject()
	}
	body := ObjectOf("versionId", previousID, "versionTime", versionTime, "parameters", parameters, "state", state)
	hash, err := ComputeEntryHash(body, previousID)
	if err != nil {
		return nil, err
	}
	number, _, _ := strings.Cut(previousID, "-")
	versionID := nextVersionNumber(number) + "-" + hash
	body.Set("versionId", versionID)
	proofs, err := signDocument(body, signers)
	if err != nil {
		return nil, err
	}
	entry := body.Clone()
	entry.Set("proof", proofs)
	prefix := log
	if !strings.HasSuffix(log, "\n") {
		prefix += "\n"
	}
	return &UpdatedLog{Log: prefix + SerializeEntry(entry), VersionID: versionID}, nil
}

// nextVersionNumber returns the decimal number after the leading integer of s
// (parseInt semantics), or "NaN" if s does not start with one.
func nextVersionNumber(s string) string {
	s = strings.TrimLeft(s, " \t\n\r")
	end := 0
	if end < len(s) && (s[end] == '+' || s[end] == '-') {
		end++
	}
	digitsStart := end
	for end < len(s) && isDigit(s[end]) {
		end++
	}
	if end == digitsStart {
		return "NaN"
	}
	n, err := strconv.ParseFloat(s[:end], 64)
	if err != nil {
		return "NaN"
	}
	return FormatNumber(n + 1)
}

// WitnessProof returns a witness's eddsa-jcs-2022 proof over
// {"versionId": versionID} (profile §3). created is omitted when empty.
func WitnessProof(versionID string, key ed25519.PrivateKey, created string) (*Object, error) {
	return CreateProof(ObjectOf("versionId", versionID), key, ProofOptions{Created: created})
}
