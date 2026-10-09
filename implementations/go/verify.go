package vhlog

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// FutureTolerance is how far a versionTime may be ahead of the resolver's
// clock (profile §4).
const FutureTolerance = 300 * time.Second

const defaultTTL = 3600

var supportedLogVersions = []string{LogVersion}

// Witness is one entry of a witness list.
type Witness struct {
	ID string `json:"id"`
}

// WitnessConfig is a non-empty witness parameter.
type WitnessConfig struct {
	Threshold int       `json:"threshold"`
	Witnesses []Witness `json:"witnesses"`
}

// Parameters is the parameter set active after an entry.
type Parameters struct {
	LogVersion    string
	SCID          string
	UpdateKeys    []string
	NextKeyHashes []string
	// Witness is nil when the parameter is {} (no witnesses).
	Witness  *WitnessConfig
	Watchers []string
	// Deactivated is this entry's own value; it is not inherited.
	Deactivated bool
	TTL         int64
}

// VerifiedEntry is an entry that passed every per-entry check.
type VerifiedEntry struct {
	// Entry is the parsed log line.
	Entry         *Object
	VersionID     string
	VersionTime   string
	VersionNumber int
	// Time is VersionTime as an instant.
	Time time.Time
	// Parameters are the parameters active after this entry.
	Parameters Parameters
	// WitnessRule is the witness list this entry must satisfy, or nil if it
	// needs no witnessing.
	WitnessRule *WitnessConfig
}

// State returns the entry's state value.
func (e *VerifiedEntry) State() any {
	v, _ := e.Entry.Get("state")
	return v
}

// VerifiedLog is the outcome of VerifyLog.
type VerifiedLog struct {
	// Entries is the valid, witnessed prefix of the log.
	Entries []*VerifiedEntry
	// Lines are the raw lines of the log, for copy comparison.
	Lines []string
	// Failure is the first failure, or nil if the whole log is valid.
	Failure *VHLogError
}

// FullyValid reports whether every line of the log is a valid, witnessed entry.
func (v *VerifiedLog) FullyValid() bool {
	return v.Failure == nil && len(v.Entries) == len(v.Lines)
}

// ParseVersionTime parses a versionTime: "YYYY-MM-DDTHH:MM:SSZ" or the same
// with "+00:00", whole seconds, a real calendar date (proleptic Gregorian,
// any 4-digit year) and a time between 00:00:00 and 23:59:59.
func ParseVersionTime(value string) (time.Time, bool) {
	var rest string
	switch {
	case len(value) == 20 && value[19] == 'Z':
		rest = value[:19]
	case len(value) == 25 && value[19:] == "+00:00":
		rest = value[:19]
	default:
		return time.Time{}, false
	}
	// YYYY-MM-DDTHH:MM:SS
	for i := 0; i < 19; i++ {
		switch i {
		case 4, 7:
			if rest[i] != '-' {
				return time.Time{}, false
			}
		case 10:
			if rest[i] != 'T' {
				return time.Time{}, false
			}
		case 13, 16:
			if rest[i] != ':' {
				return time.Time{}, false
			}
		default:
			if !isDigit(rest[i]) {
				return time.Time{}, false
			}
		}
	}
	num := func(a, b int) int {
		n := 0
		for _, c := range rest[a:b] {
			n = n*10 + int(c-'0')
		}
		return n
	}
	y, mo, d, h, mi, s := num(0, 4), num(5, 7), num(8, 10), num(11, 13), num(14, 16), num(17, 19)
	if mo < 1 || mo > 12 || d < 1 || d > daysIn(y, mo) || h > 23 || mi > 59 || s > 59 {
		return time.Time{}, false
	}
	return time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC), true
}

func daysIn(year, month int) int {
	switch month {
	case 2:
		if (year%4 == 0 && year%100 != 0) || year%400 == 0 {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

// IsWatcherURL reports whether value is an acceptable watchers URL (profile
// §4): printable ASCII only, an http or https scheme, and a non-empty
// authority.
func IsWatcherURL(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	rest, ok := strings.CutPrefix(value, "https://")
	if !ok {
		if rest, ok = strings.CutPrefix(value, "http://"); !ok {
			return false
		}
	}
	return rest != "" && rest[0] != '/' && rest[0] != '?' && rest[0] != '#'
}

func isInteger(f float64) bool {
	return !math.IsInf(f, 0) && !math.IsNaN(f) && f == math.Trunc(f)
}

func asStringArray(v any) ([]string, bool) {
	arr, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(arr))
	for i, e := range arr {
		s, ok := e.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

func validateWitness(value any, version int) (*WitnessConfig, error) {
	fail := func(format string, args ...any) error {
		return newError(ErrInvalidParameter, version, "witness: "+format, args...)
	}
	obj, ok := value.(*Object)
	if !ok {
		return nil, fail("must be an object")
	}
	if obj.Len() == 0 {
		return nil, nil
	}
	list, _ := obj.Get("witnesses")
	items, ok := list.([]any)
	if !ok || len(items) == 0 {
		return nil, fail("witnesses must be a non-empty array")
	}
	ids := map[string]bool{}
	witnesses := make([]Witness, 0, len(items))
	for _, item := range items {
		w, ok := item.(*Object)
		var id string
		if ok {
			raw, _ := w.Get("id")
			id, ok = raw.(string)
		}
		if !ok {
			return nil, fail("each witness needs a string id")
		}
		mk, isDidKey := strings.CutPrefix(id, "did:key:")
		if _, valid := PublicKeyFromMultikey(mk); !isDidKey || !valid {
			return nil, fail("witness id %s is not an Ed25519 did:key", id)
		}
		// Ids are compared after NFC normalisation (profile §3). A valid
		// did:key id is ASCII, for which NFC is the identity.
		if ids[id] {
			return nil, fail("duplicate witness id %s", id)
		}
		ids[id] = true
		witnesses = append(witnesses, Witness{ID: id})
	}
	raw, _ := obj.Get("threshold")
	threshold, ok := raw.(float64)
	if !ok || !isInteger(threshold) || threshold < 1 || threshold > float64(len(ids)) {
		return nil, fail("threshold must be an integer between 1 and the number of witnesses")
	}
	return &WitnessConfig{Threshold: int(threshold), Witnesses: witnesses}, nil
}

// applyParameters applies an entry's parameters to the previously active set
// (Read step 1 and the pre-rotation rule of step 7).
func applyParameters(raw *Object, previous *Parameters, version int) (Parameters, error) {
	invalid := func(format string, args ...any) error {
		return newError(ErrInvalidParameter, version, format, args...)
	}
	for _, k := range raw.keys {
		if raw.values[k] == nil {
			return Parameters{}, invalid("%s must not be null", k)
		}
	}
	if previous == nil && !raw.Has("logVersion") {
		return Parameters{}, newError(ErrUnsupportedLogVersion, 1, "logVersion missing from first entry")
	}
	if v, ok := raw.Get("logVersion"); ok {
		s, isString := v.(string)
		if !isString || !slices.Contains(supportedLogVersions, s) {
			return Parameters{}, newError(ErrUnsupportedLogVersion, version, "unsupported logVersion %s", Stringify(v))
		}
		if previous != nil && slices.Index(supportedLogVersions, s) < slices.Index(supportedLogVersions, previous.LogVersion) {
			return Parameters{}, newError(ErrUnsupportedLogVersion, version, "logVersion may not be lowered")
		}
	}
	if previous == nil {
		if v, _ := raw.Get("scid"); !isString(v) {
			return Parameters{}, invalid("scid missing from first entry")
		}
		if !raw.Has("updateKeys") {
			return Parameters{}, invalid("updateKeys missing from first entry")
		}
	} else if raw.Has("scid") {
		return Parameters{}, invalid("scid may only appear in the first entry")
	}
	var updateKeys, nextKeyHashes, watchers []string
	if v, ok := raw.Get("updateKeys"); ok {
		keys, isArray := asStringArray(v)
		if !isArray || slices.ContainsFunc(keys, func(k string) bool { _, ok := PublicKeyFromMultikey(k); return !ok }) {
			return Parameters{}, invalid("updateKeys must be an array of Ed25519 multikeys")
		}
		updateKeys = keys
	}
	if v, ok := raw.Get("nextKeyHashes"); ok {
		hashes, isArray := asStringArray(v)
		if !isArray || slices.ContainsFunc(hashes, func(h string) bool { return CheckSHA256Multihash(h) != MultihashOK }) {
			return Parameters{}, invalid("nextKeyHashes must be an array of SHA-256 multihashes")
		}
		nextKeyHashes = hashes
	}
	var witness *WitnessConfig
	if v, ok := raw.Get("witness"); ok {
		w, err := validateWitness(v, version)
		if err != nil {
			return Parameters{}, err
		}
		witness = w
	} else if previous != nil {
		witness = previous.Witness
	}
	if v, ok := raw.Get("watchers"); ok {
		urls, isArray := asStringArray(v)
		if !isArray || slices.ContainsFunc(urls, func(u string) bool { return !IsWatcherURL(u) }) {
			return Parameters{}, invalid("watchers must be an array of URLs")
		}
		watchers = urls
	}
	deactivated := false
	if v, ok := raw.Get("deactivated"); ok {
		b, isBool := v.(bool)
		if !isBool {
			return Parameters{}, invalid("deactivated must be a boolean")
		}
		deactivated = b
	}
	var ttl int64 = defaultTTL
	if previous != nil {
		ttl = previous.TTL
	}
	if v, ok := raw.Get("ttl"); ok {
		f, isNumber := v.(float64)
		if !isNumber || !isInteger(f) || f < 0 || f > 1<<31 {
			return Parameters{}, invalid("ttl must be an integer between 0 and 2^31")
		}
		ttl = int64(f)
	}

	if previous != nil && len(previous.NextKeyHashes) > 0 {
		if updateKeys == nil {
			return Parameters{}, newError(ErrPrerotationViolation, version, "updateKeys must be explicit while pre-rotation is active")
		}
		if nextKeyHashes == nil {
			return Parameters{}, newError(ErrPrerotationViolation, version, "nextKeyHashes must be explicit while pre-rotation is active")
		}
		for _, k := range updateKeys {
			if !slices.Contains(previous.NextKeyHashes, KeyHash(k)) {
				return Parameters{}, newError(ErrPrerotationViolation, version, "key %s was not committed", k)
			}
		}
	}

	p := Parameters{Witness: witness, Deactivated: deactivated, TTL: ttl}
	if v, ok := raw.Get("logVersion"); ok {
		p.LogVersion = v.(string)
	} else {
		p.LogVersion = previous.LogVersion
	}
	if v, ok := raw.Get("scid"); ok {
		p.SCID = v.(string)
	} else {
		p.SCID = previous.SCID
	}
	p.UpdateKeys = firstNonNil(updateKeys, previous, func(q *Parameters) []string { return q.UpdateKeys })
	p.NextKeyHashes = firstNonNil(nextKeyHashes, previous, func(q *Parameters) []string { return q.NextKeyHashes })
	p.Watchers = firstNonNil(watchers, previous, func(q *Parameters) []string { return q.Watchers })
	return p, nil
}

func isString(v any) bool {
	_, ok := v.(string)
	return ok
}

// firstNonNil returns value, else the previous entry's value, else an empty slice.
func firstNonNil(value []string, previous *Parameters, get func(*Parameters) []string) []string {
	if value != nil {
		return value
	}
	if previous != nil && get(previous) != nil {
		return get(previous)
	}
	return []string{}
}

func verifyProofs(entry *Object, activeKeys []string, version int) error {
	raw, _ := entry.Get("proof")
	proofs := raw.([]any)
	if len(proofs) == 0 {
		return newError(ErrInvalidProof, version, "proof array is empty")
	}
	document := entry.without("proof")
	for _, proof := range proofs {
		var multikey string
		ok := false
		if p, isObject := proof.(*Object); isObject {
			vm, _ := p.Get("verificationMethod")
			multikey, ok = MultikeyFromVerificationMethod(vm)
		}
		if !ok {
			return newError(ErrInvalidProof, version, "proof verificationMethod is not did:key:<mk>#<mk>")
		}
		if !slices.Contains(activeKeys, multikey) {
			return newError(ErrUnauthorizedKey, version, "%s is not an active update key", multikey)
		}
		if !VerifyProof(document, proof) {
			return newError(ErrInvalidProof, version, "proof failed verification")
		}
	}
	return nil
}

func verifyVersionID(entry *Object, versionID string, expected int, previousVersionID string) error {
	number, hash, ok := strings.Cut(versionID, "-")
	if !ok || hash == "" || strings.Contains(hash, "-") || !isCanonicalNumber(number, expected) {
		return newError(ErrInvalidVersionID, expected, "expected versionId %d-<hash>, got %s", expected, versionID)
	}
	switch CheckSHA256Multihash(hash) {
	case MultihashNotBase58:
		return newError(ErrInvalidVersionID, expected, "entry hash is not base58btc")
	case MultihashUnsupported:
		return newError(ErrInvalidHashAlgorithm, expected, "entry hash is not a SHA-256 multihash")
	}
	computed, err := ComputeEntryHash(entry, previousVersionID)
	if err != nil || computed != hash {
		return newError(ErrEntryHashMismatch, expected, "entry hash does not match")
	}
	return nil
}

// isCanonicalNumber reports whether s is [1-9][0-9]* and equals n.
func isCanonicalNumber(s string, n int) bool {
	if s == "" || s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return s == fmt.Sprint(n)
}

func verifySCID(entry *Object, scid string) error {
	switch CheckSHA256Multihash(scid) {
	case MultihashUnsupported:
		return newError(ErrInvalidHashAlgorithm, 1, "SCID is not a SHA-256 multihash")
	case MultihashNotBase58:
		return newError(ErrSCIDMismatch, 1, "SCID is not base58btc")
	}
	preliminary := entry.without("proof")
	preliminary.Set("versionId", SCIDPlaceholder)
	parsed, err := ParseJSON(strings.ReplaceAll(Stringify(preliminary), scid, SCIDPlaceholder))
	if err != nil {
		return newError(ErrSCIDMismatch, 1, "SCID does not match")
	}
	computed, err := ComputeSCID(parsed.(*Object))
	if err != nil || computed != scid {
		return newError(ErrSCIDMismatch, 1, "SCID does not match")
	}
	return nil
}

// verifyEntry runs the per-entry checks (profile §4, steps 1–7) on one parsed line.
func verifyEntry(raw any, previous *VerifiedEntry, now time.Time) (*VerifiedEntry, error) {
	version := 1
	if previous != nil {
		version = previous.VersionNumber + 1
		if previous.Parameters.Deactivated {
			return nil, newError(ErrEntryAfterDeactivation, version, "entry follows a deactivating entry")
		}
	}
	entry, ok := raw.(*Object)
	var versionID, versionTime string
	var rawParams *Object
	if ok && entry.Len() == len(entryFieldOrder) {
		for _, k := range entryFieldOrder {
			ok = ok && entry.Has(k)
		}
		if ok {
			v, _ := entry.Get("versionId")
			t, _ := entry.Get("versionTime")
			p, _ := entry.Get("parameters")
			s, _ := entry.Get("state")
			pr, _ := entry.Get("proof")
			var isVID, isVT, isState, isProof bool
			versionID, isVID = v.(string)
			versionTime, isVT = t.(string)
			rawParams, ok = p.(*Object)
			_, isState = s.(*Object)
			_, isProof = pr.([]any)
			ok = ok && isVID && isVT && isState && isProof
		}
	} else {
		ok = false
	}
	if !ok {
		return nil, newError(ErrInvalidEntry, version, "entry does not have the required properties and types")
	}

	var prevParams *Parameters
	if previous != nil {
		prevParams = &previous.Parameters
	}
	params, err := applyParameters(rawParams, prevParams, version)
	if err != nil {
		return nil, err
	}

	var activeKeys []string
	var witnessRule *WitnessConfig
	if previous == nil {
		activeKeys = params.UpdateKeys
		witnessRule = params.Witness
	} else {
		if len(previous.Parameters.NextKeyHashes) > 0 {
			activeKeys = params.UpdateKeys
		} else {
			activeKeys = previous.Parameters.UpdateKeys
		}
		if rawParams.Has("witness") && previous.Parameters.Witness == nil {
			witnessRule = params.Witness
		} else {
			witnessRule = previous.Parameters.Witness
		}
	}
	if err := verifyProofs(entry, activeKeys, version); err != nil {
		return nil, err
	}
	previousID := params.SCID
	if previous != nil {
		previousID = previous.VersionID
	}
	if err := verifyVersionID(entry, versionID, version, previousID); err != nil {
		return nil, err
	}

	t, ok := ParseVersionTime(versionTime)
	if !ok {
		return nil, newError(ErrInvalidVersionTime, version, "invalid versionTime %s", versionTime)
	}
	if previous != nil && !t.After(previous.Time) {
		return nil, newError(ErrInvalidVersionTime, version, "versionTime must be later than the previous entry's")
	}
	if t.After(now.Add(FutureTolerance)) {
		return nil, newError(ErrFutureVersionTime, version, "versionTime is in the future")
	}
	if previous == nil {
		if err := verifySCID(entry, params.SCID); err != nil {
			return nil, err
		}
	}
	return &VerifiedEntry{
		Entry:         entry,
		VersionID:     versionID,
		VersionTime:   versionTime,
		VersionNumber: version,
		Time:          t,
		Parameters:    params,
		WitnessRule:   witnessRule,
	}, nil
}

type witnessRecord struct {
	versionID string
	proofs    []any
}

// parseWitnessFile parses a witness file: a JSON array of {versionId, proof[]}.
func parseWitnessFile(data []byte) ([]witnessRecord, bool) {
	v, err := ParseJSON(string(data))
	if err != nil {
		return nil, false
	}
	items, ok := v.([]any)
	if !ok {
		return nil, false
	}
	records := make([]witnessRecord, 0, len(items))
	for _, item := range items {
		obj, ok := item.(*Object)
		if !ok {
			return nil, false
		}
		vid, _ := obj.Get("versionId")
		proofs, _ := obj.Get("proof")
		id, isString := vid.(string)
		list, isArray := proofs.([]any)
		if !isString || !isArray {
			return nil, false
		}
		records = append(records, witnessRecord{id, list})
	}
	return records, true
}

// checkWitnesses returns the index of the first entry that is not witnessed
// and the error for it, or -1 (Verifying Witness Proofs During Resolution).
func checkWitnesses(entries []*VerifiedEntry, witnessFile []byte) (int, *VHLogError) {
	first := slices.IndexFunc(entries, func(e *VerifiedEntry) bool { return e.WitnessRule != nil })
	if first == -1 {
		return -1, nil
	}
	var records []witnessRecord
	if witnessFile != nil {
		var ok bool
		if records, ok = parseWitnessFile(witnessFile); !ok {
			return first, newError(ErrInvalidWitnessFile, first+1, "witness file is malformed")
		}
	}
	position := map[string]int{}
	for i, e := range entries {
		position[e.VersionID] = i
	}
	type approval struct {
		id        string
		index     int
		proof     any
		versionID string
		checked   bool
		valid     bool
	}
	// A proof over entry j's versionId approves every entry <= j.
	var approvals []*approval
	for _, r := range records {
		index, ok := position[r.versionID]
		if !ok {
			continue
		}
		for _, proof := range r.proofs {
			p, isObject := proof.(*Object)
			if !isObject {
				continue
			}
			vm, _ := p.Get("verificationMethod")
			if mk, ok := MultikeyFromVerificationMethod(vm); ok {
				approvals = append(approvals, &approval{id: "did:key:" + mk, index: index, proof: proof, versionID: r.versionID})
			}
		}
	}
	isValid := func(a *approval) bool {
		if !a.checked {
			a.valid = VerifyProof(ObjectOf("versionId", a.versionID), a.proof)
			a.checked = true
		}
		return a.valid
	}
	for i := first; i < len(entries); i++ {
		rule := entries[i].WitnessRule
		if rule == nil {
			continue
		}
		ids := map[string]bool{}
		for _, w := range rule.Witnesses {
			ids[w.ID] = true
		}
		approved := map[string]bool{}
		for _, a := range approvals {
			if a.index >= i && ids[a.id] && !approved[a.id] && isValid(a) {
				approved[a.id] = true
			}
		}
		if len(approved) < rule.Threshold {
			return i, newError(ErrWitnessThresholdNotMet, i+1,
				"entry %d has %d of %d required witness approvals", i+1, len(approved), rule.Threshold)
		}
	}
	return -1, nil
}

// VerifyLog verifies a whole log file and returns its valid, witnessed prefix
// and the first failure. witnessFile is the raw content of the witness file,
// or nil if there is none. now is the resolver's clock.
func VerifyLog(log string, witnessFile []byte, now time.Time) *VerifiedLog {
	lines := SplitLogLines(log)
	result := &VerifiedLog{Lines: lines}
	if log == "" {
		result.Lines = []string{}
		result.Failure = newError(ErrInvalidLog, 0, "log is empty")
		return result
	}
	var previous *VerifiedEntry
	for i, line := range lines {
		entry, err := verifyLine(line, i+1, previous, now)
		if err != nil {
			result.Failure = err
			break
		}
		result.Entries = append(result.Entries, entry)
		previous = entry
	}
	if index, err := checkWitnesses(result.Entries, witnessFile); err != nil {
		result.Entries = result.Entries[:index]
		result.Failure = err
	}
	return result
}

func verifyLine(line string, number int, previous *VerifiedEntry, now time.Time) (*VerifiedEntry, *VHLogError) {
	raw, err := ParseJSON(line)
	if err != nil {
		return nil, newError(ErrInvalidLog, number, "line %d is not JSON", number)
	}
	if _, ok := raw.(*Object); !ok {
		return nil, newError(ErrInvalidLog, number, "line %d is not a JSON object", number)
	}
	if !isSafeJSON(raw) {
		return nil, newError(ErrInvalidLog, number, "line %d has a non-finite number or a lone surrogate", number)
	}
	entry, err := verifyEntry(raw, previous, now)
	if err != nil {
		return nil, err.(*VHLogError)
	}
	return entry, nil
}
