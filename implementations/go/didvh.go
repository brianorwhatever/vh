package vhlog

// did:vh (docs/didvh-profile.md). A did:vh DID log has the same format and
// verification as a VH-Log log (did:vh and VH-Log are both derived from
// did:webvh), so the log is verified by the VH-Log code with the did:vh
// Specialisation. This file adds the DID syntax, the srcLog/srcWitness and DID
// URL rules, the resolution options, and DID Resolution metadata and errors.

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	// DidVhMethod is the did:vh method parameter value this package supports.
	DidVhMethod = "did:vh:1.0"
	// DidVhPrefix starts every did:vh DID.
	DidVhPrefix = "did:vh:"
)

// DidVhErrorCode is a did:vh (DID Resolution) error code.
type DidVhErrorCode string

// did:vh error codes.
const (
	DidVhInvalidDid          DidVhErrorCode = "invalidDid"
	DidVhInvalidDidURL       DidVhErrorCode = "invalidDidUrl"
	DidVhInvalidOptions      DidVhErrorCode = "invalidOptions"
	DidVhNotFound            DidVhErrorCode = "notFound"
	DidVhFeatureNotSupported DidVhErrorCode = "featureNotSupported"
	DidVhLogForked           DidVhErrorCode = "logForked"
	DidVhInsufficientCopies  DidVhErrorCode = "insufficientCopies"
)

// DidVhError is a did:vh failure, with the VH-Log error behind it where there
// is one.
type DidVhError struct {
	Code    DidVhErrorCode
	Message string
	VHLog   *VHLogError
}

func didVhError(code DidVhErrorCode, format string, args ...any) *DidVhError {
	return &DidVhError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Error implements error.
func (e *DidVhError) Error() string { return string(e.Code) + ": " + e.Message }

// ---------------------------------------------------------------- the DID

func isBase58(c byte) bool {
	return (c >= '1' && c <= '9') || (c >= 'A' && c <= 'Z' && c != 'I' && c != 'O') || (c >= 'a' && c <= 'z' && c != 'l')
}

// ParseDidVh returns the SCID of a did:vh DID, or false if did does not match
// the ABNF.
func ParseDidVh(did string) (string, bool) {
	scid, ok := strings.CutPrefix(did, DidVhPrefix)
	if !ok || len(scid) != 46 {
		return "", false
	}
	for i := 0; i < len(scid); i++ {
		if !isBase58(scid[i]) {
			return "", false
		}
	}
	return scid, true
}

// isDecimal reports whether s is a non-negative integer without leading zeros.
func isDecimal(s string) bool {
	return s != "" && isDigits(s) && (s == "0" || s[0] != '0')
}

func isDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// isMethodSyntax reports whether value is did:vh:<major>.<minor>.
func isMethodSyntax(value string) bool {
	rest, ok := strings.CutPrefix(value, DidVhPrefix)
	if !ok {
		return false
	}
	major, minor, ok := strings.Cut(rest, ".")
	return ok && isDecimal(major) && isDecimal(minor)
}

// DidVhSpecialisation is the did:vh specialisation of VH-Log: "method"
// instead of "logVersion", a closed parameter set, and state.id =
// did:vh:<SCID> in every entry. With a non-empty expectedSCID, the log's SCID
// must also be that of the DID being resolved.
func DidVhSpecialisation(expectedSCID string) *Specialisation {
	return &Specialisation{
		VersionParameter: "method",
		Versions:         []string{DidVhMethod},
		VersionSyntax:    isMethodSyntax,
		ClosedParameters: true,
		CheckState: func(state *Object, scid string, version int) error {
			if expectedSCID != "" && scid != expectedSCID {
				return newError(ErrInvalidState, version, "the log is for did:vh:%s, not did:vh:%s", scid, expectedSCID)
			}
			id, _ := state.Get("id")
			if id != DidVhPrefix+scid {
				return newError(ErrInvalidState, version, "state.id must be %s%s", DidVhPrefix, scid)
			}
			return nil
		},
	}
}

// ---------------------------------------------------------------- create / update

// CreatedDid is the result of CreateDid.
type CreatedDid struct {
	Log       string
	Did       string
	SCID      string
	VersionID string
}

// CreateDid creates a did:vh DID log. The document uses did:vh:{SCID}
// wherever it refers to the DID; method and scid are added to the parameters
// if absent. Like CreateLog, it does not validate its input.
func CreateDid(document any, parameters *Object, versionTime string, signers []ed25519.PrivateKey) (*CreatedDid, error) {
	created, err := CreateLogWith(document, parameters, versionTime, signers, "method", DidVhMethod)
	if err != nil {
		return nil, err
	}
	return &CreatedDid{Log: created.Log, Did: DidVhPrefix + created.SCID, SCID: created.SCID, VersionID: created.VersionID}, nil
}

// UpdateDid appends an entry to a did:vh DID log. Deactivate with parameters
// {"deactivated": true}.
func UpdateDid(log string, document any, parameters *Object, versionTime string, signers []ed25519.PrivateKey) (*UpdatedLog, error) {
	return UpdateLog(log, document, parameters, versionTime, signers)
}

// ---------------------------------------------------------------- shared URL checks

// PercentDecode decodes %XX escapes in s; it fails on a malformed escape or
// if the result is not UTF-8.
func PercentDecode(s string) (string, bool) {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out = append(out, s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		hi, ok1 := hexValue(s[i+1])
		lo, ok2 := hexValue(s[i+2])
		if !ok1 || !ok2 {
			return "", false
		}
		out = append(out, byte(hi<<4|lo))
		i += 2
	}
	if !utf8.Valid(out) {
		return "", false
	}
	return string(out), true
}

// isWhiteSpace reports whether r has the Unicode White_Space property.
func isWhiteSpace(r rune) bool {
	switch {
	case r >= 0x09 && r <= 0x0D, r == 0x20, r == 0x85, r == 0xA0, r == 0x1680,
		r >= 0x2000 && r <= 0x200A, r == 0x2028, r == 0x2029, r == 0x202F, r == 0x205F, r == 0x3000:
		return true
	}
	return false
}

func isOctet(s string) bool {
	if len(s) == 0 || len(s) > 3 || !isDecimal(s) {
		return false
	}
	n, _ := strconv.Atoi(s)
	return n <= 255
}

func isLoopbackHost(host string) bool {
	if host == "localhost" || host == "[::1]" {
		return true
	}
	parts := strings.Split(host, ".")
	return len(parts) == 4 && parts[0] == "127" && isOctet(parts[0]) && isOctet(parts[1]) && isOctet(parts[2]) && isOctet(parts[3])
}

func isDomainName(host string) bool {
	name := strings.TrimSuffix(host, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	labels := strings.Split(name, ".")
	if isDigits(labels[len(labels)-1]) { // an IPv4 literal, or ends in a number
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; !(c >= 'a' && c <= 'z' || isDigit(c) || c == '-') {
				return false
			}
		}
	}
	return true
}

// splitScheme splits scheme:rest (profile §3 steps 1–2), lowercasing the
// scheme; it fails unless value is printable ASCII starting with a scheme.
func splitScheme(value string) (scheme, rest string, ok bool) {
	if value == "" {
		return "", "", false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return "", "", false
		}
	}
	scheme, rest, ok = strings.Cut(value, ":")
	if !ok || scheme == "" {
		return "", "", false
	}
	for i := 0; i < len(scheme); i++ {
		c := scheme[i] | 0x20
		letter := c >= 'a' && c <= 'z'
		if !letter && (i == 0 || !(isDigit(scheme[i]) || scheme[i] == '+' || scheme[i] == '.' || scheme[i] == '-')) {
			return "", "", false
		}
	}
	return strings.ToLower(scheme), rest, true
}

// checkAuthority checks an http(s) authority (profile §3).
func checkAuthority(authority string, https bool) bool {
	if strings.Contains(authority, "@") {
		return false
	}
	var host, port string
	hasPort := false
	if strings.HasPrefix(authority, "[") {
		end := strings.Index(authority, "]")
		if end == -1 {
			return false
		}
		host = authority[:end+1]
		if after := authority[end+1:]; after != "" {
			if port, hasPort = strings.CutPrefix(after, ":"); !hasPort {
				return false
			}
		}
	} else {
		host, port, hasPort = strings.Cut(authority, ":")
	}
	host = strings.ToLower(host)
	if hasPort {
		n, err := strconv.Atoi(port)
		if port == "" || len(port) > 5 || !isDigits(port) || err != nil || n > 65535 {
			return false
		}
	}
	if https {
		return !strings.HasPrefix(host, "[") && isDomainName(host)
	}
	return isLoopbackHost(host)
}

// checkSegments checks the segments of a path that starts with "/" (profile
// §3). Each is percent-decoded and must not be "." or ".." or contain "/",
// "\" or NUL. With strict (the src DID URL parameter), it must also be
// non-empty and not start or end with white space.
func checkSegments(path string, strict bool) bool {
	for _, raw := range strings.Split(path[1:], "/") {
		segment, ok := PercentDecode(raw)
		if !ok || segment == "." || segment == ".." || strings.ContainsAny(segment, "/\\\x00") {
			return false
		}
		if strict {
			if segment == "" {
				return false
			}
			first, _ := utf8.DecodeRuneInString(segment)
			last, _ := utf8.DecodeLastRuneInString(segment)
			if isWhiteSpace(first) || isWhiteSpace(last) {
				return false
			}
		}
	}
	return true
}

// ---------------------------------------------------------------- srcLog / srcWitness references

// RefKind is the kind of a srcLog or srcWitness reference: "web",
// "loopback", "file" or "other".
type RefKind string

// Reference kinds.
const (
	RefWeb      RefKind = "web"
	RefLoopback RefKind = "loopback"
	RefFile     RefKind = "file"
	RefOther    RefKind = "other"
)

// CheckRef validates a srcLog or srcWitness reference, which names a file
// (profile §3.1), and returns its kind. It fails with invalidOptions.
func CheckRef(ref string) (RefKind, error) {
	invalid := func(why string) (RefKind, error) {
		return "", didVhError(DidVhInvalidOptions, "reference %q: %s", ref, why)
	}
	scheme, rest, ok := splitScheme(ref)
	if !ok {
		return invalid("not a printable-ASCII absolute URL")
	}
	if strings.Contains(rest, "#") {
		return invalid("must not have a fragment")
	}
	switch scheme {
	case "https", "http":
		after, ok := strings.CutPrefix(rest, "//")
		if !ok {
			return invalid("missing authority")
		}
		end := strings.IndexAny(after, "/?")
		if end == -1 {
			end = len(after)
		}
		authority, path := after[:end], after[end:]
		path, _, _ = strings.Cut(path, "?")
		if !checkAuthority(authority, scheme == "https") {
			if scheme == "http" {
				return invalid("http is only allowed with a loopback host")
			}
			return invalid("invalid https host")
		}
		if path == "" {
			return invalid("must have a path")
		}
		if !checkSegments(path, false) {
			return invalid("invalid path segment")
		}
		if scheme == "http" {
			return RefLoopback, nil
		}
		return RefWeb, nil
	case "file":
		if strings.Contains(rest, "?") {
			return invalid("must not have a query")
		}
		path := rest
		if after, ok := strings.CutPrefix(rest, "//"); ok {
			slash := strings.Index(after, "/")
			if slash == -1 {
				return invalid("file URL needs an absolute path")
			}
			if host := strings.ToLower(after[:slash]); host != "" && host != "localhost" {
				return invalid("file URL host must be empty or localhost")
			}
			path = after[slash:]
		} else if !strings.HasPrefix(rest, "/") {
			return invalid("file URL needs an absolute path")
		}
		if !checkSegments(path, false) {
			return invalid("invalid path segment")
		}
		return RefFile, nil
	}
	if rest == "" {
		return invalid("empty URL")
	}
	return RefOther, nil
}

// ---------------------------------------------------------------- the src DID URL parameter

// SrcReferences validates a (percent-decoded) src DID URL parameter and
// derives the srcLog and srcWitness references from it (profile §3.2). It
// fails with invalidDidUrl.
func SrcReferences(src string) (srcLog, srcWitness string, err error) {
	invalid := func(why string) (string, string, error) {
		return "", "", didVhError(DidVhInvalidDidURL, "src %q: %s", src, why)
	}
	scheme, rest, ok := splitScheme(src)
	if !ok {
		return invalid("not a printable-ASCII absolute URL")
	}
	if strings.ContainsAny(rest, "?#") {
		return invalid("must not have a query or fragment")
	}
	if scheme == "http" || scheme == "file" {
		return invalid(scheme + " is not allowed in a DID URL")
	}
	if !strings.HasPrefix(rest, "//") || len(rest) == 2 || rest[2] == '/' {
		return invalid("not a hierarchical URL with an authority")
	}
	base := strings.TrimSuffix(rest, "/")
	if scheme == "https" {
		after := base[2:]
		authority, path := after, ""
		if slash := strings.Index(after, "/"); slash != -1 {
			authority, path = after[:slash], after[slash:]
		}
		if !checkAuthority(authority, true) {
			return invalid("invalid https host")
		}
		if path != "" && !checkSegments(path, true) {
			return invalid("invalid path segment")
		}
	}
	location := scheme + ":" + base
	return location + "/did.jsonl", location + "/did-witness.json", nil
}

// ---------------------------------------------------------------- DID URLs

// DidURL is a dereferenced did:vh DID URL.
type DidURL struct {
	Did string
	// Options are the resolution options from the query, in order: srcLog and
	// srcWitness (from src), versionId, versionTime, versionNumber (a number).
	Options *Object
	// Fragment is set when HasFragment is.
	Fragment    string
	HasFragment bool
}

var (
	urlParameters = []string{"src", "versionId", "versionTime", "versionNumber"}
	optionOnly    = []string{"didLog", "didWitness", "srcLog", "srcWitness", "checkWatchers", "extraWatchers", "minCopies", "includeDidLog"}
)

// ParseDidURL parses a did:vh DID URL as a dereferencer does (profile §4). It
// fails with invalidDidUrl.
func ParseDidURL(didURL string) (*DidURL, error) {
	invalid := func(format string, args ...any) (*DidURL, error) {
		return nil, didVhError(DidVhInvalidDidURL, "%q: %s", didURL, fmt.Sprintf(format, args...))
	}
	u := &DidURL{Options: NewObject()}
	beforeFragment := didURL
	if hash := strings.Index(didURL, "#"); hash != -1 {
		beforeFragment, u.Fragment, u.HasFragment = didURL[:hash], didURL[hash+1:], true
	}
	did, query, hasQuery := strings.Cut(beforeFragment, "?")
	if _, ok := ParseDidVh(did); !ok {
		return invalid("not a did:vh DID")
	}
	u.Did = did
	if !hasQuery {
		return u, nil
	}
	seen := map[string]bool{}
	for _, pair := range strings.Split(query, "&") {
		rawKey, rawValue, ok := strings.Cut(pair, "=")
		if !ok {
			return invalid("query parameter %q has no value", pair)
		}
		key, ok1 := PercentDecode(rawKey)
		value, ok2 := PercentDecode(rawValue)
		if !ok1 || !ok2 {
			return invalid("malformed percent-encoding")
		}
		if slices.Contains(optionOnly, key) {
			return invalid("%s is a resolution option, not a DID URL parameter", key)
		}
		if !slices.Contains(urlParameters, key) {
			continue
		}
		if seen[key] {
			return invalid("%s given more than once", key)
		}
		seen[key] = true
		switch key {
		case "src":
			srcLog, srcWitness, err := SrcReferences(value)
			if err != nil {
				return nil, err
			}
			u.Options.Set("srcLog", srcLog)
			u.Options.Set("srcWitness", srcWitness)
		case "versionNumber":
			if len(value) > 16 || !isDecimal(value) || value == "0" {
				return invalid("versionNumber must be a positive integer")
			}
			n, _ := strconv.ParseFloat(value, 64)
			u.Options.Set(key, n)
		default:
			u.Options.Set(key, value)
		}
	}
	return u, nil
}

// ---------------------------------------------------------------- resolve

// ResolverContext is the context of a did:vh resolver (profile §5).
type ResolverContext struct {
	// Now is the resolver's clock; the zero time means the current time.
	Now time.Time
	// Remote is true for a resolver that accepts requests from other systems.
	Remote bool
}

// DidDocumentMetadata is the did:vh DID document metadata.
type DidDocumentMetadata struct {
	VersionID   string         `json:"versionId"`
	VersionTime string         `json:"versionTime"`
	Created     string         `json:"created"`
	Updated     string         `json:"updated"`
	SCID        string         `json:"scid"`
	Deactivated bool           `json:"deactivated"`
	TTL         int64          `json:"ttl"`
	Witness     *WitnessConfig `json:"witness,omitempty"`
	Watchers    []string       `json:"watchers"`
}

// DidResolution is the result of ResolveDid. On error, Error is set and
// DidDocument and DidDocumentMetadata are nil.
type DidResolution struct {
	Error *DidVhError
	// Warnings are the VH-Log warnings (such as invalid-entries).
	Warnings []Warning
	// DidLog and DidWitness are set when includeDidLog is true; DidWitness
	// only when the log needs witnessing.
	DidLog              *string
	DidWitness          any
	DidDocument         any
	DidDocumentMetadata *DidDocumentMetadata
}

// JSON returns the result as {didResolutionMetadata, didDocument,
// didDocumentMetadata}.
func (r *DidResolution) JSON() *Object {
	if r.Error != nil {
		details := ObjectOf("title", string(r.Error.Code), "detail", r.Error.Message)
		if r.Error.VHLog != nil {
			report, _ := ParseJSON(Stringify(r.Error.VHLog))
			details.Set("vhLog", report)
		}
		meta := ObjectOf("error", string(r.Error.Code), "problemDetails", details)
		return ObjectOf("didResolutionMetadata", meta, "didDocument", nil, "didDocumentMetadata", NewObject())
	}
	meta := ObjectOf("contentType", "application/did+json")
	if len(r.Warnings) > 0 {
		meta.Set("warnings", toJSONValue(r.Warnings))
	}
	if r.DidLog != nil {
		meta.Set("didLog", *r.DidLog)
		if r.DidWitness != nil {
			meta.Set("didWitness", r.DidWitness)
		}
	}
	return ObjectOf("didResolutionMetadata", meta, "didDocument", r.DidDocument, "didDocumentMetadata", toJSONValue(r.DidDocumentMetadata))
}

// toJSONValue converts a Go value with json tags to this package's JSON model.
func toJSONValue(v any) any {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	out, err := ParseJSON(string(data))
	if err != nil {
		panic(err)
	}
	return out
}

func isPositiveInteger(v any) bool {
	f, ok := v.(float64)
	return ok && isInteger(f) && f >= 1
}

func intOption(v any) *int {
	f, ok := v.(float64)
	if !ok {
		return nil
	}
	n := int(min(f, float64(1<<53)))
	return &n
}

// validateDidOptions validates did:vh resolution options (profile §5, step 2).
func validateDidOptions(options any, remote bool) (*Object, error) {
	invalid := func(format string, args ...any) (*Object, error) {
		return nil, didVhError(DidVhInvalidOptions, format, args...)
	}
	o, ok := options.(*Object)
	if !ok {
		return invalid("resolution options must be an object")
	}
	if o.Has("didLog") == o.Has("srcLog") {
		return invalid("exactly one of didLog and srcLog must be given")
	}
	if o.Has("didWitness") && o.Has("srcWitness") {
		return invalid("at most one of didWitness and srcWitness may be given")
	}
	if v, ok := o.Get("didLog"); ok && !isString(v) {
		return invalid("didLog must be a string")
	}
	if v, ok := o.Get("didWitness"); ok {
		if _, isArray := v.([]any); !isArray {
			return invalid("didWitness must be an array")
		}
	}
	for _, key := range []string{"srcLog", "srcWitness"} {
		v, ok := o.Get(key)
		if !ok {
			continue
		}
		s, _ := v.(string)
		if !isString(v) {
			s = "\x00" // not printable ASCII, so CheckRef rejects it
		}
		kind, err := CheckRef(s)
		if err != nil {
			return nil, err
		}
		if remote && (kind == RefFile || kind == RefLoopback) {
			return invalid("%s: a resolver that serves other systems must not use local file or loopback references", key)
		}
	}
	selectors := 0
	for _, k := range []string{"versionId", "versionTime", "versionNumber"} {
		if o.Has(k) {
			selectors++
		}
	}
	if selectors > 1 {
		return invalid("at most one of versionId, versionTime and versionNumber may be given")
	}
	if v, ok := o.Get("versionId"); ok && !isString(v) {
		return invalid("versionId must be a string")
	}
	if v, ok := o.Get("versionTime"); ok {
		s, _ := v.(string)
		if _, valid := ParseVersionTime(s); !valid || !isString(v) {
			return invalid("versionTime must be a whole-second UTC ISO 8601 time")
		}
	}
	if v, ok := o.Get("versionNumber"); ok && !isPositiveInteger(v) {
		return invalid("versionNumber must be a positive integer")
	}
	if v, ok := o.Get("checkWatchers"); ok {
		f, isNumber := v.(float64)
		if v != "all" && !(isNumber && isInteger(f) && f >= 0) {
			return invalid(`checkWatchers must be a non-negative integer or "all"`)
		}
	}
	if v, ok := o.Get("extraWatchers"); ok {
		list, isArray := v.([]any)
		valid := isArray
		for _, u := range list {
			s, isStr := u.(string)
			valid = valid && isStr && strings.HasPrefix(s, "https://") && IsWatcherURL(s)
		}
		if !valid {
			return invalid("extraWatchers must be an array of https URLs")
		}
	}
	if v, ok := o.Get("minCopies"); ok && !isPositiveInteger(v) {
		return invalid("minCopies must be a positive integer")
	}
	if v, ok := o.Get("includeDidLog"); ok {
		if _, isBool := v.(bool); !isBool {
			return invalid("includeDidLog must be a boolean")
		}
	}
	return o, nil
}

var didVhErrorMap = map[ErrorCode]DidVhErrorCode{
	ErrNotFound:              DidVhNotFound,
	ErrInvalidOption:         DidVhInvalidOptions,
	ErrForkDetected:          DidVhLogForked,
	ErrMinCopiesNotMet:       DidVhInsufficientCopies,
	ErrUnsupportedLogVersion: DidVhFeatureNotSupported,
}

func fromVHLog(e *VHLogError) *DidVhError {
	code, ok := didVhErrorMap[e.Code]
	if !ok {
		code = DidVhInvalidDid
	}
	return &DidVhError{Code: code, Message: e.Message, VHLog: e}
}

// ResolveDid is did:vh resolve(did, resolutionOptions) (profile §5). options
// is a JSON value in this package's model (see ParseJSON). The resolver is
// offline: it verifies a log passed in didLog (and didWitness), and returns
// featureNotSupported when it would have to retrieve anything.
func ResolveDid(did string, options any, ctx ResolverContext) *DidResolution {
	r, err := resolveDid(did, options, ctx)
	if err != nil {
		return &DidResolution{Error: err}
	}
	return r
}

func resolveDid(did string, options any, ctx ResolverContext) (*DidResolution, *DidVhError) {
	scid, ok := ParseDidVh(did)
	if !ok {
		return nil, didVhError(DidVhInvalidDid, "%q is not a did:vh DID", did)
	}
	o, err := validateDidOptions(options, ctx.Remote)
	if err != nil {
		return nil, err.(*DidVhError)
	}
	if o.Has("srcLog") {
		return nil, didVhError(DidVhFeatureNotSupported, "this resolver does not retrieve srcLog references")
	}
	checkWatchers, hasCheck := o.Get("checkWatchers")
	extraWatchers, _ := o.Get("extraWatchers")
	if extra, _ := extraWatchers.([]any); (hasCheck && checkWatchers != 0.0) || len(extra) > 0 {
		return nil, didVhError(DidVhFeatureNotSupported, "this resolver does not retrieve copies from watchers")
	}
	spec := DidVhSpecialisation(scid)
	now := ctx.Now
	if now.IsZero() {
		now = time.Now().UTC().Truncate(time.Second)
	}
	logValue, _ := o.Get("didLog")
	logText := logValue.(string)
	witnessValue, hasWitness := o.Get("didWitness")
	var witnessFile []byte
	if hasWitness {
		witnessFile = []byte(Stringify(witnessValue))
	}
	// Whether the log needs witnessing does not depend on the witness file.
	// Without one, the first entry that needs it fails, which cuts it from
	// Entries.
	unwitnessed := VerifyLogWith(logText, nil, now, spec)
	witnessed := unwitnessed.Failure != nil && unwitnessed.Failure.Code == ErrWitnessThresholdNotMet
	for _, e := range unwitnessed.Entries {
		witnessed = witnessed || e.WitnessRule != nil
	}
	if witnessed && o.Has("srcWitness") {
		return nil, didVhError(DidVhFeatureNotSupported, "this resolver does not retrieve srcWitness references")
	}
	in := ResolveInput{Log: logText, Witness: witnessFile, Now: now, Specialisation: spec}
	if v, ok := o.Get("versionId"); ok {
		s := v.(string)
		in.Options.VersionID = &s
	}
	if v, ok := o.Get("versionTime"); ok {
		s := v.(string)
		in.Options.VersionTime = &s
	}
	if v, ok := o.Get("versionNumber"); ok {
		in.Options.VersionNumber = intOption(v)
	}
	if v, ok := o.Get("minCopies"); ok {
		in.Options.MinCopies = intOption(v)
	}
	res, rerr := Resolve(in)
	if rerr != nil {
		return nil, fromVHLog(rerr.(*VHLogError))
	}
	selected := o.Has("versionId") || o.Has("versionTime") || o.Has("versionNumber")
	if !selected && res.Error != nil && res.Error.Code == ErrUnsupportedLogVersion {
		// Entries after the last valid one may change the document or its keys (profile §5).
		return nil, fromVHLog(res.Error)
	}
	m := res.Metadata
	out := &DidResolution{
		Warnings:    m.Warnings,
		DidDocument: res.State,
		DidDocumentMetadata: &DidDocumentMetadata{
			VersionID: m.VersionID, VersionTime: m.VersionTime, Created: m.Created, Updated: m.Updated,
			SCID: m.SCID, Deactivated: m.Deactivated, TTL: m.TTL, Witness: m.Witness, Watchers: m.Watchers,
		},
	}
	// A deactivated DID's document is returned only for an explicit version selector (profile §5).
	if m.Deactivated && !selected {
		out.DidDocument = nil
	}
	if include, _ := o.Get("includeDidLog"); include == true {
		lines := SplitLogLines(logText)
		valid := len(lines)
		if res.FirstInvalidVersion != nil {
			valid = *res.FirstInvalidVersion - 1
		}
		var b strings.Builder
		for _, line := range lines[:valid] {
			b.WriteString(line)
			b.WriteByte('\n')
		}
		didLog := b.String()
		out.DidLog = &didLog
		if witnessed {
			out.DidWitness = []any{}
			if hasWitness {
				out.DidWitness = witnessValue
			}
		}
	}
	return out, nil
}
