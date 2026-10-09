package vhlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// JSON values
//
// VH-Log hashes and signatures depend on RFC 8785 canonicalisation, which
// treats every number as an IEEE-754 double and orders object keys by UTF-16
// code units. encoding/json's generic decoding loses the information needed to
// do that faithfully (it replaces lone surrogates with U+FFFD and its maps are
// unordered), so this package has its own small JSON model:
//
//	null    -> nil
//	boolean -> bool
//	number  -> float64
//	string  -> string
//	array   -> []any
//	object  -> *Object
//
// Strings are stored as WTF-8: valid UTF-8, except that a lone UTF-16
// surrogate (which JSON can express as "\ud800") is kept as its 3-byte
// generalised UTF-8 form so that it survives a round trip, exactly as a
// JavaScript string would.

// Object is a JSON object that remembers the order in which its keys were
// first set. Setting an existing key replaces its value in place, so parsing a
// document with a duplicate key keeps the last value, as JSON.parse does.
type Object struct {
	keys   []string
	values map[string]any
}

// NewObject returns an empty Object.
func NewObject() *Object {
	return &Object{values: map[string]any{}}
}

// ObjectOf builds an Object from alternating key/value arguments, e.g.
// ObjectOf("id", "example", "n", 1.0). It panics if a key is not a string.
func ObjectOf(pairs ...any) *Object {
	if len(pairs)%2 != 0 {
		panic("vhlog.ObjectOf: odd number of arguments")
	}
	o := NewObject()
	for i := 0; i < len(pairs); i += 2 {
		o.Set(pairs[i].(string), pairs[i+1])
	}
	return o
}

// Len returns the number of members.
func (o *Object) Len() int { return len(o.keys) }

// Keys returns the member names in insertion order.
func (o *Object) Keys() []string { return slices.Clone(o.keys) }

// Has reports whether the object has a member named key.
func (o *Object) Has(key string) bool {
	_, ok := o.values[key]
	return ok
}

// Get returns the value of member key and whether it exists.
func (o *Object) Get(key string) (any, bool) {
	v, ok := o.values[key]
	return v, ok
}

// Set adds or replaces member key. A replaced member keeps its position.
func (o *Object) Set(key string, value any) {
	if o.values == nil {
		o.values = map[string]any{}
	}
	if _, ok := o.values[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = value
}

// Delete removes member key if present.
func (o *Object) Delete(key string) {
	if _, ok := o.values[key]; !ok {
		return
	}
	delete(o.values, key)
	o.keys = slices.DeleteFunc(o.keys, func(k string) bool { return k == key })
}

// Clone returns a shallow copy of the object.
func (o *Object) Clone() *Object {
	c := &Object{keys: slices.Clone(o.keys), values: make(map[string]any, len(o.values))}
	for k, v := range o.values {
		c.values[k] = v
	}
	return c
}

// without returns a shallow copy of o lacking key.
func (o *Object) without(key string) *Object {
	c := o.Clone()
	c.Delete(key)
	return c
}

// MarshalJSON implements json.Marshaler using Stringify.
func (o *Object) MarshalJSON() ([]byte, error) {
	return []byte(Stringify(o)), nil
}

// UnmarshalJSON implements json.Unmarshaler using ParseJSON.
func (o *Object) UnmarshalJSON(data []byte) error {
	v, err := ParseJSON(string(data))
	if err != nil {
		return err
	}
	obj, ok := v.(*Object)
	if !ok {
		return errors.New("vhlog: JSON value is not an object")
	}
	*o = *obj
	return nil
}

// ---------------------------------------------------------------- parsing

// ParseJSON parses JSON text (RFC 8259) the way ECMAScript's JSON.parse does:
// numbers become float64 (correctly rounded; out-of-range values become ±Inf),
// duplicate keys keep the last value, and lone surrogate escapes are kept.
func ParseJSON(text string) (any, error) {
	p := parser{s: text}
	p.skipSpace()
	v, err := p.value()
	if err != nil {
		return nil, err
	}
	p.skipSpace()
	if p.i != len(p.s) {
		return nil, p.errorf("unexpected data after JSON value")
	}
	return v, nil
}

type parser struct {
	s string
	i int
}

func (p *parser) errorf(format string, args ...any) error {
	return fmt.Errorf("invalid JSON at offset %d: %s", p.i, fmt.Sprintf(format, args...))
}

func (p *parser) skipSpace() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) literal(word string, v any) (any, error) {
	if !strings.HasPrefix(p.s[p.i:], word) {
		return nil, p.errorf("unexpected character")
	}
	p.i += len(word)
	return v, nil
}

func (p *parser) value() (any, error) {
	if p.i >= len(p.s) {
		return nil, p.errorf("unexpected end of input")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object()
	case c == '[':
		return p.array()
	case c == '"':
		return p.str()
	case c == 't':
		return p.literal("true", true)
	case c == 'f':
		return p.literal("false", false)
	case c == 'n':
		return p.literal("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	default:
		return nil, p.errorf("unexpected character %q", c)
	}
}

func (p *parser) object() (any, error) {
	p.i++ // {
	obj := NewObject()
	p.skipSpace()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return obj, nil
	}
	for {
		p.skipSpace()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return nil, p.errorf("expected object key")
		}
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		p.skipSpace()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return nil, p.errorf("expected ':'")
		}
		p.i++
		p.skipSpace()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		obj.Set(key, v)
		p.skipSpace()
		if p.i >= len(p.s) {
			return nil, p.errorf("unterminated object")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case '}':
			p.i++
			return obj, nil
		default:
			return nil, p.errorf("expected ',' or '}'")
		}
	}
}

func (p *parser) array() (any, error) {
	p.i++ // [
	arr := []any{}
	p.skipSpace()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return arr, nil
	}
	for {
		p.skipSpace()
		v, err := p.value()
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		p.skipSpace()
		if p.i >= len(p.s) {
			return nil, p.errorf("unterminated array")
		}
		switch p.s[p.i] {
		case ',':
			p.i++
		case ']':
			p.i++
			return arr, nil
		default:
			return nil, p.errorf("expected ',' or ']'")
		}
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func (p *parser) number() (any, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	switch {
	case p.i < len(p.s) && p.s[p.i] == '0':
		p.i++
	case p.i < len(p.s) && p.s[p.i] >= '1' && p.s[p.i] <= '9':
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	default:
		return nil, p.errorf("invalid number")
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		if p.i >= len(p.s) || !isDigit(p.s[p.i]) {
			return nil, p.errorf("invalid number")
		}
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if p.i >= len(p.s) || !isDigit(p.s[p.i]) {
			return nil, p.errorf("invalid number")
		}
		for p.i < len(p.s) && isDigit(p.s[p.i]) {
			p.i++
		}
	}
	f, err := strconv.ParseFloat(p.s[start:p.i], 64)
	if err != nil && !errors.Is(err, strconv.ErrRange) {
		return nil, p.errorf("invalid number")
	}
	// Out-of-range values are ±Inf, as in JSON.parse; I-JSON checks reject them later.
	return f, nil
}

func hexValue(c byte) (uint16, bool) {
	switch {
	case c >= '0' && c <= '9':
		return uint16(c - '0'), true
	case c >= 'a' && c <= 'f':
		return uint16(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return uint16(c-'A') + 10, true
	}
	return 0, false
}

func (p *parser) str() (string, error) {
	p.i++ // opening quote
	var buf []byte
	for {
		if p.i >= len(p.s) {
			return "", p.errorf("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return string(buf), nil
		case c < 0x20:
			return "", p.errorf("control character in string")
		case c == '\\':
			if p.i+1 >= len(p.s) {
				return "", p.errorf("unterminated escape")
			}
			e := p.s[p.i+1]
			p.i += 2
			switch e {
			case '"', '\\', '/':
				buf = append(buf, e)
			case 'b':
				buf = append(buf, '\b')
			case 'f':
				buf = append(buf, '\f')
			case 'n':
				buf = append(buf, '\n')
			case 'r':
				buf = append(buf, '\r')
			case 't':
				buf = append(buf, '\t')
			case 'u':
				if p.i+4 > len(p.s) {
					return "", p.errorf("short unicode escape")
				}
				var u uint16
				for k := 0; k < 4; k++ {
					h, ok := hexValue(p.s[p.i+k])
					if !ok {
						return "", p.errorf("invalid unicode escape")
					}
					u = u<<4 | h
				}
				p.i += 4
				buf = appendUnit(buf, u)
			default:
				return "", p.errorf("invalid escape")
			}
		case c == 0xED && p.i+2 < len(p.s) && p.s[p.i+1] >= 0xA0 && p.s[p.i+1] <= 0xBF:
			// A raw generalised-UTF-8 surrogate (only possible when this text came
			// from a string that already held a lone surrogate).
			u := 0xD000 | uint16(p.s[p.i+1]&0x3F)<<6 | uint16(p.s[p.i+2]&0x3F)
			p.i += 3
			buf = appendUnit(buf, u)
		default:
			buf = append(buf, c)
			p.i++
		}
	}
}

// appendUnit appends one UTF-16 code unit, joining a low surrogate with a
// preceding lone high surrogate into a proper 4-byte UTF-8 sequence.
func appendUnit(buf []byte, u uint16) []byte {
	if u >= 0xDC00 && u <= 0xDFFF {
		if n := len(buf); n >= 3 && buf[n-3] == 0xED && buf[n-2] >= 0xA0 && buf[n-2] <= 0xAF {
			high := 0xD000 | rune(buf[n-2]&0x3F)<<6 | rune(buf[n-1]&0x3F)
			r := 0x10000 + (high-0xD800)<<10 + (rune(u) - 0xDC00)
			return utf8.AppendRune(buf[:n-3], r)
		}
	}
	if u >= 0xD800 && u <= 0xDFFF {
		return append(buf, 0xED, byte(0x80|(u>>6)&0x3F), byte(0x80|u&0x3F))
	}
	return utf8.AppendRune(buf, rune(u))
}

// decodeWTF8 decodes one code point at s[i:], returning lone surrogates as
// themselves and invalid bytes as U+FFFD with size 1.
func decodeWTF8(s string, i int) (rune, int) {
	if s[i] == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2] >= 0x80 && s[i+2] <= 0xBF {
		return 0xD000 | rune(s[i+1]&0x3F)<<6 | rune(s[i+2]&0x3F), 3
	}
	return utf8.DecodeRuneInString(s[i:])
}

// isWellFormed reports whether s holds no lone surrogate (String.prototype.isWellFormed).
func isWellFormed(s string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == 0xED && s[i+1] >= 0xA0 && s[i+1] <= 0xBF {
			return false
		}
	}
	return true
}

// toUTF8 returns the UTF-8 bytes of s, with lone surrogates replaced by
// U+FFFD (as TextEncoder and node:crypto do).
func toUTF8(s string) []byte {
	if isWellFormed(s) && utf8.ValidString(s) {
		return []byte(s)
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		r, n := decodeWTF8(s, i)
		if r >= 0xD800 && r <= 0xDFFF {
			r = utf8.RuneError
		}
		out = utf8.AppendRune(out, r)
		i += n
	}
	return out
}

// utf16Units returns the UTF-16 code units of s.
func utf16Units(s string) []uint16 {
	units := make([]uint16, 0, len(s))
	for i := 0; i < len(s); {
		r, n := decodeWTF8(s, i)
		i += n
		if r >= 0x10000 {
			r -= 0x10000
			units = append(units, uint16(0xD800+(r>>10)), uint16(0xDC00+(r&0x3FF)))
		} else {
			units = append(units, uint16(r))
		}
	}
	return units
}

// ---------------------------------------------------------------- serialising

// Stringify serialises a JSON value compactly, exactly as ECMAScript's
// JSON.stringify does: object members in insertion order, numbers in
// Number::toString form, non-finite numbers as null, and lone surrogates
// escaped. Besides the types ParseJSON produces it accepts int, int64,
// []string, map[string]any (keys in JCS order) and json.Marshaler values.
func Stringify(v any) string {
	var b strings.Builder
	writeValue(&b, v, false)
	return b.String()
}

// writeValue writes v; with canonical set, object keys are sorted (JCS) and a
// non-finite number is an error (reported by panicking with errNonFinite).
func writeValue(b *strings.Builder, v any, canonical bool) {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case float64:
		if math.IsNaN(x) || math.IsInf(x, 0) {
			if canonical {
				panic(errNonFinite)
			}
			b.WriteString("null")
			return
		}
		b.WriteString(FormatNumber(x))
	case int:
		writeValue(b, float64(x), canonical)
	case int64:
		writeValue(b, float64(x), canonical)
	case string:
		writeString(b, x)
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeValue(b, e, canonical)
		}
		b.WriteByte(']')
	case []string:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteByte(',')
			}
			writeString(b, e)
		}
		b.WriteByte(']')
	case *Object:
		keys := x.keys
		if canonical {
			keys = sortKeysUTF16(keys)
		}
		writeMembers(b, keys, func(k string) any { return x.values[k] }, canonical)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		writeMembers(b, sortKeysUTF16(keys), func(k string) any { return x[k] }, canonical)
	case json.Marshaler:
		raw, err := x.MarshalJSON()
		if err != nil {
			panic(fmt.Errorf("vhlog: %T.MarshalJSON: %w", x, err))
		}
		parsed, err := ParseJSON(string(raw))
		if err != nil {
			panic(fmt.Errorf("vhlog: %T.MarshalJSON returned invalid JSON: %w", x, err))
		}
		writeValue(b, parsed, canonical)
	default:
		panic(fmt.Errorf("vhlog: cannot serialise %T as JSON", v))
	}
}

func writeMembers(b *strings.Builder, keys []string, get func(string) any, canonical bool) {
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		writeString(b, k)
		b.WriteByte(':')
		writeValue(b, get(k), canonical)
	}
	b.WriteByte('}')
}

const hexDigits = "0123456789abcdef"

func writeString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			switch c {
			case '"':
				b.WriteString(`\"`)
			case '\\':
				b.WriteString(`\\`)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				if c < 0x20 {
					b.WriteString(`\u00`)
					b.WriteByte(hexDigits[c>>4])
					b.WriteByte(hexDigits[c&0xF])
				} else {
					b.WriteByte(c)
				}
			}
			i++
			continue
		}
		r, n := decodeWTF8(s, i)
		if r >= 0xD800 && r <= 0xDFFF {
			b.WriteString(`\u`)
			for shift := 12; shift >= 0; shift -= 4 {
				b.WriteByte(hexDigits[(r>>shift)&0xF])
			}
		} else {
			b.WriteRune(r) // invalid bytes become U+FFFD
		}
		i += n
	}
	b.WriteByte('"')
}

// FormatNumber formats a finite float64 as ECMAScript's Number::toString does,
// which is the number serialisation RFC 8785 requires: shortest round-trip
// digits, plain notation for exponents in [-7, 21), "e+N"/"e-N" otherwise, and
// "0" for negative zero.
func FormatNumber(f float64) string {
	if f == 0 {
		return "0"
	}
	if math.IsNaN(f) {
		return "NaN"
	}
	if math.IsInf(f, 0) {
		if f > 0 {
			return "Infinity"
		}
		return "-Infinity"
	}
	sign := ""
	if f < 0 {
		sign = "-"
		f = -f
	}
	// "d.ddddde±XX": the shortest digits that round-trip.
	e := strconv.FormatFloat(f, 'e', -1, 64)
	mantissa, expText, _ := strings.Cut(e, "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	exp, _ := strconv.Atoi(expText)
	k, n := len(digits), exp+1
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		expSign := "+"
		if n-1 < 0 {
			expSign = "-"
		}
		abs := n - 1
		if abs < 0 {
			abs = -abs
		}
		if k == 1 {
			out = digits + "e" + expSign + strconv.Itoa(abs)
		} else {
			out = digits[:1] + "." + digits[1:] + "e" + expSign + strconv.Itoa(abs)
		}
	}
	return sign + out
}

// sortKeysUTF16 returns keys sorted by UTF-16 code units (RFC 8785 §3.2.3).
func sortKeysUTF16(keys []string) []string {
	type keyed struct {
		key   string
		units []uint16
	}
	items := make([]keyed, len(keys))
	for i, k := range keys {
		items[i] = keyed{k, utf16Units(k)}
	}
	slices.SortFunc(items, func(a, b keyed) int { return slices.Compare(a.units, b.units) })
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.key
	}
	return out
}

var errNonFinite = errors.New("JCS: non-finite number")

// Canonicalize returns the RFC 8785 (JCS) serialisation of a JSON value. It
// fails if the value contains a non-finite number or an unsupported type.
func Canonicalize(v any) (s string, err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(error); ok {
				err = e
				return
			}
			panic(r)
		}
	}()
	var b strings.Builder
	writeValue(&b, v, true)
	return b.String(), nil
}

// CanonicalizeText parses JSON text and returns its JCS serialisation.
func CanonicalizeText(text string) (string, error) {
	v, err := ParseJSON(text)
	if err != nil {
		return "", err
	}
	return Canonicalize(v)
}

// isSafeJSON reports whether v is I-JSON-safe (profile §4): every number is
// finite and every string and key is well-formed Unicode.
func isSafeJSON(v any) bool {
	switch x := v.(type) {
	case float64:
		return !math.IsInf(x, 0) && !math.IsNaN(x)
	case string:
		return isWellFormed(x)
	case []any:
		for _, e := range x {
			if !isSafeJSON(e) {
				return false
			}
		}
	case *Object:
		for _, k := range x.keys {
			if !isWellFormed(k) || !isSafeJSON(x.values[k]) {
				return false
			}
		}
	}
	return true
}
