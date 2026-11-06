// JCS — RFC 8785 JSON Canonicalization Scheme.
//
// Hand-rolled on purpose: encoding/json round-trips numbers through
// float64/float32 by default (destroying exactness) and sorts map keys
// lexicographically by UTF-8 bytes, while JCS needs:
//
//  1. member ordering by UTF-16 code units (§3.2.3);
//  2. number serialization per ES6 ToString(number) with a "shortest
//     round-trip" mantissa (§3.2.2.2);
//  3. escaping of only what RFC 8785 requires (§3.2.2.2);
//  4. duplicate-key and lone-surrogate rejection (§3.2.1, I-JSON).
//
// The token walk uses encoding/json's Decoder + UseNumber so numbers keep
// their exact literal text; each value is re-serialized with the ES6 rules,
// so the output is byte-for-byte the RFC's canonical form.
package auditspec

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// CanonicalJSON returns the RFC 8785 canonical serialization of v, or an
// error if v is not canonicalizable JSON (invalid UTF-8, lone surrogates,
// duplicate keys, NaN/Infinity, trailing data after the value).
func CanonicalJSON(v []byte) ([]byte, error) {
	if !utf8.Valid(v) {
		return nil, errors.New("jcs: input is not valid UTF-8")
	}
	// Lone-surrogate check must run on the raw bytes: a valid UTF-8 stream
	// can still carry unpaired UTF-16 code units in \u escapes, which RFC
	// 8785 §3.2.2.2 forbids (and which would corrupt the UTF-16 key
	// ordering if let through).
	if err := rejectLoneSurrogates(v); err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(v)))
	dec.UseNumber()
	var out strings.Builder
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("jcs: %w", err)
	}
	if err := canonicalValue(&out, dec, tok); err != nil {
		return nil, err
	}
	// Refuse trailing garbage (a second JSON value, a stray token, ...).
	if dec.More() {
		return nil, errors.New("jcs: trailing data after JSON value")
	}
	return []byte(out.String()), nil
}

func canonicalValue(out *strings.Builder, dec *json.Decoder, tok json.Token) error {
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return canonicalObject(out, dec)
		case '[':
			return canonicalArray(out, dec)
		default:
			return fmt.Errorf("jcs: unexpected delimiter %q", t)
		}
	case string:
		writeEscapedString(out, t)
		return nil
	case json.Number:
		s, err := formatNumber(string(t))
		if err != nil {
			return err
		}
		out.WriteString(s)
		return nil
	case bool:
		if t {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
		return nil
	case nil:
		out.WriteString("null")
		return nil
	default:
		return fmt.Errorf("jcs: unsupported token %T", tok)
	}
}

func canonicalArray(out *strings.Builder, dec *json.Decoder) error {
	out.WriteByte('[')
	first := true
	for dec.More() {
		if !first {
			out.WriteByte(',')
		}
		first = false
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("jcs: array: %w", err)
		}
		if err := canonicalValue(out, dec, tok); err != nil {
			return err
		}
	}
	// Consume the closing ']'.
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("jcs: array close: %w", err)
	}
	out.WriteByte(']')
	return nil
}

// member is one object member with its already-canonicalized value, ready
// for the UTF-16 code-unit sort of §3.2.3.
type member struct {
	key   string
	runes []uint16
	val   string
}

func canonicalObject(out *strings.Builder, dec *json.Decoder) error {
	out.WriteByte('{')
	var members []member
	seen := make(map[string]bool)
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("jcs: object: %w", err)
		}
		key, ok := keyTok.(string)
		if !ok {
			return fmt.Errorf("jcs: object key is %T, want string", keyTok)
		}
		if seen[key] {
			return fmt.Errorf("jcs: duplicate key %q", key)
		}
		seen[key] = true
		valTok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("jcs: object value for %q: %w", key, err)
		}
		var val strings.Builder
		if err := canonicalValue(&val, dec, valTok); err != nil {
			return err
		}
		members = append(members, member{key: key, runes: utf16.Encode([]rune(key)), val: val.String()})
	}
	// Consume the closing '}'.
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("jcs: object close: %w", err)
	}
	sort.SliceStable(members, func(i, j int) bool {
		return lessUTF16(members[i].runes, members[j].runes)
	})
	for i, m := range members {
		if i > 0 {
			out.WriteByte(',')
		}
		writeEscapedString(out, m.key)
		out.WriteByte(':')
		out.WriteString(m.val)
	}
	out.WriteByte('}')
	return nil
}

// lessUTF16 compares two UTF-16 code-unit sequences by unsigned value, the
// RFC 8785 §3.2.3 member ordering. This differs from UTF-8 byte ordering for
// supplementary-plane code points (the §3.2.3 test pins exactly that).
func lessUTF16(a, b []uint16) bool {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// writeEscapedString writes s as a JSON string escaping only what RFC 8785
// §3.2.2.2 requires: quote, backslash, the five short escapes, and the other
// control characters as \uXXXX with lowercase hex. Everything else (non-ASCII
// included) is written raw — shortest UTF-8 form is the canonical one.
func writeEscapedString(out *strings.Builder, s string) {
	out.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			out.WriteString(`\"`)
		case '\\':
			out.WriteString(`\\`)
		case '\b':
			out.WriteString(`\b`)
		case '\f':
			out.WriteString(`\f`)
		case '\n':
			out.WriteString(`\n`)
		case '\r':
			out.WriteString(`\r`)
		case '\t':
			out.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(out, `\u%04x`, r)
			} else {
				out.WriteRune(r)
			}
		}
	}
	out.WriteByte('"')
}

// formatNumber serializes a JSON number literal per ES6 ToString(number):
// the shortest decimal that round-trips through IEEE 754 double, with
// decimal notation when -6 < n <= 21 and exponential otherwise (§3.2.2.2).
// NaN and Infinity (already impossible in the JSON grammar) and values that
// overflow a double are rejected.
func formatNumber(s string) (string, error) {
	f, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return "", fmt.Errorf("jcs: number %q is not representable as an IEEE 754 double: %w", s, err)
	}
	if math.IsInf(f, 0) || math.IsNaN(f) {
		return "", fmt.Errorf("jcs: number %q is not permitted in JSON", s)
	}
	if f == 0 {
		// Covers +0 and -0.
		return "0", nil
	}
	rep := strconv.FormatFloat(f, 'e', -1, 64) // shortest round-trip: "[-]d.dddde±X"
	neg := false
	if rep[0] == '-' {
		neg = true
		rep = rep[1:]
	}
	var digits strings.Builder
	exp := 0
	for i := 0; i < len(rep); i++ {
		c := rep[i]
		if c == 'e' {
			exp, _ = strconv.Atoi(rep[i+1:])
			break
		}
		if c != '.' {
			digits.WriteByte(c)
		}
	}
	k := digits.Len()
	n := exp + 1 // ECMA-262 n: the decimal exponent of the leading digit.

	var out strings.Builder
	if neg {
		out.WriteByte('-')
	}
	switch {
	case n > 21 || n <= -6:
		// Exponential notation.
		out.WriteString(digits.String()[:1])
		if k > 1 {
			out.WriteByte('.')
			out.WriteString(digits.String()[1:])
		}
		out.WriteByte('e')
		if exp < 0 {
			out.WriteByte('-')
		} else {
			out.WriteByte('+')
		}
		out.WriteString(strconv.Itoa(expAbs(exp)))
	case n >= k:
		out.WriteString(digits.String())
		for i := 0; i < n-k; i++ {
			out.WriteByte('0')
		}
	case n > 0:
		out.WriteString(digits.String()[:n])
		out.WriteByte('.')
		out.WriteString(digits.String()[n:])
	default: // -6 < n <= 0
		out.WriteString("0.")
		for i := 0; i < -n; i++ {
			out.WriteByte('0')
		}
		out.WriteString(digits.String())
	}
	return out.String(), nil
}

func expAbs(e int) int {
	if e < 0 {
		return -e
	}
	return e
}

// rejectLoneSurrogates scans the raw JSON text for \uXXXX escapes whose code
// unit is an unpaired surrogate: a high surrogate must be immediately
// followed by a low surrogate escape, and a low surrogate must have a high
// surrogate before it. Raw UTF-8-encoded surrogates are rejected earlier by
// utf8.Valid; escapes are ASCII and need this pass. (encoding/json happens
// to reject most of these too, but its exact behaviour has varied across Go
// versions, and the RFC requires the rejection regardless.)
func rejectLoneSurrogates(b []byte) error {
	inStr := false
	for i := 0; i < len(b); {
		c := b[i]
		if inStr {
			switch c {
			case '\\':
				if i+1 >= len(b) {
					return errors.New("jcs: trailing backslash in string")
				}
				if b[i+1] != 'u' {
					i += 2 // Escaped non-\u character.
					continue
				}
				if i+6 > len(b) || !isHex4(b[i+2:i+6]) {
					return errors.New("jcs: malformed \\u escape")
				}
				v := hexVal(b[i+2 : i+6])
				switch {
				case v >= 0xD800 && v <= 0xDBFF:
					// High surrogate: require the pairing low surrogate.
					if i+12 <= len(b) && b[i+6] == '\\' && b[i+7] == 'u' && isHex4(b[i+8:i+12]) {
						lo := hexVal(b[i+8 : i+12])
						if lo >= 0xDC00 && lo <= 0xDFFF {
							i += 12
							continue
						}
					}
					return fmt.Errorf("jcs: lone surrogate \\u%04x", v)
				case v >= 0xDC00 && v <= 0xDFFF:
					return fmt.Errorf("jcs: lone surrogate \\u%04x", v)
				default:
					i += 6
					continue
				}
			case '"':
				inStr = false
				i++
			default:
				i++
			}
			continue
		}
		if c == '"' {
			inStr = true
		}
		i++
	}
	return nil
}

func isHex4(b []byte) bool {
	if len(b) != 4 {
		return false
	}
	for _, c := range b {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

func hexVal(b []byte) uint16 {
	var v uint16
	for _, c := range b {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint16(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint16(c-'a') + 10
		default:
			v |= uint16(c-'A') + 10
		}
	}
	return v
}
