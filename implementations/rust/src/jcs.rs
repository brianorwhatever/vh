//! RFC 8785 JSON Canonicalization Scheme.

use serde_json::Value;
use std::fmt::Write;

/// Canonicalises a JSON value. Every number is treated as an IEEE-754 double.
pub fn canonicalize(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

/// Parses JSON text and canonicalises it.
pub fn canonicalize_str(text: &str) -> Result<String, serde_json::Error> {
    Ok(canonicalize(&serde_json::from_str(text)?))
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&format_number(n.as_f64().unwrap_or(f64::NAN))),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, &map[key]);
            }
            out.push('}');
        }
    }
}

/// Serialises a string as ECMAScript's `JSON.stringify` does.
fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Formats a double with ECMAScript's `Number::toString` rules (ECMA-262
/// §6.1.6.1.20): shortest round-tripping digits, closest to the exact value.
///
/// # Panics
/// If `value` is not finite (JSON cannot express it).
pub fn format_number(value: f64) -> String {
    assert!(value.is_finite(), "JCS: non-finite number");
    ryu_js::Buffer::new().format_finite(value).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_follow_ecmascript() {
        let cases = [
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (-1.5, "-1.5"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (1e-7, "1e-7"),
            (1e-6, "0.000001"),
            (123456789012345678.0, "123456789012345680"),
            (5e-324, "5e-324"),
            (896365914996807.2, "896365914996807.2"),
        ];
        for (n, want) in cases {
            assert_eq!(format_number(n), want);
        }
    }

    #[test]
    fn big_integers_are_doubles() {
        let out =
            canonicalize_str(r#"{"big":123456789012345678,"bigger":9007199254740993}"#).unwrap();
        assert_eq!(
            out,
            r#"{"big":123456789012345680,"bigger":9007199254740992}"#
        );
    }

    #[test]
    fn keys_sort_by_utf16_code_units() {
        // U+1F600 (surrogates D83D DE00) sorts before U+FB33 in UTF-16, after it by code point.
        let out = canonicalize_str("{\"\u{fb33}\":1,\"\u{1f600}\":2,\"a\":3}").unwrap();
        assert_eq!(out, "{\"a\":3,\"\u{1f600}\":2,\"\u{fb33}\":1}");
    }

    #[test]
    fn strings_escape_like_json_stringify() {
        let out = canonicalize_str(r#""\u000f\n\"\\/\u007f ""#).unwrap();
        assert_eq!(out, "\"\\u000f\\n\\\"\\\\/\u{7f}\u{2028}\"");
    }
}
