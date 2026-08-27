//! A minimal JSON writer.
//!
//! Deliberately hand-rolled rather than pulling in serde. Every dependency in
//! this crate is pinned with `=` and there are four of them; a derive-macro
//! stack for what amounts to three flat report shapes would be the largest
//! dependency change in the project's history, and the reports are emitted, not
//! parsed, so none of serde's real value applies.
//!
//! The one thing this MUST get right is escaping. The strings that flow through
//! here are file paths and evidence text taken from the live system -- a module
//! is free to ship a filename containing a quote or a backslash, and the WebUI
//! runs `JSON.parse` on the result, so a single unescaped byte turns a diagnostic
//! into a broken page. Control characters below 0x20 are escaped as `\u00XX`
//! because raw ones are invalid inside a JSON string.

use std::fmt::Write as _;

/// Escape `s` into `out` as the *contents* of a JSON string (no surrounding
/// quotes). `\u{2028}`/`\u{2029}` are escaped too: both are valid in JSON but
/// are line terminators in older JavaScript parsers.
fn escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// A JSON value being built. Only the shapes the reports need.
pub enum J {
    Str(String),
    Num(i64),
    Bool(bool),
    Null,
    Arr(Vec<J>),
    /// Insertion-ordered so a textual diff of two reports reads cleanly.
    Obj(Vec<(&'static str, J)>),
}

impl J {
    pub fn s(v: impl Into<String>) -> J {
        J::Str(v.into())
    }
    /// `Some` -> string, `None` -> `null`. The distinction matters: a missing
    /// owner and an empty owner are different answers.
    pub fn os(v: Option<impl Into<String>>) -> J {
        match v {
            Some(x) => J::Str(x.into()),
            None => J::Null,
        }
    }

    fn write(&self, out: &mut String) {
        match self {
            J::Str(s) => {
                out.push('"');
                escape_into(out, s);
                out.push('"');
            }
            J::Num(n) => {
                let _ = write!(out, "{n}");
            }
            J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            J::Null => out.push_str("null"),
            J::Arr(v) => {
                out.push('[');
                for (i, x) in v.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    x.write(out);
                }
                out.push(']');
            }
            J::Obj(kv) => {
                out.push('{');
                for (i, (k, v)) in kv.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    escape_into(out, k);
                    out.push_str("\":");
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        self.write(&mut s);
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The case that turns a diagnostic into a broken WebUI page: a path a
    /// module is perfectly free to ship.
    #[test]
    fn quotes_and_backslashes_in_a_path_survive() {
        let j = J::Obj(vec![("target", J::s("/product/app/He said \"hi\"\\x.apk"))]);
        assert_eq!(
            j.render(),
            r#"{"target":"/product/app/He said \"hi\"\\x.apk"}"#
        );
    }

    /// Evidence is multi-line in several checks; a raw newline inside a JSON
    /// string is invalid, not merely ugly.
    #[test]
    fn control_characters_are_escaped() {
        let j = J::s("a\nb\tc\u{1}d");
        assert_eq!(j.render(), r#""a\nb\tc\u0001d""#);
    }

    #[test]
    fn nesting_and_null_render() {
        let j = J::Obj(vec![
            ("n", J::Num(-3)),
            ("ok", J::Bool(true)),
            ("owner", J::os(None::<String>)),
            ("xs", J::Arr(vec![J::s("a"), J::Num(1)])),
        ]);
        assert_eq!(j.render(), r#"{"n":-3,"ok":true,"owner":null,"xs":["a",1]}"#);
    }

}
