
use std::fmt::Write as _;

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

pub enum J {
    Str(String),
    Num(i64),
    Bool(bool),
    Null,
    Arr(Vec<J>),
    Obj(Vec<(&'static str, J)>),
}

impl J {
    pub fn s(v: impl Into<String>) -> J {
        J::Str(v.into())
    }
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

    #[test]
    fn quotes_and_backslashes_in_a_path_survive() {
        let j = J::Obj(vec![("target", J::s("/product/app/He said \"hi\"\\x.apk"))]);
        assert_eq!(
            j.render(),
            r#"{"target":"/product/app/He said \"hi\"\\x.apk"}"#
        );
    }

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
