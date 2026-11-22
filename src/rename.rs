use serde::{Deserialize, Serialize};
use std::path::PathBuf;
#[derive(Clone, Serialize, Deserialize)]
pub struct Change {
    pub file: PathBuf,
    pub from: String,
    pub to: String,
    pub occurrences: usize,
}
pub fn valid(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
        && ![
            "if",
            "else",
            "for",
            "while",
            "return",
            "int",
            "void",
            "char",
            "float",
            "double",
            "long",
            "short",
            "struct",
            "class",
            "def",
            "fn",
            "let",
            "const",
            "static",
            "import",
            "from",
            "try",
            "except",
            "switch",
            "case",
            "break",
            "continue",
            "true",
            "false",
            "None",
            "null",
            "new",
            "delete",
            "auto",
            "unsigned",
            "signed",
            "bool",
            "public",
            "private",
            "protected",
            "namespace",
            "using",
            "extern",
            "sizeof",
            "typedef",
            "volatile",
            "enum",
            "union",
            "do",
            "goto",
            "async",
            "await",
            "var",
            "function",
            "this",
            "self",
            "super",
            "in",
            "is",
            "not",
            "and",
            "or",
            "pass",
            "raise",
            "with",
            "as",
            "yield",
            "finally",
            "lambda",
            "assert",
            "global",
            "nonlocal",
        ]
        .contains(&name)
}
pub fn symbol_at(text: &str, character: usize) -> String {
    let at = text
        .char_indices()
        .nth(character)
        .map(|(i, _)| i)
        .unwrap_or(text.len());
    let bytes = text.as_bytes();
    let mut start = at;
    let mut end = at;
    while start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_') {
        start -= 1;
    }
    while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
        end += 1;
    }
    text[start..end].into()
}
// File-wide lexical rename: comments and literals remain unchanged; no type/scope inference.
pub fn replace(text: &str, from: &str, to: &str) -> Result<(String, usize), String> {
    if !valid(from) || !valid(to) || from == to {
        return Err("invalid identifier or unchanged name".into());
    }
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut count = 0;
    while i < b.len() {
        let start = i;
        if b[i] == b'#' || b[i..].starts_with(b"//") {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if b[i..].starts_with(b"/*") {
            i += 2;
            while i < b.len() && !b[i..].starts_with(b"*/") {
                i += 1;
            }
            i = (i + 2).min(b.len());
        } else if b"'\"`".contains(&b[i]) {
            let quote = b[i];
            let triple = b.get(i..i + 3).is_some_and(|s| s == [quote, quote, quote]);
            let width = if triple { 3 } else { 1 };
            i += width;
            while i < b.len() {
                if b[i] == b'\\' {
                    i = (i + 2).min(b.len());
                    continue;
                }
                if b.get(i..i + width)
                    .is_some_and(|s| s.iter().all(|c| *c == quote))
                {
                    i += width;
                    break;
                }
                i += 1;
            }
        } else if b[i].is_ascii_alphabetic() || b[i] == b'_' {
            i += 1;
            while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
                i += 1;
            }
            let word = &text[start..i];
            if word == from {
                out.push_str(to);
                count += 1;
                continue;
            }
        } else {
            i += text[i..].chars().next().unwrap().len_utf8();
        }
        out.push_str(&text[start..i]);
    }
    Ok((out, count))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_whole_code_identifiers_change() {
        let (s, n) = replace(
            "int uVar1=uVar10; // uVar1\nchar *s=\"uVar1\"; uVar1++; /* uVar1 */",
            "uVar1",
            "counter",
        )
        .unwrap();
        assert_eq!(n, 2);
        assert!(s.contains("uVar10"));
        assert!(s.contains("\"uVar1\""));
        assert!(s.contains("counter++"));
        assert!(!valid("int"));
        assert_eq!(symbol_at("x uVar1;", 4), "uVar1");
    }
}
