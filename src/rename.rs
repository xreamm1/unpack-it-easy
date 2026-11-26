use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
#[derive(Clone, Serialize, Deserialize)]
pub struct Change {
    pub file: PathBuf,
    pub from: String,
    pub to: String,
    pub occurrences: usize,
}
#[derive(Clone, Copy, PartialEq)]
enum Language {
    Python,
    C,
    Rust,
    Js,
    Java,
    CSharp,
}
fn language(path: &Path) -> Option<Language> {
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "py" | "pyw" => Some(Language::Python),
        "c" | "cpp" | "cxx" | "cc" | "h" | "hpp" => Some(Language::C),
        "rs" => Some(Language::Rust),
        "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs" => Some(Language::Js),
        "java" => Some(Language::Java),
        "cs" => Some(Language::CSharp),
        _ => None,
    }
}
fn start(c: char, lang: Language) -> bool {
    c == '_'
        || unicode_ident::is_xid_start(c)
        || c == '$' && matches!(lang, Language::Js | Language::Java)
}
fn continuation(c: char, lang: Language) -> bool {
    start(c, lang) || unicode_ident::is_xid_continue(c)
}
pub fn valid(name: &str, path: &Path) -> bool {
    let Some(lang) = language(path) else {
        return false;
    };
    let mut chars = name.chars();
    if !chars.next().is_some_and(|c| start(c, lang)) || !chars.all(|c| continuation(c, lang)) {
        return false;
    }
    let words = match lang {
        Language::Python => "False None True and as assert async await break class continue def del elif else except finally for from global if import in is lambda nonlocal not or pass raise return try while with yield",
        Language::C => "alignas alignof and and_eq asm auto bitand bitor bool break case catch char char8_t char16_t char32_t class compl concept const consteval constexpr constinit const_cast continue co_await co_return co_yield decltype default delete do double dynamic_cast else enum explicit export extern false float for friend goto if inline int long mutable namespace new noexcept not not_eq nullptr operator or or_eq private protected public register reinterpret_cast requires return short signed sizeof static static_assert static_cast struct switch template this thread_local throw true try typedef typeid typename union unsigned using virtual void volatile wchar_t while xor xor_eq _Alignas _Alignof _Atomic _Bool _Complex _Generic _Imaginary _Noreturn _Static_assert _Thread_local",
        Language::Rust => "as async await break const continue crate dyn else enum extern false fn for if impl in let loop match mod move mut pub ref return self Self static struct super trait true type unsafe use where while abstract become box do final macro override priv typeof unsized virtual yield try",
        Language::Js => "await break case catch class const continue debugger default delete do else enum export extends false finally for function if implements import in instanceof interface let new null package private protected public return static super switch this throw true try typeof var void while with yield",
        Language::Java => "abstract assert boolean break byte case catch char class const continue default do double else enum extends final finally float for goto if implements import instanceof int interface long native new package private protected public return short static strictfp super switch synchronized this throw throws transient try void volatile while true false null _",
        Language::CSharp => "abstract as base bool break byte case catch char checked class const continue decimal default delegate do double else enum event explicit extern false finally fixed float for foreach goto if implicit in int interface internal is lock long namespace new null object operator out override params private protected public readonly ref return sbyte sealed short sizeof stackalloc static string struct switch this throw true try typeof uint ulong unchecked unsafe ushort using virtual void volatile while",
    };
    !words.split_whitespace().any(|word| word == name)
}
pub fn symbol_at(text: &str, character: usize, path: &Path) -> String {
    let Some(lang) = language(path) else {
        return String::new();
    };
    let at = text
        .char_indices()
        .nth(character)
        .map(|(at, _)| at)
        .unwrap_or(text.len());
    let mut begin = at;
    for (index, c) in text[..at].char_indices().rev() {
        if !continuation(c, lang) {
            break;
        }
        begin = index;
    }
    let mut end = at;
    for (offset, c) in text[at..].char_indices() {
        if !continuation(c, lang) {
            break;
        }
        end = at + offset + c.len_utf8();
    }
    text[begin..end].into()
}
fn raw_end(text: &str, at: usize, lang: Language) -> Option<usize> {
    let tail = &text[at..];
    if lang == Language::C {
        for prefix in ["u8R\"", "LR\"", "uR\"", "UR\"", "R\""] {
            if let Some(rest) = tail.strip_prefix(prefix) {
                let open = rest.find('(').filter(|at| *at <= 16)?;
                let delimiter = &rest[..open];
                if delimiter
                    .chars()
                    .any(|c| c.is_whitespace() || matches!(c, ')' | '\\'))
                {
                    return None;
                }
                let close = format!("){delimiter}\"");
                return Some(
                    rest[open + 1..]
                        .find(&close)
                        .map(|offset| at + prefix.len() + open + 1 + offset + close.len())
                        .unwrap_or(text.len()),
                );
            }
        }
    }
    if lang == Language::Rust {
        for prefix in ["br", "cr", "r"] {
            if let Some(rest) = tail.strip_prefix(prefix) {
                let hashes = rest.bytes().take_while(|c| *c == b'#').count();
                if rest.as_bytes().get(hashes) != Some(&b'"') {
                    continue;
                }
                let close = format!("\"{}", "#".repeat(hashes));
                let body = at + prefix.len() + hashes + 1;
                return Some(
                    text[body..]
                        .find(&close)
                        .map(|offset| body + offset + close.len())
                        .unwrap_or(text.len()),
                );
            }
        }
    }
    None
}
// Lexical file-wide rename; scopes are not inferred. Ambiguous literals fail before editing.
pub fn replace(text: &str, from: &str, to: &str, path: &Path) -> Result<(String, usize), String> {
    replace_many(
        text,
        &std::collections::BTreeMap::from([(from.to_owned(), to.to_owned())]),
        path,
    )
}
pub fn replace_many(
    text: &str,
    names: &std::collections::BTreeMap<String, String>,
    path: &Path,
) -> Result<(String, usize), String> {
    if names.is_empty()
        || names
            .iter()
            .any(|(from, to)| !valid(from, path) || !valid(to, path) || from == to)
    {
        return Err("invalid identifier, unsupported language or unchanged name".into());
    }
    let lang = language(path).unwrap();
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    let mut count = 0;
    while at < bytes.len() {
        let begin = at;
        if let Some(end) = raw_end(text, at, lang) {
            at = end;
        } else if lang == Language::Python && bytes[at] == b'#'
            || lang != Language::Python && bytes[at..].starts_with(b"//")
        {
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
        } else if lang != Language::Python && bytes[at..].starts_with(b"/*") {
            at += 2;
            at = memchr::memmem::find(&bytes[at..], b"*/")
                .map(|end| at + end + 2)
                .unwrap_or(bytes.len());
        } else {
            let prefixes: &[&str] = match lang {
                Language::Python => &[
                    "fr", "rf", "br", "rb", "f", "r", "b", "u", "FR", "RF", "F", "R", "B", "U",
                ],
                Language::C => &["u8", "L", "u", "U"],
                Language::CSharp => &["@$", "$@", "@", "$"],
                Language::Rust => &["b", "c"],
                _ => &[],
            };
            let prefix = prefixes
                .iter()
                .find(|prefix| {
                    text[at..].starts_with(**prefix)
                        && matches!(bytes.get(at + prefix.len()), Some(b'"' | b'\''))
                })
                .copied()
                .unwrap_or("");
            let quote_at = at + prefix.len();
            let quote = bytes[quote_at];
            let lifetime = lang == Language::Rust
                && quote == b'\''
                && text[quote_at + 1..]
                    .chars()
                    .next()
                    .is_some_and(|c| start(c, lang))
                && text[quote_at + 1..].chars().nth(1) != Some('\'');
            if matches!(quote, b'\'' | b'"') && !lifetime || quote == b'`' && lang == Language::Js {
                let triple = lang == Language::Python
                    && bytes
                        .get(quote_at..quote_at + 3)
                        .is_some_and(|s| s == [quote, quote, quote]);
                let width = if triple { 3 } else { 1 };
                let verbatim = lang == Language::CSharp && prefix.contains('@');
                at = quote_at + width;
                while at < bytes.len() {
                    if !verbatim && bytes[at] == b'\\' {
                        at = (at + 2).min(bytes.len());
                        continue;
                    }
                    if verbatim && bytes.get(at..at + 2) == Some(b"\"\"") {
                        at += 2;
                        continue;
                    }
                    if bytes
                        .get(at..at + width)
                        .is_some_and(|s| s.iter().all(|byte| *byte == quote))
                    {
                        at += width;
                        break;
                    }
                    at += 1;
                }
                let formatted = lang == Language::Python
                    && prefix.to_ascii_lowercase().contains('f')
                    || lang == Language::CSharp && prefix.contains('$')
                    || lang == Language::Js && quote == b'`';
                if formatted
                    && text[begin..at]
                        .split(|c: char| !continuation(c, lang))
                        .any(|word| names.contains_key(word))
                {
                    return Err(
                        "rename involving interpolated strings requires a syntax-aware editor"
                            .into(),
                    );
                }
            } else if lang == Language::Js && bytes[at] == b'/' {
                return Err(
                    "ambiguous JavaScript slash/regex syntax; rename was not applied".into(),
                );
            } else {
                let c = text[at..].chars().next().unwrap();
                if start(c, lang) {
                    at += c.len_utf8();
                    while at < bytes.len() {
                        let c = text[at..].chars().next().unwrap();
                        if !continuation(c, lang) {
                            break;
                        }
                        at += c.len_utf8();
                    }
                    if let Some(to) = names.get(&text[begin..at]) {
                        out.push_str(to);
                        count += 1;
                        continue;
                    }
                } else {
                    at += c.len_utf8();
                }
            }
        }
        out.push_str(&text[begin..at]);
    }
    Ok((out, count))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn c_preprocessor_and_unicode_are_renamed_without_touching_literals() {
        let path = Path::new("a.cpp");
        let (text, count) = replace(
            "#define счёт 1\nint счёт=счётчик; // счёт\nauto s=R\"raw(счёт \" text)raw\";",
            "счёт",
            "итог",
            path,
        )
        .unwrap();
        assert_eq!(count, 2);
        assert!(text.contains("#define итог"));
        assert!(text.contains("счётчик"));
        assert!(text.contains("// счёт"));
        assert!(text.contains("raw(счёт"));
        assert!(!valid("int", path));
        assert!(valid("int", Path::new("a.py")));
        assert_eq!(symbol_at("x счёт;", 4, path), "счёт");
    }
    #[test]
    fn python_floor_division_and_hash_comments_have_different_roles() {
        let (text, count) = replace(
            "счёт = 6 // счёт # счёт\ns = \"счёт\"",
            "счёт",
            "число",
            Path::new("a.py"),
        )
        .unwrap();
        assert_eq!(count, 2);
        assert!(text.contains("// число # счёт"));
        assert!(text.contains("\"счёт\""));
        assert!(valid("cafe\u{301}", Path::new("a.py")));
    }
    #[test]
    fn rust_raw_strings_and_csharp_verbatim_strings_remain_unchanged() {
        let (text, count) = replace(
            "#[x] let x=r###\"x \" x\"###; x;",
            "x",
            "y",
            Path::new("a.rs"),
        )
        .unwrap();
        assert_eq!(count, 3);
        assert!(text.contains("r###\"x \" x\"###"));
        let (text, count) =
            replace("var x=@\"x \"\" x\"; x++;", "x", "y", Path::new("a.cs")).unwrap();
        assert_eq!(count, 2);
        assert!(text.contains("@\"x \"\" x\""));
        assert!(replace("x=1; f\"{x}\"", "x", "y", Path::new("a.py")).is_err());
    }
}
