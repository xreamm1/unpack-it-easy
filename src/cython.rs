use regex::Regex;
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_SOURCE_BYTES: u64 = 32 * 1024 * 1024;
const MAX_BLOCKS: usize = 65_536;
const MAX_TOKENS: usize = 1_000_000;

#[derive(Clone, Copy)]
enum Token<'a> {
    Identifier(&'a str),
    Number(&'a str),
    Literal(&'a str),
    Punctuation(u8),
}

struct Block<'a> {
    address: &'a str,
    native_name: &'a str,
    header_start: usize,
    header_end: usize,
    body: &'a str,
}

fn identifier(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn tokens(source: &str) -> Result<Vec<Token<'_>>, String> {
    let bytes = source.as_bytes();
    let mut result = vec![];
    let mut at = 0;
    while at < bytes.len() {
        if result.len() >= MAX_TOKENS {
            return Err("Cython metadata token budget reached".into());
        }
        match bytes[at] {
            byte if byte.is_ascii_whitespace() => at += 1,
            b'/' if bytes.get(at + 1) == Some(&b'/') => {
                at += 2;
                while at < bytes.len() && bytes[at] != b'\n' {
                    at += 1;
                }
            }
            b'/' if bytes.get(at + 1) == Some(&b'*') => {
                at += 2;
                while at + 1 < bytes.len() && &bytes[at..at + 2] != b"*/" {
                    at += 1;
                }
                at = (at + 2).min(bytes.len());
            }
            quote @ (b'"' | b'\'') => {
                let start = at + 1;
                at += 1;
                while at < bytes.len() && bytes[at] != quote {
                    if bytes[at] == b'\\' {
                        at += 1;
                    }
                    at = (at + 1).min(bytes.len());
                }
                if at >= bytes.len() {
                    break;
                }
                if quote == b'"' {
                    result.push(Token::Literal(&source[start..at]));
                } else {
                    result.push(Token::Punctuation(b'\''));
                }
                at += 1;
            }
            byte if byte.is_ascii_alphabetic() || byte == b'_' => {
                let start = at;
                at += 1;
                while at < bytes.len() && (bytes[at].is_ascii_alphanumeric() || bytes[at] == b'_') {
                    at += 1;
                }
                result.push(Token::Identifier(&source[start..at]));
            }
            byte if byte.is_ascii_digit() => {
                let start = at;
                at += 1;
                while at < bytes.len() && bytes[at].is_ascii_alphanumeric() {
                    at += 1;
                }
                result.push(Token::Number(&source[start..at]));
            }
            byte => {
                result.push(Token::Punctuation(byte));
                at += 1;
            }
        }
    }
    Ok(result)
}

fn calls(tokens: &[Token<'_>], name: &str) -> bool {
    tokens.windows(2).any(|pair| matches!(pair, [Token::Identifier(found), Token::Punctuation(b'(')] if *found == name))
}

fn arguments<'a>(tokens: &'a [Token<'a>], open: usize) -> Option<Vec<&'a [Token<'a>]>> {
    let mut depth = 1usize;
    let mut start = open + 1;
    let mut result = vec![];
    for (index, token) in tokens.iter().enumerate().skip(start) {
        match token {
            Token::Punctuation(b'(' | b'[' | b'{') => depth += 1,
            Token::Punctuation(b')') if depth == 1 => {
                result.push(&tokens[start..index]);
                return Some(result);
            }
            Token::Punctuation(b')' | b']' | b'}') => depth = depth.checked_sub(1)?,
            Token::Punctuation(b',') if depth == 1 => {
                if result.len() >= 16 {
                    return None;
                }
                result.push(&tokens[start..index]);
                start = index + 1;
            }
            _ => (),
        }
    }
    None
}

fn source_line(tokens: &[Token<'_>]) -> Option<u32> {
    let [Token::Number(number)] = tokens else {
        return None;
    };
    let number = number.trim_end_matches(['u', 'U', 'l', 'L']);
    let value = if let Some(hex) = number
        .strip_prefix("0x")
        .or_else(|| number.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16).ok()?
    } else if number.len() > 1 && number.starts_with('0') {
        u32::from_str_radix(number, 8).ok()?
    } else {
        number.parse().ok()?
    };
    (1..=10_000_000).contains(&value).then_some(value)
}

fn replace_comments(path: &Path, source: &str) -> Result<(), String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let temporary = path.with_extension(format!("uie-cython-{}-{stamp}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| error.to_string())?;
        file.write_all(source.as_bytes())
            .map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

pub fn annotate(c_file: &Path, report: &mut Value) -> Result<usize, String> {
    if !report.is_object() {
        return Err("Cython metadata requires a native report object".into());
    }
    let mut bytes = vec![];
    File::open(c_file)
        .map_err(|error| error.to_string())?
        .take(MAX_SOURCE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        return Err("Cython metadata source limit: 32 MiB".into());
    }
    let source = String::from_utf8(bytes).map_err(|error| error.to_string())?;
    let headers = Regex::new(r"(?m)^/\* Function at ([0-9A-Fa-f]{1,16}): ([^\r\n]{1,1024}?) \*/")
        .map_err(|error| error.to_string())?;
    let matches: Vec<_> = headers.captures_iter(&source).collect();
    if matches.len() > MAX_BLOCKS {
        return Err("Cython metadata function budget reached".into());
    }
    let mut blocks = vec![];
    for (index, capture) in matches.iter().enumerate() {
        let header = capture.get(0).unwrap();
        let label = capture.get(2).unwrap().as_str();
        let native_name = label
            .rsplit_once(" [cython: ")
            .and_then(|(_, original)| original.strip_suffix(']'))
            .unwrap_or(label);
        blocks.push(Block {
            address: capture.get(1).unwrap().as_str(),
            native_name,
            header_start: header.start(),
            header_end: header.end(),
            body: &source[header.end()
                ..matches
                    .get(index + 1)
                    .map_or(source.len(), |next| next.get(0).unwrap().start())],
        });
    }
    let mut helpers = BTreeSet::new();
    for block in &blocks {
        if !identifier(block.native_name)
            || !["PyCode_NewEmpty", "PyFrame_New", "PyTraceBack_Here"]
                .iter()
                .all(|name| block.body.contains(name))
        {
            continue;
        }
        let parsed = tokens(block.body)?;
        if ["PyCode_NewEmpty", "PyFrame_New", "PyTraceBack_Here"]
            .iter()
            .all(|name| calls(&parsed, name))
        {
            helpers.insert(block.native_name);
        }
    }
    if helpers.is_empty() {
        return Ok(0);
    }
    let mut replacements = vec![];
    let mut records = vec![];
    let mut ambiguous = 0usize;
    for block in &blocks {
        if helpers.contains(block.native_name)
            || !helpers.iter().any(|helper| block.body.contains(helper))
        {
            continue;
        }
        let parsed = tokens(block.body)?;
        let mut names: BTreeMap<&str, (BTreeSet<u32>, BTreeSet<&str>, usize)> = BTreeMap::new();
        for (index, pair) in parsed.windows(2).enumerate() {
            let [Token::Identifier(helper), Token::Punctuation(b'(')] = pair else {
                continue;
            };
            if !helpers.contains(helper) {
                continue;
            }
            let Some(args) = arguments(&parsed, index + 1).filter(|args| args.len() == 4) else {
                continue;
            };
            let [Token::Literal(name)] = args[0] else {
                continue;
            };
            if name.len() > 512 || !name.contains('.') || !name.split('.').all(identifier) {
                continue;
            }
            let entry = names.entry(name).or_default();
            if let Some(line) = source_line(args[2]) {
                entry.0.insert(line);
            } else {
                entry.2 += 1;
            }
            if let [Token::Literal(file)] = args[3] {
                if file.len() <= 4096 && !file.contains(['\r', '\n', '\0']) {
                    entry.1.insert(file);
                }
            }
        }
        if names.len() > 1 {
            ambiguous += 1;
            continue;
        }
        let Some((name, (lines, files, unknown_lines))) = names.into_iter().next() else {
            continue;
        };
        let label = format!(
            "/* Function at {}: {} [cython: {}] */",
            block.address, name, block.native_name
        );
        replacements.push((block.header_start, block.header_end, label));
        records.push(json!({"native_address":block.address,"native_name":block.native_name,"python_name":name,"python_source_lines":lines,"python_source_files":files,"unresolved_source_line_calls":unknown_lines,"evidence":"literal name at a call to a helper verified by PyCode_NewEmpty + PyFrame_New + PyTraceBack_Here","source_line_interpretation":"traceback error sites; not function definition lines","body_recovered":false}));
    }
    let mut annotated = source.clone();
    for (start, end, label) in replacements.into_iter().rev() {
        annotated.replace_range(start..end, &label);
    }
    if annotated != source {
        replace_comments(c_file, &annotated)?;
    }
    if let Some(functions) = report["functions"].as_array_mut() {
        for function in functions {
            if let Some(record) = records.iter().find(|record| {
                record["native_address"]
                    .as_str()
                    .zip(function["address"].as_str())
                    .is_some_and(|(left, right)| left.eq_ignore_ascii_case(right))
            }) {
                function["python_name"] = record["python_name"].clone();
                function["python_source_lines"] = record["python_source_lines"].clone();
                function["python_source_files"] = record["python_source_files"].clone();
                function["group"] = json!("user");
            }
        }
    }
    let count = records.len();
    report["cython_recovery"] = json!({"engine":"UIE Rust Cython traceback metadata","verified_helpers":helpers,"mapped_native_functions":count,"ambiguous_native_functions":ambiguous,"interpretation":"Recovered names and traceback error-site metadata only; function bodies remain native pseudocode. No original Python or semantic equivalence claim. Header comments alone were changed; all native identifiers, function bodies and line counts are retained.","records":records});
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    const HELPER: &str = "/* Function at 180020000: FUN_180020000 */\nvoid FUN_180020000(char*a,int b,int c,char*d) { PyCode_NewEmpty(d,a,c); PyFrame_New(0,0,0,0); PyTraceBack_Here(0); }\n";
    fn sample(source: &str) -> std::path::PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let root = std::env::temp_dir().join(format!(
            "uie-cython-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("sample.c");
        fs::write(&path, source).unwrap();
        path
    }
    #[test]
    fn names_and_error_lines_are_recovered_without_changing_native_bodies() {
        let body = "\nvoid FUN_180001000(void) { FUN_180020000(\"app.App.foo\", 0, 0x5e, \"app.py\"); FUN_180020000(\"app.App.foo\", 0, unknown_line, file); }\n";
        let original = format!("{HELPER}/* Function at 180001000: FUN_180001000 */{body}")
            .replace('\n', "\r\n");
        let path = sample(&original);
        let mut report =
            json!({"functions":[{"address":"180001000","name":"FUN_180001000","line":3}]});
        assert_eq!(annotate(&path, &mut report).unwrap(), 1);
        let result = fs::read_to_string(&path).unwrap();
        assert!(result.contains("app.App.foo [cython: FUN_180001000]"));
        assert!(result.ends_with(&body.replace('\n', "\r\n")));
        assert_eq!(
            result.bytes().filter(|byte| *byte == b'\n').count(),
            original.bytes().filter(|byte| *byte == b'\n').count()
        );
        assert_eq!(report["functions"][0]["python_source_lines"], json!([94]));
        assert_eq!(report["functions"][0]["name"], "FUN_180001000");
        assert_eq!(
            report["cython_recovery"]["records"][0]["unresolved_source_line_calls"],
            1
        );
        let before = report.clone();
        assert_eq!(annotate(&path, &mut report).unwrap(), 1);
        assert_eq!(report, before);
        assert_eq!(fs::read_to_string(&path).unwrap(), result);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn ambiguous_names_and_unverified_helpers_are_not_applied() {
        let source = format!("{HELPER}/* Function at 180001000: FUN_180001000 */\nvoid f() {{ FUN_180020000(\"app.one\",0,1,\"a.py\"); FUN_180020000(\"app.two\",0,2,\"a.py\"); other(\"app.fake\",0,1,\"a.py\"); }}\n");
        let path = sample(&source);
        let mut report = json!({"functions":[]});
        assert_eq!(annotate(&path, &mut report).unwrap(), 0);
        assert_eq!(report["cython_recovery"]["ambiguous_native_functions"], 1);
        assert_eq!(fs::read_to_string(&path).unwrap(), source);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn helper_names_in_comments_and_strings_do_not_verify_a_helper() {
        let source = "/* Function at 180020000: fake */\nvoid fake() { const char*s=\"PyCode_NewEmpty( PyFrame_New( PyTraceBack_Here(\"; /* PyCode_NewEmpty(); PyFrame_New(); PyTraceBack_Here(); */ }\n/* Function at 180001000: f */\nvoid f() { fake(\"app.fake\",0,1,\"a.py\"); }\n";
        let path = sample(source);
        let mut report = json!({"functions":[]});
        assert_eq!(annotate(&path, &mut report).unwrap(), 0);
        assert_eq!(fs::read_to_string(&path).unwrap(), source);
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
