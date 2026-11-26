use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

const MAX_REPORT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_ROWS: usize = 100_000;
const MAX_COMMENT_BYTES: usize = 300;

fn report(path: &Path) -> Result<Value, String> {
    let file = fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if file.metadata().map_err(|error| error.to_string())?.len() > MAX_REPORT_BYTES {
        return Err("native report exceeds export size limit".into());
    }
    serde_json::from_reader(file).map_err(|error| error.to_string())
}

fn module_name(module: &str) -> Result<(), String> {
    if module.is_empty()
        || module.len() > 240
        || module.trim() != module
        || matches!(module, "." | "..")
        || !module
            .chars()
            .all(|ch| ch.is_alphanumeric() || "._- ()".contains(ch))
    {
        return Err("use a module filename, without a path or debugger expressions".into());
    }
    Ok(())
}

fn rva(value: &Value) -> Result<u64, String> {
    let number = if let Some(number) = value.as_u64() {
        number
    } else if let Some(text) = value.as_str() {
        let digits = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .ok_or("RVA strings must use the 0x prefix")?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid RVA in native report".into());
        }
        u64::from_str_radix(digits, 16).map_err(|error| error.to_string())?
    } else {
        return Err("native report entry has no RVA; absolute addresses are not exported".into());
    };
    if number > u32::MAX as u64 {
        return Err("RVA exceeds the PE address range; absolute addresses are not exported".into());
    }
    Ok(number)
}

fn visible(text: &str, max_bytes: usize) -> String {
    let mut result = String::new();
    for ch in text.chars() {
        let ch = if ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}') {
            ' '
        } else {
            ch
        };
        if result.len() + ch.len_utf8() > max_bytes {
            break;
        }
        result.push(ch);
    }
    result
}

// Match x64dbg's quoted command argument rules, including trailing backslashes.
fn quoted(text: &str) -> String {
    let mut result = String::from("\"");
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            let mut count = 1;
            while chars.peek() == Some(&'\\') {
                chars.next();
                count += 1;
            }
            match chars.peek().copied() {
                Some('"' | '{') => {
                    result.push_str(&"\\".repeat(count * 2 + 1));
                    result.push(chars.next().unwrap());
                }
                None => result.push_str(&"\\".repeat(count * 2)),
                _ => result.push_str(&"\\".repeat(count)),
            }
        } else {
            if matches!(ch, '"' | '{') {
                result.push('\\');
            }
            result.push(ch);
        }
    }
    result.push('"');
    result
}

fn label(name: &str, address: u64) -> String {
    let mut symbol = String::from("uie_");
    for ch in name.chars().take(160) {
        symbol.push(if ch.is_ascii_alphanumeric() || ch == '_' {
            ch
        } else {
            '_'
        });
    }
    symbol.push_str(&format!("_{address:x}"));
    symbol
}

fn script(native: &Value, constants: Option<&Value>, module: &str) -> Result<String, String> {
    module_name(module)?;
    let functions = native["functions"]
        .as_array()
        .ok_or("native report has no functions array")?;
    if functions.len() > MAX_ROWS {
        return Err("too many symbols to export".into());
    }
    let mut labels = BTreeMap::new();
    let mut comments: BTreeMap<u64, BTreeSet<String>> = BTreeMap::new();
    for function in functions {
        let address = rva(&function["rva"])?;
        let name = function["python_name"]
            .as_str()
            .or_else(|| function["name"].as_str())
            .ok_or("native symbol has no name")?;
        labels
            .entry(address)
            .or_insert_with(|| label(name, address));
        comments
            .entry(address)
            .or_default()
            .insert(format!("UIE symbol: {}", visible(name, 240)));
    }
    if let Some(rows) = constants.and_then(|value| value["annotations"].as_array()) {
        if rows.len() > MAX_ROWS {
            return Err("too many decoded-string annotations to export".into());
        }
        for row in rows {
            if row["kind"].as_str() != Some("string_candidate") {
                continue;
            }
            // Stack locations are synthetic: annotate the decoding instruction, never the stack offset.
            let address = rva(&row["instruction_rva"])?;
            let value = row["value"].as_str().ok_or("decoded string has no text")?;
            let encoding = row["encoding"].as_str().unwrap_or("ASCII");
            comments.entry(address).or_default().insert(format!(
                "UIE static string candidate ({}): {}",
                visible(encoding, 24),
                visible(value, MAX_COMMENT_BYTES)
            ));
        }
    }
    if labels.is_empty() && comments.is_empty() {
        return Err("no native symbols or decoded strings to export".into());
    }
    let base = format!("mod.fromname(\"{module}\")");
    let maximum = labels
        .keys()
        .chain(comments.keys())
        .copied()
        .max()
        .unwrap_or(0);
    let mut text = format!(
        "// UIE x64dbg offline annotation import\n// Module: {module}\n// Load the matching binary before running this script. No process is started here.\n// Labels are normalized; original names remain in comments.\n// Import replaces labels/comments at annotated RVAs. Static string candidates are unverified.\ncmp {}, 0\njne uie_module_loaded\nlog \"UIE: module is not loaded; import cancelled\"\nret\nuie_module_loaded:\ncmp {}, 0x{maximum:x}\nja uie_module_valid\nlog \"UIE: module size does not cover report RVAs; import cancelled\"\nret\nuie_module_valid:\n",
        quoted(&base), quoted(&format!("mod.size({base})"))
    );
    for (address, name) in labels {
        text.push_str(&format!(
            "lblset {}, {}\n",
            quoted(&format!("{base}+0x{address:x}")),
            quoted(&name)
        ));
    }
    for (address, values) in comments {
        let comment = visible(
            &values.into_iter().collect::<Vec<_>>().join(" | "),
            MAX_COMMENT_BYTES,
        );
        text.push_str(&format!(
            "cmtset {}, {}\n",
            quoted(&format!("{base}+0x{address:x}")),
            quoted(&comment)
        ));
    }
    text.push_str("ret\n");
    Ok(text)
}

/// Write a script only; this never launches x64dbg or the analyzed program.
pub fn export(output: &Path, module: &str) -> Result<PathBuf, String> {
    module_name(module)?;
    let native = report(&output.join("native-report.json"))?;
    let constants_path = output.join("native-constants-report.json");
    let constants = match fs::metadata(&constants_path) {
        Ok(_) => Some(report(&constants_path)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            native.get("uie_constant_analysis").cloned()
        }
        Err(error) => return Err(error.to_string()),
    };
    let text = script(&native, constants.as_ref(), module)?;
    for index in 0..1000 {
        let suffix = if index == 0 {
            String::new()
        } else {
            format!("-{index}")
        };
        let path = output.join(format!("uie-x64dbg{suffix}.txt"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                file.write_all(text.as_bytes())
                    .map_err(|error| error.to_string())?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("too many existing x64dbg exports".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn quotes_follow_debugger_rules_for_paths_braces_and_trailing_slashes() {
        assert_eq!(quoted("C:\\temp\\"), "\"C:\\temp\\\\\"");
        assert_eq!(quoted("x\"{rax}"), "\"x\\\"\\{rax}\"");
        assert_eq!(quoted("a\\\"b"), "\"a\\\\\\\"b\"");
        assert_eq!(visible("bad\r\nret\0\u{2028}name", 100), "bad  ret  name");
    }

    #[test]
    fn module_and_rva_are_validated_instead_of_using_absolute_addresses() {
        assert!(module_name("sample (1).exe").is_ok());
        for module in ["../bad.exe", "a\";run", "a:b", "a\nret", ""] {
            assert!(module_name(module).is_err());
        }
        assert_eq!(rva(&json!("0x102a")).unwrap(), 0x102a);
        assert_eq!(rva(&json!(0x102au64)).unwrap(), 0x102a);
        assert!(rva(&json!("0x14000102a")).is_err());
        assert!(rva(&json!("14000102a")).is_err());
        assert!(rva(&Value::Null).is_err());
    }

    #[test]
    fn exports_lazy_symbols_and_stack_strings_at_instruction_rvas() {
        let native = json!({"lazy":true,"functions":[{"name":"FUN_140001000","python_name":"core.Rect.cell","rva":"0x1000","address":"140001000"}]});
        let constants = json!({"annotations":[{"kind":"string_candidate","instruction_rva":"0x102a","location":"stack-0x20","value":"hello\";ret\n{rax}"},{"kind":"constant","instruction_rva":"0x1000","value":"0x123"}]});
        let text = script(&native, Some(&constants), "sample (1).exe").unwrap();
        assert!(text.contains(
            "lblset \"mod.fromname(\\\"sample (1).exe\\\")+0x1000\", \"uie_core_Rect_cell_1000\""
        ));
        assert!(text.contains("cmtset \"mod.fromname(\\\"sample (1).exe\\\")+0x102a\""));
        assert!(!text.contains("stack-0x20"));
        assert!(!text.contains("140001000"));
        assert!(!text.contains("ret\n{rax}"));
        assert!(text.contains("cmp \"mod.size(mod.fromname(\\\"sample (1).exe\\\"))\", 0x102a"));
        assert!(text.ends_with("ret\n"));
    }
}
