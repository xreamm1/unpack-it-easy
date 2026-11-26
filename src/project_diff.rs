use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Read,
    path::{Component, Path},
};

const MAX_FILES: usize = 100_000;
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_FUNCTION_TEXT: usize = 32 * 1024 * 1024;

#[derive(Clone, Serialize)]
struct Function {
    file: String,
    line: usize,
    address: String,
    name: String,
    body_sha256: String,
}
#[derive(Default)]
struct Snapshot {
    files: BTreeMap<String, String>,
    functions: BTreeMap<String, Function>,
    skipped_function_files: Vec<String>,
    manifest_matches: Option<bool>,
    bytes: u64,
}

fn safe(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
}
fn name(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}
fn source(path: &Path) -> bool {
    path.starts_with("source")
        || (path.components().count() == 1
            && path.extension().is_some_and(|extension| extension == "c")
            && path.file_stem().is_some_and(|stem| {
                stem == "decompiled" || stem.to_string_lossy().ends_with("_decompiled")
            }))
}
fn function_header(line: &str) -> Option<(&str, &str)> {
    let text = line
        .trim()
        .strip_prefix("/* Function at ")?
        .strip_suffix("*/")?
        .trim();
    let (address, label) = text.split_once(": ")?;
    if address.is_empty() || !address.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    Some((address, label.trim()))
}
fn functions(file: &str, bytes: &[u8], snapshot: &mut Snapshot) -> Result<(), String> {
    if !file.ends_with(".c") && !file.ends_with(".cpp") {
        return Ok(());
    }
    if bytes.len() > MAX_FUNCTION_TEXT {
        snapshot.skipped_function_files.push(file.into());
        return Ok(());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|error| format!("invalid UTF-8 native source {file}: {error}"))?;
    let lines: Vec<_> = text.lines().collect();
    let headers: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(line, text)| {
            function_header(text).map(|(address, label)| (line, address, label))
        })
        .collect();
    for (index, (line, address, label)) in headers.iter().enumerate() {
        let end = headers.get(index + 1).map_or(lines.len(), |next| next.0);
        let body = lines[line + 1..end]
            .iter()
            .map(|line| line.trim_end())
            .collect::<Vec<_>>()
            .join("\n");
        if !body.contains('{') {
            continue;
        } // Lazy indexes and failed-disassembly comments are not recovered bodies.
        let scope = if file.starts_with("source/functions/") || !file.contains('/') {
            "<root>"
        } else {
            file
        };
        let key = format!("{scope}@{}", address.to_ascii_lowercase());
        let function = Function {
            file: file.into(),
            line: line + 1,
            address: address.to_ascii_lowercase(),
            name: (*label).into(),
            body_sha256: format!("{:x}", Sha256::digest(body.trim().as_bytes())),
        };
        if let Some(previous) = snapshot.functions.insert(key, function.clone()) {
            if previous.body_sha256 != function.body_sha256 {
                return Err(format!("conflicting native bodies at {address} in project"));
            }
        }
    }
    Ok(())
}
fn add(relative: &Path, bytes: &[u8], snapshot: &mut Snapshot) -> Result<(), String> {
    if snapshot.files.len() >= MAX_FILES {
        return Err("comparison file limit reached".into());
    }
    snapshot.bytes = snapshot
        .bytes
        .checked_add(bytes.len() as u64)
        .ok_or("comparison size overflow")?;
    if snapshot.bytes > MAX_BYTES {
        return Err("comparison source limit: 512 MiB".into());
    }
    let file = name(relative);
    snapshot
        .files
        .insert(file.clone(), format!("{:x}", Sha256::digest(bytes)));
    functions(&file, bytes, snapshot)
}
fn regular(path: &Path) -> Result<fs::Metadata, String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("comparison rejects links: {}", path.display()));
    }
    Ok(metadata)
}
fn bounded_read(path: &Path, remaining: u64) -> Result<Vec<u8>, String> {
    let metadata = regular(path)?;
    if !metadata.is_file() || metadata.len() > remaining {
        return Err(format!(
            "invalid or oversized comparison file: {}",
            path.display()
        ));
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(remaining + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > remaining {
        return Err("comparison file grew beyond size limit".into());
    }
    Ok(bytes)
}
fn directory(root: &Path) -> Result<Snapshot, String> {
    if !regular(root)?.is_dir() {
        return Err("comparison root is not a directory".into());
    }
    let mut snapshot = Snapshot::default();
    let mut folders = vec![root.to_path_buf()];
    let mut visited = 0;
    while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(&folder).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            visited += 1;
            if visited > MAX_FILES {
                return Err("comparison directory entry limit reached".into());
            }
            let path = entry.path();
            let relative = path.strip_prefix(root).map_err(|error| error.to_string())?;
            if !source(relative) {
                continue;
            }
            let metadata = regular(&path)?;
            if metadata.is_dir() {
                folders.push(path);
            } else if metadata.is_file() {
                add(
                    relative,
                    &bounded_read(&path, MAX_BYTES - snapshot.bytes)?,
                    &mut snapshot,
                )?;
            } else {
                return Err(format!("unsupported comparison entry: {}", path.display()));
            }
        }
    }
    if snapshot.files.is_empty() {
        return Err("project contains no recovered source files".into());
    }
    Ok(snapshot)
}
fn manifest_hashes(manifest: &Value) -> Result<BTreeMap<String, String>, String> {
    let rows = manifest["source_sha256"]
        .as_object()
        .ok_or("invalid project source manifest")?;
    let mut result = BTreeMap::new();
    for (path, hash) in rows {
        let normalized = path.replace('\\', "/");
        if !safe(Path::new(&normalized)) || !source(Path::new(&normalized)) {
            return Err("unsafe source path in comparison manifest".into());
        }
        let hash = hash.as_str().ok_or("invalid source hash")?;
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid source SHA-256".into());
        }
        if result
            .insert(normalized, hash.to_ascii_lowercase())
            .is_some()
        {
            return Err("duplicate source manifest path".into());
        }
    }
    if result.is_empty() {
        return Err("empty comparison source manifest".into());
    }
    Ok(result)
}
fn snapshot(path: &Path) -> Result<Snapshot, String> {
    let metadata = regular(path)?;
    if metadata.is_dir() {
        return directory(path);
    }
    if !metadata.is_file() {
        return Err("comparison input is not a regular file".into());
    }
    if path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("uie"))
    {
        if metadata.len() > MAX_BYTES {
            return Err("comparison archive limit: 512 MiB".into());
        }
        let mut archive =
            zip::ZipArchive::new(File::open(path).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        if archive.len() > MAX_FILES {
            return Err("comparison archive entry limit reached".into());
        }
        let mut result = Snapshot::default();
        let mut names = BTreeSet::new();
        let mut manifest = None;
        let mut expanded = 0u64;
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).map_err(|error| error.to_string())?;
            let relative = entry.name().replace('\\', "/");
            let relative = Path::new(&relative);
            if !safe(relative)
                || entry.is_dir()
                || !names.insert(name(relative))
                || entry
                    .unix_mode()
                    .is_some_and(|mode| !matches!(mode & 0o170000, 0 | 0o100000))
            {
                return Err("unsafe or duplicate comparison archive entry".into());
            }
            expanded = expanded
                .checked_add(entry.size())
                .ok_or("archive size overflow")?;
            if expanded > MAX_BYTES {
                return Err("comparison expanded archive limit: 512 MiB".into());
            }
            if source(relative) || relative == Path::new("project.json") {
                let limit = if relative == Path::new("project.json") {
                    1024 * 1024
                } else {
                    MAX_BYTES - result.bytes
                };
                let mut bytes = Vec::new();
                entry
                    .by_ref()
                    .take(limit + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|error| error.to_string())?;
                if bytes.len() as u64 > limit {
                    return Err("oversized comparison archive entry".into());
                }
                if relative == Path::new("project.json") {
                    manifest = Some(
                        serde_json::from_slice::<Value>(&bytes)
                            .map_err(|error| error.to_string())?,
                    );
                } else {
                    add(relative, &bytes, &mut result)?;
                }
            }
        }
        let manifest = manifest.ok_or("missing project.json in comparison archive")?;
        let _: crate::project::Project = serde_json::from_value(manifest.clone())
            .map_err(|error| format!("invalid comparison project manifest: {error}"))?;
        if manifest["output"].as_str() != Some(".") {
            return Err("invalid comparison archive root".into());
        }
        result.manifest_matches = Some(manifest_hashes(&manifest)? == result.files);
        return Ok(result);
    }
    bounded_read(path, 1024 * 1024)?;
    let project = crate::project::open(path)?;
    let mut result = directory(&project.output)?;
    result.manifest_matches = Some(
        project
            .source_sha256
            .iter()
            .map(|(path, hash)| (name(path), hash.clone()))
            .collect::<BTreeMap<_, _>>()
            == result.files,
    );
    Ok(result)
}

/// Compares recovered text and bytes, not program behavior. Archives are read without extraction.
pub fn compare(left: &Path, right: &Path) -> Result<Value, String> {
    let left = snapshot(left)?;
    let right = snapshot(right)?;
    let added: Vec<_> = right
        .files
        .keys()
        .filter(|key| !left.files.contains_key(*key))
        .collect();
    let removed: Vec<_> = left
        .files
        .keys()
        .filter(|key| !right.files.contains_key(*key))
        .collect();
    let changed: Vec<_> = left
        .files
        .iter()
        .filter_map(|(file, hash)| {
            right
                .files
                .get(file)
                .filter(|other| *other != hash)
                .map(|other| json!({"file":file,"left_sha256":hash,"right_sha256":other}))
        })
        .collect();
    let mut matches = Vec::new();
    let mut left_remaining = left.functions.clone();
    let mut right_remaining = right.functions.clone();
    for (key, function) in &left.functions {
        if let Some(other) = right_remaining.remove(key) {
            matches.push((function.clone(), other, "module and address"));
            left_remaining.remove(key);
        }
    }
    let mut names: BTreeMap<(String, String), usize> = BTreeMap::new();
    for (key, function) in left_remaining.iter().chain(right_remaining.iter()) {
        let scope = key
            .rsplit_once('@')
            .map_or(key.as_str(), |(scope, _)| scope);
        *names
            .entry((scope.to_owned(), function.name.clone()))
            .or_default() += 1;
    }
    let right_names: BTreeMap<_, _> = right_remaining
        .iter()
        .map(|(key, function)| {
            let scope = key
                .rsplit_once('@')
                .map_or(key.as_str(), |(scope, _)| scope);
            ((scope.to_owned(), function.name.clone()), key.clone())
        })
        .collect();
    let left_keys: Vec<_> = left_remaining.keys().cloned().collect();
    for key in left_keys {
        let function = &left_remaining[&key];
        let scope = key
            .rsplit_once('@')
            .map_or(key.as_str(), |(scope, _)| scope);
        if function.name.starts_with("FUN_")
            || function.name.starts_with("sub_")
            || names.get(&(scope.to_owned(), function.name.clone())) != Some(&2)
        {
            continue;
        }
        if let Some(right_key) = right_names.get(&(scope.to_owned(), function.name.clone())) {
            let other = right_remaining.remove(right_key).unwrap();
            let function = left_remaining.remove(&key).unwrap();
            matches.push((function, other, "unique name; address changed"));
        }
    }
    let function_changes:Vec<_>=matches.iter().filter(|(left,right,_)|left.body_sha256!=right.body_sha256||left.name!=right.name||left.address!=right.address).map(|(left,right,matched_by)|json!({"left":left,"right":right,"matched_by":matched_by,"body_changed":left.body_sha256!=right.body_sha256})).collect();
    Ok(
        json!({"interpretation":"Byte and recovered C text comparison only; differences do not prove functional or semantic changes. Native functions match by module/address first, then an unambiguous non-generated name.","files":{"added":added,"removed":removed,"changed":changed},"native_functions":{"changed":function_changes,"added":right_remaining.values().collect::<Vec<_>>(),"removed":left_remaining.values().collect::<Vec<_>>(),"matched":matches.len()},"left_manifest_matches":left.manifest_matches,"right_manifest_matches":right.manifest_matches,"function_text_skipped":{"left":left.skipped_function_files,"right":right.skipped_function_files}}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    fn roots() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("uie-diff-{}-{stamp}", std::process::id()));
        let left = root.join("left");
        let right = root.join("right");
        fs::create_dir_all(left.join("source")).unwrap();
        fs::create_dir_all(right.join("source")).unwrap();
        (root, left, right)
    }
    #[test]
    fn detects_files_and_native_body_changes() {
        let (root, left, right) = roots();
        fs::write(left.join("source/same.py"), "print(1)\n").unwrap();
        fs::write(right.join("source/same.py"), "print(1)\n").unwrap();
        fs::write(left.join("source/gone.py"), "gone").unwrap();
        fs::write(right.join("source/new.py"), "new").unwrap();
        fs::write(
            left.join("app_decompiled.c"),
            "/* Function at 140001000: test */\nint test(void) { return 1; }\n",
        )
        .unwrap();
        fs::write(
            right.join("app_decompiled.c"),
            "/* Function at 140001000: test */\nint test(void) { return 2; }\n",
        )
        .unwrap();
        let report = compare(&left, &right).unwrap();
        assert_eq!(report["files"]["added"], json!(["source/new.py"]));
        assert_eq!(report["files"]["removed"], json!(["source/gone.py"]));
        assert_eq!(report["native_functions"]["matched"], 1);
        assert_eq!(
            report["native_functions"]["changed"][0]["body_changed"],
            true
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn indexes_are_not_function_bodies_and_bad_manifests_fail() {
        let (root, left, right) = roots();
        for path in [&left, &right] {
            fs::write(
                path.join("app_decompiled.c"),
                "/* Function at 140001000: FUN_140001000 */\n",
            )
            .unwrap();
        }
        let report = compare(&left, &right).unwrap();
        assert_eq!(report["native_functions"]["matched"], 0);
        assert_eq!(report["files"]["changed"], json!([]));
        let bad = root.join("bad.json");
        fs::write(&bad, "{}").unwrap();
        assert!(compare(&bad, &right).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn compares_archive_without_extracting_it() {
        use std::io::Write;
        let (root, left, right) = roots();
        fs::write(right.join("source/a.py"), "print(7)\n").unwrap();
        let target = left.join("snapshot.uie");
        let mut archive = zip::ZipWriter::new(File::create(&target).unwrap());
        let options = zip::write::SimpleFileOptions::default();
        let bytes = b"print(7)\n";
        let analysis = crate::detect::inspect(b"unknown").unwrap();
        let mut project =
            crate::project::capture("test-input-hash", &right, false, &analysis).unwrap();
        project.output = ".".into();
        archive.start_file("project.json", options).unwrap();
        archive
            .write_all(&serde_json::to_vec(&project).unwrap())
            .unwrap();
        archive.start_file("source/a.py", options).unwrap();
        archive.write_all(bytes).unwrap();
        archive.finish().unwrap();
        let before = fs::read_dir(&left)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>();
        let report = compare(&target, &right).unwrap();
        assert_eq!(report["left_manifest_matches"], true);
        assert_eq!(report["files"]["changed"], json!([]));
        assert_eq!(
            fs::read_dir(left)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect::<BTreeSet<_>>(),
            before
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn matches_many_uniquely_named_functions_after_all_addresses_move() {
        let (root, left, right) = roots();
        let mut first = String::new();
        let mut second = String::new();
        for index in 0..2000u64 {
            let name = format!("owned_function_{index}");
            first.push_str(&format!(
                "/* Function at {:x}: {name} */\nint {name}(void) {{ return {index}; }}\n",
                0x140001000 + index * 16
            ));
            second.push_str(&format!(
                "/* Function at {:x}: {name} */\nint {name}(void) {{ return {index}; }}\n",
                0x180001000 + (2000 - index) * 16
            ));
        }
        fs::write(left.join("app_decompiled.c"), first).unwrap();
        fs::write(right.join("app_decompiled.c"), second).unwrap();
        let report = compare(&left, &right).unwrap();
        assert_eq!(report["native_functions"]["matched"], 2000);
        assert!(report["native_functions"]["changed"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["body_changed"] == false));
        fs::remove_dir_all(root).unwrap();
    }
}
