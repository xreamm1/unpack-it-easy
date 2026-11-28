use crate::project::{self, Project};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

const MAX_DATABASE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DATABASE_FILES: usize = 100_000;
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const REPORTS: &[&str] = &[
    "indicators.json",
    "renames.json",
    "asar-report.json",
    "java-report.json",
    "triage-report.json",
    "analysis.json",
    "objects-report.json",
    "python-report.json",
    "native-report.json",
    "analysis-profile.json",
    "native-lift-report.json",
    "native-constants-report.json",
    "native-tables-report.json",
    "nuitka-modules-report.json",
    "python-methods-report.json",
    "python-api-types.json",
    "cython-strings-report.json",
    "cython-slots-report.json",
    "raw-native-pseudocode.txt",
    "unpack-report.json",
    "packed-analysis.json",
    "uie-session.json",
    "uie-session.log",
    "equivalence.json",
    "smoke-test.json",
    "decompiled.c",
];

fn safe_relative(path: &Path) -> bool {
    let Some(text) = path.to_str() else {
        return false;
    };
    let normalized = text.replace('\\', "/");
    !normalized.contains([':', '\0'])
        && normalized
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && path.components().all(|c| matches!(c, Component::Normal(_)))
}

fn bounded_copy(
    input: impl Read,
    output: &mut impl Write,
    declared: u64,
    remaining: u64,
) -> Result<u64, String> {
    let limit = declared.min(remaining);
    let written = std::io::copy(&mut input.take(limit + 1), output).map_err(|e| e.to_string())?;
    if written != declared || written > remaining {
        return Err(
            "archive entry size differs from its header or exceeds the extraction limit".into(),
        );
    }
    Ok(written)
}

pub fn export(path: &Path, project: &Project) -> Result<(), String> {
    let mut files = BTreeMap::new();
    let mut size = 0;
    let actual_sources = project::source_hashes(&project.output)?;
    let source_set_changed = actual_sources != project.source_sha256;
    for relative in actual_sources.into_keys() {
        add_file(
            &mut files,
            relative.clone(),
            &project.output.join(relative),
            &mut size,
        )?;
    }
    for name in REPORTS {
        let file = project.output.join(name);
        if file.is_file() && !files.contains_key(Path::new(name)) {
            add_file(&mut files, PathBuf::from(name), &file, &mut size)?;
        }
    }
    let native_reports: Vec<_> = files
        .keys()
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name == "native-report.json")
        })
        .cloned()
        .collect();
    for relative in native_reports {
        let mut report: serde_json::Value =
            serde_json::from_slice(&files[&relative]).map_err(|e| e.to_string())?;
        if report["lazy"].as_bool() != Some(true) {
            continue;
        }
        let Some(input) = report["native_input"].as_str() else {
            continue;
        };
        let input = PathBuf::from(input);
        let input = if input.is_absolute() {
            input
        } else {
            project.output.join(relative.parent().unwrap()).join(input)
        };
        let expected = report["native_input_sha256"]
            .as_str()
            .ok_or("lazy project is missing its original binary hash")?
            .to_owned();
        if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("invalid native input hash".into());
        }
        let embedded = PathBuf::from(format!("native-inputs/{expected}.bin"));
        if !files.contains_key(&embedded) {
            add_file(&mut files, embedded.clone(), &input, &mut size)?;
        }
        if format!("{:x}", Sha256::digest(&files[&embedded])) != expected {
            return Err(
                "original native binary changed; cannot save a portable lazy project".into(),
            );
        }
        // Relative to the report, including reports for nested modules.
        let depth = relative.parent().unwrap().components().count();
        report["native_input"] = serde_json::json!(format!(
            "{}native-inputs/{expected}.bin",
            "../".repeat(depth)
        ));
        let updated = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
        size = size - files[&relative].len() as u64 + updated.len() as u64;
        files.insert(relative, updated);
    }
    if files.is_empty() {
        return Err("нет файлов для базы".into());
    }
    let mut manifest = serde_json::to_value(project).map_err(|e| e.to_string())?;
    manifest["output"] = serde_json::json!(".");
    let mut hashes = BTreeMap::new();
    let mut changed = source_set_changed;
    for (relative, bytes) in &files {
        if relative.starts_with("source") || relative.extension().is_some_and(|e| e == "c") {
            let hash = format!("{:x}", Sha256::digest(bytes));
            if project
                .source_sha256
                .get(relative)
                .is_some_and(|old| old != &hash)
            {
                changed = true;
            }
            hashes.insert(relative.clone(), hash);
        }
    }
    manifest["source_sha256"] = serde_json::to_value(hashes).map_err(|e| e.to_string())?;
    if changed {
        manifest["verification"] = serde_json::json!(
            "ручные правки сохранены; эквивалентность после редактирования не проверена"
        );
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    if manifest_bytes.len() > MAX_MANIFEST_BYTES
        || files.len() + 1 > MAX_DATABASE_FILES
        || size
            .checked_add(manifest_bytes.len() as u64)
            .is_none_or(|total| total > MAX_DATABASE_BYTES)
    {
        return Err("project manifest or database exceeds the supported size limit".into());
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let temporary = path.with_extension(format!("uie.tmp_{stamp}"));
    let result = (|| {
        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        let mut archive = ZipWriter::new(file);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        archive
            .start_file("project.json", options)
            .map_err(|e| e.to_string())?;
        archive
            .write_all(&manifest_bytes)
            .map_err(|e| e.to_string())?;
        for (relative, bytes) in files {
            archive
                .start_file(relative.to_string_lossy().replace('\\', "/"), options)
                .map_err(|e| e.to_string())?;
            archive.write_all(&bytes).map_err(|e| e.to_string())?;
        }
        let finished = archive.finish().map_err(|e| e.to_string())?;
        finished.sync_all().map_err(|e| e.to_string())?;
        if finished.metadata().map_err(|e| e.to_string())?.len() > MAX_DATABASE_BYTES {
            return Err("compressed database exceeds the supported file size".into());
        }
        drop(finished);
        fs::rename(&temporary, path).map_err(|e| e.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn add_file(
    files: &mut BTreeMap<PathBuf, Vec<u8>>,
    relative: PathBuf,
    file: &Path,
    size: &mut u64,
) -> Result<(), String> {
    if !safe_relative(&relative) {
        return Err("недопустимый путь в базе".into());
    }
    let input = File::open(file).map_err(|e| e.to_string())?;
    let length = input.metadata().map_err(|e| e.to_string())?.len();
    if length > MAX_DATABASE_BYTES.saturating_sub(*size) || files.len() >= MAX_DATABASE_FILES {
        return Err("база превышает лимит 512 MiB / 100000 файлов".into());
    }
    let mut bytes = vec![];
    input
        .take(MAX_DATABASE_BYTES - *size + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    *size += bytes.len() as u64;
    if *size > MAX_DATABASE_BYTES {
        return Err("база выросла во время сохранения".into());
    }
    files.insert(relative, bytes);
    Ok(())
}

pub fn unpack(path: &Path) -> Result<Project, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > MAX_DATABASE_BYTES {
        return Err("слишком большая база".into());
    }
    let mut archive = ZipArchive::new(file).map_err(|e| format!("повреждённая база .uie: {e}"))?;
    if archive.len() > MAX_DATABASE_FILES {
        return Err("слишком много файлов в базе".into());
    }
    let mut entries = HashSet::new();
    let mut total = 0u64;
    for index in 0..archive.len() {
        let entry = archive.by_index(index).map_err(|e| e.to_string())?;
        let relative = PathBuf::from(entry.name().replace('\\', "/"));
        if !safe_relative(&relative) || !entries.insert(relative.clone()) || entry.is_dir() {
            return Err("недопустимый или повторяющийся путь в базе".into());
        }
        let native = relative.components().count() == 1
            && relative.extension().is_some_and(|e| e == "c")
            && relative
                .file_stem()
                .is_some_and(|s| s.to_string_lossy().ends_with("_decompiled"));
        if relative != Path::new("project.json")
            && !relative.starts_with("source")
            && !relative.starts_with("native-inputs")
            && !native
            && !REPORTS.iter().any(|name| relative == Path::new(name))
        {
            return Err("неизвестный файл в базе".into());
        }
        total = total
            .checked_add(entry.size())
            .ok_or("размер базы переполнен")?;
        if total > MAX_DATABASE_BYTES {
            return Err("распакованная база превышает 512 MiB".into());
        }
    }
    let mut metadata = String::new();
    archive
        .by_name("project.json")
        .map_err(|e| e.to_string())?
        .take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_string(&mut metadata)
        .map_err(|e| e.to_string())?;
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err("слишком большой заголовок базы".into());
    }
    let mut project: Project = serde_json::from_str(&metadata).map_err(|e| e.to_string())?;
    if project.output != Path::new(".") {
        return Err("недопустимый корень базы".into());
    }
    let folder = project::app_root()
        .join("projects")
        .join(format!("open_{}", project::sha256(path)?));
    let marker = folder.join(".uie-complete");
    if !marker.is_file() {
        fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
        let mut actual_total = metadata.len() as u64;
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).map_err(|e| e.to_string())?;
            if entry.name() == "project.json" {
                continue;
            }
            let destination = folder.join(entry.name().replace('\\', "/"));
            fs::create_dir_all(destination.parent().unwrap()).map_err(|e| e.to_string())?;
            let mut output = File::create(&destination).map_err(|e| e.to_string())?;
            let declared = entry.size();
            match bounded_copy(
                &mut entry,
                &mut output,
                declared,
                MAX_DATABASE_BYTES - actual_total,
            ) {
                Ok(written) => actual_total += written,
                Err(error) => {
                    drop(output);
                    let _ = fs::remove_file(destination);
                    return Err(error);
                }
            }
        }
        fs::write(marker, b"UIE 1").map_err(|e| e.to_string())?;
    }
    project.output = folder;
    Ok(project)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture_root(name: &str) -> PathBuf {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("uie-{name}-{stamp}"));
        fs::create_dir_all(root.join("source")).unwrap();
        fs::write(root.join("source/main.py"), "answer = 42\n").unwrap();
        root
    }
    #[test]
    fn actual_output_is_bounded_even_when_zip_size_is_forged() {
        let root = fixture_root("forged-zip");
        let project = project::capture(
            "fixture",
            &root,
            false,
            &crate::detect::inspect(b"fixture").unwrap(),
        )
        .unwrap();
        let mut manifest = serde_json::to_value(project).unwrap();
        manifest["output"] = serde_json::json!(".");
        let mut zip = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        zip.start_file("project.json", options).unwrap();
        zip.write_all(&serde_json::to_vec(&manifest).unwrap())
            .unwrap();
        zip.start_file("source/bad.bin", options).unwrap();
        zip.write_all(&vec![0; 2 * 1024 * 1024]).unwrap();
        let mut bytes = zip.finish().unwrap().into_inner();
        let mut patched = 0;
        for offset in 0..bytes.len().saturating_sub(64) {
            let (name_at, size_at) = if bytes[offset..].starts_with(b"PK\x03\x04") {
                (offset + 30, offset + 22)
            } else if bytes[offset..].starts_with(b"PK\x01\x02") {
                (offset + 46, offset + 24)
            } else {
                continue;
            };
            if bytes[name_at..].starts_with(b"source/bad.bin") {
                bytes[size_at..size_at + 4].copy_from_slice(&1u32.to_le_bytes());
                patched += 1;
            }
        }
        assert_eq!(patched, 2);
        let path = root.join("forged.uie");
        fs::write(&path, bytes).unwrap();
        assert!(unpack(&path).is_err());
        let extraction = project::app_root()
            .join("projects")
            .join(format!("open_{}", project::sha256(&path).unwrap()));
        assert!(!extraction.join(".uie-complete").exists());
        assert!(!extraction.join("source/bad.bin").exists());
        if extraction.exists() {
            fs::remove_dir_all(extraction).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn oversized_manifest_preserves_the_previous_database() {
        let root = fixture_root("large-manifest");
        let mut analysis = crate::detect::inspect(b"fixture").unwrap();
        analysis.notes.push("x".repeat(MAX_MANIFEST_BYTES));
        let project = project::capture("fixture", &root, false, &analysis).unwrap();
        let target = root.join("saved.uie");
        fs::write(&target, b"previous database").unwrap();
        assert!(export(&target, &project).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"previous database");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn lazy_database_keeps_its_binary_after_original_is_moved() {
        let root = fixture_root("portable-native");
        let input = root.join("original.dll");
        fs::write(&input, b"owned binary fixture").unwrap();
        let hash = project::sha256(&input).unwrap();
        fs::write(
            root.join("native-report.json"),
            serde_json::to_vec(
                &serde_json::json!({"lazy":true,"native_input":input,"native_input_sha256":hash}),
            )
            .unwrap(),
        )
        .unwrap();
        let project = project::capture(
            "fixture",
            &root,
            false,
            &crate::detect::inspect(b"fixture").unwrap(),
        )
        .unwrap();
        let target = root.join("portable.uie");
        export(&target, &project).unwrap();
        fs::rename(&input, root.join("moved.dll")).unwrap();
        let restored = project::open(&target).unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(restored.output.join("native-report.json")).unwrap())
                .unwrap();
        let binary = restored
            .output
            .join(report["native_input"].as_str().unwrap());
        assert_eq!(project::sha256(&binary).unwrap(), hash);
        assert!(!Path::new(report["native_input"].as_str().unwrap()).is_absolute());
        fs::remove_dir_all(restored.output).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn database_contains_source_assets_and_manual_changes() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("uie-roundtrip-{stamp}"));
        fs::create_dir_all(root.join("source/assets")).unwrap();
        fs::write(root.join("source/тест.py"), "print('first')\n").unwrap();
        fs::write(root.join("source/assets/icon.bin"), [0, 255, 19]).unwrap();
        let renames = vec![crate::rename::Change {
            file: "source/тест.py".into(),
            from: "uVar1".into(),
            to: "counter".into(),
            occurrences: 2,
        }];
        fs::write(
            root.join("renames.json"),
            serde_json::to_vec(&renames).unwrap(),
        )
        .unwrap();
        fs::write(root.join("indicators.json"), b"{\"hits\":[]}").unwrap();
        let analysis = crate::detect::inspect(b"unknown").unwrap();
        let project = project::capture("test-sha", &root, false, &analysis).unwrap();
        fs::write(root.join("source/тест.py"), "print('manual fix')\n").unwrap();
        let target = root.join("sample_decompiled.uie");
        export(&target, &project).unwrap();
        let restored = project::open(&target).unwrap();
        assert_eq!(
            fs::read_to_string(restored.output.join("source/тест.py")).unwrap(),
            "print('manual fix')\n"
        );
        assert_eq!(
            fs::read(restored.output.join("source/assets/icon.bin")).unwrap(),
            [0, 255, 19]
        );
        let changes: Vec<crate::rename::Change> =
            serde_json::from_slice(&fs::read(restored.output.join("renames.json")).unwrap())
                .unwrap();
        assert_eq!(changes[0].to, "counter");
        assert!(restored.output.join("indicators.json").is_file());
        assert!(restored.verification.contains("ручные правки"));
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(restored.output).unwrap();
    }
    #[test]
    fn archive_paths_cannot_escape_the_project() {
        assert!(!safe_relative(Path::new("../outside.py")));
        assert!(!safe_relative(Path::new("C:/outside.py")));
        for name in [
            "C:\\outside.py",
            "source/../outside.py",
            "source/x:stream",
            "//server/share",
            "source//x",
        ] {
            assert!(!safe_relative(Path::new(name)));
        }
        assert!(safe_relative(Path::new("source/тест.py")));
    }
}
