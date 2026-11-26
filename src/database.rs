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
            .write_all(&serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        for (relative, bytes) in files {
            archive
                .start_file(relative.to_string_lossy().replace('\\', "/"), options)
                .map_err(|e| e.to_string())?;
            archive.write_all(&bytes).map_err(|e| e.to_string())?;
        }
        archive
            .finish()
            .map_err(|e| e.to_string())?
            .sync_all()
            .map_err(|e| e.to_string())?;
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
        .take(1024 * 1024 + 1)
        .read_to_string(&mut metadata)
        .map_err(|e| e.to_string())?;
    if metadata.len() > 1024 * 1024 {
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
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).map_err(|e| e.to_string())?;
            if entry.name() == "project.json" {
                continue;
            }
            let destination = folder.join(entry.name().replace('\\', "/"));
            fs::create_dir_all(destination.parent().unwrap()).map_err(|e| e.to_string())?;
            let mut output = File::create(destination).map_err(|e| e.to_string())?;
            std::io::copy(&mut entry, &mut output).map_err(|e| e.to_string())?;
        }
        fs::write(marker, b"UIE 1").map_err(|e| e.to_string())?;
    }
    project.output = folder;
    Ok(project)
}

#[cfg(test)]
mod tests {
    use super::*;
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
        assert!(safe_relative(Path::new("source/тест.py")));
    }
}
