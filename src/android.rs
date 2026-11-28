//! Static Android recovery using the pinned upstream JADX distribution.
use crate::engine::{run_tool, Event, Settings, TOOL_TIMEOUT_SECONDS};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    ffi::OsString,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
    },
};

const VERSION: &str = "1.5.7";
const URL: &str = "https://github.com/skylot/jadx/releases/download/v1.5.7/jadx-1.5.7.zip";
const HASH: &str = "1755e4242ade71a077438723689f404079592ec7764a3a0572f98fef94ebcbf3";
const DOWNLOAD_SIZE: u64 = 74_766_896;
const MAX_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

fn logged_error(text: &str) -> bool {
    text.split(['\r', '\n'])
        .any(|record| record.trim_start().starts_with("ERROR"))
}

pub fn progress(line: &str) -> Option<crate::telemetry::Progress> {
    let rest = line
        .strip_prefix("INFO")?
        .trim_start()
        .strip_prefix("- progress:")?
        .trim();
    let mut words = rest.split_whitespace();
    let done = words.next()?.parse::<usize>().ok()?;
    if words.next()? != "of" {
        return None;
    }
    let total = words.next()?.parse::<usize>().ok()?;
    if total == 0 || done > total {
        return None;
    }
    Some(crate::telemetry::Progress {
        phase: "Android / JADX".into(),
        file: String::new(),
        done,
        total,
    })
}

struct Temporary(PathBuf);
impl Temporary {
    fn new(parent: &Path) -> Result<Self, String> {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| e.to_string())?
            .as_nanos();
        for n in 0..100 {
            let path = parent.join(format!(".android-{}-{stamp}-{n}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.to_string()),
            }
        }
        Err("cannot allocate Android temporary directory".into())
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        // Only remove this freshly created child, never a replacement link or its target.
        if fs::symlink_metadata(&self.0).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink()) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
fn cancelled(cancel: &AtomicBool) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        Err("Android recovery cancelled".into())
    } else {
        Ok(())
    }
}
fn safe_path(name: &str) -> bool {
    let name = name.strip_suffix('/').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 1024
        && name.split('/').count() <= 64
        && name.split('/').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with(['.', ' '])
                && !part.chars().any(|c| {
                    c.is_control() || ['\\', ':', '*', '?', '"', '<', '>', '|'].contains(&c)
                })
                && !matches!(
                    part.split('.')
                        .next()
                        .unwrap()
                        .to_ascii_uppercase()
                        .as_str(),
                    "CON"
                        | "PRN"
                        | "AUX"
                        | "NUL"
                        | "COM1"
                        | "COM2"
                        | "COM3"
                        | "COM4"
                        | "COM5"
                        | "COM6"
                        | "COM7"
                        | "COM8"
                        | "COM9"
                        | "LPT1"
                        | "LPT2"
                        | "LPT3"
                        | "LPT4"
                        | "LPT5"
                        | "LPT6"
                        | "LPT7"
                        | "LPT8"
                        | "LPT9"
                )
        })
}

/// Stream every entry, so sizes and CRCs are checked before any external parser runs.
fn inspect_zip(path: &Path, cancel: &AtomicBool) -> Result<(usize, u64, usize), String> {
    let mut archive = zip::ZipArchive::new(File::open(path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("invalid Android ZIP: {e}"))?;
    if archive.len() > MAX_ENTRIES {
        return Err("too many Android ZIP entries".into());
    }
    let mut names = HashSet::new();
    let mut files = HashSet::new();
    let mut paths = Vec::new();
    let mut total = 0;
    let mut dex = 0;
    for n in 0..archive.len() {
        cancelled(cancel)?;
        let mut entry = archive.by_index(n).map_err(|e| e.to_string())?;
        let name = entry.name().trim_end_matches('/').to_string();
        if !safe_path(entry.name())
            || entry.unix_mode().is_some_and(|m| m & 0o170000 == 0o120000)
            || !names.insert(name.to_lowercase())
        {
            return Err("unsafe, linked or duplicate Android ZIP path".into());
        }
        if !entry.is_dir() {
            files.insert(name.to_lowercase());
        }
        paths.push(name.to_lowercase());
        if entry.size() > MAX_BYTES - total {
            return Err("Android ZIP exceeds 512 MiB decoded limit".into());
        }
        let expected = entry.size();
        if name.to_ascii_lowercase().ends_with(".dex") {
            validate_dex_stream(&mut entry, expected, cancel)?;
            dex += 1;
            total += expected;
            continue;
        }
        let mut actual = 0;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            cancelled(cancel)?;
            let read = entry
                .read(&mut buffer)
                .map_err(|e| format!("Android ZIP read/CRC failed: {e}"))?;
            if read == 0 {
                break;
            }
            actual += read as u64;
            if actual > expected || actual > MAX_BYTES - total {
                return Err("Android ZIP size mismatch".into());
            }
        }
        if actual != expected {
            return Err("truncated Android ZIP entry".into());
        }
        total += actual;
    }
    for path in paths {
        let mut parent = Path::new(&path).parent();
        while let Some(p) = parent {
            if files.contains(p.to_string_lossy().as_ref()) {
                return Err("Android ZIP file/directory conflict".into());
            }
            parent = p.parent();
        }
    }
    Ok((archive.len(), total, dex))
}

fn adler_update(a: &mut u32, b: &mut u32, bytes: &[u8]) {
    for chunk in bytes.chunks(5552) {
        for &value in chunk {
            *a += u32::from(value);
            *b += *a;
        }
        *a %= 65521;
        *b %= 65521;
    }
}

fn validate_dex_stream(
    file: &mut impl Read,
    length: u64,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let mut header = [0u8; 112];
    file.read_exact(&mut header)
        .map_err(|_| "truncated DEX header".to_string())?;
    if &header[..4] != b"dex\n"
        || header[7] != 0
        || !matches!(&header[4..7], b"035" | b"037" | b"038" | b"039" | b"040")
    {
        return Err("unsupported DEX magic/version (supported: 035, 037–040; compact/container DEX excluded)".into());
    }
    let number = |offset| u32::from_le_bytes(header[offset..offset + 4].try_into().unwrap());
    if length > MAX_BYTES
        || number(32) as u64 != length
        || number(36) != 112
        || number(40) != 0x12345678
    {
        return Err("invalid DEX size, header or byte order".into());
    }
    for (at, stride) in [(56, 4u64), (64, 4), (72, 12), (80, 8), (88, 8), (96, 32)] {
        let count = u64::from(number(at));
        let offset = u64::from(number(at + 4));
        if (count == 0 && offset != 0)
            || (count > 0 && (offset < 112 || offset % 4 != 0 || offset + count * stride > length))
        {
            return Err("DEX identifier table lies outside the file".into());
        }
    }
    let data_size = u64::from(number(104));
    let data_offset = u64::from(number(108));
    let map_offset = u64::from(number(52));
    if data_offset + data_size > length
        || (map_offset != 0 && (map_offset < 112 || map_offset % 4 != 0 || map_offset + 4 > length))
    {
        return Err("DEX data or map lies outside the file".into());
    }
    let mut signature = sha1::Sha1::new();
    signature.update(&header[32..]);
    let (mut a, mut b) = (1u32, 0u32);
    adler_update(&mut a, &mut b, &header[12..]);
    let mut actual = 112u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        cancelled(cancel)?;
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        actual += count as u64;
        if actual > length {
            return Err("DEX length mismatch".into());
        }
        signature.update(&buffer[..count]);
        adler_update(&mut a, &mut b, &buffer[..count]);
    }
    if actual != length || signature.finalize()[..] != header[12..32] || (b << 16 | a) != number(8)
    {
        return Err("DEX signature/checksum or length mismatch".into());
    }
    Ok(())
}

fn validate_dex(path: &Path, cancel: &AtomicBool) -> Result<(), String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let length = file.metadata().map_err(|e| e.to_string())?.len();
    validate_dex_stream(&mut file, length, cancel)
}

fn verified_archive(path: &Path) -> Result<(), String> {
    if fs::symlink_metadata(path)
        .map_err(|e| e.to_string())?
        .file_type()
        .is_symlink()
        || fs::metadata(path).map_err(|e| e.to_string())?.len() != DOWNLOAD_SIZE
        || crate::project::sha256(path)? != HASH
    {
        return Err("JADX distribution integrity check failed".into());
    }
    Ok(())
}

/// Derive the expected executable JARs from the authenticated archive, not a mutable manifest.
fn jars(
    archive: &Path,
    destination: &Path,
    extract: bool,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let mut zip = zip::ZipArchive::new(File::open(archive).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut expected = HashSet::new();
    for n in 0..zip.len() {
        cancelled(cancel)?;
        let mut entry = zip.by_index(n).map_err(|e| e.to_string())?;
        let name = entry.name().to_string();
        if !name.starts_with("lib/") || !name.ends_with(".jar") || name.split('/').count() != 2 {
            continue;
        }
        expected.insert(name[4..].to_string());
        let target = destination.join(&name[4..]);
        let mut digest = Sha256::new();
        let mut output = if extract {
            Some(File::create(&target).map_err(|e| e.to_string())?)
        } else {
            None
        };
        let mut buffer = [0u8; 64 * 1024];
        loop {
            cancelled(cancel)?;
            let count = entry.read(&mut buffer).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
            if let Some(ref mut output) = output {
                output
                    .write_all(&buffer[..count])
                    .map_err(|e| e.to_string())?;
            }
        }
        if !extract
            && (fs::symlink_metadata(&target)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
                || crate::project::sha256(&target)? != format!("{:x}", digest.finalize()))
        {
            return Err("cached JADX JAR integrity check failed".into());
        }
    }
    if expected.is_empty() {
        return Err("JADX distribution contains no lib JARs".into());
    }
    for file in fs::read_dir(destination).map_err(|e| e.to_string())? {
        let file = file.map_err(|e| e.to_string())?;
        if !expected.remove(&file.file_name().to_string_lossy().into_owned()) {
            return Err("unexpected file in managed JADX library directory".into());
        }
    }
    if !expected.is_empty() {
        return Err("managed JADX library directory is incomplete".into());
    }
    Ok(())
}

pub fn prepare(
    output: &Path,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<PathBuf, String> {
    cancelled(cancel)?;
    let root = crate::runtime::root().join("jadx");
    let archive = root.join("jadx-1.5.7.zip");
    let installed = root.join(VERSION);
    let lib = installed.join("lib");
    if archive.exists() {
        verified_archive(&archive)?;
    } else {
        if crate::runtime::is_offline() {
            return Err("offline mode: verified JADX distribution is missing".into());
        }
        let temp = Temporary::new(&root)?;
        let download = temp.0.join("download.zip");
        run_tool(
            &crate::engine::find_tool(&[if cfg!(windows) { "curl.exe" } else { "curl" }]),
            &[
                "--fail".into(),
                "--location".into(),
                "--proto".into(),
                "=https".into(),
                "--proto-redir".into(),
                "=https".into(),
                "--max-filesize".into(),
                DOWNLOAD_SIZE.to_string().into(),
                "--retry".into(),
                "2".into(),
                URL.into(),
                "--output".into(),
                download.clone().into_os_string(),
            ],
            output,
            &output.join("jadx-download.log"),
            300,
            cancel,
            events,
        )?;
        verified_archive(&download)?;
        fs::rename(download, &archive).map_err(|e| e.to_string())?;
    }
    inspect_zip(&archive, cancel)?;
    if installed.exists() {
        if fs::symlink_metadata(&installed)
            .map_err(|e| e.to_string())?
            .file_type()
            .is_symlink()
            || fs::symlink_metadata(&lib)
                .map_err(|e| e.to_string())?
                .file_type()
                .is_symlink()
        {
            return Err("managed JADX directory cannot be a link".into());
        }
        jars(&archive, &lib, false, cancel)?;
    } else {
        let temp = Temporary::new(&root)?;
        fs::create_dir(temp.0.join("lib")).map_err(|e| e.to_string())?;
        jars(&archive, &temp.0.join("lib"), true, cancel)?;
        fs::rename(&temp.0, &installed).map_err(|e| e.to_string())?;
    }
    Ok(lib)
}

fn counts(root: &Path) -> Result<(usize, usize), String> {
    let mut dirs = vec![root.to_path_buf()];
    let (mut java, mut resources) = (0, 0);
    while let Some(dir) = dirs.pop() {
        if !dir.exists() {
            continue;
        }
        for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_symlink() {
                return Err("unexpected link in JADX output".into());
            }
            if kind.is_dir() {
                dirs.push(entry.path());
            } else if kind.is_file() {
                if entry.path().starts_with(root.join("java"))
                    && entry.path().extension().is_some_and(|e| e == "java")
                {
                    java += 1;
                } else if entry.path().starts_with(root.join("resources")) {
                    resources += 1;
                }
            }
        }
    }
    Ok((java, resources))
}

pub fn decompile(
    input: &Path,
    settings: &mut Settings,
    output: &Path,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<(), String> {
    cancelled(cancel)?;
    fs::create_dir_all(output).map_err(|e| e.to_string())?;
    let output = output.canonicalize().map_err(|e| e.to_string())?;
    let mut magic = [0u8; 8];
    File::open(input)
        .map_err(|e| e.to_string())?
        .read_exact(&mut magic)
        .map_err(|e| e.to_string())?;
    let extension = if magic.starts_with(b"PK\x03\x04") {
        "apk"
    } else if magic.starts_with(b"dex\n") {
        "dex"
    } else {
        return Err("Android recovery accepts only APK or standalone DEX content".into());
    };
    if fs::metadata(input).map_err(|e| e.to_string())?.len() > MAX_BYTES {
        return Err("Android input exceeds 512 MiB".into());
    }
    let work = Temporary::new(&output)?;
    let snapshot = work.0.join(format!("input.{extension}"));
    let copied = std::io::copy(
        &mut File::open(input)
            .map_err(|e| e.to_string())?
            .take(MAX_BYTES + 1),
        &mut File::create(&snapshot).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if copied > MAX_BYTES {
        return Err("Android input exceeds 512 MiB".into());
    }
    let (entries, decoded_bytes, dex_files) = if extension == "apk" {
        let counts = inspect_zip(&snapshot, cancel)?;
        let mut archive = zip::ZipArchive::new(File::open(&snapshot).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        if archive.by_name("AndroidManifest.xml").is_err() {
            return Err("APK is missing AndroidManifest.xml".into());
        }
        counts
    } else {
        validate_dex(&snapshot, cancel)?;
        (1, copied, 1)
    };
    if settings.offline && !crate::runtime::is_offline() {
        crate::runtime::set_offline(true);
    }
    let lib = prepare(&output, cancel, events)?
        .canonicalize()
        .map_err(|e| e.to_string())?;
    let source = output.join("source");
    let java = source.join("java");
    let resources = source.join("resources");
    if java.exists() || resources.exists() {
        return Err("Android output already exists; existing sources were preserved".into());
    }
    let threads = std::thread::available_parallelism()
        .map(|n| n.get().min(4))
        .unwrap_or(1);
    let args: Vec<OsString> = vec!["-Xmx1024m".into(), "-cp".into(), lib.join("*").into_os_string(),
        "jadx.cli.JadxCLI".into(), "--config".into(), "none".into(), "--disable-plugins".into(),
        "jadx-script,kotlin-script,java-convert,java-input,smali-input,raung-input,aab-input,xapk-input,rename-mappings".into(),
        "--deobf-cfg-file-mode".into(), "ignore".into(), "--mappings-mode".into(), "ignore".into(),
        "-j".into(), threads.to_string().into(), "-ds".into(), java.into_os_string(),
        "-dr".into(), resources.into_os_string(), snapshot.into_os_string()];
    let result = run_tool(
        &crate::runtime::java().to_string_lossy(),
        &args,
        &work.0,
        &output.join("jadx.log"),
        TOOL_TIMEOUT_SECONDS,
        cancel,
        events,
    );
    let (source_files, resource_files) = counts(&source)?;
    let result = result.and_then(|()| {
        if dex_files > 0 && source_files == 0 {
            Err("JADX emitted no Java for the input DEX; resources alone are incomplete".into())
        } else if source_files + resource_files == 0 {
            Err("JADX emitted no sources or resources; see jadx.log".into())
        } else {
            let log = File::open(output.join("jadx.log")).map_err(|e| e.to_string())?;
            if log.metadata().map_err(|e| e.to_string())?.len() > 16 * 1024 * 1024 {
                return Err("JADX log exceeds diagnostic budget; review partial output".into());
            }
            let mut text = String::new();
            log.take(16 * 1024 * 1024 + 1)
                .read_to_string(&mut text)
                .map_err(|e| e.to_string())?;
            if logged_error(&text) {
                return Err("JADX reported errors; partial files preserved, see jadx.log".into());
            }
            Ok(())
        }
    });
    let report = serde_json::json!({"decompiler":format!("JADX {VERSION}"), "input_format":extension,
        "archive_entries":entries, "decoded_input_bytes":decoded_bytes, "dex_files":dex_files,
        "source_files":source_files, "resource_files":resource_files,
        "target_executed":false, "functional_equivalence_verified":false, "source_completeness_verified":false,
        "status":if result.is_ok() && source_files > 0 {"source recovered; equivalence unverified"} else if result.is_ok() {"resources recovered; no Java emitted"} else {"partial or failed"},
        "error":result.as_ref().err(), "limitations":"Recovered Java is approximate; obfuscation, native libraries and unsupported bytecode may prevent complete recovery."});
    fs::write(
        output.join("android-report.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    result.map_err(|e| format!("Android recovery incomplete ({source_files} Java files and {resource_files} resources preserved): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn errors_during_carriage_return_progress_are_not_hidden() {
        assert!(logged_error(
            "INFO - progress: 1 of 2\r    \rERROR - Failed to read zip entry: classes2.dex\n"
        ));
        assert!(!logged_error("INFO - checking ERROR label\rINFO - done\n"));
    }
    fn owned_dex_header() -> [u8; 112] {
        let mut bytes = [0u8; 112];
        bytes[..8].copy_from_slice(b"dex\n035\0");
        bytes[32..36].copy_from_slice(&112u32.to_le_bytes());
        bytes[36..40].copy_from_slice(&112u32.to_le_bytes());
        bytes[40..44].copy_from_slice(&0x12345678u32.to_le_bytes());
        let signature = sha1::Sha1::digest(&bytes[32..]);
        bytes[12..32].copy_from_slice(&signature);
        let (mut a, mut b) = (1u32, 0u32);
        adler_update(&mut a, &mut b, &bytes[12..]);
        bytes[8..12].copy_from_slice(&(b << 16 | a).to_le_bytes());
        bytes
    }
    #[test]
    fn java_resource_assets_are_not_counted_as_recovered_classes() {
        let temp = Temporary::new(&std::env::temp_dir()).unwrap();
        fs::create_dir_all(temp.0.join("resources/assets")).unwrap();
        fs::write(
            temp.0.join("resources/assets/Example.java"),
            "resource, not a recovered class",
        )
        .unwrap();
        assert_eq!(counts(&temp.0).unwrap(), (0, 1));
        fs::create_dir_all(temp.0.join("java/sample")).unwrap();
        fs::write(temp.0.join("java/sample/Hello.java"), "class Hello {}").unwrap();
        assert_eq!(counts(&temp.0).unwrap(), (1, 1));
    }
    #[test]
    fn progress_does_not_accept_invalid_counters() {
        let p = progress("INFO  - progress: 38 of 47 (80%)").unwrap();
        assert_eq!((p.done, p.total), (38, 47));
        for value in [
            "progress: 1 of 2",
            "INFO - progress: -1 of 2",
            "INFO - progress: 3 of 2",
            "INFO - progress: 0 of 0",
        ] {
            assert!(progress(value).is_none());
        }
    }
    #[test]
    fn rejects_unsafe_paths() {
        for name in [
            "../x",
            "/x",
            "a\\b",
            "a//b",
            "a/CON.txt",
            "a/x.",
            "a:C",
            "a\0b",
        ] {
            assert!(!safe_path(name), "{name:?}");
        }
        assert!(safe_path("res/layout/activity_main.xml"));
    }
    #[test]
    fn validates_dex_header_and_versions() {
        let temp = Temporary::new(&std::env::temp_dir()).unwrap();
        let path = temp.0.join("fixture.dex");
        let mut bytes = owned_dex_header();
        fs::write(&path, bytes).unwrap();
        assert!(validate_dex(&path, &AtomicBool::new(false)).is_ok());
        let mut outside = bytes;
        outside[56..60].copy_from_slice(&1u32.to_le_bytes());
        outside[60..64].copy_from_slice(&0xfffffff0u32.to_le_bytes());
        fs::write(&path, outside).unwrap();
        assert!(validate_dex(&path, &AtomicBool::new(false))
            .unwrap_err()
            .contains("identifier table"));
        bytes[8] ^= 1;
        fs::write(&path, bytes).unwrap();
        assert!(validate_dex(&path, &AtomicBool::new(false)).is_err());
        bytes[4..7].copy_from_slice(b"041");
        fs::write(&path, bytes).unwrap();
        assert!(validate_dex(&path, &AtomicBool::new(false)).is_err());
        bytes[4..7].copy_from_slice(b"035");
        bytes[32] = 111;
        fs::write(&path, bytes).unwrap();
        assert!(validate_dex(&path, &AtomicBool::new(false)).is_err());
    }
    #[test]
    fn zip_rejects_traversal_duplicates_links_and_conflicts() {
        let temp = Temporary::new(&std::env::temp_dir()).unwrap();
        let path = temp.0.join("fixture.apk");
        for names in [
            vec!["classes.dex"],
            vec!["../classes.dex"],
            vec!["a.dex", "A.dex"],
            vec!["a", "a/b"],
        ] {
            let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
            for name in &names {
                zip.start_file(*name, zip::write::SimpleFileOptions::default())
                    .unwrap();
                zip.write_all(&owned_dex_header()).unwrap();
            }
            zip.finish().unwrap();
            assert_eq!(
                inspect_zip(&path, &AtomicBool::new(false)).is_ok(),
                names == ["classes.dex"]
            );
        }
        let mut zip = zip::ZipWriter::new(File::create(&path).unwrap());
        zip.add_symlink(
            "classes.dex",
            "../outside",
            zip::write::SimpleFileOptions::default(),
        )
        .unwrap();
        zip.finish().unwrap();
        assert!(inspect_zip(&path, &AtomicBool::new(false)).is_err());
    }

    #[test]
    fn cached_libraries_reject_tampering_and_extra_plugins() {
        let temp = Temporary::new(&std::env::temp_dir()).unwrap();
        let archive = temp.0.join("distribution.zip");
        let lib = temp.0.join("lib");
        fs::create_dir(&lib).unwrap();
        let mut zip = zip::ZipWriter::new(File::create(&archive).unwrap());
        zip.start_file("lib/jadx.jar", zip::write::SimpleFileOptions::default())
            .unwrap();
        zip.write_all(b"trusted fixture").unwrap();
        zip.finish().unwrap();
        let cancel = AtomicBool::new(false);
        jars(&archive, &lib, true, &cancel).unwrap();
        jars(&archive, &lib, false, &cancel).unwrap();
        fs::write(lib.join("plugin.jar"), b"unexpected").unwrap();
        assert!(jars(&archive, &lib, false, &cancel).is_err());
        fs::remove_file(lib.join("plugin.jar")).unwrap();
        fs::write(lib.join("jadx.jar"), b"changed").unwrap();
        assert!(jars(&archive, &lib, false, &cancel).is_err());
    }

    #[test]
    fn zip_checks_actual_payload_crc_and_cancellation() {
        let temp = Temporary::new(&std::env::temp_dir()).unwrap();
        let archive = temp.0.join("test.apk");
        let mut zip = zip::ZipWriter::new(File::create(&archive).unwrap());
        zip.start_file(
            "assets/fixture.bin",
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored),
        )
        .unwrap();
        zip.write_all(b"fixture-payload").unwrap();
        zip.finish().unwrap();
        assert!(inspect_zip(&archive, &AtomicBool::new(false)).is_ok());
        assert!(inspect_zip(&archive, &AtomicBool::new(true)).is_err());
        let mut bytes = fs::read(&archive).unwrap();
        let offset = bytes
            .windows(15)
            .position(|b| b == b"fixture-payload")
            .unwrap();
        bytes[offset] ^= 1;
        fs::write(&archive, bytes).unwrap();
        assert!(inspect_zip(&archive, &AtomicBool::new(false)).is_err());
    }
}
