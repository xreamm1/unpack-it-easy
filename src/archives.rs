use crate::engine::{run_tool, Event, Settings, TOOL_TIMEOUT_SECONDS};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
    },
};
const MAX_HEADER: u64 = 16 * 1024 * 1024;
const MAX_OUTPUT: u64 = 512 * 1024 * 1024;
const MAX_FILES: usize = 100_000;
const CFR_HASH: &str = "f686e8f3ded377d7bc87d216a90e9e9512df4156e75b06c655a16648ae8765b2";

fn safe_name(name: &str) -> bool {
    !name.is_empty()
        && !name.contains(['/', '\\', ':', '\0'])
        && name != "."
        && name != ".."
        && !name.ends_with(['.', ' '])
        && ![
            "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
            "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ]
        .contains(
            &name
                .split('.')
                .next()
                .unwrap()
                .to_ascii_uppercase()
                .as_str(),
        )
}
pub fn asar(
    input: &Path,
    output: &Path,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<(), String> {
    let mut file = File::open(input).map_err(|e| e.to_string())?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    let mut prefix = [0; 16];
    file.read_exact(&mut prefix).map_err(|e| e.to_string())?;
    let n = |at| u32::from_le_bytes(prefix[at..at + 4].try_into().unwrap()) as u64;
    let header_size = n(4);
    let json_size = n(12);
    if n(0) != 4
        || !(8..=MAX_HEADER).contains(&header_size)
        || n(8) + 4 != header_size
        || json_size > header_size - 8
        || 8 + header_size > size
    {
        return Err("invalid ASAR header".into());
    }
    let mut bytes = vec![0; json_size as usize];
    file.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    let header: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let mut queue = vec![(PathBuf::new(), header, 0)];
    let mut files = vec![];
    let mut total = 0u64;
    let mut count = 0;
    let mut names = std::collections::HashSet::new();
    while let Some((relative, node, depth)) = queue.pop() {
        if depth > 64 {
            return Err("ASAR directory depth exceeded".into());
        }
        if let Some(children) = node.get("files").and_then(Value::as_object) {
            for (name, value) in children {
                count += 1;
                if count > MAX_FILES || !safe_name(name) {
                    return Err("invalid ASAR path or too many entries".into());
                }
                let path = relative.join(name);
                if !names.insert(path.to_string_lossy().to_lowercase()) {
                    return Err("duplicate ASAR path".into());
                }
                queue.push((path, value.clone(), depth + 1));
            }
        } else {
            if node.get("link").is_some() {
                return Err("ASAR links are not extracted".into());
            }
            let len = node["size"].as_u64().ok_or("missing ASAR size")?;
            total = total.checked_add(len).ok_or("ASAR size overflow")?;
            if total > MAX_OUTPUT {
                return Err("ASAR output exceeds 512 MiB".into());
            }
            let unpacked = node["unpacked"].as_bool().unwrap_or(false);
            let offset = if unpacked {
                0
            } else {
                node["offset"]
                    .as_str()
                    .ok_or("missing ASAR offset")?
                    .parse::<u64>()
                    .map_err(|e| e.to_string())?
            };
            let start = (8 + header_size)
                .checked_add(offset)
                .ok_or("ASAR offset overflow")?;
            if !unpacked && start.checked_add(len).is_none_or(|end| end > size) {
                return Err("ASAR entry outside archive".into());
            }
            files.push((relative, len, start, unpacked));
        }
    }
    let root = output.join("source");
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let unpack_root = PathBuf::from(format!("{}.unpacked", input.display()));
    let count = files.len();
    for (index, (relative, len, start, unpacked)) in files.into_iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let destination = root.join(&relative);
        fs::create_dir_all(destination.parent().unwrap()).map_err(|e| e.to_string())?;
        let mut target = File::create(&destination).map_err(|e| e.to_string())?;
        let copied = if unpacked {
            let source = unpack_root.join(&relative);
            let canonical = source.canonicalize().map_err(|e| e.to_string())?;
            let canonical_root = unpack_root.canonicalize().map_err(|e| e.to_string())?;
            if !canonical.starts_with(canonical_root) {
                return Err("ASAR unpacked path escapes root".into());
            }
            std::io::copy(
                &mut File::open(source).map_err(|e| e.to_string())?.take(len),
                &mut target,
            )
        } else {
            file.seek(SeekFrom::Start(start))
                .map_err(|e| e.to_string())?;
            std::io::copy(&mut (&mut file).take(len), &mut target)
        }
        .map_err(|e| e.to_string())?;
        if copied != len {
            return Err("truncated ASAR entry".into());
        }
        target.flush().map_err(|e| e.to_string())?;
        let _ = events.send(Event::Progress(crate::telemetry::Progress {
            phase: "ASAR extraction".into(),
            file: relative.to_string_lossy().into_owned(),
            done: index + 1,
            total: count,
        }));
    }
    fs::write(output.join("asar-report.json"),serde_json::to_vec_pretty(&serde_json::json!({"files":count,"bytes":total,"method":"ASAR source extraction; no execution"})).unwrap()).map_err(|e|e.to_string())
}

pub fn prepare_cfr(
    output: &Path,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<PathBuf, String> {
    let root = crate::runtime::root();
    let jar = root.join("cfr/cfr-0.152.jar");
    if !jar.is_file() {
        if crate::runtime::is_offline() {
            return Err("offline mode: CFR is missing".into());
        }
        fs::create_dir_all(jar.parent().unwrap()).map_err(|e| e.to_string())?;
        let partial = jar.with_extension("part");
        run_tool(
            "curl.exe",
            &[
                "--fail".into(),
                "--location".into(),
                "--retry".into(),
                "2".into(),
                "https://www.benf.org/other/cfr/cfr-0.152.jar".into(),
                "--output".into(),
                partial.clone().into_os_string(),
            ],
            output,
            &output.join("cfr-download.log"),
            180,
            cancel,
            events,
        )?;
        if crate::project::sha256(&partial)? != CFR_HASH {
            return Err("CFR checksum mismatch".into());
        }
        fs::rename(partial, &jar).map_err(|e| e.to_string())?;
    }
    if crate::project::sha256(&jar)? != CFR_HASH {
        return Err("CFR checksum mismatch".into());
    }
    Ok(jar)
}

pub fn java(
    input: &Path,
    settings: &mut Settings,
    output: &Path,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<(), String> {
    crate::runtime::prepare(
        settings,
        &crate::detect::Route::Java,
        true,
        output,
        cancel,
        events,
    )?;
    let jar = prepare_cfr(output, cancel, events)?;
    let java = crate::runtime::environment()
        .into_iter()
        .find(|(key, _)| key == "JAVA_HOME")
        .map(|(_, path)| PathBuf::from(path).join("bin/java.exe"))
        .ok_or("bundled Java missing")?;
    let source = output.join("source");
    // Validate JAR paths before passing the archive to the external decompiler.
    if input
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("jar"))
    {
        let mut archive = zip::ZipArchive::new(File::open(input).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let mut size = 0u64;
        if archive.len() > MAX_FILES {
            return Err("too many JAR entries".into());
        }
        for index in 0..archive.len() {
            let entry = archive.by_index(index).map_err(|e| e.to_string())?;
            let name = entry.name().trim_end_matches('/');
            if name.split('/').any(|part| !safe_name(part)) {
                return Err("invalid JAR path".into());
            }
            size = size.checked_add(entry.size()).ok_or("JAR size overflow")?;
            if size > MAX_OUTPUT {
                return Err("JAR output exceeds 512 MiB".into());
            }
        }
    }
    run_tool(
        &java.to_string_lossy(),
        &[
            "-Xmx1024m".into(),
            "-jar".into(),
            jar.into_os_string(),
            input.as_os_str().into(),
            "--outputdir".into(),
            source.clone().into_os_string(),
            "--silent".into(),
            "true".into(),
        ],
        output,
        &output.join("cfr.log"),
        TOOL_TIMEOUT_SECONDS,
        cancel,
        events,
    )?;
    let mut dirs = vec![source];
    let mut sources = 0;
    while let Some(dir) = dirs.pop() {
        for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            if entry.file_type().map_err(|e| e.to_string())?.is_dir() {
                dirs.push(entry.path());
            } else if entry.path().extension().is_some_and(|e| e == "java") {
                sources += 1;
            }
        }
    }
    if sources == 0 {
        return Err("CFR emitted no Java sources; see cfr.log".into());
    }
    fs::write(output.join("java-report.json"),serde_json::to_vec_pretty(&serde_json::json!({"decompiler":"CFR 0.152","source_files":sources,"verification":"source emitted; functional equivalence unverified"})).unwrap()).map_err(|e|e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn asar_extracts_and_rejects_traversal() {
        let base = std::env::temp_dir().join(format!("uie-asar-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        let input = base.join("app.asar");
        let (tx, _) = std::sync::mpsc::channel();
        for (name, valid) in [("main.js", true), ("../bad.js", false)] {
            let json =
                serde_json::to_vec(&serde_json::json!({"files":{name:{"size":3,"offset":"0"}}}))
                    .unwrap();
            let pad = (4 - json.len() % 4) % 4;
            let h = 8 + json.len() + pad;
            let mut bytes = vec![];
            for n in [4u32, h as u32, (h - 4) as u32, json.len() as u32] {
                bytes.extend(n.to_le_bytes());
            }
            bytes.extend(json);
            bytes.extend(vec![0; pad]);
            bytes.extend(b"abc");
            fs::write(&input, bytes).unwrap();
            assert_eq!(
                asar(&input, &base.join("out"), &AtomicBool::new(false), &tx).is_ok(),
                valid
            );
        }
        assert_eq!(fs::read(base.join("out/source/main.js")).unwrap(), b"abc");
        let _ = fs::remove_dir_all(base);
    }
}
