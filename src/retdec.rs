use std::{
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    time::{SystemTime, UNIX_EPOCH},
};

struct TemporaryAnalysis {
    path: PathBuf,
    parent: PathBuf,
}
impl Drop for TemporaryAnalysis {
    fn drop(&mut self) {
        if let (Ok(path), Ok(parent)) = (self.path.canonicalize(), self.parent.canonicalize()) {
            if path.parent() == Some(parent.as_path())
                && path
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("uie-retdec-"))
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}
fn save_log(source: &Path, destination: &Path) -> Result<(), String> {
    let mut file = fs::File::open(source).map_err(|e| e.to_string())?;
    let length = file.metadata().map_err(|e| e.to_string())?.len();
    file.seek(SeekFrom::Start(length.saturating_sub(64 * 1024)))
        .map_err(|e| e.to_string())?;
    let mut bytes = vec![];
    file.take(64 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    fs::write(destination, bytes).map_err(|e| e.to_string())
}

pub fn available() -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "retdec-decompiler.exe"
    } else {
        "retdec-decompiler"
    };
    let root = crate::runtime::root().join("retdec");
    for path in [
        root.join("bin").join(name),
        root.join("retdec/bin").join(name),
        root.join(name),
    ] {
        if path.is_file() {
            return Some(path);
        }
    }
    let found = crate::engine::find_tool(&[name]);
    (!found.is_empty()).then(|| PathBuf::from(found))
}

pub fn prepare(
    offline: bool,
    work: &Path,
    cancel: &AtomicBool,
    events: &std::sync::mpsc::Sender<crate::engine::Event>,
) -> Result<PathBuf, String> {
    let managed = crate::runtime::root().join("retdec/bin/retdec-decompiler.exe");
    if !cfg!(windows) {
        return available().ok_or_else(|| {
            "Install RetDec for this host before preparing its offline installation".into()
        });
    }
    if cancel.load(Ordering::Relaxed) {
        return Err("RetDec preparation cancelled".into());
    }
    let bundle = crate::runtime::root().join("retdec");
    let ready = managed.is_file()
        && bundle.join("bin/libcrypto-1_1-x64.dll").is_file()
        && bundle.join("share/retdec/support").is_dir()
        && bundle.join("LICENSE-THIRD-PARTY").is_file()
        && bundle.join("licenses/Python-OpenSSL-LICENSE.txt").is_file()
        && bundle.join("licenses/OpenSSL-1.1.1-LICENSE.txt").is_file();
    if !ready {
        if offline {
            return Err(
                "offline: managed RetDec is missing; prepare the offline bundle while online"
                    .into(),
            );
        }
        fs::create_dir_all(work).map_err(|e| e.to_string())?;
        let script = work.join("install-retdec.ps1");
        fs::write(&script, include_str!("install-engines.ps1")).map_err(|e| e.to_string())?;
        let powershell = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("C:\\Windows"))
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        crate::engine::run_tool(
            &powershell.to_string_lossy(),
            &[
                "-NoProfile".into(),
                "-NonInteractive".into(),
                "-ExecutionPolicy".into(),
                "Bypass".into(),
                "-File".into(),
                script.into_os_string(),
                "-Root".into(),
                crate::runtime::root().into_os_string(),
                "-Route".into(),
                "retdec".into(),
            ],
            work,
            &work.join("prepare-retdec.log"),
            3600,
            cancel,
            events,
        )?;
    }
    if !managed.is_file() {
        return Err("RetDec installation did not produce its managed executable".into());
    }
    crate::engine::run_tool(
        &managed.to_string_lossy(),
        &["--version".into()],
        work,
        &work.join("retdec-version.log"),
        30,
        cancel,
        events,
    )?;
    Ok(managed)
}

fn arguments(input: &Path, output: &Path, start: u64, end: u64) -> Vec<OsString> {
    vec![
        "--select-ranges".into(),
        format!("0x{start:x}-0x{end:x}").into(),
        "--select-decode-only".into(),
        "--backend-no-time-varying-info".into(),
        "-o".into(),
        output.as_os_str().into(),
        input.as_os_str().into(),
    ]
}

/// RetDec performs static decoding only. Output is native pseudocode, never original Python.
pub fn decompile_range(
    input: &Path,
    output: &Path,
    start: u64,
    end: u64,
    cancel: &AtomicBool,
) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("RetDec cancelled".into());
    }
    if start >= end {
        return Err("RetDec range must have start < end".into());
    }
    let input = input.canonicalize().map_err(|error| error.to_string())?;
    if !input.is_file() {
        return Err("RetDec input is not a file".into());
    }
    if output.exists() {
        return Err("RetDec output already exists; existing edits were preserved".into());
    }
    let tool = available().ok_or("RetDec is not installed; extract its official distribution into engines/retdec or add retdec-decompiler to PATH")?;
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    let work = std::env::temp_dir().join(format!("uie-retdec-{}-{stamp}", std::process::id()));
    fs::create_dir(&work).map_err(|error| error.to_string())?;
    let _cleanup = TemporaryAnalysis {
        path: work.clone(),
        parent: std::env::temp_dir(),
    };
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let temporary = work.join("function.c");
    let log = work.join("retdec.log");
    let (events, _receiver) = mpsc::channel();
    drop(_receiver);
    // No added global deadline: cancellation uses the shared process-tree termination path.
    let run = crate::engine::run_tool(
        &tool.to_string_lossy(),
        &arguments(&input, &temporary, start, end),
        &work,
        &log,
        u64::MAX,
        cancel,
        &events,
    );
    let diagnostic = output.with_extension("retdec.log");
    if log.is_file() {
        save_log(&log, &diagnostic)?;
    }
    run.map_err(|error| format!("{error}; retained diagnostics: {}", diagnostic.display()))?;
    if cancel.load(Ordering::Relaxed) {
        return Err("RetDec cancelled".into());
    }
    let metadata = fs::metadata(&temporary)
        .map_err(|_| format!("RetDec emitted no pseudocode; see {}", diagnostic.display()))?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "RetDec emitted empty pseudocode; see {}",
            diagnostic.display()
        ));
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let mut source = fs::File::open(&temporary).map_err(|error| error.to_string())?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|error| error.to_string())?;
    if let Err(error) = std::io::copy(&mut source, &mut destination) {
        drop(destination);
        let _ = fs::remove_file(output);
        return Err(error.to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn owned_analysis_directory_is_removed_and_tail_log_is_bounded() {
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("uie-retdec-cleanup-{}-{stamp}", std::process::id()));
        fs::create_dir(&path).unwrap();
        let log = path.join("retdec.log");
        fs::write(&log, vec![b'x'; 100_000]).unwrap();
        let output = std::env::temp_dir().join(format!("uie-retdec-log-{stamp}.txt"));
        save_log(&log, &output).unwrap();
        assert_eq!(fs::metadata(&output).unwrap().len(), 64 * 1024);
        {
            let _guard = TemporaryAnalysis {
                path: path.clone(),
                parent: std::env::temp_dir(),
            };
        }
        assert!(!path.exists());
        fs::remove_file(output).unwrap();
    }

    #[test]
    fn range_and_paths_are_separate_arguments() {
        let args = arguments(
            Path::new("input with spaces.exe"),
            Path::new("output with spaces.c"),
            0x140001000,
            0x140001020,
        );
        assert_eq!(args[1], "0x140001000-0x140001020");
        assert_eq!(args[2], "--select-decode-only");
        assert_eq!(args[5], "output with spaces.c");
        assert_eq!(args[6], "input with spaces.exe");
    }

    #[test]
    fn rejects_empty_range_and_honors_precancel_without_starting_tool() {
        let missing = Path::new("nonexistent-retdec-test.exe");
        assert!(
            decompile_range(missing, missing, 10, 10, &AtomicBool::new(false))
                .unwrap_err()
                .contains("start < end")
        );
        assert!(
            decompile_range(missing, missing, 10, 20, &AtomicBool::new(true))
                .unwrap_err()
                .contains("cancelled")
        );
    }

    #[test]
    #[ignore = "requires official RetDec distribution and the owned scalar fixture"]
    fn owned_fixture_emits_scalar_pseudocode_without_modifying_input() {
        let input =
            PathBuf::from(std::env::var_os("UIE_RETDEC_FIXTURE").expect("set UIE_RETDEC_FIXTURE"));
        let before = crate::project::sha256(&input).unwrap();
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let output = std::env::temp_dir().join(format!("uie-retdec-validation-{stamp}.c"));
        decompile_range(
            &input,
            &output,
            0x180001000,
            0x18000101f,
            &AtomicBool::new(false),
        )
        .unwrap();
        let text = fs::read_to_string(&output).unwrap();
        assert!(text.contains("int64_t scalar_mask(int64_t a1, int64_t a2)"));
        assert!(text.contains("return a2 ^ 291 | a1 & -0xff00ff00ff0100;"));
        assert_eq!(before, crate::project::sha256(&input).unwrap());
        fs::remove_file(output).unwrap();
    }
}
