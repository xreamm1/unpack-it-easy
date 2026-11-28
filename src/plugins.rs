//! Explicitly selected, checksum-pinned external decompilers. Never auto-route samples.
use crate::engine::{run_analysis_tool, Event, Settings, TOOL_TIMEOUT_SECONDS};
use serde::Deserialize;
use std::{
    collections::HashSet,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, mpsc::Sender},
};

const MAX_MANIFEST: u64 = 64 * 1024;
const MAX_PLUGINS: usize = 128;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plugin {
    pub id: String,
    pub name: String,
    #[serde(default)]
    enabled: bool,
    executable: PathBuf,
    sha256: String,
    pub extensions: Vec<String>,
    args: Vec<String>,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
}

fn default_timeout() -> u64 {
    TOOL_TIMEOUT_SECONDS
}

fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn plain_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || linked(&metadata) {
        return Err(format!("not a regular file: {}", path.display()));
    }
    Ok(())
}

fn parse(bytes: &[u8]) -> Result<Option<Plugin>, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if !value.is_object() {
        return Err("plugin manifest must be an object".into());
    }
    match value.get("enabled") {
        None | Some(serde_json::Value::Bool(false)) => return Ok(None),
        Some(serde_json::Value::Bool(true)) => (),
        _ => return Err("enabled must be a boolean".into()),
    }
    let plugin: Plugin = serde_json::from_value(value).map_err(|e| e.to_string())?;
    plugin.validate()?;
    Ok(Some(plugin))
}

/// Manager validation is also applied to disabled manifests. This never executes code.
pub fn validate_manager_manifest(bytes: &[u8], verify_executable: bool) -> Result<Plugin, String> {
    if bytes.len() as u64 > MAX_MANIFEST {
        return Err("plugin manifest exceeds 64 KiB".into());
    }
    let plugin: Plugin = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    plugin.validate()?;
    if verify_executable {
        if fs::metadata(&plugin.executable)
            .map_err(|e| e.to_string())?
            .len()
            > 512 * 1024 * 1024
        {
            return Err("plugin executable exceeds 512 MiB verification limit".into());
        }
        plugin.verify()?;
    }
    Ok(plugin)
}

impl Plugin {
    fn validate(&self) -> Result<(), String> {
        if self.id.is_empty()
            || self.id.len() > 64
            || !self
                .id
                .bytes()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            || !self.id.as_bytes()[0].is_ascii_alphanumeric()
            || self.name.trim().is_empty()
            || self.name.len() > 128
            || self
                .name
                .chars()
                .any(|c| c.is_control() || matches!(c, '/' | '\\' | ':'))
        {
            return Err("invalid plugin id or display name".into());
        }
        if !self.executable.is_absolute() || self.executable.to_str().is_none() {
            return Err("plugin executable must be an absolute Unicode path".into());
        }
        let filename = self
            .executable
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        let stem = self
            .executable
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        let extension = self
            .executable
            .extension()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        if ["bat", "cmd", "ps1", "py", "pyw", "sh", "dll", "js", "vbs"]
            .contains(&extension.as_str())
            || [
                "cmd",
                "powershell",
                "pwsh",
                "sh",
                "bash",
                "dash",
                "zsh",
                "python",
                "python3",
                "node",
                "wscript",
                "cscript",
            ]
            .contains(&stem.as_str())
            || (cfg!(windows) && !filename.ends_with(".exe"))
        {
            return Err("plugins require a native executable, not a shell, script or DLL".into());
        }
        if self.sha256.len() != 64 || !self.sha256.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err("plugin sha256 must contain 64 hexadecimal digits".into());
        }
        if self.extensions.is_empty()
            || self.extensions.len() > 32
            || self.extensions.iter().any(|ext| {
                ext.is_empty()
                    || ext.len() > 16
                    || !ext
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            })
        {
            return Err(
                "extensions must be a nonempty whitelist of lowercase suffixes without dots".into(),
            );
        }
        if self.timeout_seconds == 0 || self.timeout_seconds > TOOL_TIMEOUT_SECONDS {
            return Err(format!(
                "plugin timeout must be between 1 and {TOOL_TIMEOUT_SECONDS} seconds"
            ));
        }
        if self.args.len() > 128
            || !self.args.iter().any(|a| a == "{input}")
            || !self.args.iter().any(|a| a == "{output}")
        {
            return Err("plugin args must include separate {input} and {output} arguments".into());
        }
        for arg in &self.args {
            if arg.len() > 4096
                || arg.chars().any(char::is_control)
                || (arg != "{input}" && arg != "{output}" && arg.contains(['{', '}']))
            {
                return Err("invalid plugin argument or placeholder".into());
            }
        }
        Ok(())
    }

    fn arguments(&self, input: &Path, output: &Path) -> Vec<OsString> {
        self.args
            .iter()
            .map(|arg| match arg.as_str() {
                "{input}" => input.as_os_str().to_owned(),
                "{output}" => output.as_os_str().to_owned(),
                _ => arg.into(),
            })
            .collect()
    }

    fn verify(&self) -> Result<(), String> {
        plain_file(&self.executable)?;
        let mut magic = [0; 4];
        File::open(&self.executable)
            .map_err(|e| e.to_string())?
            .read_exact(&mut magic)
            .map_err(|e| e.to_string())?;
        if !(magic.starts_with(b"MZ")
            || magic == *b"\x7fELF"
            || [
                [0xfe, 0xed, 0xfa, 0xce],
                [0xce, 0xfa, 0xed, 0xfe],
                [0xfe, 0xed, 0xfa, 0xcf],
                [0xcf, 0xfa, 0xed, 0xfe],
                [0xca, 0xfe, 0xba, 0xbe],
                [0xbe, 0xba, 0xfe, 0xca],
            ]
            .contains(&magic))
        {
            return Err("plugin must be a native executable (PE, ELF or Mach-O)".into());
        }
        if !crate::project::sha256(&self.executable)?.eq_ignore_ascii_case(&self.sha256) {
            return Err(format!("plugin {} executable SHA-256 mismatch", self.id));
        }
        Ok(())
    }
}

fn list_at(root: &Path) -> Result<Vec<Plugin>, String> {
    match fs::symlink_metadata(root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.to_string()),
        Ok(metadata) if !metadata.is_dir() || linked(&metadata) => {
            return Err("plugin directory must be a real directory".into())
        }
        _ => (),
    }
    let mut result = vec![];
    let mut ids = HashSet::new();
    let mut count = 0;
    for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if !path.extension().is_some_and(|ext| ext == "json") {
            continue;
        }
        count += 1;
        if count > MAX_PLUGINS {
            return Err("too many plugin manifests".into());
        }
        plain_file(&path)?;
        let mut bytes = vec![];
        File::open(&path)
            .map_err(|e| e.to_string())?
            .take(MAX_MANIFEST + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_MANIFEST {
            return Err("plugin manifest exceeds 64 KiB".into());
        }
        if let Some(plugin) = parse(&bytes).map_err(|e| format!("{}: {e}", path.display()))? {
            if !ids.insert(plugin.id.clone()) {
                return Err(format!("duplicate plugin id: {}", plugin.id));
            }
            result.push(plugin);
        }
    }
    result.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(result)
}

/// Only explicitly enabled manifests are returned. Calling this never runs code.
pub fn list() -> Result<Vec<Plugin>, String> {
    list_at(&crate::runtime::root().join("plugins"))
}

fn source_count(source: &Path) -> Result<usize, String> {
    let mut directories = vec![source.to_path_buf()];
    let mut files = 0;
    let mut entries = 0;
    let mut bytes = 0u64;
    while let Some(directory) = directories.pop() {
        let metadata = fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
        if linked(&metadata) || !metadata.is_dir() {
            return Err("plugin source directory is not a real directory".into());
        }
        for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            entries += 1;
            if entries > crate::engine::MAX_COLLECTED_FILES {
                return Err("too many plugin output entries".into());
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            if linked(&metadata) {
                return Err("plugin output contains a link or reparse point".into());
            }
            if metadata.is_dir() {
                directories.push(entry.path());
            } else if metadata.is_file() {
                files += 1;
                bytes = bytes
                    .checked_add(metadata.len())
                    .ok_or("plugin output size overflow")?;
                if bytes > 512 * 1024 * 1024 {
                    return Err("plugin output exceeds 512 MiB".into());
                }
            } else {
                return Err("plugin output contains a special file".into());
            }
        }
    }
    Ok(files)
}

/// Run only after an explicit user selection. Does not replace built-in routing.
pub fn run(
    id: &str,
    input: &Path,
    settings: &Settings,
    output: &Path,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<(), String> {
    crate::engine::set_analysis_policy(settings.analysis_limits.clone());
    let plugin = list()?
        .into_iter()
        .find(|p| p.id == id && p.enabled)
        .ok_or("plugin is missing or disabled")?;
    run_plugin(plugin, input, output, cancel, events)
}

fn run_plugin(
    plugin: Plugin,
    input: &Path,
    output: &Path,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<(), String> {
    let extension = input
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !plugin.extensions.contains(&extension) {
        return Err("input extension is not allowed by this plugin".into());
    }
    plain_file(input)?;
    let input = input.canonicalize().map_err(|e| e.to_string())?;
    let executable = plugin
        .executable
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if input == executable {
        return Err("the analyzed input cannot be the plugin executable".into());
    }
    plugin.verify()?;
    fs::create_dir_all(output).map_err(|e| e.to_string())?;
    let output = output.canonicalize().map_err(|e| e.to_string())?;
    let source = output.join("source");
    // create_dir, not create_dir_all: never reuse sample-controlled work or source paths.
    let work = output.join("plugin-work");
    fs::create_dir(&work).map_err(|e| format!("fresh plugin working directory required: {e}"))?;
    fs::create_dir(&source).map_err(|e| format!("fresh plugin source directory required: {e}"))?;
    let staged = work.join(format!("input.{extension}"));
    fs::copy(&input, &staged).map_err(|e| e.to_string())?;
    // Keep the report handle owned even if a plugin tampers with paths while running.
    let mut report = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(output.join("plugin-report.json"))
        .map_err(|e| e.to_string())?;
    let args = plugin.arguments(&staged, &source);
    let _ = events.send(Event::Log(format!(
        "Third-party decompiler: {}; functional equivalence is unverified",
        plugin.name
    )));
    plugin.verify()?;
    let execution = run_analysis_tool(
        plugin
            .executable
            .to_str()
            .ok_or("invalid executable path")?,
        &args,
        &work,
        &output.join("plugin.log"),
        plugin.timeout_seconds,
        cancel,
        events,
    );
    let inspection = source_count(&source);
    let files = inspection.as_ref().copied().unwrap_or(0);
    let result = execution
        .and_then(|()| inspection.map(|_| ()))
        .and_then(|()| {
            if files == 0 {
                Err("plugin emitted no recovered files; see plugin.log".into())
            } else {
                Ok(())
            }
        });
    let bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "plugin_id": plugin.id, "plugin_name": plugin.name, "executable_sha256": plugin.sha256,
        "source_files": files, "success": result.is_ok(), "functional_equivalence": false,
        "verification": "third-party recovered output; functional equivalence unverified",
        "error": result.as_ref().err(), "partial_output_preserved": true,
    }))
    .map_err(|e| e.to_string())?;
    report.write_all(&bytes).map_err(|e| e.to_string())?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> serde_json::Value {
        serde_json::json!({"id":"example", "name":"Example decompiler", "enabled":true,
            "executable": std::env::current_exe().unwrap(), "sha256":"a".repeat(64),
            "extensions":["bin"], "args":["--input","{input}","--output","{output}"]})
    }
    #[test]
    fn disabled_is_opt_in_and_never_resolves_tools() {
        assert!(parse(br#"{"id":"disabled"}"#).unwrap().is_none());
        assert!(
            parse(br#"{"enabled":false,"executable":"../untrusted.py"}"#)
                .unwrap()
                .is_none()
        );
        assert!(parse(br#"{"enabled":"true"}"#).is_err());
    }
    #[test]
    fn manifests_reject_traversal_unknown_fields_and_interpolation() {
        for (field, value) in [
            ("id", serde_json::json!("../escape")),
            ("name", serde_json::json!("Bad\nname")),
            ("executable", serde_json::json!("relative/tool.exe")),
            ("extensions", serde_json::json!(["../exe"])),
            (
                "args",
                serde_json::json!(["{input}", "{output}", "{unknown}"]),
            ),
            ("args", serde_json::json!(["--in={input}", "{output}"])),
            (
                "timeout_seconds",
                serde_json::json!(TOOL_TIMEOUT_SECONDS + 1),
            ),
            ("command", serde_json::json!("tool {input} > {output}")),
        ] {
            let mut value_manifest = manifest();
            value_manifest[field] = value;
            assert!(
                parse(&serde_json::to_vec(&value_manifest).unwrap()).is_err(),
                "{field}"
            );
        }
    }
    #[test]
    fn arguments_are_literal_argv_and_paths_are_not_reparsed() {
        let mut value = manifest();
        value["args"] = serde_json::json!(["{input}", "{output}", "; echo test", "$(test)"]);
        let plugin = parse(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .unwrap();
        let input = Path::new("sample {output}; space.bin");
        let args = plugin.arguments(input, Path::new("source files"));
        assert_eq!(
            args,
            vec![
                input.as_os_str(),
                std::ffi::OsStr::new("source files"),
                std::ffi::OsStr::new("; echo test"),
                std::ffi::OsStr::new("$(test)")
            ]
        );
    }
    #[test]
    fn executable_checksum_is_checked_without_execution() {
        let mut value = manifest();
        let mut plugin = parse(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .unwrap();
        assert!(plugin.verify().unwrap_err().contains("SHA-256"));
        value["sha256"] =
            serde_json::json!(crate::project::sha256(&std::env::current_exe().unwrap()).unwrap());
        plugin = parse(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .unwrap();
        plugin.verify().unwrap();
    }

    #[test]
    fn listing_ignores_disabled_manifests_and_rejects_duplicate_ids() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("uie-plugin-list-{}-{stamp}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::write(
            root.join("disabled.json"),
            br#"{"enabled":false,"executable":"../sample.py"}"#,
        )
        .unwrap();
        assert!(list_at(&root).unwrap().is_empty());
        let bytes = serde_json::to_vec(&manifest()).unwrap();
        fs::write(root.join("one.json"), &bytes).unwrap();
        assert_eq!(list_at(&root).unwrap().len(), 1);
        fs::write(root.join("two.json"), &bytes).unwrap();
        assert!(list_at(&root).unwrap_err().contains("duplicate"));
        fs::remove_dir_all(root).unwrap();
    }

    // This helper only runs when the owned test executable is explicitly selected.
    #[test]
    #[ignore]
    fn owned_plugin_helper() {
        let args: Vec<_> = std::env::args_os().collect();
        let paths: Vec<_> = args
            .windows(2)
            .filter(|pair| pair[0] == "--skip")
            .map(|pair| PathBuf::from(&pair[1]))
            .collect();
        assert!((2..=3).contains(&paths.len()));
        assert_eq!(fs::read(&paths[0]).unwrap(), b"owned harmless fixture");
        assert_eq!(
            paths[0].parent().unwrap().canonicalize().unwrap(),
            std::env::current_dir().unwrap().canonicalize().unwrap()
        );
        fs::write(paths[1].join("recovered.txt"), "owned helper output").unwrap();
        assert_eq!(
            paths.len(),
            2,
            "owned fixture requested a failure after writing partial output"
        );
    }

    #[test]
    fn owned_helper_runs_in_fresh_working_directory_and_reports_unverified_output() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("uie-plugin-owned-{}-{stamp}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let input = root.join("sample.bin");
        fs::write(&input, b"owned harmless fixture").unwrap();
        let mut value = manifest();
        value["sha256"] =
            serde_json::json!(crate::project::sha256(&std::env::current_exe().unwrap()).unwrap());
        value["args"] = serde_json::json!([
            "--exact",
            "plugins::tests::owned_plugin_helper",
            "--ignored",
            "--nocapture",
            "--skip",
            "{input}",
            "--skip",
            "{output}"
        ]);
        let plugin = parse(&serde_json::to_vec(&value).unwrap())
            .unwrap()
            .unwrap();
        let output = root.join("result");
        let (tx, _rx) = std::sync::mpsc::channel();
        run_plugin(
            plugin.clone(),
            &input,
            &output,
            &AtomicBool::new(false),
            &tx,
        )
        .unwrap();
        assert_eq!(
            fs::read(output.join("source/recovered.txt")).unwrap(),
            b"owned helper output"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join("plugin-report.json")).unwrap()).unwrap();
        assert_eq!(report["functional_equivalence"], false);
        assert_eq!(report["success"], true);
        assert!(run_plugin(
            plugin.clone(),
            &input,
            &output,
            &AtomicBool::new(false),
            &tx
        )
        .is_err());
        let mut failing = plugin;
        failing
            .args
            .extend(["--skip".into(), "fixture-fail".into()]);
        let partial = root.join("partial");
        assert!(run_plugin(failing, &input, &partial, &AtomicBool::new(false), &tx).is_err());
        assert!(partial.join("source/recovered.txt").is_file());
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(partial.join("plugin-report.json")).unwrap()).unwrap();
        assert_eq!(report["success"], false);
        assert_eq!(report["functional_equivalence"], false);
        fs::remove_dir_all(root).unwrap();
    }
}
