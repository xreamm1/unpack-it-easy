use serde::Deserialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
const API: &str = "https://api.github.com/repos/xreamm1/unpack-it-easy/releases/latest";
const MAX_EXE: u64 = 128 * 1024 * 1024;
#[derive(Clone, Debug)]
pub struct Release {
    pub version: String,
    pub url: String,
    pub sha256: String,
    pub notes: String,
}
pub enum Message {
    Checked(Result<Option<Release>, String>),
    Downloaded(Result<PathBuf, String>),
}
#[derive(Deserialize)]
struct ApiRelease {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    draft: bool,
    #[serde(default)]
    prerelease: bool,
    assets: Vec<Asset>,
}
#[derive(Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    digest: Option<String>,
    size: u64,
}
const MAX_NOTES_CHARS: usize = 16_000;
fn bounded_notes(notes: &str) -> String {
    let mut output: String = notes.chars().take(MAX_NOTES_CHARS).collect();
    if notes.chars().count() > MAX_NOTES_CHARS {
        output.push_str("\n[Release notes truncated; see GitHub for the full text]");
    }
    output
}
fn version(text: &str) -> Option<[u64; 3]> {
    let values = text
        .trim_start_matches('v')
        .split('.')
        .map(str::parse)
        .collect::<Result<Vec<u64>, _>>()
        .ok()?;
    values.try_into().ok()
}
pub fn parse(bytes: &[u8], current: &str) -> Result<Option<Release>, String> {
    let api: ApiRelease = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    let next = version(&api.tag_name).ok_or("invalid release version")?;
    if api.draft || api.prerelease || next <= version(current).ok_or("invalid current version")? {
        return Ok(None);
    }
    let asset = api
        .assets
        .into_iter()
        .find(|a| a.name == "UIE.exe")
        .ok_or("release has no UIE.exe")?;
    let hash = asset
        .digest
        .and_then(|d| d.strip_prefix("sha256:").map(str::to_owned))
        .ok_or("release has no SHA-256 digest")?;
    let prefix = format!(
        "https://github.com/xreamm1/unpack-it-easy/releases/download/{}/",
        api.tag_name
    );
    if asset.size == 0
        || asset.size > MAX_EXE
        || !asset.browser_download_url.starts_with(&prefix)
        || hash.len() != 64
        || !hash.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid release asset".into());
    }
    Ok(Some(Release {
        version: api.tag_name,
        url: asset.browser_download_url,
        sha256: hash.to_ascii_lowercase(),
        notes: bounded_notes(api.body.as_deref().unwrap_or_default()),
    }))
}
fn curl(url: &str, path: &Path, limit: u64, timeout: u64) -> Result<(), String> {
    let mut command = Command::new("curl.exe");
    command
        .args([
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "5",
            "--max-time",
            &timeout.to_string(),
            "--max-filesize",
            &limit.to_string(),
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--user-agent",
            "UIE-updater",
            "--output",
        ])
        .arg(path)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return if status.success() {
                Ok(())
            } else {
                Err(format!("update request failed: {status}"))
            };
        }
        if start.elapsed() > Duration::from_secs(timeout + 2) {
            let _ = child.kill();
            let _ = child.wait();
            return Err("update request timed out".into());
        }
        thread::sleep(Duration::from_millis(50));
    }
}
pub fn check() -> Result<Option<Release>, String> {
    if !cfg!(windows) {
        return Ok(None);
    }
    let folder = std::env::temp_dir().join(format!("uie-check-{}", std::process::id()));
    fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
    let file = folder.join("latest.json");
    curl(API, &file, 1024 * 1024, 15)?;
    parse(
        &fs::read(file).map_err(|e| e.to_string())?,
        env!("CARGO_PKG_VERSION"),
    )
}
pub fn download(release: &Release) -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let folder = exe
        .parent()
        .ok_or("executable folder missing")?
        .join(".uie-update")
        .join(&release.version);
    fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
    let file = folder.join("UIE.exe.part");
    curl(&release.url, &file, MAX_EXE, 300)?;
    if crate::project::sha256(&file)? != release.sha256 {
        return Err("update SHA-256 mismatch".into());
    }
    let mut header = [0; 2];
    use std::io::Read;
    fs::File::open(&file)
        .map_err(|e| e.to_string())?
        .read_exact(&mut header)
        .map_err(|e| e.to_string())?;
    if header != *b"MZ" {
        return Err("update is not a Windows executable".into());
    }
    Ok(file)
}
pub fn start_check() -> mpsc::Receiver<Message> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(Message::Checked(check()));
    });
    rx
}
pub fn start_download(release: Release) -> mpsc::Receiver<Message> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(Message::Downloaded(download(&release)));
    });
    rx
}
fn quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "''"))
}
fn script(target: &Path, staged: &Path, hash: &str, pid: u32) -> String {
    format!(
        r#"$ErrorActionPreference='Stop'
$target={target}
$staged={staged}
try {{ $process=[Diagnostics.Process]::GetProcessById({pid}); if(-not $process.WaitForExit(60000)){{throw 'UIE did not exit'}} }} catch [ArgumentException] {{}}
$stream=[IO.File]::OpenRead($staged)
$algorithm=[Security.Cryptography.SHA256]::Create()
try {{ $actual=[BitConverter]::ToString($algorithm.ComputeHash($stream)).Replace('-','') }} finally {{ $stream.Dispose(); $algorithm.Dispose() }}
if($actual -ne '{hash}'){{throw 'Update checksum mismatch'}}
$backup=$target+'.backup-'+[DateTime]::UtcNow.Ticks
for($attempt=0;$attempt -lt 20;$attempt++){{
 try {{ [IO.File]::Replace($staged,$target,$backup);  $startInfo=[Diagnostics.ProcessStartInfo]::new(); $startInfo.FileName=$target; $startInfo.WorkingDirectory=[IO.Path]::GetDirectoryName($target); $startInfo.UseShellExecute=$false; [void][Diagnostics.Process]::Start($startInfo); exit 0 }}
 catch {{ if($attempt -eq 19){{throw}}; [Threading.Thread]::Sleep(500) }}
}}
"#,
        target = quote(target),
        staged = quote(staged)
    )
}
pub fn install(staged: &Path, hash: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let helper = staged.with_extension("ps1");
    fs::write(
        &helper,
        format!("\u{feff}{}", script(&exe, staged, hash, std::process::id())),
    )
    .map_err(|e| e.to_string())?;
    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(helper)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command.spawn().map_err(|e| e.to_string())?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn release_notes_preserve_text_and_handle_absent_or_long_body() {
        let mut value = serde_json::json!({"tag_name":"v0.5.0","body":"## Changes\n- Fixed a crash\n- исправлено окно","assets":[{"name":"UIE.exe","browser_download_url":"https://github.com/xreamm1/unpack-it-easy/releases/download/v0.5.0/UIE.exe","size":100,"digest":format!("sha256:{}","a".repeat(64))}]});
        let parse_release = |value: &serde_json::Value| {
            parse(&serde_json::to_vec(value).unwrap(), "0.4.1")
                .unwrap()
                .unwrap()
        };
        assert_eq!(parse_release(&value).notes, value["body"].as_str().unwrap());
        value["body"] = serde_json::Value::Null;
        assert!(parse_release(&value).notes.is_empty());
        value.as_object_mut().unwrap().remove("body");
        assert!(parse_release(&value).notes.is_empty());
        value["body"] = serde_json::json!("я".repeat(MAX_NOTES_CHARS + 1));
        let notes = parse_release(&value).notes;
        assert!(notes.ends_with("[Release notes truncated; see GitHub for the full text]"));
        assert_eq!(
            notes.chars().take(MAX_NOTES_CHARS).collect::<String>(),
            "я".repeat(MAX_NOTES_CHARS)
        );
    }
    #[test]
    #[cfg(windows)]
    fn installer_replaces_only_after_hash_verification() {
        use std::os::windows::process::CommandExt;
        let root = std::env::temp_dir().join(format!("uie-install-тест-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("UIE.exe");
        let staged = root.join("new.exe");
        fs::write(&target, b"old").unwrap();
        fs::write(&staged, b"MZverified").unwrap();
        let hash = crate::project::sha256(&staged).unwrap();
        let mut text = script(&target, &staged, &hash, 99_999_999);
        text = text.replace("[void][Diagnostics.Process]::Start($startInfo);", "");
        let helper = root.join("test.ps1");
        fs::write(&helper, format!("\u{feff}{text}")).unwrap();
        let status = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&helper)
            .creation_flags(0x08000000)
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(fs::read(&target).unwrap(), b"MZverified");
        assert!(fs::read_dir(&root).unwrap().any(|entry| entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("UIE.exe.backup-")));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn versions_and_assets_are_validated() {
        let json = serde_json::json!({"tag_name":"v0.4.0","assets":[{"name":"UIE.exe","browser_download_url":"https://github.com/xreamm1/unpack-it-easy/releases/download/v0.4.0/UIE.exe","size":100,"digest":format!("sha256:{}","a".repeat(64))}]});
        let bytes = serde_json::to_vec(&json).unwrap();
        assert!(parse(&bytes, "0.3.1").unwrap().is_some());
        assert!(parse(&bytes, "0.4.0").unwrap().is_none());
        let mut bad = json;
        bad["assets"][0]["browser_download_url"] =
            serde_json::json!("https://example.test/UIE.exe");
        assert!(parse(&serde_json::to_vec(&bad).unwrap(), "0.3.1").is_err());
        assert!(version("v1.2.3-preview").is_none());
    }
    #[test]
    fn helper_preserves_paths_and_verifies_before_replacement() {
        let s = script(
            Path::new("C:/lab/it's/UIE.exe"),
            Path::new("C:/lab/new.exe"),
            &"a".repeat(64),
            123,
        );
        assert!(s.contains("it''s"));
        assert!(s.contains("WaitForExit(60000)"));
        assert!(s.find("ComputeHash").unwrap() < s.find("[IO.File]::Replace").unwrap());
    }
}
