use crate::{
    detect::{self, Analysis},
    engine::{run_tool, Event},
};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, mpsc::Sender},
};

const VERSION: &str = "5.3.0";
const MAX_UNPACKED: u64 = 1024 * 1024 * 1024;

fn platform() -> Result<(&'static str, &'static str), String> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => Ok(("win64.zip", "d127996c76615e431be810e9c8d2910dbe3dd400600c5c0c50276fc5a17a9705")),
        ("windows", "x86") => Ok(("win32.zip", "36a740f077637d66da90a133a2a166e90dd692be5d08b2350fec97ed23809d53")),
        ("linux", "x86_64") => Ok(("amd64_linux.tar.xz", "79cea8a50b6fa102d10c7b79a419cd77dead3cc2d78661de2dc5e5815dc505c1")),
        ("linux", "aarch64") => Ok(("arm64_linux.tar.xz", "2a4afa860ac7aa6968f88df7841823746e5d00ba56affdf9342c2f5254fb776f")),
        _ => Err("Install UPX on PATH for this host; automatic UPX download supports Windows x86/x64 and Linux x64/ARM64".into()),
    }
}
pub fn prepare(
    offline: bool,
    work: &Path,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<PathBuf, String> {
    let name = if cfg!(windows) { "upx.exe" } else { "upx" };
    let root = crate::runtime::root().join("upx");
    let tool = root.join(name);
    if tool.is_file() {
        return Ok(tool);
    }
    let installed = crate::engine::find_tool(&[name]);
    if !installed.is_empty() {
        return Ok(installed.into());
    }
    if offline {
        return Err("offline: UPX is missing; prepare the offline bundle while online".into());
    }
    let (asset, checksum) = platform()?;
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let archive = work.join(format!("upx-{VERSION}-{asset}"));
    run_tool(
        &crate::engine::find_tool(&[if cfg!(windows) { "curl.exe" } else { "curl" }]),
        &[
            "--fail".into(),
            "--location".into(),
            "--connect-timeout".into(),
            "10".into(),
            "--max-time".into(),
            "180".into(),
            "--max-filesize".into(),
            "16777216".into(),
            "--output".into(),
            archive.clone().into_os_string(),
            format!(
                "https://github.com/upx/upx/releases/download/v{VERSION}/upx-{VERSION}-{asset}"
            )
            .into(),
        ],
        work,
        &work.join("upx-download.log"),
        190,
        cancel,
        events,
    )?;
    if crate::project::sha256(&archive)? != checksum {
        return Err("UPX archive SHA256 mismatch".into());
    }
    let partial = root.join(format!("{name}.part"));
    if cfg!(windows) {
        let mut zip = zip::ZipArchive::new(fs::File::open(&archive).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let directory = asset.trim_end_matches(".zip");
        for file in [name, "LICENSE", "COPYING"] {
            let mut entry = zip
                .by_name(&format!("upx-{VERSION}-{directory}/{file}"))
                .map_err(|e| e.to_string())?;
            let size = entry.size();
            if size > 16 * 1024 * 1024 {
                return Err("UPX file size limit".into());
            }
            let destination = if file == name {
                partial.clone()
            } else {
                root.join(file)
            };
            let count = std::io::copy(
                &mut (&mut entry).take(size + 1),
                &mut fs::File::create(destination).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            if count != size {
                return Err("UPX distribution file truncated".into());
            }
        }
    } else {
        let directory = asset.trim_end_matches(".tar.xz");
        run_tool(
            &crate::engine::find_tool(&["tar"]),
            &[
                "-xJf".into(),
                archive.into_os_string(),
                "-C".into(),
                root.as_os_str().into(),
                "--strip-components=1".into(),
                format!("upx-{VERSION}-{directory}/upx").into(),
                format!("upx-{VERSION}-{directory}/LICENSE").into(),
                format!("upx-{VERSION}-{directory}/COPYING").into(),
            ],
            work,
            &work.join("upx-extract.log"),
            30,
            cancel,
            events,
        )?;
        if !tool.is_file() {
            return Err("UPX executable missing from archive".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o755))
                .map_err(|e| e.to_string())?;
        }
        return Ok(tool);
    }
    fs::rename(partial, &tool).map_err(|e| e.to_string())?;
    Ok(tool)
}

pub fn indicated(analysis: &Analysis) -> bool {
    analysis
        .packer_hints
        .iter()
        .any(|hint| hint.to_ascii_lowercase().contains("upx"))
}

pub fn automatic(
    input: &Path,
    analysis: &Analysis,
    output: &Path,
    offline: bool,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<Option<(PathBuf, Analysis)>, String> {
    if !indicated(analysis) {
        return Ok(None);
    }
    let work = output.join("unpacking");
    fs::create_dir(&work).map_err(|e| e.to_string())?;
    let original_hash = crate::project::sha256(input)?;
    let result = (|| {
        let tool = prepare(offline, &work, cancel, events)?;
        let staged = work.join(input.file_name().ok_or("input has no filename")?);
        fs::copy(input, &staged).map_err(|e| e.to_string())?;
        run_tool(
            &tool.to_string_lossy(),
            &[
                "-d".into(),
                "--".into(),
                staged
                    .file_name()
                    .ok_or("staged file has no filename")?
                    .into(),
            ],
            &work,
            &work.join("upx.log"),
            120,
            cancel,
            events,
        )?;
        let size = fs::metadata(&staged).map_err(|e| e.to_string())?.len();
        if size == 0 || size > MAX_UNPACKED {
            return Err("UPX output size limit".into());
        }
        let mut unpacked = detect::inspect_file(&staged)?;
        if unpacked.route == detect::Route::Unknown || indicated(&unpacked) {
            return Err("UPX output is unrecognized or still appears packed".into());
        }
        if crate::project::sha256(&staged)? == original_hash {
            return Err("UPX did not change the copied file".into());
        }
        unpacked.notes.push(
            "UPX decompressed a staged copy without executing the target. Original input retained."
                .into(),
        );
        Ok((staged, unpacked))
    })();
    let report = match &result {
        Ok((path, found)) => {
            serde_json::json!({"tool":"UPX", "success":true, "input_sha256":original_hash, "unpacked_sha256":crate::project::sha256(path)?, "unpacked_file":path, "analysis":found, "target_executed":false})
        }
        Err(error) => {
            serde_json::json!({"tool":"UPX", "success":false, "input_sha256":original_hash, "error":error, "target_executed":false})
        }
    };
    fs::write(
        output.join("unpack-report.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    result.map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unrelated_binaries_are_not_sent_to_an_unpacker() {
        let analysis = detect::inspect(b"ordinary text").unwrap();
        let (tx, _) = std::sync::mpsc::channel();
        assert!(automatic(
            Path::new("does-not-exist"),
            &analysis,
            Path::new("does-not-exist"),
            true,
            &AtomicBool::new(false),
            &tx
        )
        .unwrap()
        .is_none());
    }
}
