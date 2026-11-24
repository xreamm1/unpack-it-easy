use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
    sync::{atomic::AtomicBool, mpsc},
};
const URL: &str =
    "https://github.com/x64dbg/x64dbg/releases/download/2026.05.27/snapshot_2026-05-27_12-11.zip";
const HASH: &str = "d41966dfc5b435a372798245300ca0ab7bb8e48bdbf48512c6fb20fcca427697";
pub fn executable(architecture: &str) -> Result<PathBuf, String> {
    match architecture {
        "x64" => Ok(crate::runtime::root().join("x64dbg/release/x64/x64dbg.exe")),
        "x86" => Ok(crate::runtime::root().join("x64dbg/release/x32/x32dbg.exe")),
        _ => Err("x64dbg supports Windows x86/x64 PE targets only".into()),
    }
}
pub fn prepare(architecture: &str, offline: bool) -> Result<PathBuf, String> {
    if !cfg!(windows) {
        return Err("x64dbg integration is available on Windows only".into());
    }
    let exe = executable(architecture)?;
    if exe.is_file() {
        return Ok(exe);
    }
    if offline {
        return Err("offline: x64dbg is not installed; prepare it while online".into());
    }
    let root = crate::runtime::root().join("x64dbg");
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let archive = root.join(format!("download-{stamp}.zip"));
    let (tx, _rx) = mpsc::channel();
    crate::engine::run_tool(
        &crate::engine::find_tool(&["curl.exe"]),
        &[
            "--fail".into(),
            "--location".into(),
            "--connect-timeout".into(),
            "10".into(),
            "--max-time".into(),
            "300".into(),
            "--max-filesize".into(),
            "67108864".into(),
            "--output".into(),
            archive.clone().into_os_string(),
            URL.into(),
        ],
        &root,
        &root.join(format!("download-{stamp}.log")),
        310,
        &AtomicBool::new(false),
        &tx,
    )?;
    if crate::project::sha256(&archive)? != HASH {
        return Err("x64dbg download checksum mismatch".into());
    }
    unpack(&archive, &root)?;
    if !exe.is_file() {
        return Err("x64dbg executable is missing from archive".into());
    }
    Ok(exe)
}
fn unpack(archive: &Path, root: &Path) -> Result<(), String> {
    let mut zip = zip::ZipArchive::new(fs::File::open(archive).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if zip.len() > 20_000 {
        return Err("x64dbg archive entry limit".into());
    }
    let mut total = 0u64;
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i).map_err(|e| e.to_string())?;
        let relative = entry
            .enclosed_name()
            .ok_or("unsafe debugger archive path")?;
        if relative
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return Err("unsafe debugger archive path".into());
        }
        total = total
            .checked_add(entry.size())
            .ok_or("debugger archive overflow")?;
        if total > 256 * 1024 * 1024 {
            return Err("debugger archive too large".into());
        }
        let output = root.join(relative);
        if entry.is_dir() {
            fs::create_dir_all(output).map_err(|e| e.to_string())?;
        } else {
            fs::create_dir_all(output.parent().unwrap()).map_err(|e| e.to_string())?;
            let expected = entry.size();
            let copied = std::io::copy(
                &mut (&mut entry).take(expected + 1),
                &mut fs::File::create(output).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            if copied != expected {
                return Err("debugger archive size mismatch".into());
            }
        }
    }
    Ok(())
}
pub fn launch(exe: &Path, target: Option<&Path>) -> Result<(), String> {
    let mut command = Command::new(exe);
    if let Some(target) = target {
        command.arg(target);
        if let Some(parent) = target.parent() {
            command.current_dir(parent);
        }
    }
    command.spawn().map_err(|e| e.to_string())?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn architecture_selection_is_explicit() {
        assert!(executable("x64").unwrap().ends_with("x64/x64dbg.exe"));
        assert!(executable("x86").unwrap().ends_with("x32/x32dbg.exe"));
        assert!(executable("ARM64").is_err());
    }
}
