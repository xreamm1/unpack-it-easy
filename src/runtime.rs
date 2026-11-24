use crate::{
    detect::Route,
    engine::{run_tool, Event, Settings, TOOL_TIMEOUT_SECONDS},
};
use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::{atomic::AtomicBool, mpsc::Sender},
};

static OFFLINE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub fn set_offline(value: bool) {
    OFFLINE.store(value, std::sync::atomic::Ordering::Relaxed);
}
pub fn is_offline() -> bool {
    OFFLINE.load(std::sync::atomic::Ordering::Relaxed)
}

pub fn root() -> PathBuf {
    env::var_os("UIE_ENGINES_DIR")
        .or_else(|| env::var_os("TOKER_ENGINES_DIR"))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("engines")))
                .unwrap_or_else(|| PathBuf::from("engines"))
        })
}

pub fn discover(settings: &mut Settings) {
    let path = root().join("engines.json");
    if let Ok(text) = fs::read_to_string(path) {
        if let Ok(manifest) =
            serde_json::from_str::<serde_json::Value>(text.trim_start_matches('\u{feff}'))
        {
            for (key, field) in [
                ("diec", &mut settings.diec),
                ("extractor", &mut settings.extractor),
                ("pylingual", &mut settings.pylingual),
                ("ilspy", &mut settings.ilspy),
                ("ghidra", &mut settings.ghidra),
                ("python", &mut settings.python),
            ] {
                if let Some(value) = manifest[key].as_str() {
                    let path = if Path::new(value).is_absolute() {
                        PathBuf::from(value)
                    } else {
                        root().join(value)
                    };
                    if path.is_file() {
                        *field = path.to_string_lossy().into_owned();
                    }
                }
            }
        }
    }
}

pub fn environment() -> Vec<(String, OsString)> {
    let root = root();
    let mut vars = vec![];
    if is_offline() {
        for name in [
            "HF_HUB_OFFLINE",
            "TRANSFORMERS_OFFLINE",
            "HF_DATASETS_OFFLINE",
            "UV_OFFLINE",
        ] {
            vars.push((name.into(), "1".into()));
        }
    }
    for (name, path) in [
        ("HF_HOME", root.join("models")),
        ("HF_HUB_CACHE", root.join("models/hub")),
        ("HUGGINGFACE_HUB_CACHE", root.join("models/hub")),
        ("UV_PYTHON_INSTALL_DIR", root.join("python")),
        ("UV_CACHE_DIR", root.join("cache")),
        ("UV_PYTHON_BIN_DIR", root.join("python-bin")),
    ] {
        vars.push((name.into(), path.into_os_string()));
    }
    if let Ok(text) = fs::read_to_string(root.join("engines.json")) {
        if let Ok(manifest) =
            serde_json::from_str::<serde_json::Value>(text.trim_start_matches('\u{feff}'))
        {
            for (key, variable) in [("java_home", "JAVA_HOME"), ("dotnet_root", "DOTNET_ROOT")] {
                if let Some(path) = manifest[key].as_str() {
                    let path = if Path::new(path).is_absolute() {
                        PathBuf::from(path)
                    } else {
                        root.join(path)
                    };
                    vars.push((variable.into(), path.into_os_string()));
                }
            }
            if let Some(uv) = manifest["uv"].as_str() {
                let uv = if Path::new(uv).is_absolute() {
                    PathBuf::from(uv)
                } else {
                    root.join(uv)
                };
                if let Some(parent) = uv.parent() {
                    let mut paths = vec![parent.to_path_buf()];
                    if let Some(path) = env::var_os("PATH") {
                        paths.extend(env::split_paths(&path));
                    }
                    if let Ok(path) = env::join_paths(paths) {
                        vars.push(("PATH".into(), path));
                    }
                }
            }
        }
    }
    vars
}

pub fn java() -> PathBuf {
    environment()
        .into_iter()
        .find(|(key, _)| key == "JAVA_HOME")
        .map(|(_, path)| PathBuf::from(path))
        .or_else(|| env::var_os("JAVA_HOME").map(PathBuf::from))
        .map(|home| {
            home.join(if cfg!(windows) {
                "bin/java.exe"
            } else {
                "bin/java"
            })
        })
        .unwrap_or_else(|| {
            PathBuf::from(crate::engine::find_tool(&[if cfg!(windows) {
                "java.exe"
            } else {
                "java"
            }]))
        })
}

pub fn prepare(
    settings: &mut Settings,
    route: &Route,
    decompile: bool,
    output: &Path,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<(), String> {
    discover(settings);
    let exists = |path: &str| !path.is_empty() && Path::new(path).is_file();
    let backend_ready = !decompile
        || match route {
            Route::PythonArchive => exists(&settings.extractor) && exists(&settings.pylingual),
            Route::PythonBytecode => exists(&settings.pylingual),
            Route::DotNet => exists(&settings.ilspy),
            Route::Native => exists(&settings.ghidra),
            Route::Java => java().is_file(),
            Route::Asar | Route::Unknown => true,
        };
    if backend_ready && (exists(&settings.diec) || !cfg!(windows)) {
        return Ok(());
    }
    if settings.offline || is_offline() {
        return Err(
            "offline mode: required engines are missing; prepare the offline bundle while online"
                .into(),
        );
    }
    if !cfg!(windows) {
        return Err("Missing analysis backend. On Linux install native dependencies and configure engines/engines.json; see docs/linux.md. The Windows PowerShell installer is not used.".into());
    }
    let root = root();
    fs::create_dir_all(&root).map_err(|e| e.to_string())?;
    let script = root.join("install-engines.ps1");
    fs::write(&script, include_str!("install-engines.ps1")).map_err(|e| e.to_string())?;
    let install_route = if backend_ready {
        "detect"
    } else {
        match route {
            Route::PythonArchive | Route::PythonBytecode => "python",
            Route::DotNet => "dotnet",
            Route::Native => "native",
            Route::Java => "java",
            Route::Asar | Route::Unknown => "detect",
        }
    };
    let powershell = env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let args = [
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-ExecutionPolicy".into(),
        "Bypass".into(),
        "-File".into(),
        script.into_os_string(),
        "-Root".into(),
        root.into_os_string(),
        "-Route".into(),
        install_route.into(),
    ];
    run_tool(
        &powershell.to_string_lossy(),
        &args,
        output,
        &output.join(format!("prepare-{install_route}.log")),
        TOOL_TIMEOUT_SECONDS,
        cancel,
        events,
    )?;
    discover(settings);
    Ok(())
}

fn offline_output(root: &Path) -> Result<PathBuf, String> {
    let parent = root.join("offline-preparation");
    fs::create_dir_all(&parent).map_err(|e| e.to_string())?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    for suffix in 0..100 {
        let output = parent.join(format!("run-{stamp}-{suffix}"));
        match fs::create_dir(&output) {
            Ok(()) => return Ok(output),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("could not allocate offline preparation directory".into())
}

pub fn prepare_offline(
    mut settings: Settings,
    versions: String,
    cancel: std::sync::Arc<AtomicBool>,
    events: Sender<Event>,
) {
    set_offline(false);
    settings.offline = false;
    let result = (|| -> Result<(), String> {
        if versions != "all"
            && !["3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"].contains(&versions.as_str())
        {
            return Err("unsupported offline Python version".into());
        }
        let output = offline_output(&root())?;
        fs::create_dir_all(&output).map_err(|e| e.to_string())?;
        for route in [
            Route::PythonArchive,
            Route::Native,
            Route::DotNet,
            Route::Java,
        ] {
            prepare(&mut settings, &route, true, &output, &cancel, &events)?;
        }
        crate::archives::prepare_cfr(&output, &cancel, &events)?;
        if cfg!(windows) {
            crate::debugger::prepare("x64", false)?;
        }
        let script = output.join("prepare_offline.py");
        fs::write(&script, include_str!("prepare_offline.py")).map_err(|e| e.to_string())?;
        run_tool(
            &settings.python,
            &[
                script.into_os_string(),
                "--root".into(),
                root().into_os_string(),
                "--versions".into(),
                versions.into(),
            ],
            &output,
            &output.join("models.log"),
            24 * 3600,
            &cancel,
            &events,
        )?;
        Ok(())
    })();
    let _ = events.send(Event::OfflineReady(result));
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_offline_preparation_has_fresh_log_paths() {
        let root = std::env::temp_dir().join(format!("uie-offline-retry-{}", std::process::id()));
        let a = offline_output(&root).unwrap();
        let b = offline_output(&root).unwrap();
        assert_ne!(a, b);
        fs::write(a.join("models.log"), "old").unwrap();
        assert!(!b.join("models.log").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn offline_missing_engines_never_start_installer() {
        let mut settings = Settings {
            offline: true,
            ..Default::default()
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let result = prepare(
            &mut settings,
            &Route::Native,
            true,
            &std::env::temp_dir(),
            &AtomicBool::new(false),
            &tx,
        );
        assert!(result.unwrap_err().contains("offline"));
        assert!(rx.try_recv().is_err());
    }
}
