use crate::detect::{inspect_file, Analysis, Route};
use serde::{Deserialize, Serialize};
use std::{
    env,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::{Read, Seek},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub const TOOL_TIMEOUT_SECONDS: u64 = 3600;
pub const DIE_TIMEOUT_SECONDS: u64 = 90;
pub const MAX_LOG_CHUNK: u64 = 64 * 1024;
pub const MAX_COLLECTED_FILES: usize = 100_000;
pub const FUNCTION_TIMEOUT_SECONDS: usize = 60;

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub diec: String,
    pub extractor: String,
    pub pylingual: String,
    pub ilspy: String,
    pub ghidra: String,
    pub output: String,
    pub all_modules: bool,
    pub python: String,
    pub force_rebuild: bool,
    pub english: bool,
    pub offline: bool,
    pub hide_updates: bool,
    pub lazy_native: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            diec: String::new(),
            extractor: String::new(),
            pylingual: String::new(),
            ilspy: String::new(),
            ghidra: String::new(),
            output: String::new(),
            all_modules: false,
            python: String::new(),
            force_rebuild: false,
            english: true,
            offline: false,
            hide_updates: false,
            lazy_native: true,
        }
    }
}

pub enum Event {
    Log(String),
    Output(PathBuf),
    Stage(usize, String, Instant),
    EndStage(Instant),
    Progress(crate::telemetry::Progress),
    Problem(crate::telemetry::Problem),
    Identity(String),
    Indicators(crate::indicators::Report),
    OfflineReady(Result<(), String>),
    Analysis(Analysis),
    Finished(Result<Option<PathBuf>, String>),
}

impl Event {
    fn stage(index: usize, text: String) -> Self {
        Self::Stage(index, text, Instant::now())
    }
}

pub fn config_path() -> PathBuf {
    env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| env::var_os("XDG_CONFIG_HOME").map(PathBuf::from))
        .or_else(|| env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
        .unwrap_or_else(env::temp_dir)
        .join("UnpackItEasy")
        .join("settings.json")
}

fn canonical_path(path: &Path) -> Result<PathBuf, String> {
    let path = path.canonicalize().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        // cmd.exe batch launchers cannot reliably consume verbatim-path prefixes.
        let text = path.to_string_lossy();
        if let Some(tail) = text.strip_prefix(r"\\?\UNC\") {
            return Ok(PathBuf::from(format!(r"\\{tail}")));
        }
        if let Some(tail) = text.strip_prefix(r"\\?\") {
            return Ok(PathBuf::from(tail));
        }
    }
    Ok(path)
}

pub fn find_tool(names: &[&str]) -> String {
    let mut folders = vec![];
    if let Ok(exe) = env::current_exe() {
        if let Some(parent) = exe.parent() {
            folders.push(parent.join("tools"));
        }
    }
    if let Some(path) = env::var_os("PATH") {
        folders.extend(env::split_paths(&path));
    }
    if let Some(profile) = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME")) {
        folders.push(PathBuf::from(&profile).join(".local/bin"));
        folders.push(PathBuf::from(profile).join(".dotnet/tools"));
    }
    for folder in folders {
        for name in names {
            let path = folder.join(name);
            if path.is_file() {
                return path.to_string_lossy().into_owned();
            }
        }
    }
    String::new()
}

impl Settings {
    pub fn load() -> Self {
        let mut settings: Self = fs::read(config_path())
            .ok()
            .and_then(|data| serde_json::from_slice(&data).ok())
            .unwrap_or_default();
        for (field, names) in [
            (&mut settings.diec, &["diec.exe", "diec"][..]),
            (
                &mut settings.extractor,
                &[
                    "pyinstxtractor-ng.exe",
                    "pyinstxtractor-ng",
                    "pyinstxtractor-ng.py",
                ][..],
            ),
            (&mut settings.pylingual, &["pylingual.exe", "pylingual"][..]),
            (&mut settings.ilspy, &["ilspycmd.exe", "ilspycmd"][..]),
            (
                &mut settings.ghidra,
                &["analyzeHeadless.bat", "analyzeHeadless"][..],
            ),
        ] {
            if field.is_empty() {
                *field = find_tool(names);
            }
        }
        {
            settings.output = env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|p| p.join("results")))
                .unwrap_or_else(|| PathBuf::from("results"))
                .to_string_lossy()
                .into_owned();
        }
        crate::runtime::discover(&mut settings);
        settings
    }

    pub fn save(&self) -> Result<(), String> {
        let path = config_path();
        fs::create_dir_all(path.parent().unwrap()).map_err(|e| e.to_string())?;
        fs::write(
            path,
            serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }
}

fn hidden(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    #[cfg(not(windows))]
    let _ = command;
}

pub fn open_folder(path: &Path) -> Result<(), String> {
    let mut command = Command::new(if cfg!(windows) {
        "explorer.exe"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    });
    command.arg(path);
    hidden(&mut command);
    command.spawn().map(|_| ()).map_err(|e| e.to_string())
}

fn log(events: &Sender<Event>, text: impl Into<String>) {
    let _ = events.send(Event::Log(text.into()));
}

fn feed_output(pending: &mut Vec<u8>, bytes: &[u8], events: &Sender<Event>) {
    pending.extend_from_slice(bytes);
    while let Some(end) = memchr::memchr(b'\n', pending) {
        let line = String::from_utf8_lossy(&pending[..end])
            .trim_end_matches('\r')
            .to_string();
        if let Some(json) = line
            .find("UIE_EVENT ")
            .and_then(|start| {
                serde_json::Deserializer::from_str(&line[start + 10..])
                    .into_iter::<serde_json::Value>()
                    .next()
            })
            .and_then(Result::ok)
        {
            match json["kind"].as_str() {
                Some("progress") => {
                    if let Ok(value) = serde_json::from_value(json) {
                        let _ = events.send(Event::Progress(value));
                    }
                }
                Some("problem") => {
                    if let Ok(value) = serde_json::from_value(json) {
                        let _ = events.send(Event::Problem(value));
                    }
                }
                _ => (),
            }
        } else if !line.is_empty() {
            log(events, line);
        }
        pending.drain(..=end);
    }
    if pending.len() > 256 * 1024 {
        log(events, String::from_utf8_lossy(pending).into_owned());
        pending.clear();
    }
}

fn drain(file: &mut File, events: &Sender<Event>, pending: &mut Vec<u8>) -> Result<(), String> {
    let mut bytes = vec![];
    file.take(MAX_LOG_CHUNK)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if !bytes.is_empty() {
        feed_output(pending, &bytes, events);
    }
    Ok(())
}

pub fn run_tool(
    tool: &str,
    args: &[OsString],
    cwd: &Path,
    log_path: &Path,
    timeout: u64,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<(), String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("отменено".into());
    }
    let tool =
        canonical_path(Path::new(tool)).map_err(|e| format!("не найден инструмент {tool}: {e}"))?;
    let output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(log_path)
        .map_err(|e| e.to_string())?;
    let mut reader = File::open(log_path).map_err(|e| e.to_string())?;
    log(
        events,
        format!(
            "запуск: {} {:?}\nлог: {}",
            tool.display(),
            args,
            log_path.display()
        ),
    );
    let mut command = if tool
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("dll"))
    {
        let mut command = Command::new(if cfg!(windows) {
            crate::runtime::root().join("dotnet/dotnet.exe")
        } else {
            PathBuf::from(find_tool(&["dotnet"]))
        });
        command.arg(&tool);
        command
    } else {
        Command::new(&tool)
    };
    command
        .args(args)
        .current_dir(cwd)
        .stdin(Stdio::null())
        .env("PYTHONUNBUFFERED", "1")
        .env("PYTHONIOENCODING", "utf-8")
        .env("PYTHONUTF8", "1")
        .env("HF_HUB_DISABLE_XET", "1")
        .env("UV_PYTHON_PREFERENCE", "only-managed")
        .env("COLUMNS", "160")
        .env("NO_COLOR", "1")
        .stdout(Stdio::from(output.try_clone().map_err(|e| e.to_string())?))
        .stderr(Stdio::from(output));
    hidden(&mut command);
    if let Some(parent) = tool.parent() {
        let mut paths = vec![parent.to_path_buf(), parent.join("bootstrap/Scripts")];
        if let Some(path) = env::var_os("PATH") {
            paths.extend(env::split_paths(&path));
        }
        command.env("PATH", env::join_paths(paths).map_err(|e| e.to_string())?);
        if parent.join("python").is_dir() {
            command.env("UV_PYTHON_INSTALL_DIR", parent.join("python"));
        }
    }
    command.envs(crate::runtime::environment());
    command.env("HF_HUB_DOWNLOAD_TIMEOUT", "30");
    if args.iter().any(|arg| {
        Path::new(arg)
            .file_name()
            .is_some_and(|name| name == "prepare_offline.py")
    }) {
        for key in [
            "HF_HUB_OFFLINE",
            "TRANSFORMERS_OFFLINE",
            "HF_DATASETS_OFFLINE",
            "UV_OFFLINE",
        ] {
            command.env_remove(key);
        }
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("{}: {e}", tool.display()))?;
    let start = Instant::now();
    let mut pending = vec![];
    loop {
        let _ = drain(&mut reader, events, &mut pending);
        if cancel.load(Ordering::Relaxed) || start.elapsed().as_secs() >= timeout {
            #[cfg(windows)]
            {
                let mut kill = Command::new("taskkill.exe");
                kill.args(["/PID", &child.id().to_string(), "/T", "/F"]);
                hidden(&mut kill);
                let _ = kill.stdout(Stdio::null()).stderr(Stdio::null()).status();
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(if cancel.load(Ordering::Relaxed) {
                "отменено".into()
            } else {
                format!("таймаут {timeout} секунд; процесс остановлен")
            });
        }
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            while reader.stream_position().unwrap_or(0)
                < reader.metadata().map_err(|e| e.to_string())?.len()
            {
                drain(&mut reader, events, &mut pending)?;
            }
            if !pending.is_empty() {
                feed_output(&mut pending, b"\n", events);
            }
            return if status.success() {
                Ok(())
            } else {
                Err(format!(
                    "инструмент завершился с {status}; лог: {}",
                    log_path.display()
                ))
            };
        }
        thread::sleep(Duration::from_millis(150));
    }
}

#[cfg(test)]
fn new_output(parent: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let parent = canonical_path(parent)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    for index in 0..100 {
        let path = parent.join(format!("uie_{now}_{index}"));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("не удалось создать уникальный каталог".into())
}

fn named_output(parent: &Path, input: &Path) -> Result<PathBuf, String> {
    fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let parent = canonical_path(parent)?;
    let name = input.file_stem().unwrap_or_default().to_string_lossy();
    for index in 1..10000 {
        let suffix = if index == 1 {
            String::new()
        } else {
            format!("_{index}")
        };
        let path = parent.join(format!("{name}_decompiled{suffix}"));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(e) => return Err(e.to_string()),
        }
    }
    Err("слишком много результатов с одинаковым именем".into())
}

fn primary_pyc<'a>(files: &'a [PathBuf], root: &Path) -> Option<&'a PathBuf> {
    for name in ["app", "__main__", "main"] {
        if let Some(file) = files
            .iter()
            .find(|p| p.parent() == Some(root) && p.file_stem().is_some_and(|s| s == name))
        {
            return Some(file);
        }
    }
    files
        .iter()
        .find(|p| p.parent() == Some(root))
        .or_else(|| files.first())
}

fn collect_files(root: &Path, extension: &str) -> Result<Vec<PathBuf>, String> {
    let mut directories = vec![root.to_path_buf()];
    let mut result = vec![];
    let mut visited = 0;
    while let Some(directory) = directories.pop() {
        for entry in fs::read_dir(directory).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            visited += 1;
            if visited > MAX_COLLECTED_FILES {
                return Err("слишком много извлечённых файлов".into());
            }
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                directories.push(entry.path());
            } else if kind.is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case(extension))
            {
                result.push(entry.path());
            }
        }
    }
    result.sort();
    Ok(result)
}

fn required(path: &str, label: &str) -> Result<(), String> {
    if path.is_empty() || !Path::new(path).is_file() {
        Err(format!("укажи путь к {label} в настройках инструментов"))
    } else {
        Ok(())
    }
}

fn copy_resources(root: &Path, destination: &Path) -> Result<usize, String> {
    let extensions = [
        "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "json", "ttf", "otf", "wav", "mp3", "ui",
        "qss", "css", "html", "txt",
    ];
    let mut count = 0;
    for extension in extensions {
        for file in collect_files(root, extension)? {
            let relative = file.strip_prefix(root).map_err(|e| e.to_string())?;
            if relative
                .components()
                .next()
                .is_some_and(|c| c.as_os_str() == "PYZ.pyz_extracted")
            {
                continue;
            }
            let target = destination.join(relative);
            fs::create_dir_all(target.parent().unwrap()).map_err(|e| e.to_string())?;
            fs::copy(file, target).map_err(|e| e.to_string())?;
            count += 1;
        }
    }
    Ok(count)
}

fn equivalence_rates(text: &str) -> Vec<f64> {
    text.lines()
        .filter(|line| line.contains("code object success rate"))
        .filter_map(|line| {
            let before = line.split_once('%')?.0;
            let value = before.split_whitespace().last()?.parse::<f64>().ok()?;
            (value.is_finite() && (0.0..=100.0).contains(&value)).then_some(value)
        })
        .collect()
}

fn decompile_python(
    input: &Path,
    analysis: &Analysis,
    settings: &Settings,
    output: &Path,
    public_prefix: &Path,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<(), String> {
    let bytecode = if analysis.route == Route::PythonArchive {
        let extraction = output.join("extraction");
        fs::create_dir(&extraction).map_err(|e| e.to_string())?;
        // Work on a copy. Never run the analyzed executable.
        let staged = extraction.join("sample.bin");
        fs::copy(input, &staged).map_err(|e| e.to_string())?;
        let mut extractor_args = vec![];
        if settings.extractor == settings.python && !settings.python.is_empty() {
            extractor_args.extend(["-m".into(), "pyinstxtractor_ng".into()]);
        }
        extractor_args.push(staged.into_os_string());
        let _ = events.send(Event::stage(3, "извлечение архива pyinstaller".into()));
        run_tool(
            &settings.extractor,
            &extractor_args,
            &extraction,
            &output.join("extractor.log"),
            TOOL_TIMEOUT_SECONDS,
            cancel,
            events,
        )?;
        let extracted = extraction.join("sample.bin_extracted");
        let mut files = collect_files(&extracted, "pyc")?;
        if !settings.all_modules {
            files.retain(|p| {
                p.parent() == Some(extracted.as_path())
                    && p.file_stem().is_some_and(|stem| {
                        let name = stem.to_string_lossy();
                        !name.starts_with("pyiboot")
                            && !name.starts_with("pyimod")
                            && !name.starts_with("pyi_rth_")
                    })
            });
        }
        if files.is_empty() {
            return Err("не найдены .pyc; проверь extractor.log или включи все модули".into());
        }
        // Mirror selected bytecode into one tree. PyLingual can process the tree in one invocation.
        let selection = output.join("bytecode");
        for path in files {
            let relative = path.strip_prefix(&extracted).map_err(|e| e.to_string())?;
            let destination = selection.join(relative);
            fs::create_dir_all(destination.parent().unwrap()).map_err(|e| e.to_string())?;
            fs::copy(path, destination).map_err(|e| e.to_string())?;
        }
        selection
    } else {
        let selection = output.join("bytecode");
        fs::create_dir(&selection).map_err(|e| e.to_string())?;
        fs::copy(input, selection.join("input.pyc")).map_err(|e| e.to_string())?;
        selection
    };
    let sources = output.join("source");
    if analysis.route == Route::PythonArchive {
        let resources = copy_resources(&output.join("extraction/sample.bin_extracted"), &sources)?;
        log(events, format!("сохранено ресурсов: {resources}"));
    }
    if let Ok(bytes) = fs::read(output.join("indicators.json")) {
        if let Ok(mut report) = serde_json::from_slice::<crate::indicators::Report>(&bytes) {
            crate::indicators::resources(
                &output.join("extraction/sample.bin_extracted"),
                &mut report,
                cancel,
            )?;
            write_json(&output.join("indicators.json"), &report)?;
            let _ = events.send(Event::Indicators(report));
        }
    }
    let expected = collect_files(&bytecode, "pyc")?;
    log(
        events,
        format!(
            "pylingual: {} файлов .pyc; первый запуск может загружать модели",
            expected.len()
        ),
    );
    let mut args = vec![];
    if settings.pylingual == settings.python && !settings.python.is_empty() {
        let bridge = output.join("uie-pylingual.py");
        fs::write(
            output.join("model_download.py"),
            include_str!("model_download.py"),
        )
        .map_err(|e| e.to_string())?;
        fs::write(&bridge, include_str!("pylingual_bridge.py")).map_err(|e| e.to_string())?;
        args.push(bridge.into_os_string());
    }
    args.extend([OsString::from("-o"), sources.clone().into_os_string()]);
    let application_name = input
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    if settings.pylingual == settings.python && !settings.python.is_empty() {
        args.extend([
            "--application-name".into(),
            application_name.clone().into(),
            "--output-prefix".into(),
            public_prefix.as_os_str().into(),
        ]);
    }
    if let Some(version) = &analysis.python_version {
        args.extend([OsString::from("-v"), OsString::from(version)]);
    }
    args.push(bytecode.clone().into_os_string());
    let _ = events.send(Event::stage(
        4,
        "декомпиляция python через pylingual".into(),
    ));
    let execution = run_tool(
        &settings.pylingual,
        &args,
        output,
        &output.join("pylingual.log"),
        TOOL_TIMEOUT_SECONDS,
        cancel,
        events,
    );
    let _ = events.send(Event::stage(5, "проверка полноты и эквивалентности".into()));
    let mut recovered = vec![];
    let mut missing = vec![];
    for file in &expected {
        let relative = file.strip_prefix(&bytecode).map_err(|e| e.to_string())?;
        let name = if primary_pyc(&expected, &bytecode) == Some(file)
            && settings.pylingual == settings.python
            && !settings.python.is_empty()
        {
            format!("{application_name}_decompiled.py")
        } else {
            format!(
                "decompiled_{}.py",
                relative.file_stem().unwrap().to_string_lossy()
            )
        };
        let target = sources
            .join(relative.parent().unwrap_or(Path::new("")))
            .join(name);
        if target.metadata().is_ok_and(|metadata| metadata.len() != 0) {
            recovered.push(target);
        } else {
            missing.push(relative.to_string_lossy().into_owned());
        }
    }
    let tool_log = fs::read_to_string(output.join("pylingual.log")).unwrap_or_default();
    let rates = equivalence_rates(&tool_log);
    let verified = rates.len() == expected.len() && rates.iter().all(|rate| *rate == 100.0);
    let report = serde_json::json!({
        "selected_pyc": expected.len(), "emitted_source_files": recovered.len(),
        "missing_source_files": missing, "sources": recovered,
        "bytecode_equivalence_percent": rates, "internal_equivalence_passed": verified,
        "verification": "internal bytecode comparison is separate from a functional application test",
    });
    write_json(&output.join("python-report.json"), &report)?;
    execution?;
    if !missing.is_empty() {
        return Err(format!(
            "частичный результат: {}/{} .py; см. python-report.json и pylingual.log",
            recovered.len(),
            expected.len()
        ));
    }
    if !verified {
        return Err(format!("исходники сохранены, но полная эквивалентность не подтверждена: {rates:?}; см. python-report.json"));
    }
    log(
        events,
        format!(
            "получено {} файлов .py; корректность сверяй по equivalence results в pylingual.log",
            recovered.len()
        ),
    );
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), String> {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

fn decompile_dotnet(
    input: &Path,
    settings: &Settings,
    output: &Path,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<(), String> {
    let _ = events.send(Event::stage(
        4,
        format!(
            "ilspy: {}",
            input.file_name().unwrap_or_default().to_string_lossy()
        ),
    ));
    let source = output.join("source");
    run_tool(
        &settings.ilspy,
        &[
            "-p".into(),
            "-o".into(),
            source.clone().into_os_string(),
            input.as_os_str().into(),
        ],
        output,
        &output.join("ilspy.log"),
        TOOL_TIMEOUT_SECONDS,
        cancel,
        events,
    )?;
    if collect_files(&source, "cs")?.is_empty() {
        return Err("ilspy не создал .cs".into());
    }
    Ok(())
}

pub fn lazy_function(settings: Settings, root: &Path, address: &str) -> Result<PathBuf, String> {
    lazy_function_with_cancel(settings, root, address, &AtomicBool::new(false))
}

struct GhidraSelectionWork {
    path: PathBuf,
    parent: PathBuf,
}
impl Drop for GhidraSelectionWork {
    fn drop(&mut self) {
        if let (Ok(path), Ok(parent)) = (self.path.canonicalize(), self.parent.canonicalize()) {
            if path.parent() == Some(parent.as_path())
                && parent.file_name().is_some_and(|name| name == "lazy-ghidra")
                && path.file_name().is_some_and(|name| {
                    name.to_string_lossy()
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() || b == b'-')
                })
            {
                let _ = fs::remove_dir_all(path);
            }
        }
    }
}

fn ghidra_selected_range(
    mut settings: Settings,
    root: &Path,
    input: &Path,
    result: &Path,
    start: u64,
    end: u64,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let (tx, _rx) = std::sync::mpsc::channel();
    crate::runtime::prepare(&mut settings, &Route::Native, true, root, cancel, &tx)?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let work = root.join("lazy-ghidra").join(format!("{start:x}-{stamp}"));
    fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let _cleanup = GhidraSelectionWork {
        path: work.clone(),
        parent: root.join("lazy-ghidra"),
    };
    fs::write(
        work.join("UieFunction.java"),
        include_str!("UieFunction.java")
            .replace("FUNCTION_TIMEOUT", &FUNCTION_TIMEOUT_SECONDS.to_string()),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        work.join("UiePythonTypes.java"),
        include_str!("UiePythonTypes.java"),
    )
    .map_err(|e| e.to_string())?;
    let temporary = work.join("function.c");
    run_tool(
        &settings.ghidra,
        &[
            work.as_os_str().into(),
            "Selected".into(),
            "-import".into(),
            input.as_os_str().into(),
            "-noanalysis".into(),
            "-scriptPath".into(),
            work.as_os_str().into(),
            "-preScript".into(),
            "UiePythonTypes.java".into(),
            work.join("python-api-types.json").into_os_string(),
            "-postScript".into(),
            "UieFunction.java".into(),
            temporary.clone().into_os_string(),
            format!("{start:x}").into(),
            format!("{end:x}").into(),
            "-deleteProject".into(),
        ],
        &work,
        &root.join(format!("lazy-{start:x}-ghidra.log")),
        u64::MAX,
        cancel,
        &tx,
    )?;
    if cancel.load(Ordering::Relaxed) {
        return Err("отменено".into());
    }
    let mut source = File::open(&temporary)
        .map_err(|_| "Ghidra did not emit the selected function; see its lazy log")?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(result)
        .map_err(|e| e.to_string())?;
    if let Err(error) = std::io::copy(&mut source, &mut destination) {
        drop(destination);
        let _ = fs::remove_file(result);
        return Err(error.to_string());
    }
    Ok(())
}

pub fn lazy_function_with_cancel(
    mut settings: Settings,
    root: &Path,
    address: &str,
    cancel: &AtomicBool,
) -> Result<PathBuf, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("отменено".into());
    }
    if address.is_empty() || address.len() > 16 || !address.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid native function address".into());
    }
    let report: serde_json::Value = serde_json::from_slice(
        &fs::read(root.join("native-report.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if report["lazy"].as_bool() != Some(true)
        || !report["functions"].as_array().is_some_and(|rows| {
            rows.iter()
                .any(|row| row["address"].as_str() == Some(address))
        })
    {
        return Err("function not in lazy index".into());
    }
    let source = root.join("source/functions");
    fs::create_dir_all(&source).map_err(|e| e.to_string())?;
    let result = source.join(format!("FUN_{address}.c"));
    if result.is_file() {
        return Ok(result);
    }
    if !root.join("UIEProject.gpr").is_file() {
        if report["index_engine"]
            .as_str()
            .is_some_and(|name| name.contains("Rust"))
            || report["native_input"].is_string()
        {
            let input = PathBuf::from(
                report["native_input"]
                    .as_str()
                    .ok_or("missing original binary path")?,
            );
            if crate::project::sha256(&input)?
                != report["native_input_sha256"].as_str().unwrap_or("")
            {
                return Err("original binary changed; rebuild its index".into());
            }
            let function = report["functions"]
                .as_array()
                .and_then(|rows| {
                    rows.iter()
                        .find(|row| row["address"].as_str() == Some(address))
                })
                .ok_or("function missing")?;
            let end = u64::from_str_radix(
                function["end"].as_str().ok_or(
                    "function extent is unknown; no complete body can be inferred from this index",
                )?,
                16,
            )
            .map_err(|e| e.to_string())?;
            let start = u64::from_str_radix(address, 16).map_err(|e| e.to_string())?;
            if crate::retdec::available().is_none() {
                ghidra_selected_range(settings, root, &input, &result, start, end, cancel)?;
                return Ok(result);
            }
            if let Err(retdec_error) =
                crate::retdec::decompile_range(&input, &result, start, end, cancel)
            {
                if cancel.load(Ordering::Relaxed) {
                    return Err(retdec_error);
                }
                fs::write(
                    root.join(format!("lazy-{address}-retdec-error.log")),
                    &retdec_error,
                )
                .map_err(|e| e.to_string())?;
                ghidra_selected_range(settings, root, &input, &result, start, end, cancel)
                    .map_err(|ghidra_error| {
                        format!("RetDec: {retdec_error}\nGhidra: {ghidra_error}")
                    })?;
                return Ok(result);
            }
            let text = fs::read_to_string(&result).map_err(|e| e.to_string())?;
            let symbol = function["name"]
                .as_str()
                .unwrap_or("native_function")
                .replace("*/", "* /");
            fs::write(
                &result,
                format!("/* Function at {address}: {symbol} */\n{text}"),
            )
            .map_err(|e| e.to_string())?;
            return Ok(result);
        }
        return Err(
            "saved Ghidra cache is missing; reopen the original binary to rebuild its index".into(),
        );
    }
    let program = report["ghidra_program"]
        .as_str()
        .ok_or("missing Ghidra program name")?;
    if program.starts_with('-')
        || !program
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-. ()".contains(c))
    {
        return Err("invalid Ghidra program name".into());
    }
    let (tx, _rx) = std::sync::mpsc::channel();
    crate::runtime::prepare(&mut settings, &Route::Native, true, root, cancel, &tx)?;
    let scripts = root.join(".uie-scripts");
    fs::create_dir_all(&scripts).map_err(|e| e.to_string())?;
    fs::write(
        scripts.join("UiePythonTypes.java"),
        include_str!("UiePythonTypes.java"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        scripts.join("UieFunction.java"),
        include_str!("UieFunction.java")
            .replace("FUNCTION_TIMEOUT", &FUNCTION_TIMEOUT_SECONDS.to_string()),
    )
    .map_err(|e| e.to_string())?;
    let temporary = result.with_extension("c.pending");
    let ghidra_result = run_tool(
        &settings.ghidra,
        &[
            root.as_os_str().into(),
            "UIEProject".into(),
            "-process".into(),
            program.into(),
            "-noanalysis".into(),
            "-readOnly".into(),
            "-scriptPath".into(),
            scripts.into_os_string(),
            "-preScript".into(),
            "UiePythonTypes.java".into(),
            root.join("python-api-types.json").into_os_string(),
            "-postScript".into(),
            "UieFunction.java".into(),
            temporary.clone().into_os_string(),
            address.into(),
        ],
        root,
        &root.join(format!("lazy-{address}.log")),
        u64::MAX,
        cancel,
        &tx,
    );
    if cancel.load(Ordering::Relaxed) {
        return Err("отменено".into());
    }
    if ghidra_result.is_err() || !temporary.is_file() {
        if crate::retdec::available().is_some() {
            let input = PathBuf::from(
                report["native_input"]
                    .as_str()
                    .ok_or("missing original binary path for RetDec")?,
            );
            if crate::project::sha256(&input)?
                != report["native_input_sha256"].as_str().unwrap_or("")
            {
                return Err(
                    "original binary changed; rebuild its index before RetDec analysis".into(),
                );
            }
            let function = report["functions"]
                .as_array()
                .and_then(|rows| {
                    rows.iter()
                        .find(|row| row["address"].as_str() == Some(address))
                })
                .ok_or("function missing")?;
            let end = u64::from_str_radix(
                function["end"].as_str().ok_or("missing function extent")?,
                16,
            )
            .map_err(|e| e.to_string())?;
            let start = u64::from_str_radix(address, 16).map_err(|e| e.to_string())?;
            let _ = fs::remove_file(&temporary);
            crate::retdec::decompile_range(&input, &temporary, start, end, cancel)?;
            let text = fs::read_to_string(&temporary).map_err(|e| e.to_string())?;
            let symbol = function["name"]
                .as_str()
                .unwrap_or("native_function")
                .replace("*/", "* /");
            fs::write(
                &temporary,
                format!("/* Function at {address}: {symbol} */\n{text}"),
            )
            .map_err(|e| e.to_string())?;
        } else {
            return Err(ghidra_result.err().unwrap_or_else(|| {
                "Ghidra did not emit this function; see lazy function log".into()
            }));
        }
    }
    fs::rename(temporary, &result).map_err(|e| e.to_string())?;
    Ok(result)
}

fn decompile_native(
    input: &Path,
    settings: &Settings,
    output: &Path,
    public_prefix: &Path,
    cancel: &AtomicBool,
    events: &Sender<Event>,
) -> Result<(), String> {
    if settings.lazy_native {
        match crate::native_index::build(input, output, cancel) {
            Ok(count) => {
                match crate::native_lift::analyze(input,output,cancel){
                    Ok(_)=>{
                        let path=output.join("native-report.json");
                        let mut report:serde_json::Value=serde_json::from_slice(&fs::read(&path).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?;
                        for(filename,key)in[("cython-strings-report.json","cython_literal_tables"),("native-constants-report.json","uie_constant_analysis"),("native-tables-report.json","uie_table_patterns")]{if let Ok(bytes)=fs::read(output.join(filename)){if let Ok(value)=serde_json::from_slice::<serde_json::Value>(&bytes){report[key]=value;}}}
                        write_json(&path,&report)?;
                    }
                    Err(error) if !cancel.load(Ordering::Relaxed)=>log(events,format!("Additional scalar/string recovery unavailable: {error}; metadata index retained")),
                    Err(error)=>return Err(error),
                }
                log(events,format!("UIE Rust native index: {count} entries; function bodies are decompiled on selection"));
                return Ok(());
            }
            Err(error) if !cancel.load(Ordering::Relaxed) => log(
                events,
                format!("Rust metadata index unavailable: {error}; using Ghidra discovery"),
            ),
            Err(error) => return Err(error),
        }
    }
    match crate::native_lift::analyze(input, output, cancel) {
        Ok(report) => log(
            events,
            format!(
                "UIE Rust native lift: {} complete scalar functions; see native-lift-report.json",
                report.lifted
            ),
        ),
        Err(error) => log(
            events,
            format!("UIE Rust native lift: {error}; continuing with Ghidra"),
        ),
    }
    let _ = events.send(Event::stage(
        4,
        format!(
            "ghidra: {}",
            input.file_name().unwrap_or_default().to_string_lossy()
        ),
    ));
    let scripts = output.join(".uie-scripts");
    fs::create_dir_all(&scripts).map_err(|e| e.to_string())?;
    fs::write(
        scripts.join("UieExport.java"),
        GHIDRA_SCRIPT.replace("FUNCTION_TIMEOUT", &FUNCTION_TIMEOUT_SECONDS.to_string()),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        scripts.join("UieAnalysis.java"),
        include_str!("UieAnalysis.java"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        scripts.join("UieFunction.java"),
        include_str!("UieFunction.java")
            .replace("FUNCTION_TIMEOUT", &FUNCTION_TIMEOUT_SECONDS.to_string()),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        scripts.join("UiePythonTypes.java"),
        include_str!("UiePythonTypes.java"),
    )
    .map_err(|e| e.to_string())?;
    let filename = format!(
        "{}_decompiled.c",
        input.file_stem().unwrap_or_default().to_string_lossy()
    );
    let c_file = output.join(&filename);
    let public_source = public_prefix.join(&filename);
    let mut native_args = vec![
        output.as_os_str().into(),
        "UIEProject".into(),
        "-import".into(),
        input.as_os_str().into(),
        "-scriptPath".into(),
        scripts.clone().into_os_string(),
    ];
    if settings.lazy_native {
        native_args.extend([
            OsString::from("-preScript"),
            OsString::from("UieAnalysis.java"),
            output.join("analysis-profile.json").into_os_string(),
        ]);
    }
    native_args.extend([
        OsString::from("-preScript"),
        OsString::from("UiePythonTypes.java"),
        output.join("python-api-types.json").into_os_string(),
        OsString::from("-postScript"),
        OsString::from("UieExport.java"),
        c_file.clone().into_os_string(),
        public_source.into_os_string(),
        output.join("nuitka-modules-report.json").into_os_string(),
        output.join("python-methods-report.json").into_os_string(),
        if settings.lazy_native {
            "index".into()
        } else {
            "full".into()
        },
    ]);
    if !settings.lazy_native {
        native_args.push("-deleteProject".into());
    }
    run_tool(
        &settings.ghidra,
        &native_args,
        output,
        &output.join("ghidra.log"),
        u64::MAX,
        cancel,
        events,
    )?;
    let _ = events.send(Event::stage(5, "проверка функций и отчёта констант".into()));
    let mut report: serde_json::Value = serde_json::from_slice(
        &fs::read(output.join("native-report.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    for (filename, key) in [
        ("cython-strings-report.json", "cython_literal_tables"),
        ("native-constants-report.json", "uie_constant_analysis"),
        ("native-tables-report.json", "uie_table_patterns"),
    ] {
        if let Ok(bytes) = fs::read(output.join(filename)) {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                report[key] = value;
            }
        }
    }
    if settings.lazy_native {
        report["ghidra_program"] =
            serde_json::json!(input.file_name().unwrap_or_default().to_string_lossy());
        report["native_input"] = serde_json::json!(input.to_string_lossy());
        report["native_input_sha256"] = serde_json::json!(crate::project::sha256(input)?);
        report["recovery_contract"] = serde_json::json!({"output_kind":"native function index", "original_python_recovered":false,"functional_equivalence_verified":false});
        write_json(&output.join("native-report.json"), &report)?;
        log(
            events,
            format!(
                "native function index: {} functions; select a symbol to decompile",
                report["indexed"]
            ),
        );
        return Ok(());
    }
    if let Ok(bytes) = fs::read(output.join("native-constants-report.json")) {
        if let Ok(constants) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            report["uie_constant_analysis"] = constants;
            write_json(&output.join("native-report.json"), &report)?;
        }
    }
    if let Ok(bytes) = fs::read(output.join("nuitka-modules-report.json")) {
        if let Ok(modules) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            report["nuitka_modules"] = modules;
        }
    }
    if let Ok(bytes) = fs::read(output.join("python-methods-report.json")) {
        if let Ok(methods) = serde_json::from_slice::<serde_json::Value>(&bytes) {
            report["python_methods"] = methods;
        }
    }
    match crate::cython::annotate(&c_file, &mut report) {
        Ok(count) if count > 0 => log(events, format!("Python traceback metadata: {count} native functions received qualified Python names")),
        Ok(_) => (),
        Err(error) => log(events, format!("Python traceback metadata: {error}")),
    }
    match crate::cython_slots::recover(input, &c_file, output) {
        Ok(count) if count > 0 => {
            let aliases = crate::cython_slots::annotate_aliases(&c_file, output)?;
            log(
                events,
                format!(
                    "Cython object names: {aliases} references annotated; raw pseudocode retained"
                ),
            );
            report["cython_object_slots"] = serde_json::from_slice(
                &fs::read(output.join("cython-slots-report.json")).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            log(
                events,
                format!("Cython initializer dataflow: {count} constant object slots recovered"),
            );
        }
        Ok(_) => (),
        Err(error) => log(
            events,
            format!("Cython object slots not recovered: {error}"),
        ),
    }
    let native_python = report["nuitka_modules"]["marker_found"].as_bool() == Some(true)
        || report["cython_recovery"]["mapped_native_functions"]
            .as_u64()
            .unwrap_or(0)
            > 0;
    report["recovery_contract"] = serde_json::json!({
        "output_kind":"native C pseudocode", "native_python_evidence":native_python,
        "original_python_recovered":false, "functional_equivalence_verified":false,
        "symbol_metadata_is_not_source_recovery":true,
    });
    write_json(&output.join("native-report.json"), &report)?;
    log(
        events,
        format!(
            "ghidra: {} функций; {} исключено как runtime; {} участков высокой энтропии",
            report["decompiled"],
            report["filtered_runtime"],
            report["high_entropy_sections"]
                .as_array()
                .map_or(0, Vec::len)
        ),
    );
    if report["decompiled"].as_u64().unwrap_or(0) == 0 {
        return Err("ghidra не создала пользовательских функций; см. native-report.json".into());
    }
    if report["failed"].as_u64().unwrap_or(0) > 0 {
        return Err("часть native-функций не декомпилирована; см. native-report.json".into());
    }
    if native_python {
        return Err("native pseudocode and Python metadata saved; original Python source recovery remains incomplete".into());
    }
    Ok(())
}

pub fn job(
    input: PathBuf,
    mut settings: Settings,
    decompile: bool,
    cancel: Arc<AtomicBool>,
    events: Sender<Event>,
) {
    crate::runtime::set_offline(settings.offline);
    let mut result_path = None;
    let result = (|| -> Result<Option<PathBuf>, String> {
        let _ = events.send(Event::stage(0, "чтение заголовков и сигнатур".into()));
        let input = canonical_path(&input)?;
        let mut analysis = inspect_file(&input)?;
        let mut indicators = crate::indicators::inspect(&input, &cancel)?;
        let input_hash = indicators.sha256.clone();
        let _ = events.send(Event::Indicators(indicators.clone()));
        let _ = events.send(Event::Identity(input_hash.clone()));
        if decompile && !settings.force_rebuild {
            match crate::project::cached(
                &input_hash,
                settings.all_modules,
                &input,
                settings.lazy_native,
            ) {
                Ok(Some(project)) => {
                    log(&events, "открыт сохранённый проект; SHA256 образца и исходников совпадает; повторная декомпиляция не выполнялась");
                    log(&events, &project.verification);
                    let _ = events.send(Event::Analysis(project.analysis));
                    let _ = events.send(Event::Output(project.output.clone()));
                    let _ = events.send(Event::stage(6, "открытие проверенного проекта".into()));
                    return Ok(Some(project.output));
                }
                Ok(None) => (),
                Err(error) => log(&events, format!("проект пропущен: {error}")),
            }
        }
        log(
            &events,
            format!(
                "{} / {}\n{}",
                analysis.format,
                analysis.architecture,
                analysis.route.label()
            ),
        );
        let _ = events.send(Event::Analysis(analysis.clone()));
        let output = named_output(Path::new(&settings.output), &input)?;
        result_path = Some(output.clone());
        let _ = events.send(Event::Output(output.clone()));
        write_json(&output.join("indicators.json"), &indicators)?;
        let _ = events.send(Event::stage(1, "подготовка встроенных движков".into()));
        crate::runtime::prepare(
            &mut settings,
            &analysis.route,
            decompile,
            &output,
            &cancel,
            &events,
        )?;
        if decompile {
            match analysis.route {
                Route::PythonArchive => {
                    required(&settings.extractor, "pyinstxtractor-ng.exe")?;
                    required(&settings.pylingual, "pylingual.exe")?;
                }
                Route::PythonBytecode => required(&settings.pylingual, "pylingual.exe")?,
                Route::DotNet => required(&settings.ilspy, "ilspycmd.exe")?,
                Route::Native => required(&settings.ghidra, "analyzeHeadless.bat")?,
                Route::Asar | Route::Java => (),
                Route::Unknown => {
                    return Err(
                        "формат не распознан; автоматическая декомпиляция недоступна".into(),
                    )
                }
            }
        }
        log(&events, format!("каталог результата: {}", output.display()));
        let _ = events.send(Event::stage(2, "расширенный анализ detect it easy".into()));
        if !settings.diec.is_empty() {
            let die_log = output.join("diec.log");
            match run_tool(
                &settings.diec,
                &[OsString::from("-j"), input.clone().into_os_string()],
                &output,
                &die_log,
                DIE_TIMEOUT_SECONDS,
                &cancel,
                &events,
            ) {
                Ok(()) => {
                    match fs::read(&die_log)
                        .ok()
                        .and_then(|data| serde_json::from_slice(&data).ok())
                    {
                        Some(value) => analysis.detect_it_easy = Some(value),
                        None => analysis
                            .notes
                            .push("diec вернул не JSON; см. diec.log".into()),
                    }
                }
                Err(error) => {
                    if cancel.load(Ordering::Relaxed) {
                        return Err(error);
                    }
                    analysis.notes.push(format!("diec: {error}"));
                }
            }
        }
        if let Some(value) = &analysis.detect_it_easy {
            for signature in crate::detect::die_summary(value) {
                let lower = signature.to_ascii_lowercase();
                if lower.starts_with("compiler:")
                    || lower.starts_with("linker:")
                    || lower.starts_with("language:")
                {
                    analysis
                        .compiler_hints
                        .retain(|h| !h.starts_with("не определён"));
                    if !analysis.compiler_hints.contains(&signature) {
                        analysis.compiler_hints.push(signature.clone());
                    }
                }
                if (lower.starts_with("packer:") || lower.starts_with("protector:"))
                    && !analysis.packer_hints.contains(&signature)
                {
                    analysis.packer_hints.push(signature.clone());
                }
                log(&events, format!("DIE: {signature}"));
            }
        }
        write_json(&output.join("analysis.json"), &analysis)?;
        let _ = events.send(Event::Analysis(analysis.clone()));
        if !decompile {
            return Ok(Some(output));
        }
        if cancel.load(Ordering::Relaxed) {
            return Err("отменено".into());
        }
        let mut unpack_error = None;
        let mut primary_input = input.clone();
        if crate::unpack::indicated(&analysis) {
            let _ = events.send(Event::stage(
                3,
                "UPX: decompressing a copy; target is not executed".into(),
            ));
            write_json(&output.join("packed-analysis.json"), &analysis)?;
            match crate::unpack::automatic(
                &input,
                &analysis,
                &output,
                settings.offline,
                &cancel,
                &events,
            ) {
                Ok(Some((path, found))) => {
                    primary_input = path;
                    analysis = found;
                    let preparation = output.join("unpacked-engine-preparation");
                    fs::create_dir_all(&preparation).map_err(|e| e.to_string())?;
                    crate::runtime::prepare(
                        &mut settings,
                        &analysis.route,
                        true,
                        &preparation,
                        &cancel,
                        &events,
                    )?;
                    write_json(&output.join("analysis.json"), &analysis)?;
                    let _ = events.send(Event::Analysis(analysis.clone()));
                    log(
                        &events,
                        format!("UPX decompressed successfully → {}", analysis.route.label()),
                    );
                }
                Ok(None) => (),
                Err(error) => {
                    if cancel.load(Ordering::Relaxed) {
                        return Err(error);
                    }
                    log(
                        &events,
                        format!("UPX: {error}; continuing static analysis of the packed input"),
                    );
                    unpack_error = Some(format!("UPX unpacking incomplete: {error}"));
                }
            }
        }
        if analysis.route == Route::Native {
            let _ = events.send(Event::stage(3, "поиск соседних модулей".into()));
        }
        let plan = crate::triage::discover(&input, &analysis)?;
        let dependency_snapshot = crate::project::dependency_snapshot(&input, &plan.modules)?;
        write_json(&output.join("triage-report.json"), &plan)?;
        if !plan.triggers.is_empty() {
            log(
                &events,
                format!(
                    "directory triage: {} модулей; {}",
                    plan.modules.len(),
                    plan.triggers.join(", ")
                ),
            );
        }
        let primary_result = match analysis.route {
            Route::Asar => {
                let _ = events.send(Event::stage(3, "ASAR extraction".into()));
                crate::archives::asar(&primary_input, &output, &cancel, &events)
            }
            Route::Java => {
                let _ = events.send(Event::stage(4, "Java → CFR".into()));
                crate::archives::java(&primary_input, &mut settings, &output, &cancel, &events)
            }
            Route::PythonArchive | Route::PythonBytecode => decompile_python(
                &primary_input,
                &analysis,
                &settings,
                &output,
                Path::new(""),
                &cancel,
                &events,
            ),
            Route::DotNet => decompile_dotnet(&primary_input, &settings, &output, &cancel, &events),
            Route::Native => decompile_native(
                &primary_input,
                &settings,
                &output,
                Path::new(""),
                &cancel,
                &events,
            ),
            Route::Unknown => unreachable!(),
        };
        let mut errors = primary_result.err().into_iter().collect::<Vec<_>>();
        errors.extend(unpack_error);
        let mut module_results = vec![];
        for (index, module) in plan.modules.iter().enumerate() {
            if cancel.load(Ordering::Relaxed) {
                return Err("отменено".into());
            }
            let relative = Path::new("source/modules").join(&module.relative);
            let module_output = output.join(&relative);
            fs::create_dir_all(&module_output).map_err(|e| e.to_string())?;
            log(
                &events,
                format!(
                    "модуль {} / {}: {} → {}",
                    index + 1,
                    plan.modules.len(),
                    module.relative.display(),
                    module.route
                ),
            );
            let result = (|| -> Result<(), String> {
                if module.route == "source" {
                    let destination = module_output.join(module.path.file_name().unwrap());
                    fs::copy(&module.path, destination).map_err(|e| e.to_string())?;
                    return Ok(());
                }
                let found = inspect_file(&module.path)?;
                crate::runtime::prepare(
                    &mut settings,
                    &found.route,
                    true,
                    &module_output,
                    &cancel,
                    &events,
                )?;
                write_json(&module_output.join("analysis.json"), &found)?;
                match found.route {
                    Route::Native => decompile_native(
                        &module.path,
                        &settings,
                        &module_output,
                        &relative,
                        &cancel,
                        &events,
                    ),
                    Route::DotNet => {
                        decompile_dotnet(&module.path, &settings, &module_output, &cancel, &events)
                    }
                    Route::PythonArchive | Route::PythonBytecode => decompile_python(
                        &module.path,
                        &found,
                        &settings,
                        &module_output,
                        &relative,
                        &cancel,
                        &events,
                    ),
                    Route::Asar => {
                        crate::archives::asar(&module.path, &module_output, &cancel, &events)
                    }
                    Route::Java => crate::archives::java(
                        &module.path,
                        &mut settings,
                        &module_output,
                        &cancel,
                        &events,
                    ),
                    Route::Unknown => Err("формат модуля не поддержан".into()),
                }
            })();
            if let Err(error) = &result {
                errors.push(format!("{}: {error}", module.relative.display()));
            }
            module_results.push(serde_json::json!({"module":module,"output":relative,"success":result.is_ok(),"provenance":if module.route=="source"{"copied existing source"}else{"decompiler output"},"error":result.err()}));
        }
        write_json(
            &output.join("triage-report.json"),
            &serde_json::json!({"discovery":plan,"results":module_results}),
        )?;
        crate::indicators::resources(&output.join("source"), &mut indicators, &cancel)?;
        write_json(&output.join("indicators.json"), &indicators)?;
        let _ = events.send(Event::Indicators(indicators));
        if crate::project::sha256(&input)? != input_hash
            || !crate::project::dependencies_match(&input, &dependency_snapshot)?
        {
            return Err("input files changed during analysis; outputs remain unverified and were not cached".into());
        }
        if !errors.is_empty() {
            return Err(errors.join("; "));
        }
        if let Err(error) = crate::project::save(
            &input_hash,
            &output,
            settings.all_modules,
            &analysis,
            &input,
            &dependency_snapshot,
        ) {
            log(&events, format!("не удалось сохранить проект: {error}"));
        }
        Ok(Some(output))
    })();
    if let Some(output) = result_path {
        let status = match &result {
            Ok(_) => "completed".to_string(),
            Err(error) => error.clone(),
        };
        let _ = fs::write(output.join("status.txt"), status);
        if result.is_err() {
            log(
                &events,
                format!("логи и частичные результаты: {}", output.display()),
            );
        }
    }
    let _ = events.send(Event::EndStage(Instant::now()));
    let _ = events.send(Event::Finished(result));
}

const GHIDRA_SCRIPT: &str = include_str!("UieExport.java");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_ghidra_workspace_is_removed_on_early_error() {
        let root = std::env::temp_dir().join(format!("uie-ghidra-cleanup-{}", std::process::id()));
        let parent = root.join("lazy-ghidra");
        let path = parent.join("180001000-1234");
        fs::create_dir_all(&path).unwrap();
        let log = root.join("lazy-ghidra.log");
        fs::write(&log, "preserved diagnostic").unwrap();
        let outcome: Result<(), &str> = {
            let _cleanup = GhidraSelectionWork {
                path: path.clone(),
                parent,
            };
            fs::write(path.join("Selected.gpr"), "partial import").unwrap();
            Err("cancelled")
        };
        assert!(outcome.is_err());
        assert!(!path.exists());
        assert!(log.is_file());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn telemetry_handles_fragmented_utf8_and_ghidra_prefixes() {
        let (tx, rx) = std::sync::mpsc::channel();
        let mut pending = vec![];
        let text="INFO UieExport.java> UIE_EVENT {\"kind\":\"progress\",\"phase\":\"перевод\",\"file\":\"app.pyc\",\"done\":38,\"total\":47} (GhidraScript)\n";
        for byte in text.as_bytes() {
            feed_output(&mut pending, &[*byte], &tx);
        }
        assert!(pending.is_empty());
        assert!(
            matches!(rx.try_recv().unwrap(),Event::Progress(value) if value.done==38 && value.total==47 && value.phase=="перевод")
        );
    }

    #[test]
    fn unique_outputs_and_recursive_collection() {
        let base = new_output(&env::temp_dir()).unwrap();
        let first = new_output(&base).unwrap();
        let second = new_output(&base).unwrap();
        assert_ne!(first, second);
        fs::create_dir(first.join("nested")).unwrap();
        fs::write(first.join("a.pyc"), b"bytecode").unwrap();
        fs::write(first.join("nested/b.pyc"), b"bytecode").unwrap();
        fs::write(first.join("nested/c.txt"), b"text").unwrap();
        assert_eq!(collect_files(&first, "pyc").unwrap().len(), 2);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn cancellation_prevents_tool_launch() {
        let (tx, _) = std::sync::mpsc::channel();
        let cancel = AtomicBool::new(true);
        let result = run_tool(
            "does-not-exist",
            &[],
            Path::new("."),
            Path::new("unused.log"),
            1,
            &cancel,
            &tx,
        );
        assert_eq!(result.unwrap_err(), "отменено");
    }

    #[test]
    fn lazy_function_reuses_output_and_rejects_unindexed_addresses() {
        let base = std::env::temp_dir().join(format!("uie-lazy-test-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let root = new_output(&base).unwrap();
        fs::write(
            root.join("native-report.json"),
            br#"{"lazy":true,"functions":[{"address":"180001000"}]}"#,
        )
        .unwrap();
        let source = root.join("source/functions");
        fs::create_dir_all(&source).unwrap();
        let cached = source.join("FUN_180001000.c");
        fs::write(&cached, "int sample(void) { return 7; }\n").unwrap();
        assert_eq!(
            lazy_function(Settings::default(), &root, "180001000").unwrap(),
            cached
        );
        assert!(lazy_function(Settings::default(), &root, "180001001")
            .unwrap_err()
            .contains("not in lazy index"));
        assert!(lazy_function(Settings::default(), &root, "../escape").is_err());
        fs::remove_file(cached).unwrap();
        assert!(lazy_function(Settings::default(), &root, "180001000")
            .unwrap_err()
            .contains("cache is missing"));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    #[ignore = "requires managed Ghidra and an owned scalar DLL fixture"]
    fn ghidra_range_fallback_works_without_a_prebuilt_project() {
        let input =
            PathBuf::from(std::env::var_os("UIE_GHIDRA_FIXTURE").expect("set UIE_GHIDRA_FIXTURE"));
        let original_hash = crate::project::sha256(&input).unwrap();
        let base =
            std::env::temp_dir().join(format!("uie-ghidra-range-test-{}", std::process::id()));
        fs::create_dir_all(&base).unwrap();
        let root = new_output(&base).unwrap();
        let result = root.join("scalar.c");
        let settings = Settings {
            offline: true,
            ..Default::default()
        };
        ghidra_selected_range(
            settings,
            &root,
            &input,
            &result,
            0x180001000,
            0x18000101f,
            &AtomicBool::new(false),
        )
        .unwrap();
        let source = fs::read_to_string(&result).unwrap();
        assert!(source.contains("Function at 180001000"), "{source}");
        assert!(
            source.contains("0xff00ff00ff00ff00") && source.contains("0x123"),
            "{source}"
        );
        assert!(!source.contains("halt_baddata"));
        assert_eq!(crate::project::sha256(&input).unwrap(), original_hash);
        assert_eq!(fs::read_dir(root.join("lazy-ghidra")).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn partial_decompilation_is_not_full_success() {
        let text = "[12:01] INFO 100.00% code object success rate decompiler.py:1\nINFO 85.71% code object success rate";
        assert_eq!(equivalence_rates(text), vec![100.0, 85.71]);
        assert!(
            equivalence_rates("100% downloading; no result\nNaN% code object success rate")
                .is_empty()
        );
    }

    #[test]
    #[ignore]
    fn fake_external_tool() {
        let mode = fs::read_to_string("fixture-mode").unwrap_or_default();
        match mode.trim() {
            "ok" => println!("fixture output: проба"),
            "fail" => std::process::exit(7),
            "wait" => thread::sleep(Duration::from_secs(8)),
            _ => (),
        }
    }

    #[test]
    fn external_process_success_failure_and_timeout() {
        let base = new_output(&env::temp_dir()).unwrap();
        let tool = env::current_exe().unwrap().to_string_lossy().into_owned();
        let args = [
            "--ignored",
            "--exact",
            "engine::tests::fake_external_tool",
            "--nocapture",
        ]
        .map(OsString::from);
        let cancel = AtomicBool::new(false);
        let (tx, rx) = std::sync::mpsc::channel();
        fs::write(base.join("fixture-mode"), "ok").unwrap();
        run_tool(&tool, &args, &base, &base.join("ok.log"), 10, &cancel, &tx).unwrap();
        assert!(fs::read_to_string(base.join("ok.log"))
            .unwrap()
            .contains("fixture output"));
        assert!(rx
            .try_iter()
            .any(|e| matches!(e, Event::Log(s) if s.contains("fixture output"))));
        fs::write(base.join("fixture-mode"), "fail").unwrap();
        assert!(run_tool(
            &tool,
            &args,
            &base,
            &base.join("fail.log"),
            10,
            &cancel,
            &tx
        )
        .is_err());
        fs::write(base.join("fixture-mode"), "wait").unwrap();
        let start = Instant::now();
        let error =
            run_tool(&tool, &args, &base, &base.join("wait.log"), 1, &cancel, &tx).unwrap_err();
        assert!(error.contains("таймаут"));
        assert!(start.elapsed().as_secs() < 6);
        fs::remove_dir_all(base).unwrap();
    }
}
