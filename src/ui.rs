use crate::language::tr;
use crate::{
    detect::Analysis,
    engine::{self, Event, Settings},
    telemetry::{self, Problem, Session, StageClock},
};
use eframe::egui::{self, Color32, RichText};
use std::{
    collections::HashMap,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

const MAX_LOG_BYTES: usize = 160_000;
const MAX_EDITOR_BYTES: u64 = 32 * 1024 * 1024;
const STAGES: [&str; 7] = [
    "заголовки и архитектура",
    "подготовка движков",
    "сигнатуры detect it easy",
    "извлечение / соседние модули",
    "декомпиляция",
    "проверка результата",
    "редактор кода",
];
struct Document {
    path: PathBuf,
    text: String,
    dirty: bool,
    line_starts: Vec<usize>,
    symbols: Vec<(usize, String, bool)>,
    max_columns: usize,
    line_cache: HashMap<usize, egui::text::LayoutJob>,
}

impl Document {
    fn new(path: PathBuf, text: String) -> Self {
        let mut doc = Self {
            path,
            text,
            dirty: false,
            line_starts: vec![],
            symbols: vec![],
            max_columns: 0,
            line_cache: HashMap::new(),
        };
        doc.reindex();
        doc
    }
    fn reindex(&mut self) {
        self.line_starts = std::iter::once(0)
            .chain(
                self.text
                    .bytes()
                    .enumerate()
                    .filter_map(|(index, byte)| (byte == b'\n').then_some(index + 1)),
            )
            .collect();
        self.max_columns = 0;
        self.symbols.clear();
        let lines: Vec<_> = self.text.lines().collect();
        let native = self.path.extension().is_some_and(|e| {
            ["c", "cpp", "h", "hpp"]
                .iter()
                .any(|name| e.eq_ignore_ascii_case(name))
        });
        for (line, text) in lines.iter().enumerate() {
            self.max_columns = self.max_columns.max(text.chars().count());
            let symbol = text.trim();
            if ["def ", "async def ", "class ", "fn ", "pub fn "]
                .iter()
                .any(|p| symbol.starts_with(p))
            {
                self.symbols.push((line, symbol.to_string(), true));
            } else if native && symbol.to_ascii_lowercase().starts_with("/* function at ") {
                let name = symbol
                    .split_once(": ")
                    .map(|(_, name)| name.trim_end_matches("*/").trim().to_string())
                    .or_else(|| {
                        lines[line + 1..lines.len().min(line + 13)]
                            .iter()
                            .find_map(|text| {
                                let text = text.trim();
                                if text.starts_with("/*") || text.starts_with('*') {
                                    return None;
                                }
                                let before = text.split_once('(')?.0.trim();
                                before
                                    .split_whitespace()
                                    .last()
                                    .map(|name| name.trim_start_matches(['*', '&']).to_string())
                            })
                    })
                    .unwrap_or_else(|| symbol.to_string());
                let user = [
                    "impl_",
                    "modulecode_",
                    "Nuitka_Function",
                    "_create_compiled_function",
                    "_initConstants",
                    "PyInit_",
                    "__pyx_",
                    " [cython:",
                ]
                .iter()
                .any(|marker| name.contains(marker));
                self.symbols.push((line, name, user));
            }
        }
        self.line_cache.clear();
    }
}

struct NativeReport {
    file: PathBuf,
    report: serde_json::Value,
    lines: HashMap<String, usize>,
}

struct RestoredProject {
    path: PathBuf,
    project: crate::project::Project,
    indicators: Option<crate::indicators::Report>,
    workspace: LoadedWorkspace,
}

struct LoadedWorkspace {
    output: Option<PathBuf>,
    files: Vec<PathBuf>,
    documents: Vec<Document>,
    active: Option<usize>,
    tab: usize,
    status: String,
    session: Session,
    native_reports: Vec<NativeReport>,
    triage_report: Option<String>,
}
impl LoadedWorkspace {
    fn read(output: PathBuf, session: Session) -> Self {
        let mut loaded = Self {
            output: Some(output),
            files: vec![],
            documents: vec![],
            active: None,
            tab: 0,
            status: String::new(),
            session,
            native_reports: vec![],
            triage_report: None,
        };
        loaded.load_sources();
        if let (Some(root), Some(relative)) = (&loaded.output, &loaded.session.active_file) {
            if relative
                .components()
                .all(|c| matches!(c, std::path::Component::Normal(_)))
            {
                loaded.open_document(root.join(relative));
            }
        }
        loaded.load_problems();
        loaded.load_native_reports();
        loaded
    }
    fn load_sources(&mut self) {
        if let Some(output) = &self.output {
            let mut folders = vec![output.join("source")];
            if let Some(native) = crate::project::native_source(output) {
                self.files.push(native);
            }
            let mut visited = 0usize;
            while let Some(folder) = folders.pop() {
                visited += 1;
                if visited > 100_000 {
                    break;
                }
                if let Ok(entries) = fs::read_dir(folder) {
                    for entry in entries.flatten() {
                        if let Ok(kind) = entry.file_type() {
                            if kind.is_dir()
                                && entry.file_name() != ".uie-scripts"
                                && !(entry.file_name() == "scripts"
                                    && entry.path().join("UieExport.java").is_file())
                            {
                                folders.push(entry.path());
                            } else if kind.is_file()
                                && entry.path().extension().is_some_and(|e| {
                                    [
                                        "py", "cs", "c", "h", "java", "js", "ts", "jsx", "tsx",
                                        "json", "html", "css", "mjs", "cjs",
                                    ]
                                    .iter()
                                    .any(|x| e == *x)
                                })
                            {
                                self.files.push(entry.path());
                            }
                        }
                    }
                }
            }
            self.files.sort();
            let preferred = self
                .files
                .iter()
                .find(|p| {
                    p.file_name().is_some_and(|n| {
                        n.to_string_lossy().ends_with("_decompiled.py")
                            || n == "decompiled_app.py"
                            || n == "app.py"
                    })
                })
                .or_else(|| self.files.first())
                .cloned();
            if let Some(path) = preferred {
                self.open_document(path);
            }
        }
    }
    fn load_problems(&mut self) {
        if let Some(output) = &self.output {
            if let Some(report) = fs::read(output.join("objects-report.json"))
                .ok()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            {
                if let Ok(problems) =
                    serde_json::from_value::<Vec<Problem>>(report["problems"].clone())
                {
                    self.session.problems = problems;
                }
            } else if self.session.problems.is_empty() {
                for file in &self.files {
                    if let Ok(text) = fs::read_to_string(file) {
                        for (index, line) in text.lines().enumerate() {
                            if let Some(start) = line.find("***<module>") {
                                if let Some((symbol, message)) =
                                    line[start + 3..].split_once(": Failure")
                                {
                                    self.session.problems.push(Problem {
                                        file: file
                                            .strip_prefix(output)
                                            .unwrap_or(file)
                                            .to_path_buf(),
                                        symbol: symbol.into(),
                                        line: index + 1,
                                        message: message.trim_start_matches(':').trim().into(),
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    fn load_native_reports(&mut self) {
        self.native_reports.clear();
        self.triage_report = None;
        let Some(output) = &self.output else {
            return;
        };
        self.triage_report = fs::read_to_string(output.join("triage-report.json")).ok();
        let mut folders = vec![output.clone()];
        let mut visited = 0usize;
        while let Some(folder) = folders.pop() {
            visited += 1;
            if visited > 100_000 {
                break;
            }
            if let Ok(bytes) = fs::read(folder.join("native-report.json")) {
                if let Ok(report) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                    let name = report["source_file"]
                        .as_str()
                        .map(PathBuf::from)
                        .or_else(|| {
                            crate::project::native_source(&folder)
                                .and_then(|p| p.file_name().map(PathBuf::from))
                        });
                    if let Some(name) = name {
                        let file = folder
                            .join(name)
                            .strip_prefix(output)
                            .ok()
                            .map(std::path::Path::to_path_buf);
                        if let Some(file) = file {
                            let lines = report["functions"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(|f| {
                                    Some((
                                        f["name"].as_str()?.to_string(),
                                        f["line"].as_u64()? as usize,
                                    ))
                                })
                                .collect();
                            for function in report["functions"].as_array().into_iter().flatten() {
                                if function["success"].as_bool() == Some(false)
                                    && function["lazy"].as_bool() != Some(true)
                                {
                                    let line = function["line"].as_u64().unwrap_or(1) as usize;
                                    if !self
                                        .session
                                        .problems
                                        .iter()
                                        .any(|p| p.file == file && p.line == line)
                                    {
                                        self.session.problems.push(Problem{file:file.clone(),line,symbol:function["name"].as_str().unwrap_or("unknown").into(),message:function["error"].as_str().filter(|s|!s.is_empty()).unwrap_or("Ghidra decompilation failed; disassembly is available").into()});
                                    }
                                }
                            }
                            self.native_reports.push(NativeReport {
                                file,
                                report,
                                lines,
                            });
                        }
                    }
                }
            }
            if let Ok(entries) = fs::read_dir(folder) {
                for entry in entries.flatten() {
                    if entry.file_type().is_ok_and(|kind| kind.is_dir())
                        && entry.file_name() != ".uie-scripts"
                        && !(entry.file_name() == "scripts"
                            && entry.path().join("UieExport.java").is_file())
                        && entry.file_name() != "extraction"
                        && entry.file_name() != "bytecode"
                    {
                        folders.push(entry.path());
                    }
                }
            }
        }
    }
    fn open_document(&mut self, path: PathBuf) {
        if let Some(index) = self.documents.iter().position(|d| d.path == path) {
            self.active = Some(index);
            self.tab = 0;
            return;
        }
        match fs::metadata(&path).and_then(|m| {
            if m.len() > MAX_EDITOR_BYTES {
                return Err(std::io::Error::other(tr(
                    "файл больше лимита редактора 32 MiB",
                )));
            }
            fs::read_to_string(&path)
        }) {
            Ok(text) => {
                self.documents.push(Document::new(path, text));
                self.active = Some(self.documents.len() - 1);
                self.tab = 0;
            }
            Err(error) => self.status = error.to_string(),
        }
    }
}

pub struct Toker {
    about: crate::about::About,
    debugger_rx: Option<mpsc::Receiver<Result<PathBuf, String>>>,
    debugger_ready: Option<PathBuf>,
    debugger_prompt: bool,
    settings: Settings,
    input: Option<PathBuf>,
    analysis: Option<Analysis>,
    output: Option<PathBuf>,
    files: Vec<PathBuf>,
    documents: Vec<Document>,
    active: Option<usize>,
    tab: usize,
    logs: String,
    status: String,
    stage: usize,
    busy: bool,
    complete: bool,
    receiver: Option<mpsc::Receiver<Event>>,
    cancel: Arc<AtomicBool>,
    close_after_cancel: bool,
    confirm_close: bool,
    allow_close: bool,
    search: String,
    scroll_to_line: Option<usize>,
    queued_input: Option<PathBuf>,
    session: Session,
    clock: StageClock,
    base_dirty: bool,
    base_path: Option<PathBuf>,
    input_hash: String,
    verification: String,
    log_file: Option<PathBuf>,
    cursor_line: Option<usize>,
    avatar: egui::TextureHandle,
    native_reports: Vec<NativeReport>,
    triage_report: Option<String>,
    indicators: Option<crate::indicators::Report>,
    ioc_filter: String,
    rename_open: bool,
    rename_from: String,
    rename_to: String,
    visible_lines: (usize, usize),
    editor_character: usize,
    editor_focused: bool,
    offline_versions: String,
    update_checked: bool,
    update_rx: Option<mpsc::Receiver<crate::updater::Message>>,
    available_update: Option<crate::updater::Release>,
    downloaded_update: Option<PathBuf>,
    workspace_rx: Option<mpsc::Receiver<LoadedWorkspace>>,
    project_rx: Option<mpsc::Receiver<Result<RestoredProject, String>>>,
    document_rx: Option<mpsc::Receiver<Result<Document, String>>>,
    lazy_rx: Option<mpsc::Receiver<(PathBuf, Result<PathBuf, String>)>>,
    utility_rx: Option<mpsc::Receiver<Result<PathBuf, String>>>,
    literal_query: String,
    literal_hits: Vec<(String, Option<Problem>)>,
}

impl Toker {
    fn debugger_dialog(&mut self, ctx: &egui::Context) {
        if let Some(result) = self.debugger_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.debugger_rx = None;
            match result {
                Ok(exe) => {
                    self.debugger_ready = Some(exe);
                    self.debugger_prompt = true;
                }
                Err(error) => self.status = error,
            }
        }
        if !self.debugger_prompt {
            return;
        }
        let mut open = true;
        egui::Window::new("x64dbg / x32dbg")
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .open(&mut open)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label(tr("открытие образца в отладчике запускает его процесс"));
                if let Some(exe) = &self.debugger_ready {
                    if ui.button(tr("открыть пустой отладчик")).clicked() {
                        if let Err(error) = crate::debugger::launch(exe, None) {
                            self.status = error;
                        }
                        self.debugger_prompt = false;
                    }
                    if let Some(input) = &self.input {
                        if input
                            .extension()
                            .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
                            && self.analysis.as_ref().is_some_and(|a| a.format == "PE")
                            && ui.button(tr("запустить образец под отладчиком")).clicked()
                        {
                            if let Err(error) = crate::debugger::launch(exe, Some(input)) {
                                self.status = error;
                            }
                            self.debugger_prompt = false;
                        }
                    }
                }
            });
        self.debugger_prompt &= open;
    }
    fn apply_update(&mut self, ctx: &egui::Context) {
        if self.busy {
            return;
        }
        if self.has_unsaved() && !self.save_base() {
            return;
        }
        let Some(path) = &self.downloaded_update else {
            return;
        };
        let Some(release) = &self.available_update else {
            return;
        };
        match crate::updater::install(path, &release.sha256) {
            Ok(()) => {
                self.persist_session();
                self.allow_close = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            Err(error) => self.status = error,
        }
    }
    pub fn show_about(&mut self) {
        self.about.open = true;
    }
    fn updates(&mut self, ctx: &egui::Context) {
        if !self.update_checked && !self.settings.hide_updates && !self.settings.offline {
            self.update_checked = true;
            self.update_rx = Some(crate::updater::start_check());
        }
        if let Some(message) = self.update_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.update_rx = None;
            match message {
                crate::updater::Message::Checked(Ok(Some(release))) => {
                    self.available_update = Some(release)
                }
                crate::updater::Message::Checked(Ok(None)) => {
                    if !self.busy {
                        self.status = tr("обновлений нет");
                    }
                }
                crate::updater::Message::Checked(Err(error))
                | crate::updater::Message::Downloaded(Err(error)) => self.log(&error),
                crate::updater::Message::Downloaded(Ok(path)) => {
                    self.downloaded_update = Some(path);
                    if !self.busy && !self.has_unsaved() {
                        self.apply_update(ctx);
                    }
                }
            }
        }
        if let Some(release) = self.available_update.clone() {
            let mut open = true;
            egui::Window::new(tr("доступно обновление"))
                .id(egui::Id::new("update-dialog"))
                .default_width(560.0)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .open(&mut open)
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(format!(
                        "UIE {} → {}",
                        env!("CARGO_PKG_VERSION"),
                        release.version
                    ));
                    ui.separator();
                    ui.label(tr("что нового"));
                    egui::ScrollArea::vertical()
                        .id_salt("update-notes")
                        .max_height(240.0)
                        .show(ui, |ui| {
                            if release.notes.trim().is_empty() {
                                ui.weak(tr("описание обновления не опубликовано"));
                            } else {
                                ui.add(egui::Label::new(&release.notes).wrap().selectable(true));
                            }
                        });
                    ui.hyperlink_to(
                        tr("полный changelog на github"),
                        format!(
                            "https://github.com/xreamm1/unpack-it-easy/releases/tag/{}",
                            release.version
                        ),
                    );
                    ui.separator();
                    if self.update_rx.is_some() {
                        ui.spinner();
                        ui.label(tr("загрузка обновления"));
                    }
                    let label = if self.downloaded_update.is_some() {
                        tr("перезапустить и обновить")
                    } else {
                        tr("обновить")
                    };
                    if ui
                        .add_enabled(
                            !self.busy && !self.settings.offline && self.update_rx.is_none(),
                            egui::Button::new(label),
                        )
                        .clicked()
                    {
                        if self.downloaded_update.is_some() {
                            self.apply_update(ctx);
                        } else if !self.has_unsaved() || self.save_base() {
                            self.update_rx = Some(crate::updater::start_download(release));
                        }
                    }
                    if ui.button(tr("позже")).clicked() {
                        self.available_update = None;
                    }
                    if ui.button(tr("больше не показывать")).clicked() {
                        self.settings.hide_updates = true;
                        let _ = self.settings.save();
                        self.available_update = None;
                    }
                });
            if !open {
                self.available_update = None;
            }
        }
    }
    pub fn new(input: Option<PathBuf>, avatar: egui::TextureHandle) -> Self {
        let settings = Settings::load();
        crate::language::set(settings.english);
        let mut app = Self {
            about: crate::about::About::default(),
            debugger_rx: None,
            debugger_ready: None,
            debugger_prompt: false,
            settings,
            input: None,
            analysis: None,
            output: None,
            files: vec![],
            documents: vec![],
            active: None,
            tab: 1,
            logs: String::new(),
            status: tr("загрузи файл — движок будет выбран автоматически"),
            stage: 0,
            busy: false,
            complete: false,
            receiver: None,
            cancel: Arc::new(AtomicBool::new(false)),
            close_after_cancel: false,
            confirm_close: false,
            allow_close: false,
            search: String::new(),
            scroll_to_line: None,
            queued_input: input,
            session: Session::default(),
            clock: StageClock::default(),
            base_dirty: false,
            base_path: None,
            input_hash: String::new(),
            verification: String::new(),
            log_file: None,
            cursor_line: None,
            avatar,
            native_reports: vec![],
            triage_report: None,
            indicators: None,
            ioc_filter: String::new(),
            rename_open: false,
            rename_from: String::new(),
            rename_to: String::new(),
            visible_lines: (0, 50),
            editor_character: 0,
            editor_focused: false,
            offline_versions: "all".into(),
            update_checked: false,
            update_rx: None,
            available_update: None,
            downloaded_update: None,
            workspace_rx: None,
            project_rx: None,
            document_rx: None,
            lazy_rx: None,
            utility_rx: None,
            literal_query: String::new(),
            literal_hits: vec![],
        };
        if let Some(path) = app
            .queued_input
            .as_ref()
            .filter(|p| telemetry::is_base(p))
            .cloned()
        {
            app.queued_input = None;
            app.restore_project(path);
        }
        app
    }

    fn restore_project(&mut self, path: PathBuf) {
        self.busy = true;
        self.status = "loading and verifying project files".into();
        self.receiver = None;
        self.workspace_rx = None;
        self.document_rx = None;
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let (tx, rx) = mpsc::channel();
        self.project_rx = Some(rx);
        thread::spawn(move || {
            let result = (|| -> Result<RestoredProject, String> {
                let project = crate::project::open(&path)?;
                let indicators = fs::read(project.output.join("indicators.json"))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice(&bytes).ok());
                let session = fs::read(project.output.join("uie-session.json"))
                    .ok()
                    .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                    .unwrap_or_default();
                let workspace = LoadedWorkspace::read(project.output.clone(), session);
                if cancel.load(Ordering::Relaxed) {
                    return Err("project loading cancelled".into());
                }
                Ok(RestoredProject {
                    path,
                    project,
                    indicators,
                    workspace,
                })
            })();
            let _ = tx.send(result);
        });
    }
    fn apply_restored_project(&mut self, restored: RestoredProject) {
        let RestoredProject {
            path,
            project,
            indicators,
            workspace,
        } = restored;
        self.input = Some(path.clone());
        self.base_path = Some(path);
        self.input_hash = project.input_sha256;
        self.verification = project.verification.clone();
        self.base_dirty = false;
        self.analysis = Some(project.analysis);
        self.indicators = indicators;
        self.output = Some(project.output);
        self.session = workspace.session;
        self.search = self.session.search.clone();
        self.clock = StageClock::default();
        self.logs.clear();
        self.log_file = None;
        if let Some(output) = self.output.clone() {
            self.attach_log(&output);
        }
        self.files = workspace.files;
        self.documents = workspace.documents;
        self.active = workspace.active;
        self.native_reports = workspace.native_reports;
        self.triage_report = workspace.triage_report;
        self.complete = true;
        self.stage = 6;
        self.status = project.verification.clone();
        self.log(&project.verification);
        self.tab = self.session.tab.min(3);
    }
    fn log(&mut self, text: &str) {
        if let Some(path) = &self.log_file {
            if let Ok(mut file) = fs::OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(file, "{text}");
            }
        }
        self.logs.push_str(text);
        if !text.ends_with('\n') {
            self.logs.push('\n');
        }
        if self.logs.len() > MAX_LOG_BYTES {
            let mut boundary = self.logs.len() - MAX_LOG_BYTES;
            while !self.logs.is_char_boundary(boundary) {
                boundary += 1;
            }
            self.logs.drain(..boundary);
        }
    }
    fn has_unsaved(&self) -> bool {
        self.base_dirty || self.documents.iter().any(|doc| doc.dirty)
    }

    fn attach_log(&mut self, output: &std::path::Path) {
        let path = output.join("uie-session.log");
        let prefix = self.logs.clone();
        if let Ok(mut file) = fs::File::open(&path) {
            let size = file.metadata().map(|m| m.len()).unwrap_or(0);
            let _ = file.seek(SeekFrom::Start(size.saturating_sub(MAX_LOG_BYTES as u64)));
            let mut bytes = Vec::new();
            let _ = file.take(MAX_LOG_BYTES as u64).read_to_end(&mut bytes);
            self.logs = String::from_utf8_lossy(&bytes).into_owned();
            if self.logs.len() > MAX_LOG_BYTES {
                let mut start = self.logs.len() - MAX_LOG_BYTES;
                while !self.logs.is_char_boundary(start) {
                    start += 1;
                }
                self.logs.drain(..start);
            }
        }
        self.log_file = Some(path);
        if !prefix.is_empty() {
            self.log(&prefix);
        }
    }

    fn full_log(&self) -> String {
        self.log_file
            .as_ref()
            .and_then(|p| fs::read(p).ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_else(|| self.logs.clone())
    }

    fn persist_session(&mut self) {
        if let Some(output) = &self.output {
            self.session.active_file = self.active.and_then(|index| {
                self.documents[index]
                    .path
                    .strip_prefix(output)
                    .ok()
                    .map(std::path::Path::to_path_buf)
            });
            self.session.search = self.search.clone();
            self.session.tab = self.tab;
            if let Ok(data) = serde_json::to_vec_pretty(&self.session) {
                let _ = fs::write(output.join("uie-session.json"), data);
                if let Ok(bytes) = serde_json::to_vec_pretty(&self.session.renames) {
                    let _ = fs::write(output.join("renames.json"), bytes);
                }
            }
        }
    }

    fn export_debugger_symbols(&mut self) {
        let Some(root) = self.output.clone() else {
            return;
        };
        if self.utility_rx.is_some() {
            return;
        }
        let module = self
            .input
            .as_ref()
            .and_then(|input| input.file_name())
            .map(|name| name.to_string_lossy().into_owned());
        let (tx, rx) = mpsc::channel();
        self.utility_rx = Some(rx);
        thread::spawn(move || {
            let result = (|| -> Result<PathBuf, String> {
                let native: serde_json::Value = serde_json::from_slice(
                    &fs::read(root.join("native-report.json")).map_err(|e| e.to_string())?,
                )
                .map_err(|e| e.to_string())?;
                let stored = native["native_input"]
                    .as_str()
                    .and_then(|path| std::path::Path::new(path).file_name())
                    .map(|name| name.to_string_lossy().into_owned())
                    .or_else(|| native["ghidra_program"].as_str().map(str::to_owned));
                let module = stored
                    .or(module)
                    .ok_or("original module name is missing from project")?;
                crate::debugger_export::export(&root, &module)
            })();
            let _ = tx.send(result);
        });
    }
    fn compare_bases(&mut self) {
        if self.utility_rx.is_some() {
            return;
        }
        let Some(paths) = rfd::FileDialog::new()
            .add_filter("UIE", &["uie", "toker"])
            .pick_files()
        else {
            return;
        };
        if paths.len() != 2 {
            self.status = tr("выбери ровно две базы для сравнения");
            return;
        }
        let output = self
            .output
            .clone()
            .unwrap_or_else(|| crate::project::app_root().join("comparisons"));
        let (tx, rx) = mpsc::channel();
        self.utility_rx = Some(rx);
        self.status = tr("сравнение баз");
        thread::spawn(move || {
            let result = (|| -> Result<PathBuf, String> {
                let report = crate::project_diff::compare(&paths[0], &paths[1])?;
                fs::create_dir_all(&output).map_err(|e| e.to_string())?;
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_nanos();
                let path = output.join(format!("comparison-{stamp}.json"));
                let mut file = fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&path)
                    .map_err(|e| e.to_string())?;
                file.write_all(&serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?)
                    .map_err(|e| e.to_string())?;
                Ok(path)
            })();
            let _ = tx.send(result);
        });
    }
    fn request_lazy(&mut self, path: PathBuf, line: usize) {
        if self.busy || self.lazy_rx.is_some() {
            return;
        }
        let Some(output) = self.output.as_ref() else {
            return;
        };
        let Some(native) = self.native_reports.iter().find(|native| {
            output.join(&native.file) == path && native.report["lazy"].as_bool() == Some(true)
        }) else {
            return;
        };
        let Some(function) = native.report["functions"].as_array().and_then(|rows| {
            rows.iter()
                .find(|row| row["line"].as_u64() == Some(line as u64 + 1))
        }) else {
            return;
        };
        let Some(address) = function["address"].as_str().map(str::to_owned) else {
            return;
        };
        let Some(root) = path
            .ancestors()
            .skip(1)
            .take(16)
            .find(|parent| {
                parent.starts_with(output) && parent.join("native-report.json").is_file()
            })
            .map(std::path::Path::to_path_buf)
        else {
            return;
        };
        let workspace = output.clone();
        let settings = self.settings.clone();
        let (tx, rx) = mpsc::channel();
        self.lazy_rx = Some(rx);
        self.busy = true;
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        self.status = tr("декомпиляция выбранной функции");
        thread::spawn(move || {
            let result = engine::lazy_function_with_cancel(settings, &root, &address, &cancel);
            let _ = tx.send((workspace, result));
        });
    }

    fn jump_to_problem(&mut self, problem: &Problem) {
        if problem.file.is_absolute()
            || problem
                .file
                .components()
                .any(|c| !matches!(c, std::path::Component::Normal(_)))
        {
            return;
        }
        if let Some(output) = &self.output {
            let path = output.join(&problem.file);
            if !path.is_file() {
                self.status = tr("исходник для объекта не создан");
                return;
            }
            self.open_document(path.clone());
            let line = problem.line.saturating_sub(1);
            self.scroll_to_line = Some(line);
            self.cursor_line = Some(line);
            self.tab = 0;
            self.status = format!("{}: {}", problem.symbol, problem.message);
            self.request_lazy(path, line);
        }
    }

    fn constant_panel(&mut self, ui: &mut egui::Ui, in_editor: bool) {
        let mut selected = None;
        for native in &self.native_reports {
            if in_editor
                && !self.active.is_some_and(|index| {
                    self.output.as_ref().is_some_and(|output| {
                        let index_path = output.join(&native.file);
                        let document = &self.documents[index].path;
                        if index_path == *document {
                            return true;
                        }
                        let Some(parent) = index_path.parent() else {
                            return false;
                        };
                        let source = if parent.file_name().is_some_and(|name| name == "source") {
                            parent.to_path_buf()
                        } else {
                            parent.join("source")
                        };
                        document.parent().is_some_and(|directory| {
                            directory
                                .file_name()
                                .is_some_and(|name| name == "functions")
                                && directory.parent() == Some(source.as_path())
                        })
                    })
                })
            {
                continue;
            }
            let analysis = &native.report["uie_constant_analysis"];
            let Some(annotations) = analysis["annotations"].as_array() else {
                continue;
            };
            let functions = native.report["functions"].as_array();
            let body_address = self
                .active
                .and_then(|index| self.documents[index].path.file_stem())
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_prefix("FUN_"));
            let context = if in_editor && body_address.is_some() {
                functions
                    .into_iter()
                    .flatten()
                    .find(|function| function["address"].as_str() == body_address)
            } else if in_editor {
                functions
                    .into_iter()
                    .flatten()
                    .filter(|function| {
                        function["line"]
                            .as_u64()
                            .is_some_and(|line| line <= self.visible_lines.0 as u64 + 1)
                    })
                    .max_by_key(|function| function["line"].as_u64().unwrap_or(0))
                    .or_else(|| functions.and_then(|functions| functions.first()))
            } else {
                None
            };
            let rows: Vec<_> = annotations
                .iter()
                .filter(|row| context.is_none_or(|function| row["function_rva"] == function["rva"]))
                .collect();
            if rows.is_empty() {
                continue;
            }
            egui::CollapsingHeader::new(format!(
                "{} ({})",
                tr("константы и кандидаты строк"),
                rows.len()
            ))
            .id_salt((&native.file, "uie-folded", in_editor))
            .default_open(in_editor)
            .show(ui, |ui| {
                ui.weak(tr("статические кандидаты — выполнение не наблюдалось"));
                if analysis["truncated"].as_bool() == Some(true) {
                    ui.weak(tr("достигнут лимит анализа"));
                }
                egui::ScrollArea::vertical()
                    .id_salt((&native.file, "uie-folded-rows", in_editor))
                    .max_height(if in_editor { 110.0 } else { 230.0 })
                    .show_rows(ui, 20.0, rows.len(), |ui, range| {
                        for index in range {
                            let row = rows[index];
                            let text = format!(
                                "{} · {} = {}",
                                row["instruction_rva"].as_str().unwrap_or("?"),
                                row["location"].as_str().unwrap_or("?"),
                                row["value"].as_str().unwrap_or("?")
                            );
                            let text = if row["kind"].as_str() == Some("string_candidate") {
                                RichText::new(text).color(Color32::from_rgb(235, 192, 98))
                            } else {
                                RichText::new(text)
                            };
                            if ui
                                .link(text)
                                .on_hover_text(tr("перейти к содержащей функции"))
                                .clicked()
                            {
                                if let Some(function) = functions
                                    .into_iter()
                                    .flatten()
                                    .find(|function| function["rva"] == row["function_rva"])
                                {
                                    selected = Some(Problem {
                                        file: native.file.clone(),
                                        line: function["line"].as_u64().unwrap_or(1) as usize,
                                        symbol: function["name"].as_str().unwrap_or("?").into(),
                                        message: tr("статический кандидат"),
                                    });
                                }
                            }
                        }
                    });
            });
        }
        if let Some(problem) = selected {
            self.jump_to_problem(&problem);
        }
    }
    fn literal_search_panel(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(tr("строки и константы всех модулей"));
            ui.text_edit_singleline(&mut self.literal_query);
            if ui.button(tr("найти")).clicked() {
                self.literal_hits.clear();
                let query = self.literal_query.to_lowercase();
                if !query.is_empty() {
                    for native in &self.native_reports {
                        for annotation in native.report["uie_constant_analysis"]["annotations"]
                            .as_array()
                            .into_iter()
                            .flatten()
                        {
                            let value = annotation["value"]
                                .as_str()
                                .map(str::to_owned)
                                .unwrap_or_else(|| annotation["value"].to_string());
                            if !value.to_lowercase().contains(&query)
                                || self.literal_hits.len() >= 1000
                            {
                                continue;
                            }
                            let function = native.report["functions"].as_array().and_then(|rows| {
                                rows.iter()
                                    .find(|row| row["rva"] == annotation["function_rva"])
                            });
                            let problem = function.map(|row| Problem {
                                file: native.file.clone(),
                                symbol: row["name"].as_str().unwrap_or("?").into(),
                                line: row["line"].as_u64().unwrap_or(1) as usize,
                                message: "constant reference".into(),
                            });
                            self.literal_hits.push((
                                format!(
                                    "{} · {} · {}",
                                    native.file.display(),
                                    annotation["instruction_rva"].as_str().unwrap_or("?"),
                                    value
                                ),
                                problem,
                            ));
                        }
                        for table in native.report["cython_literal_tables"]["tables"]
                            .as_array()
                            .into_iter()
                            .flatten()
                        {
                            for entry in table["entries"].as_array().into_iter().flatten() {
                                let value = entry["text"].as_str().unwrap_or("");
                                if value.to_lowercase().contains(&query)
                                    && self.literal_hits.len() < 1000
                                {
                                    self.literal_hits.push((
                                        format!(
                                            "{} · {} · {}",
                                            native.file.display(),
                                            entry["text_rva_hex"].as_str().unwrap_or("?"),
                                            value
                                        ),
                                        None,
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        });
        let mut selected = None;
        egui::ScrollArea::vertical()
            .id_salt("literal-search-results")
            .max_height(170.0)
            .show_rows(ui, 18.0, self.literal_hits.len(), |ui, range| {
                for i in range {
                    let (text, problem) = &self.literal_hits[i];
                    if let Some(problem) = problem {
                        if ui.link(text).clicked() {
                            selected = Some(problem.clone());
                        }
                    } else {
                        ui.label(text);
                    }
                }
            });
        if self.literal_hits.len() == 1000 {
            ui.weak(tr("показаны первые 1000 совпадений"));
        }
        if let Some(problem) = selected {
            self.jump_to_problem(&problem);
        }
    }
    fn xref_panel(&mut self, ui: &mut egui::Ui) {
        let Some(active) = self.active else {
            return;
        };
        let Some(stem) = self.documents[active]
            .path
            .file_stem()
            .and_then(|name| name.to_str())
        else {
            return;
        };
        let Some(address) = stem.strip_prefix("FUN_") else {
            return;
        };
        let Some(output) = self.output.as_ref() else {
            return;
        };
        let body_source = self.documents[active]
            .path
            .parent()
            .and_then(|parent| parent.parent());
        let mut selected = None;
        egui::CollapsingHeader::new(tr("прямые вызовы xrefs")).show(ui, |ui| {
            ui.weak(tr(
                "кандидаты прямых вызовов — косвенные вызовы не разрешены",
            ));
            for native in &self.native_reports {
                let index = output.join(&native.file);
                let Some(parent) = index.parent() else {
                    continue;
                };
                let source = if parent.file_name().is_some_and(|name| name == "source") {
                    parent.to_path_buf()
                } else {
                    parent.join("source")
                };
                if body_source != Some(source.as_path()) {
                    continue;
                }
                for xref in native.report["call_xrefs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|row| {
                        row["target_address"].as_str() == Some(address)
                            || row["from_address"].as_str() == Some(address)
                    })
                    .take(256)
                {
                    let target = if xref["target_address"].as_str() == Some(address) {
                        "from_address"
                    } else {
                        "target_address"
                    };
                    let label = format!(
                        "{} → {} · {}",
                        xref["from_function"].as_str().unwrap_or("?"),
                        xref["target_function"].as_str().unwrap_or("?"),
                        xref["instruction_address"].as_str().unwrap_or("?")
                    );
                    if ui.link(label).clicked() {
                        if let Some(function) = native.report["functions"]
                            .as_array()
                            .and_then(|rows| rows.iter().find(|row| row["address"] == xref[target]))
                        {
                            selected = Some(Problem {
                                file: native.file.clone(),
                                symbol: function["name"].as_str().unwrap_or("?").into(),
                                line: function["line"].as_u64().unwrap_or(1) as usize,
                                message: "direct call candidate".into(),
                            });
                        }
                    }
                }
            }
        });
        if let Some(problem) = selected {
            self.jump_to_problem(&problem);
        }
    }
    fn native_report_panel(&mut self, ui: &mut egui::Ui) {
        self.literal_search_panel(ui);
        self.constant_panel(ui, false);
        let mut selected = None;
        for native in &self.native_reports {
            if let Some(methods) = native.report["python_methods"]["methods"]
                .as_array()
                .filter(|methods| !methods.is_empty())
            {
                egui::CollapsingHeader::new(format!("CPython PyMethodDef ({})", methods.len()))
                    .id_salt((&native.file, "python-methods"))
                    .show(ui, |ui| {
                        ui.weak(tr("метаданные методов не содержат python-байткод"));
                        egui::ScrollArea::vertical()
                            .id_salt((&native.file, "python-method-rows"))
                            .max_height(200.0)
                            .show_rows(ui, 20.0, methods.len(), |ui, range| {
                                for index in range {
                                    let method = &methods[index];
                                    if ui
                                        .link(format!(
                                            "{} · {} · {}",
                                            method["name"].as_str().unwrap_or("?"),
                                            method["function_rva_hex"].as_str().unwrap_or("?"),
                                            method["flags"].as_str().unwrap_or("?")
                                        ))
                                        .clicked()
                                    {
                                        if let Some(function) = native.report["functions"]
                                            .as_array()
                                            .into_iter()
                                            .flatten()
                                            .find(|function| {
                                                function["rva"] == method["function_rva_hex"]
                                            })
                                        {
                                            selected = Some(Problem {
                                                file: native.file.clone(),
                                                line: function["line"].as_u64().unwrap_or(1)
                                                    as usize,
                                                symbol: method["name"]
                                                    .as_str()
                                                    .unwrap_or("?")
                                                    .into(),
                                                message: "PyMethodDef entry".into(),
                                            });
                                        }
                                    }
                                }
                            });
                    });
            }
            if let Some(entries) = native.report["nuitka_modules"]["entries"]
                .as_array()
                .filter(|entries| !entries.is_empty())
            {
                egui::CollapsingHeader::new(tr("точки входа модулей nuitka"))
                    .id_salt((&native.file, "nuitka-entries"))
                    .show(ui, |ui| {
                        for entry in entries {
                            if ui
                                .link(format!(
                                    "{} · {} · {}",
                                    entry["name"].as_str().unwrap_or("?"),
                                    entry["init_rva_hex"].as_str().unwrap_or("?"),
                                    entry["layout"].as_str().unwrap_or("?")
                                ))
                                .clicked()
                            {
                                let function = native.report["functions"]
                                    .as_array()
                                    .into_iter()
                                    .flatten()
                                    .find(|function| function["rva"] == entry["init_rva_hex"]);
                                if let Some(function) = function {
                                    selected = Some(Problem {
                                        file: native.file.clone(),
                                        line: function["line"].as_u64().unwrap_or(1) as usize,
                                        symbol: entry["name"].as_str().unwrap_or("?").into(),
                                        message: tr("точка входа нативного модуля"),
                                    });
                                }
                            }
                        }
                    });
            }
            if let Some(records) = native.report["cython_recovery"]["records"]
                .as_array()
                .filter(|records| !records.is_empty())
            {
                egui::CollapsingHeader::new(format!(
                    "{} ({})",
                    tr("python имена из traceback"),
                    records.len()
                ))
                .id_salt((&native.file, "cython-symbols"))
                .show(ui, |ui| {
                    ui.weak(tr(
                        "восстановлены имена и места ошибок — тела остаются псевдокодом",
                    ));
                    egui::ScrollArea::vertical()
                        .id_salt((&native.file, "cython-symbol-rows"))
                        .max_height(220.0)
                        .show_rows(ui, 20.0, records.len(), |ui, range| {
                            for index in range {
                                let record = &records[index];
                                let name = record["python_name"].as_str().unwrap_or("?");
                                if ui
                                    .link(format!(
                                        "{} · {}",
                                        name,
                                        record["native_address"].as_str().unwrap_or("?")
                                    ))
                                    .clicked()
                                {
                                    let native_name = record["native_name"].as_str().unwrap_or("?");
                                    selected = Some(Problem {
                                        file: native.file.clone(),
                                        line: *native.lines.get(native_name).unwrap_or(&1),
                                        symbol: name.into(),
                                        message: tr("python имя из traceback"),
                                    });
                                }
                            }
                        });
                });
            }
            egui::CollapsingHeader::new(format!("native: {}",native.file.display())).default_open(true).show(ui,|ui| {
                ui.label(tr(&format!("функций: {}; ошибок: {}; исключено CRT / обёрток: {}",native.report["decompiled"],native.report["failed"],native.report["filtered_runtime"])));
                ui.weak(tr("энтропия и XREF обозначают кандидатов обработки данных; это не доказательство дешифратора"));
                if let Some(sections)=native.report["high_entropy_sections"].as_array() {
                    for section in sections {ui.label(tr(&format!("{} · RVA {} · энтропия {:.3} · {} байт",section["name"].as_str().unwrap_or("?"),section["rva"].as_str().unwrap_or("?"),section["max_entropy"].as_f64().unwrap_or(0.0),section["size"])));}
                }
                egui::CollapsingHeader::new(tr("инициализаторы констант")).id_salt((&native.file,"initializers")).show(ui,|ui| {
                    if let Some(functions)=native.report["constant_initializers"].as_array() {
                        for function in functions {
                            let symbol=function["function"].as_str().unwrap_or("?");
                            if ui.link(format!("{} · RVA {}",symbol,function["rva"].as_str().unwrap_or("?"))).clicked() {selected=Some(Problem{file:native.file.clone(),symbol:symbol.into(),line:function["line"].as_u64().unwrap_or(1) as usize,message:tr("инициализатор констант")});}
                        }
                    }
                });
                if let Some(strings)=native.report["python_string_references"].as_array(){
                    egui::CollapsingHeader::new(format!("Python / Nuitka / Cython strings ({})",strings.len())).id_salt((&native.file,"python-strings")).show(ui,|ui|{
                        egui::ScrollArea::vertical().max_height(220.0).show_rows(ui,20.0,strings.len(),|ui,range|{for index in range{
                            let string=&strings[index];ui.label(format!("{} · {}",string["rva"].as_str().unwrap_or("?"),string["value"].as_str().unwrap_or("?")));
                            for reference in string["references"].as_array().into_iter().flatten(){let name=reference["function"].as_str().unwrap_or("?");
                                if ui.link(name).clicked(){selected=Some(Problem{file:native.file.clone(),symbol:name.into(),line:*native.lines.get(name).unwrap_or(&1),message:"Python string XREF candidate".into()});}
                            }
                        }});
                    });
                }
                if let Some(xrefs)=native.report["constant_data_xrefs"].as_array() {
                    egui::CollapsingHeader::new(tr(&format!("XREF к данным: {}",xrefs.len()))).id_salt((&native.file,"xrefs")).show(ui,|ui| {
                        egui::ScrollArea::vertical().max_height(240.0).id_salt((&native.file,"xref-rows")).show_rows(ui,20.0,xrefs.len(),|ui,rows| {
                            for row in rows {
                                let reference=&xrefs[row];let symbol=reference["function"].as_str().unwrap_or("?");
                                if ui.link(format!("{} · {} -> {}",symbol,reference["from"].as_str().unwrap_or("?"),reference["to"].as_str().unwrap_or("?"))).clicked() {selected=Some(Problem{file:native.file.clone(),symbol:symbol.into(),line:*native.lines.get(symbol).unwrap_or(&1),message:tr("XREF к участку высокой энтропии")});}
                            }
                        });
                    });
                }
            });
        }
        if let Some(triage) = &self.triage_report {
            ui.collapsing("directory triage", |ui| {
                egui::ScrollArea::both().max_height(240.0).show(ui, |ui| {
                    ui.monospace(triage);
                });
            });
        }
        if let Some(problem) = selected {
            self.jump_to_problem(&problem);
        }
    }

    fn problem_links(&mut self, ui: &mut egui::Ui) {
        if self.session.problems.is_empty() {
            return;
        }
        ui.separator();
        ui.colored_label(
            Color32::from_rgb(242, 158, 122),
            tr(&format!(
                "несовпадающие объекты: {}",
                self.session.problems.len()
            )),
        );
        let mut selected = None;
        egui::ScrollArea::vertical()
            .id_salt(("problems", self.tab))
            .max_height(210.0)
            .show(ui, |ui| {
                for problem in &self.session.problems {
                    if ui
                        .link(format!(
                            "{}:{} · {} — {}",
                            problem.file.display(),
                            problem.line,
                            problem.symbol,
                            problem.message
                        ))
                        .clicked()
                    {
                        selected = Some(problem.clone());
                    }
                }
            });
        if let Some(problem) = selected {
            self.jump_to_problem(&problem);
        }
    }

    fn save_base(&mut self) -> bool {
        if self.busy || self.output.is_none() || self.analysis.is_none() {
            return false;
        }
        let selected = self
            .base_path
            .clone()
            .filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("uie")));
        let path = selected.or_else(|| {
            let name = self
                .input
                .as_ref()
                .and_then(|p| p.file_stem())
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "project".into());
            let name = if name.ends_with("_decompiled") {
                name
            } else {
                format!("{name}_decompiled")
            };
            rfd::FileDialog::new()
                .add_filter("Unpack It Easy", &["uie"])
                .set_file_name(format!("{name}.uie"))
                .save_file()
        });
        let Some(mut path) = path else {
            return false;
        };
        path.set_extension("uie");
        if !self.save(true) {
            return false;
        }
        self.persist_session();
        let output = self.output.clone().unwrap();
        let result = crate::project::capture(
            &self.input_hash,
            &output,
            self.settings.all_modules,
            self.analysis.as_ref().unwrap(),
        )
        .and_then(|mut project| {
            project.verification = if self.base_dirty {
                tr("ручные правки сохранены; эквивалентность после редактирования не проверена")
            } else if self.verification.is_empty() {
                self.status.clone()
            } else {
                self.verification.clone()
            };
            crate::database::export(&path, &project)
        });
        match result {
            Ok(()) => {
                self.base_path = Some(path.clone());
                self.base_dirty = false;
                self.status = tr(&format!("база сохранена: {}", path.display()));
                true
            }
            Err(error) => {
                self.status = tr(&format!("ошибка сохранения базы: {error}"));
                false
            }
        }
    }
    fn start(&mut self, input: PathBuf) {
        if self.busy {
            return;
        }
        if self.has_unsaved() {
            self.status = tr("сохрани изменённые вкладки перед загрузкой нового файла");
            return;
        }
        if !input.is_file() {
            self.status = tr("файл не найден");
            return;
        }
        if telemetry::is_base(&input) {
            self.restore_project(input);
            return;
        }
        self.workspace_rx = None;
        self.document_rx = None;
        self.input = Some(input.clone());
        self.analysis = None;
        self.output = None;
        self.files.clear();
        self.documents.clear();
        self.active = None;
        self.tab = 1;
        self.logs.clear();
        self.log_file = None;
        self.base_path = None;
        self.base_dirty = false;
        self.input_hash.clear();
        self.session = Session::default();
        self.clock = StageClock::default();
        self.verification.clear();
        self.native_reports.clear();
        self.triage_report = None;
        self.complete = false;
        self.busy = true;
        self.stage = 0;
        self.status = tr("чтение файла…");
        self.indicators = None;
        self.rename_open = false;
        self.cancel = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        let settings = self.settings.clone();
        self.settings.force_rebuild = false;
        if let Err(error) = self.settings.save() {
            self.log(&tr(&format!("настройки не сохранены: {error}")));
        }
        let cancel = self.cancel.clone();
        thread::spawn(move || engine::job(input, settings, true, cancel, tx));
    }

    fn save(&mut self, all: bool) -> bool {
        for (index, doc) in self.documents.iter_mut().enumerate() {
            if doc.dirty && (all || self.active == Some(index)) {
                if let Err(error) = fs::write(&doc.path, &doc.text) {
                    self.status = error.to_string();
                    return false;
                }
                doc.dirty = false;
            }
        }
        self.status = tr("изменения сохранены");
        true
    }
    fn load_sources(&mut self) {
        let Some(output) = self.output.clone() else {
            return;
        };
        let session = self.session.clone();
        let (tx, rx) = mpsc::channel();
        self.workspace_rx = Some(rx);
        thread::spawn(move || {
            let _ = tx.send(LoadedWorkspace::read(output, session));
        });
    }
    fn open_document(&mut self, path: PathBuf) {
        if let Some(index) = self.documents.iter().position(|d| d.path == path) {
            self.active = Some(index);
            self.tab = 0;
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.document_rx = Some(rx);
        thread::spawn(move || {
            let result = (|| {
                let metadata = fs::metadata(&path).map_err(|e| e.to_string())?;
                if metadata.len() > MAX_EDITOR_BYTES {
                    return Err("file exceeds editor limit".into());
                }
                let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
                Ok(Document::new(path, text))
            })();
            let _ = tx.send(result);
        });
    }
    fn poll(&mut self) {
        let utility = self.utility_rx.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Disconnected) => Some(Err("operation worker stopped".into())),
            Err(mpsc::TryRecvError::Empty) => None,
        });
        if let Some(result) = utility {
            self.utility_rx = None;
            match result {
                Ok(path) => {
                    self.status = path.display().to_string();
                    self.open_document(path);
                }
                Err(error) => self.status = error,
            }
        }
        let lazy = self.lazy_rx.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Disconnected) => {
                Some((PathBuf::new(), Err("lazy decompiler stopped".into())))
            }
            Err(mpsc::TryRecvError::Empty) => None,
        });
        if let Some((workspace, result)) = lazy {
            self.lazy_rx = None;
            self.busy = false;
            if self.output.as_ref() == Some(&workspace) {
                match result {
                    Ok(path) => {
                        if !self.files.contains(&path) {
                            self.files.push(path.clone());
                        }
                        self.base_dirty = true;
                        self.open_document(path);
                        self.scroll_to_line = Some(0);
                        self.status = tr("функция декомпилирована");
                    }
                    Err(error) => self.status = error,
                }
            }
        }
        let restored = self.project_rx.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                Some(Err("project loader stopped; see crash-report.log".into()))
            }
        });
        if let Some(result) = restored {
            self.project_rx = None;
            self.busy = false;
            match result {
                Ok(restored) if !self.cancel.load(Ordering::Relaxed) => {
                    self.apply_restored_project(restored)
                }
                Ok(_) => self.status = "project loading cancelled".into(),
                Err(error) => self.status = error,
            }
        }

        if let Some(loaded) = self.workspace_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.workspace_rx = None;
            self.files = loaded.files;
            self.literal_hits.clear();
            self.documents = loaded.documents;
            self.active = loaded.active;
            self.native_reports = loaded.native_reports;
            self.triage_report = loaded.triage_report;
            self.session.problems = loaded.session.problems;
            self.tab = if self.active.is_some() {
                if self.base_path.is_some() {
                    self.session.tab.min(3)
                } else {
                    0
                }
            } else {
                1
            };
        }
        if let Some(result) = self.document_rx.as_ref().and_then(|rx| rx.try_recv().ok()) {
            self.document_rx = None;
            match result {
                Ok(doc) => {
                    self.documents.push(doc);
                    self.active = Some(self.documents.len() - 1);
                    self.tab = 0;
                }
                Err(error) => self.status = error,
            }
        }

        let mut events = vec![];
        let mut disconnected = false;
        if let Some(rx) = &self.receiver {
            for _ in 0..128 {
                match rx.try_recv() {
                    Ok(event) => events.push(event),
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }
        let mut log_batch = String::new();
        for event in events {
            match event {
                Event::Log(text) => {
                    log_batch.push_str(&text);
                    log_batch.push('\n');
                }
                Event::Output(path) => {
                    self.attach_log(&path);
                    self.output = Some(path);
                }
                Event::Analysis(a) => self.analysis = Some(a),
                Event::Indicators(report) => self.indicators = Some(report),
                Event::OfflineReady(result) => {
                    self.busy = false;
                    self.receiver = None;
                    match result {
                        Ok(()) => {
                            self.settings.offline = true;
                            crate::runtime::set_offline(true);
                            self.status = tr("офлайн-комплект готов");
                            let _ = self.settings.save();
                        }
                        Err(error) => self.status = error,
                    }
                }
                Event::Stage(index, text, at) => {
                    self.clock.begin(index, at, &mut self.session);
                    self.stage = index;
                    self.status = text.clone();
                    self.log(&text);
                }
                Event::EndStage(at) => self.clock.finish(at, &mut self.session),
                Event::Identity(hash) => self.input_hash = hash,
                Event::Progress(progress) => {
                    log_batch.push_str(&format!(
                        "{} · {} · {} / {} objects\n",
                        progress.file,
                        tr(&progress.phase),
                        progress.done,
                        progress.total
                    ));
                    self.session.progress = Some(progress);
                }
                Event::Problem(problem) => self.session.problems.push(problem),
                Event::Finished(result) => {
                    self.busy = false;
                    self.receiver = None;
                    match result {
                        Ok(path) => {
                            self.output = path;
                            self.complete = true;
                            self.stage = 6;
                            self.status = tr("обработка завершена; код открыт в редакторе");
                        }
                        Err(error) => self.status = tr(&format!("неполный результат: {error}")),
                    }
                    let message = self.status.clone();
                    self.verification = message.clone();
                    self.log(&message);
                    self.load_sources();

                    self.persist_session();
                }
            }
        }
        if !log_batch.is_empty() {
            self.log(&log_batch);
        }
        if disconnected && self.busy {
            self.busy = false;
            self.status = tr("рабочий поток остановлен");
            self.receiver = None;
        }
    }
    fn progress(&mut self, ui: &mut egui::Ui) {
        ui.heading(tr("обработка файла"));
        ui.add_space(10.0);
        for (index, label) in STAGES.iter().enumerate() {
            let active = self.busy && index == self.stage;
            let color = if active {
                Color32::from_rgb(114, 222, 193)
            } else if index < self.stage || self.complete {
                Color32::from_gray(200)
            } else {
                Color32::from_gray(85)
            };
            ui.horizontal(|ui| {
                if active {
                    ui.spinner();
                } else {
                    ui.label(RichText::new(format!("{:02}", index + 1)).color(color));
                }
                ui.label(RichText::new(tr(label)).color(color));
                if let Some(seconds) = self.clock.elapsed(index, &self.session) {
                    ui.label(
                        RichText::new(format!("{seconds:.2}s"))
                            .monospace()
                            .color(color),
                    );
                } else if index < self.stage {
                    ui.weak("—");
                }
            });
            ui.add_space(10.0);
        }
        if let Some(a) = &self.analysis {
            ui.label(format!("{} / {}", a.format, a.architecture));
            for hint in a.compiler_hints.iter().chain(&a.packer_hints) {
                ui.label(tr(hint));
            }
            if let Some(die) = &a.detect_it_easy {
                for line in crate::detect::die_summary(die) {
                    ui.label(tr(&line));
                }
            }
        }
        ui.separator();
        ui.label(tr(&self.status));
        if let Some(progress) = &self.session.progress {
            ui.label(format!("{} · {}", progress.file, tr(&progress.phase)));
            if progress.total > 0 {
                ui.add(
                    egui::ProgressBar::new(
                        progress.done.min(progress.total) as f32 / progress.total as f32,
                    )
                    .text(format!("{} / {} objects", progress.done, progress.total)),
                );
            }
        }
        self.problem_links(ui);
        if self.stage == 1 {
            ui.small(tr("при первом использовании движки скачиваются автоматически; ручная настройка не требуется"));
        }
    }
    fn editor(&mut self, ui: &mut egui::Ui) {
        self.minimap(ui);
        if !self.busy && !self.session.problems.is_empty() {
            ui.horizontal(|ui| {
                ui.colored_label(
                    Color32::from_rgb(242, 158, 122),
                    tr(&format!(
                        "требуют проверки: {} несовпадающих объектов",
                        self.session.problems.len()
                    )),
                );
                if ui.link(tr("показать ошибки")).clicked() {
                    self.tab = 2;
                }
            });
        }
        let Some(active) = self.active else {
            ui.centered_and_justified(|ui| ui.label(tr("код появится здесь после декомпиляции")));
            return;
        };
        egui::ScrollArea::horizontal()
            .id_salt("tabs")
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    for (index, doc) in self.documents.iter().enumerate() {
                        let title = format!(
                            "{}{}",
                            doc.path.file_name().unwrap_or_default().to_string_lossy(),
                            if doc.dirty { " *" } else { "" }
                        );
                        if ui.selectable_label(active == index, title).clicked() {
                            self.active = Some(index);
                        }
                    }
                });
            });
        ui.horizontal(|ui| {
            if ui.button(tr("переименовать") + " · N / F2").clicked() {
                self.begin_rename(ui.ctx());
            }
            ui.label(tr("поиск"));
            ui.text_edit_singleline(&mut self.search);
            if ui.button(tr("найти")).clicked() && !self.search.is_empty() {
                if let Some(position) = self.documents[active].text.find(&self.search) {
                    self.scroll_to_line = Some(
                        self.documents[active].text[..position]
                            .bytes()
                            .filter(|b| *b == b'\n')
                            .count(),
                    );
                } else {
                    self.status = tr("не найдено");
                }
            }
            if ui.button(tr("сохранить · ctrl+s")).clicked() {
                self.save(false);
            }
        });
        ui.separator();
        self.xref_panel(ui);
        self.constant_panel(ui, true);
        let doc = &mut self.documents[active];
        ui.small(format!(
            "{}  |  {} lines  |  {} bytes",
            doc.path.display(),
            doc.line_starts.len(),
            doc.text.len()
        ));
        let mut scroll = egui::ScrollArea::both()
            .id_salt(("editor", active))
            .auto_shrink([false, false]);
        if let Some(line) = self.scroll_to_line.take() {
            scroll = scroll.vertical_scroll_offset(line as f32 * 15.0);
        }
        {
            let mut replacement = None;
            ui.scope(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                scroll.show_rows(ui, 15.0, doc.line_starts.len(), |ui, rows| {
                    self.visible_lines = (rows.start, rows.end);
                    if doc.line_cache.len() > 1024 {
                        doc.line_cache.clear();
                    }
                    ui.set_min_width(doc.max_columns as f32 * 7.9 + 70.0);
                    for line in rows {
                        let start = doc.line_starts[line];
                        let end = doc
                            .line_starts
                            .get(line + 1)
                            .copied()
                            .unwrap_or(doc.text.len());
                        let job = doc
                            .line_cache
                            .entry(line)
                            .or_insert_with(|| {
                                let line = doc.text[start..end].trim_end_matches(['\r', '\n']);
                                let cut = line
                                    .char_indices()
                                    .nth(8192)
                                    .map(|(at, _)| at)
                                    .unwrap_or(line.len());
                                highlight(&line[..cut])
                            })
                            .clone();
                        ui.horizontal(|ui| {
                            ui.add_sized(
                                [52.0, 15.0],
                                egui::Label::new(
                                    RichText::new((line + 1).to_string())
                                        .monospace()
                                        .size(13.0)
                                        .color(Color32::from_gray(100)),
                                ),
                            );
                            let original = doc.text[start..end].trim_end_matches(['\r', '\n']);
                            let editable = original.chars().nth(8192).is_none();
                            let mut edited = if editable {
                                original.to_string()
                            } else {
                                String::new()
                            };
                            let response = if editable {
                                let mut layouter = |ui: &egui::Ui, text: &str, _: f32| {
                                    ui.fonts(|fonts| fonts.layout_job(highlight(text)))
                                };
                                ui.add_sized(
                                    [doc.max_columns.max(80) as f32 * 7.9, 15.0],
                                    egui::TextEdit::multiline(&mut edited)
                                        .id_salt(("uie-line", &doc.path, line))
                                        .font(egui::FontId::monospace(13.0))
                                        .margin(egui::Vec2::ZERO)
                                        .frame(false)
                                        .lock_focus(true)
                                        .code_editor()
                                        .desired_rows(1)
                                        .layouter(&mut layouter),
                                )
                            } else {
                                ui.add_sized(
                                    [doc.max_columns.min(8192) as f32 * 7.9, 15.0],
                                    egui::Label::new(job).sense(egui::Sense::click()),
                                )
                                .on_hover_text(tr(
                                    "строка слишком длинная для встроенного редактирования",
                                ))
                            };
                            if response.has_focus() || response.clicked() {
                                self.editor_focused = true;
                                let cursor = egui::TextEdit::load_state(ui.ctx(), response.id)
                                    .and_then(|state| state.cursor.char_range())
                                    .map(|range| range.primary.index)
                                    .unwrap_or(0);
                                self.editor_character = doc.text[..start].chars().count() + cursor;
                            }
                            if response.changed() {
                                replacement = Some((start, start + original.len(), edited));
                            }
                        });
                    }
                });
            });
            if let Some((start, end, edited)) = replacement {
                doc.text.replace_range(start..end, &edited);
                doc.dirty = true;
                doc.reindex();
                self.base_dirty = true;
            }
            self.cursor_line = None;
        }
    }
}

impl Toker {
    fn hash_panel(&self, ui: &mut egui::Ui) {
        let Some(report) = &self.indicators else {
            return;
        };
        for (name, value) in [
            ("MD5", &report.md5),
            ("SHA-1", &report.sha1),
            ("SHA-256", &report.sha256),
        ] {
            ui.horizontal_wrapped(|ui| {
                ui.label(name);
                ui.monospace(value);
            });
        }
        ui.horizontal(|ui| {
            if ui.button(tr("скопировать SHA-256")).clicked() {
                ui.ctx().copy_text(report.sha256.clone());
            }
            ui.add_enabled_ui(!self.settings.offline, |ui| {
                ui.hyperlink_to(
                    "VirusTotal",
                    format!("https://www.virustotal.com/gui/file/{}", report.sha256),
                );
                ui.hyperlink_to(
                    "MalwareBazaar",
                    format!("https://bazaar.abuse.ch/sample/{}/", report.sha256),
                );
            });
        });
    }
    fn indicator_panel(&mut self, ui: &mut egui::Ui) {
        self.hash_panel(ui);
        egui::CollapsingHeader::new(tr("строки и индикаторы (IOC)"))
            .default_open(true)
            .show(ui, |ui| {
                ui.weak(tr(
                    "строковые совпадения не доказывают сетевую активность или внедрение",
                ));
                ui.horizontal(|ui| {
                    ui.label(tr("найти индикатор"));
                    ui.text_edit_singleline(&mut self.ioc_filter);
                });
                if let Some(report) = &self.indicators {
                    ui.label(format!(
                        "{} files · {} matches",
                        report.scanned_files,
                        report.hits.len()
                    ));
                    if report.truncated {
                        ui.colored_label(Color32::YELLOW, tr("ограничение отчёта достигнуто"));
                    }
                    let filter = self.ioc_filter.to_lowercase();
                    let rows: Vec<_> = report
                        .hits
                        .iter()
                        .filter(|h| {
                            filter.is_empty()
                                || h.value.to_lowercase().contains(&filter)
                                || h.kind.to_lowercase().contains(&filter)
                                || h.file.to_lowercase().contains(&filter)
                        })
                        .collect();
                    egui::ScrollArea::vertical()
                        .id_salt("ioc")
                        .max_height(260.0)
                        .show_rows(ui, 22.0, rows.len(), |ui, range| {
                            for row in range {
                                let hit = rows[row];
                                ui.horizontal(|ui| {
                                    if ui.small_button(tr("скопировать")).clicked() {
                                        ui.ctx().copy_text(hit.value.clone());
                                    }
                                    ui.label(&hit.kind);
                                    ui.add(
                                        egui::Label::new(RichText::new(&hit.value).monospace())
                                            .truncate(),
                                    )
                                    .on_hover_text(format!(
                                        "{}\n{} · 0x{:X} · {}",
                                        hit.value, hit.file, hit.offset, hit.encoding
                                    ));
                                });
                            }
                        });
                    for note in &report.notes {
                        ui.weak(tr(note));
                    }
                }
            });
    }
    fn begin_rename(&mut self, _ctx: &egui::Context) {
        let Some(index) = self.active else {
            return;
        };
        let doc = &self.documents[index];
        let character = self.editor_character;
        self.rename_from = crate::rename::symbol_at(&doc.text, character, &doc.path);
        self.rename_to.clear();
        self.rename_open = true;
    }
    fn rename_dialog(&mut self, ctx: &egui::Context) {
        if !self.rename_open {
            return;
        }
        let rename_path = self
            .active
            .map(|index| self.documents[index].path.clone())
            .unwrap_or_default();
        let mut open = true;
        egui::Window::new(tr("переименовать"))
            .id(egui::Id::new("rename-dialog"))
            .open(&mut open)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.label(tr(
                    "переименование во всём файле; строки и комментарии сохраняются",
                ));
                ui.horizontal(|ui| {
                    ui.label(tr("старое имя"));
                    ui.text_edit_singleline(&mut self.rename_from);
                });
                ui.horizontal(|ui| {
                    ui.label(tr("новое имя"));
                    ui.text_edit_singleline(&mut self.rename_to);
                });
                if ui
                    .add_enabled(
                        crate::rename::valid(&self.rename_from, &rename_path)
                            && crate::rename::valid(&self.rename_to, &rename_path)
                            && self.rename_from != self.rename_to,
                        egui::Button::new(tr("применить")),
                    )
                    .clicked()
                {
                    if let Some(index) = self.active {
                        match crate::rename::replace(
                            &self.documents[index].text,
                            &self.rename_from,
                            &self.rename_to,
                            &self.documents[index].path,
                        ) {
                            Ok((text, count)) if count > 0 => {
                                let doc = &mut self.documents[index];
                                doc.text = text;
                                doc.dirty = true;
                                doc.reindex();
                                self.session.renames.push(crate::rename::Change {
                                    file: self
                                        .output
                                        .as_ref()
                                        .and_then(|o| doc.path.strip_prefix(o).ok())
                                        .unwrap_or(&doc.path)
                                        .to_path_buf(),
                                    from: self.rename_from.clone(),
                                    to: self.rename_to.clone(),
                                    occurrences: count,
                                });
                                self.base_dirty = true;
                                self.rename_open = false;
                                self.status =
                                    format!("{} → {}: {}", self.rename_from, self.rename_to, count);
                            }
                            Ok(_) => self.status = tr("не найдено"),
                            Err(error) => self.status = error,
                        }
                    }
                }
                if ui.button(tr("отмена")).clicked() {
                    self.rename_open = false;
                }
            });
        self.rename_open &= open;
    }
    fn minimap(&mut self, ui: &mut egui::Ui) {
        let Some(index) = self.active else {
            return;
        };
        let doc = &self.documents[index];
        egui::SidePanel::right("minimap")
            .exact_width(100.0)
            .resizable(false)
            .show_inside(ui, |ui| {
                let (rect, response) = ui.allocate_exact_size(
                    egui::vec2(96.0, ui.available_height().max(100.0)),
                    egui::Sense::click_and_drag(),
                );
                let painter = ui.painter_at(rect);
                painter.rect_filled(rect, 0.0, Color32::from_gray(19));
                let count = doc.line_starts.len().max(1);
                let samples = count.min((rect.height() as usize).clamp(1, 1500));
                let mut mesh = egui::epaint::Mesh::default();
                for sample in 0..samples {
                    let line = sample * count / samples;
                    let start = doc.line_starts[line];
                    let end = doc
                        .line_starts
                        .get(line + 1)
                        .copied()
                        .unwrap_or(doc.text.len());
                    let text = doc.text[start..end].trim_end();
                    let trimmed = text.trim_start();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let indent = text.len() - trimmed.len();
                    let y = rect.top() + line as f32 / count as f32 * rect.height();
                    let left = rect.left() + (indent as f32 * 0.65).min(70.0);
                    let right = (left + trimmed.len().min(120) as f32 * 0.65).min(rect.right());
                    let color = if trimmed.starts_with(['#', '/']) {
                        Color32::from_rgb(95, 130, 95)
                    } else if trimmed.contains(['"', '\'']) {
                        Color32::from_rgb(171, 143, 96)
                    } else {
                        Color32::from_rgb(111, 153, 181)
                    };
                    mesh.add_colored_rect(
                        egui::Rect::from_min_max(egui::pos2(left, y), egui::pos2(right, y + 0.8)),
                        color,
                    );
                }
                painter.add(egui::Shape::mesh(mesh));
                let top = rect.top() + self.visible_lines.0 as f32 / count as f32 * rect.height();
                let bottom = (rect.top()
                    + self.visible_lines.1 as f32 / count as f32 * rect.height())
                .max(top + 5.0)
                .min(rect.bottom());
                painter.rect_filled(
                    egui::Rect::from_min_max(
                        egui::pos2(rect.left(), top.min(rect.bottom() - 5.0)),
                        egui::pos2(rect.right(), bottom),
                    ),
                    2.0,
                    Color32::from_rgba_unmultiplied(160, 160, 160, 65),
                );
                if response.clicked() || response.dragged() {
                    if let Some(point) = response.interact_pointer_pos() {
                        let line = (((point.y - rect.top()) / rect.height()).clamp(0.0, 1.0)
                            * count as f32) as usize;
                        self.scroll_to_line = Some(line.min(count - 1));
                        self.cursor_line = self.scroll_to_line;
                    }
                }
            });
    }
}

fn highlight(text: &str) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let mut position = 0;
    while position < text.len() {
        let start = position;
        let current = text[position..].chars().next().unwrap();
        position += current.len_utf8();
        let color = if current == '#' || text[start..].starts_with("//") {
            position = text[start..].find('\n').map_or(text.len(), |n| start + n);
            Color32::from_rgb(115, 133, 140)
        } else if current == '\'' || current == '"' {
            let mut escaped = false;
            for ch in text[position..].chars() {
                position += ch.len_utf8();
                if ch == current && !escaped {
                    break;
                }
                escaped = ch == '\\' && !escaped;
            }
            Color32::from_rgb(166, 215, 151)
        } else if current.is_alphabetic() || current == '_' {
            for ch in text[position..].chars() {
                if !(ch.is_alphanumeric() || ch == '_') {
                    break;
                }
                position += ch.len_utf8();
            }
            if [
                "def",
                "class",
                "if",
                "elif",
                "else",
                "try",
                "except",
                "finally",
                "return",
                "yield",
                "for",
                "while",
                "in",
                "is",
                "not",
                "and",
                "or",
                "import",
                "from",
                "as",
                "with",
                "pass",
                "break",
                "continue",
                "lambda",
                "async",
                "await",
                "raise",
                "pub",
                "fn",
                "let",
                "mut",
                "match",
                "struct",
                "enum",
                "use",
                "impl",
                "self",
                "public",
                "private",
                "protected",
                "void",
                "static",
                "int",
                "char",
                "bool",
                "new",
                "namespace",
            ]
            .contains(&&text[start..position])
            {
                Color32::from_rgb(137, 179, 242)
            } else if ["True", "False", "None", "true", "false", "null"]
                .contains(&&text[start..position])
            {
                Color32::from_rgb(210, 166, 232)
            } else {
                Color32::from_rgb(218, 224, 232)
            }
        } else if current.is_ascii_digit() {
            for ch in text[position..].chars() {
                if !(ch.is_ascii_alphanumeric() || ch == '.' || ch == '_') {
                    break;
                }
                position += ch.len_utf8();
            }
            Color32::from_rgb(238, 189, 124)
        } else {
            Color32::from_rgb(218, 224, 232)
        };
        job.append(
            &text[start..position],
            0.0,
            egui::TextFormat {
                font_id: egui::FontId::monospace(13.0),
                color,
                ..Default::default()
            },
        );
    }
    job
}

// Context accessors lock the same egui state. Never call one inside input_mut.
fn consume_rename_shortcut(ctx: &egui::Context, editor_focused: bool) -> bool {
    let allow_n = editor_focused || !ctx.wants_keyboard_input();
    ctx.input_mut(|input| {
        (allow_n && input.consume_key(egui::Modifiers::NONE, egui::Key::N))
            || input.consume_key(egui::Modifiers::NONE, egui::Key::F2)
    })
}

impl eframe::App for Toker {
    fn update(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        crate::language::set(self.settings.english);
        self.poll();
        self.updates(ctx);
        self.debugger_dialog(ctx);
        self.rename_dialog(ctx);
        if let Some(input) = self.queued_input.take() {
            self.start(input);
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.allow_close {
            if self.busy {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.cancel.store(true, Ordering::Relaxed);
                self.close_after_cancel = true;
            } else if self.has_unsaved() {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.confirm_close = true;
            }
        }
        if self.close_after_cancel && !self.busy {
            self.close_after_cancel = false;
            if self.has_unsaved() {
                self.confirm_close = true;
            } else {
                self.allow_close = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
        if self.confirm_close {
            egui::Window::new(tr("несохранённый код"))
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(tr("сохранить изменения перед закрытием?"));
                    if ui.button(tr("сохранить базу и закрыть")).clicked() && self.save_base()
                    {
                        self.allow_close = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if ui.button(tr("закрыть без сохранения")).clicked() {
                        self.allow_close = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if ui.button(tr("продолжить редактирование")).clicked()
                    {
                        self.confirm_close = false;
                    }
                });
        }
        if !self.busy {
            if let Some(path) =
                ctx.input(|i| i.raw.dropped_files.iter().find_map(|f| f.path.clone()))
            {
                self.start(path);
            }
        }
        if self.tab == 0
            && !self.rename_open
            && !self.busy
            && consume_rename_shortcut(ctx, self.editor_focused)
        {
            ctx.input_mut(|i| {
                i.events
                    .retain(|e| !matches!(e,egui::Event::Text(t) if t=="n"||t=="N"))
            });
            self.begin_rename(ctx);
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::CTRL, egui::Key::S)) {
            self.save(false);
        }
        if self.busy
            || self.workspace_rx.is_some()
            || self.project_rx.is_some()
            || self.document_rx.is_some()
            || self.lazy_rx.is_some()
            || self.utility_rx.is_some()
            || self.debugger_rx.is_some()
            || self.update_rx.is_some()
        {
            ctx.request_repaint_after(Duration::from_millis(150));
        }
        egui::TopBottomPanel::top("toolbar")
            .min_height(50.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    ui.image((self.avatar.id(), egui::vec2(30.0, 30.0)));
                    ui.heading(RichText::new("UIE").color(Color32::from_rgb(235, 238, 241)));
                    if ui.add_enabled(!self.settings.offline && self.update_rx.is_none(),egui::Button::new(tr("проверить обновления"))).clicked(){
                        self.update_checked=true;self.update_rx=Some(crate::updater::start_check());
                        self.status=tr("проверка обновлений");
                    }
                    if ui.button(tr("о программе")).clicked(){self.about.open=true;}
                    if cfg!(windows) && ui.add_enabled(!self.busy&&self.debugger_rx.is_none(),egui::Button::new("x64dbg / x32dbg")).clicked(){
                        let architecture=self.analysis.as_ref().map(|a|a.architecture.clone()).unwrap_or_else(||"x64".into());let offline=self.settings.offline;
                        let(tx,rx)=mpsc::channel();self.debugger_rx=Some(rx);self.status=tr("подготовка отладчика");thread::spawn(move||{let _=tx.send(crate::debugger::prepare(&architecture,offline));});
                    }
                    let previous = self.settings.english;
                    egui::ComboBox::from_id_salt("language")
                        .selected_text(if self.settings.english {
                            "English"
                        } else {
                            "русский"
                        })
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.settings.english, false, "русский");
                            ui.selectable_value(&mut self.settings.english, true, "English");
                        });
                    if ui.add_enabled(!self.busy,egui::Checkbox::new(&mut self.settings.offline,tr("офлайн"))).changed(){
                        crate::runtime::set_offline(self.settings.offline);let _=self.settings.save();
                    }
                    egui::ComboBox::from_id_salt("offline-versions").selected_text(if self.offline_versions=="all"{tr("все версии python")}else{format!("Python {}",self.offline_versions)}).show_ui(ui,|ui|{
                        ui.selectable_value(&mut self.offline_versions,"all".into(),tr("все версии python"));
                        for version in ["3.8","3.9","3.10","3.11","3.12","3.13","3.14"]{ui.selectable_value(&mut self.offline_versions,version.into(),version);}
                    });
                    if ui.add_enabled(!self.busy,egui::Button::new(tr("скачать офлайн-комплект"))).on_hover_text(tr("движки и модели сохраняются в engines; все версии требуют несколько гигабайт")).clicked(){
                        self.settings.offline=false;let _=self.settings.save();self.busy=true;
                        self.cancel=Arc::new(AtomicBool::new(false));
                        let (tx,rx)=mpsc::channel();self.receiver=Some(rx);
                        let settings=self.settings.clone();let versions=self.offline_versions.clone();let cancel=self.cancel.clone();
                        self.status=tr("подготовка офлайн-комплекта");
                        thread::spawn(move||crate::runtime::prepare_offline(settings,versions,cancel,tx));
                    }
                    if previous != self.settings.english {
                        crate::language::set(self.settings.english);
                        let _ = self.settings.save();
                    }
                    if ui
                        .add_enabled(!self.busy, egui::Button::new(tr("открыть файл")))
                        .clicked()
                    {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.start(path);
                        }
                    }
                    if ui
                        .add_enabled(!self.busy, egui::Button::new(tr("загрузить базу")))
                        .clicked()
                    {
                        if let Some(path) = rfd::FileDialog::new()
                            .add_filter(tr("база UIE"), &["uie", "toker"])
                            .pick_file()
                        {
                            self.start(path);
                        }
                    }
                    if ui
                        .add_enabled(
                            !self.busy && self.output.is_some(),
                            egui::Button::new(tr("сохранить базу")),
                        )
                        .clicked()
                    {
                        self.save_base();
                    }
                    if self.busy && ui.button(tr("остановить")).clicked() {
                        self.cancel.store(true, Ordering::Relaxed);
                        self.status = tr("остановка…");
                    }
                    if !self.busy
                        && !self.input_hash.is_empty()
                        && self.input.as_ref().is_some_and(|p| !telemetry::is_base(p))
                    {
                        let primary = crate::project::app_root()
                            .join("projects")
                            .join(format!("{}.uie", self.input_hash));
                        let legacy = primary.with_extension("toker");
                        let base = if primary.is_file() { primary } else { legacy };
                        if base.is_file() && ui.button(tr("проверенная база")).clicked()
                        {
                            self.start(base);
                        }
                    }
                    if !self.busy
                        && self.input.as_ref().is_some_and(|p| !telemetry::is_base(p))
                        && ui.button(tr("декомпилировать заново")).clicked()
                    {
                        let input = self.input.clone().unwrap();
                        self.settings.force_rebuild = true;
                        self.start(input);
                        self.settings.force_rebuild = false;
                    }
                    if let Some(output) = &self.output {
                        if ui.button(tr("каталог результата")).clicked() {
                            if let Err(e) = engine::open_folder(output) {
                                self.status = e;
                            }
                        }
                    }
                    if let Some(input) = &self.input {
                        ui.label(format!(
                            "{}{}",
                            input.file_name().unwrap_or_default().to_string_lossy(),
                            if self.has_unsaved() { " *" } else { "" }
                        ));
                    }
                });
            });
        egui::TopBottomPanel::bottom("statusbar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                if self.busy {
                    ui.spinner();
                }
                ui.label(tr(&self.status));
            });
        });
        let mut lazy_requested = None;
        egui::SidePanel::left("navigation")
            .default_width(250.0)
            .min_width(190.0)
            .show(ctx, |ui| {
                ui.add_space(8.0);
                ui.heading(tr("проект"));
                if let Some(a) = &self.analysis {
                    ui.label(format!("{} / {}", a.format, a.architecture));
                    ui.small(a.route.label().replace('→', "->"));
                    if let Some(v) = &a.python_version {
                        ui.label(format!("python {v}"));
                    }
                }
                ui.separator();
                ui.add_enabled_ui(!self.busy, |ui| {
                    ui.checkbox(&mut self.settings.all_modules, tr("включая все модули"));
                    if ui
                        .checkbox(
                            &mut self.settings.lazy_native,
                            tr("ленивая декомпиляция native"),
                        )
                        .changed()
                    {
                        let _ = self.settings.save();
                    }
                });
                ui.add_enabled_ui(!self.busy && self.utility_rx.is_none(), |ui| {
                    if ui.button(tr("экспорт символов x64dbg")).clicked() {
                        self.export_debugger_symbols();
                    }
                    if ui.button(tr("сравнить две базы")).clicked() {
                        self.compare_bases();
                    }
                });
                ui.separator();
                ui.label(tr("исходники"));
                let mut selected = None;
                egui::ScrollArea::vertical()
                    .max_height(260.0)
                    .show(ui, |ui| {
                        for path in &self.files {
                            let label = self
                                .output
                                .as_ref()
                                .and_then(|o| path.strip_prefix(o).ok())
                                .unwrap_or(path)
                                .to_string_lossy();
                            if ui
                                .selectable_label(
                                    self.active.is_some_and(|i| self.documents[i].path == *path),
                                    label,
                                )
                                .clicked()
                            {
                                selected = Some(path.clone());
                            }
                        }
                    });
                if let Some(path) = selected {
                    self.open_document(path);
                }
                if let Some(index) = self.active {
                    ui.separator();
                    ui.label(tr("функции и классы"));
                    egui::ScrollArea::vertical()
                        .id_salt("symbols")
                        .show(ui, |ui| {
                            let native = self.documents[index]
                                .path
                                .extension()
                                .is_some_and(|e| e == "c" || e == "cpp" || e == "h" || e == "hpp");
                            for group in if native {
                                vec![Some(true), Some(false)]
                            } else {
                                vec![None]
                            } {
                                let rows: Vec<_> = self.documents[index]
                                    .symbols
                                    .iter()
                                    .filter(|(_, _, user)| group.is_none_or(|group| *user == group))
                                    .collect();
                                let mut render = |ui: &mut egui::Ui| {
                                    egui::ScrollArea::vertical()
                                        .id_salt(("symbol-group", group))
                                        .max_height(300.0)
                                        .show_rows(ui, 18.0, rows.len(), |ui, range| {
                                            for row in range {
                                                let (line, symbol, _) = rows[row];
                                                if ui.selectable_label(false, symbol).clicked() {
                                                    lazy_requested = Some((
                                                        self.documents[index].path.clone(),
                                                        *line,
                                                    ));
                                                    self.scroll_to_line = Some(*line);
                                                    self.cursor_line = Some(*line);
                                                    self.tab = 0;
                                                }
                                            }
                                        });
                                };
                                if let Some(user) = group {
                                    egui::CollapsingHeader::new(format!(
                                        "{} ({})",
                                        if user {
                                            tr("пользовательские / nuitka")
                                        } else {
                                            tr("остальные")
                                        },
                                        rows.len()
                                    ))
                                    .default_open(user)
                                    .show(ui, render);
                                } else {
                                    render(ui);
                                }
                            }
                        });
                }
            });
        if let Some((path, line)) = lazy_requested {
            self.request_lazy(path, line);
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                for (index, name) in [tr("код"), tr("этапы"), tr("отчёт"), tr("лог")]
                    .iter()
                    .enumerate()
                {
                    if ui.selectable_label(self.tab == index, tr(name)).clicked() {
                        self.tab = index;
                    }
                }
            });
            ui.separator();
            match self.tab {
                0 => self.editor(ui),
                1 => {
                    self.progress(ui);
                    self.hash_panel(ui);
                }
                2 => {
                    self.problem_links(ui);
                    self.native_report_panel(ui);
                    self.indicator_panel(ui);
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        if let Some(a) = &self.analysis {
                            ui.monospace(tr(&serde_json::to_string_pretty(a).unwrap_or_default()));
                        } else {
                            ui.label(tr("отчёт появится после анализа"));
                        }
                    });
                }
                _ => {
                    ui.horizontal(|ui| {
                        if ui.button(tr("экспорт лога")).clicked() {
                            if let Some(path) = rfd::FileDialog::new()
                                .add_filter(tr("журнал"), &["log", "txt"])
                                .set_file_name("uie.log")
                                .save_file()
                            {
                                match fs::write(&path, tr(&self.full_log())) {
                                    Ok(()) => {
                                        self.status =
                                            tr(&format!("лог сохранён: {}", path.display()))
                                    }
                                    Err(error) => self.status = error.to_string(),
                                }
                            }
                        }
                        if ui.button(tr("скопировать лог")).clicked() {
                            ui.ctx().copy_text(tr(&self.full_log()));
                            self.status = tr("лог скопирован");
                        }
                    });
                    self.problem_links(ui);
                    egui::ScrollArea::both()
                        .stick_to_bottom(true)
                        .show(ui, |ui| {
                            let lines: Vec<_> = self.logs.lines().collect();
                            egui::ScrollArea::vertical().id_salt("log-lines").show_rows(
                                ui,
                                15.0,
                                lines.len(),
                                |ui, range| {
                                    for row in range {
                                        let text = lines[row];
                                        let end = text
                                            .char_indices()
                                            .nth(8192)
                                            .map(|(i, _)| i)
                                            .unwrap_or(text.len());
                                        ui.monospace(tr(&text[..end]));
                                    }
                                },
                            );
                        });
                }
            }
        });
        self.about.show(ctx);
    }
}
impl Drop for Toker {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        #[cfg(not(test))]
        let _ = self.settings.save();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn project_verification_and_document_loading_run_off_the_ui_thread() {
        let context = egui::Context::default();
        let avatar = context.load_texture(
            "project-loader-test",
            egui::ColorImage::new([1, 1], Color32::BLACK),
            egui::TextureOptions::LINEAR,
        );
        let mut app = Toker::new(None, avatar);
        let root = std::env::temp_dir().join(format!("uie-project-worker-{}", std::process::id()));
        fs::create_dir_all(root.join("source")).unwrap();
        fs::write(
            root.join("source/main.py"),
            "def sample():\n    return 42\n".repeat(10000),
        )
        .unwrap();
        let analysis = crate::detect::inspect(b"owned fixture").unwrap();
        let project = crate::project::capture("fixture", &root, false, &analysis).unwrap();
        let file = root.join("project.toker");
        fs::write(&file, serde_json::to_vec(&project).unwrap()).unwrap();
        app.restore_project(file);
        assert!(app.project_rx.is_some());
        assert!(app.busy);
        assert!(app.documents.is_empty());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while app.project_rx.is_some() && std::time::Instant::now() < deadline {
            app.poll();
            thread::sleep(Duration::from_millis(1));
        }
        assert!(app.project_rx.is_none());
        assert!(!app.busy);
        assert!(app.active.is_some());
        assert!(app.documents[0].text.contains("return 42"));
        drop(app);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn decoded_string_annotations_are_drawn_next_to_the_containing_function() {
        let context = egui::Context::default();
        context.style_mut(|style| style.animation_time = 0.0);
        let avatar = context.load_texture(
            "constant-test",
            egui::ColorImage::new([1, 1], Color32::BLACK),
            egui::TextureOptions::LINEAR,
        );
        let mut app = Toker::new(None, avatar);
        let output = std::env::temp_dir().join("uie-constant-display");
        let file = PathBuf::from("fixture_decompiled.c");
        app.output = Some(output.clone());
        app.documents.push(Document::new(
            output.join(&file),
            "void sample(void) {}\n".into(),
        ));
        app.active = Some(0);
        app.native_reports.push(NativeReport { file, lines: HashMap::new(), report: serde_json::json!({
            "functions":[{"name":"sample","rva":"0x1000","line":1}],
            "uie_constant_analysis":{"annotations":[{"kind":"string_candidate","function_rva":"0x1000","instruction_rva":"0x1020","location":"stack-0x20","value":"HELLO"}]}
        }) });
        let mut drawn = false;
        for _ in 0..3 {
            let result = context.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1200.0, 800.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| app.editor(ui));
                },
            );
            drawn |= result.shapes.iter().any(|shape| match &shape.shape {
                egui::epaint::Shape::Text(text) => text.galley.text().contains("HELLO"),
                _ => false,
            });
        }
        assert!(drawn);
    }
    #[test]
    fn code_tab_shortcut_does_not_reenter_context_lock() {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let ctx = egui::Context::default();
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                assert!(!consume_rename_shortcut(ctx, false));
            });
            let mut raw = egui::RawInput::default();
            raw.events.push(egui::Event::Key {
                key: egui::Key::N,
                physical_key: Some(egui::Key::N),
                pressed: true,
                repeat: false,
                modifiers: egui::Modifiers::NONE,
            });
            let mut renamed = false;
            let _ = ctx.run(raw, |ctx| {
                renamed |= consume_rename_shortcut(ctx, false);
            });
            tx.send(renamed).unwrap();
        });
        assert!(rx
            .recv_timeout(Duration::from_secs(3))
            .expect("code tab deadlocked while polling the rename shortcut"));
    }
    #[test]
    fn event_flood_is_bounded_and_workspace_loads_in_background() {
        let context = egui::Context::default();
        let avatar = context.load_texture(
            "async-test",
            egui::ColorImage::new([1, 1], Color32::BLACK),
            egui::TextureOptions::LINEAR,
        );
        let mut app = Toker::new(None, avatar);
        let (tx, rx) = mpsc::channel();
        for _ in 0..10_000 {
            tx.send(Event::Log("test log".into())).unwrap();
        }
        app.receiver = Some(rx);
        app.poll();
        assert_eq!(app.logs.lines().count(), 128);
        let root = std::env::temp_dir().join(format!("uie-async-{}", std::process::id()));
        fs::create_dir_all(root.join("source")).unwrap();
        fs::write(root.join("source/main.py"), "print('ready')").unwrap();
        app.receiver = None;
        app.output = Some(root.clone());
        app.load_sources();
        assert!(app.workspace_rx.is_some());
        assert!(app.documents.is_empty());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while app.workspace_rx.is_some() && std::time::Instant::now() < deadline {
            app.poll();
            thread::sleep(Duration::from_millis(1));
        }
        assert!(app.active.is_some());
        assert!(!app.documents[0].line_starts.is_empty());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn lazy_symbol_selection_opens_cached_body_without_blocking_ui() {
        let context = egui::Context::default();
        let avatar = context.load_texture(
            "lazy-test",
            egui::ColorImage::new([1, 1], Color32::BLACK),
            egui::TextureOptions::LINEAR,
        );
        let mut app = Toker::new(None, avatar);
        let root = std::env::temp_dir().join(format!("uie-lazy-ui-{}", std::process::id()));
        fs::create_dir_all(root.join("source/functions")).unwrap();
        let index = root.join("sample_decompiled.c");
        fs::write(&index, "/* Function at 180001000: sample */\n").unwrap();
        let body = root.join("source/functions/FUN_180001000.c");
        fs::write(&body, "int sample(void) { return 7; }\n").unwrap();
        let report =
            serde_json::json!({"lazy":true,"functions":[{"address":"180001000","line":1}]});
        fs::write(
            root.join("native-report.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        app.output = Some(root.clone());
        app.native_reports.push(NativeReport {
            file: "sample_decompiled.c".into(),
            report,
            lines: HashMap::new(),
        });
        app.request_lazy(index, 0);
        assert!(app.busy && app.lazy_rx.is_some());
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while (app.lazy_rx.is_some() || app.document_rx.is_some())
            && std::time::Instant::now() < deadline
        {
            app.poll();
            thread::sleep(Duration::from_millis(1));
        }
        assert!(!app.busy);
        assert_eq!(app.documents[app.active.unwrap()].path, body);
        assert!(app.base_dirty);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn minified_source_uses_bounded_visible_layout() {
        let context = egui::Context::default();
        let avatar = context.load_texture(
            "minified-test",
            egui::ColorImage::new([1, 1], Color32::BLACK),
            egui::TextureOptions::LINEAR,
        );
        let mut app = Toker::new(None, avatar);
        app.documents.push(Document::new(
            "minified.js".into(),
            "counter+=1;".repeat(200_000),
        ));
        app.active = Some(0);
        let _ = context.run(egui::RawInput::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| app.editor(ui));
        });
        assert!(app.documents[0].text.len() > 2_000_000);
        assert!(app.documents[0]
            .line_cache
            .values()
            .all(|job| job.text.chars().count() <= 8192));
    }
    #[test]
    fn problem_navigation_and_full_log_do_not_drop_data() {
        let root = std::env::temp_dir().join(format!("uie-navigation-{}", std::process::id()));
        fs::create_dir_all(root.join("source")).unwrap();
        fs::write(
            root.join("source/app.py"),
            "def first():\n    return 1\ndef second():\n    return 2\n",
        )
        .unwrap();
        let context = egui::Context::default();
        let avatar = context.load_texture(
            "test",
            egui::ColorImage::new([1, 1], Color32::BLACK),
            egui::TextureOptions::LINEAR,
        );
        let mut app = Toker::new(None, avatar);
        app.output = Some(root.clone());
        app.attach_log(&root);
        let text = "полный журнал ".repeat(MAX_LOG_BYTES / 4);
        app.log(&text);
        assert!(app.logs.len() <= MAX_LOG_BYTES);
        assert!(app.full_log().contains(&text));
        app.jump_to_problem(&Problem {
            file: "source/app.py".into(),
            symbol: "<module>.second".into(),
            line: 3,
            message: "test mismatch".into(),
        });
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while app.document_rx.is_some() && std::time::Instant::now() < deadline {
            app.poll();
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(app.tab, 0);
        assert_eq!(app.cursor_line, Some(2));
        assert_eq!(app.scroll_to_line, Some(2));
        assert_eq!(
            app.documents[app.active.unwrap()].text.lines().nth(2),
            Some("def second():")
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn c_symbols_are_grouped_and_large_view_is_virtualized() {
        let small=Document::new("small.c".into(),"/* Function at 140001000: impl_user */\nint impl_user(void) { return 1; }\n/* Function at 140002000 */\nint other(void) { return 2; }\n".into());
        assert_eq!(small.symbols[0], (0, "impl_user".into(), true));
        assert_eq!(small.symbols[1], (2, "other".into(), false));
        let text = (0..37000)
            .map(|line| format!("unsigned int value_{line} = {line}; /* native code */\n"))
            .collect::<String>();
        let expected = text.len();
        let context = egui::Context::default();
        let avatar = context.load_texture(
            "test-avatar",
            egui::ColorImage::new([1, 1], Color32::BLACK),
            egui::TextureOptions::LINEAR,
        );
        let mut app = Toker::new(None, avatar);
        app.documents.push(Document::new("large.c".into(), text));
        app.active = Some(0);
        let start = std::time::Instant::now();
        for frame in 0..20 {
            if frame == 10 {
                app.scroll_to_line = Some(36000);
            }
            let input = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1200.0, 800.0),
                )),
                ..Default::default()
            };
            let _ = context.run(input, |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| app.editor(ui));
            });
        }
        let doc = &app.documents[0];
        assert!(!doc.line_starts.is_empty());
        assert_eq!(doc.text.len(), expected);
        assert!(doc.line_cache.len() < 300);
        assert!(doc.line_cache.keys().any(|line| *line >= 35000));
        eprintln!(
            "UIE 37000-line benchmark: {:.2}ms/frame; {} rows materialized",
            start.elapsed().as_secs_f64() * 1000.0 / 20.0,
            doc.line_cache.len()
        );
    }
    #[test]
    fn highlighting_preserves_unicode_and_source() {
        let source = "def привет(x):\n    # comment\n    return 'тест\\\"' + str(12.5)\n";
        assert_eq!(highlight(source).text, source);
    }
}
