//! Read-only views of exported evidence and source type declarations.
use crate::{language::tr, telemetry::Problem};
use eframe::egui;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

const MAX_ENTRIES: usize = 20_000;
const MAX_FILE: u64 = 8 * 1024 * 1024;
const MAX_TOTAL: u64 = 64 * 1024 * 1024;
const MAX_ROWS: usize = 20_000;
const MAX_TYPES: usize = 512;
const MAX_DECLARATION: usize = 64 * 1024;

struct Reference {
    kind: &'static str,
    from: String,
    target: String,
    detail: String,
    location: Option<Problem>,
}
struct Declaration {
    name: String,
    text: String,
    location: Problem,
}
#[derive(Default)]
struct Loaded {
    references: Vec<Reference>,
    declarations: Vec<Declaration>,
    limited: bool,
    warnings: Vec<String>,
}

pub struct Inspection {
    pub open: bool,
    root: Option<PathBuf>,
    tab: usize,
    query: String,
    loaded: Loaded,
    receiver: Option<mpsc::Receiver<Result<Loaded, String>>>,
    cancel: Arc<AtomicBool>,
    message: String,
    filter_query: Option<String>,
    filter_tab: usize,
    filtered_rows: Vec<usize>,
}
impl Default for Inspection {
    fn default() -> Self {
        Self {
            open: false,
            root: None,
            tab: 0,
            query: String::new(),
            loaded: Loaded::default(),
            receiver: None,
            cancel: Arc::new(AtomicBool::new(false)),
            message: String::new(),
            filter_query: None,
            filter_tab: 0,
            filtered_rows: Vec::new(),
        }
    }
}
impl Drop for Inspection {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
impl Inspection {
    fn replace_loaded(&mut self, loaded: Loaded) {
        self.loaded = loaded;
        self.filter_query = None;
        self.filtered_rows.clear();
    }
    fn refresh_filter(&mut self) -> bool {
        if self.filter_query.as_deref() == Some(self.query.as_str()) && self.filter_tab == self.tab
        {
            return false;
        }
        let needle = self.query.to_lowercase();
        self.filtered_rows.clear();
        if self.tab == 0 {
            self.filtered_rows.extend(
                self.loaded
                    .references
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| {
                        needle.is_empty()
                            || format!("{} {} {} {}", row.kind, row.from, row.target, row.detail)
                                .to_lowercase()
                                .contains(&needle)
                    })
                    .map(|(index, _)| index),
            );
        } else {
            self.filtered_rows.extend(
                self.loaded
                    .declarations
                    .iter()
                    .enumerate()
                    .filter(|(_, row)| {
                        needle.is_empty()
                            || row.name.to_lowercase().contains(&needle)
                            || row.text.to_lowercase().contains(&needle)
                    })
                    .map(|(index, _)| index),
            );
        }
        self.filter_query = Some(self.query.clone());
        self.filter_tab = self.tab;
        true
    }
    fn start(&mut self, root: PathBuf) {
        self.cancel.store(true, Ordering::Relaxed);
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        self.message.clear();
        thread::spawn(move || {
            let _ = tx.send(load(&root, &cancel));
        });
    }
    pub fn show(&mut self, ctx: &egui::Context, root: Option<PathBuf>) -> Option<Problem> {
        if !self.open {
            return None;
        }
        if self.root != root {
            self.cancel.store(true, Ordering::Relaxed);
            self.receiver = None;
            self.replace_loaded(Loaded::default());
            self.root = root.clone();
            if let Some(root) = root.clone() {
                self.start(root);
            }
        }
        if let Some(result) = self.receiver.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(v) => Some(v),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(_) => Some(Err("inspection worker stopped".into())),
        }) {
            self.receiver = None;
            match result {
                Ok(value) => self.replace_loaded(value),
                Err(e) => self.message = e,
            }
        }
        if self.receiver.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        let mut open = self.open;
        let mut jump = None;
        egui::Window::new(if crate::language::tr("код")=="code" {"XREF / types"}else{"XREF / типы"}).open(&mut open).default_width(940.0).default_height(620.0).show(ctx,|ui|{
            ui.horizontal(|ui|{
                ui.selectable_value(&mut self.tab,0,"XREF");
                ui.selectable_value(&mut self.tab,1,if crate::language::tr("код")=="code" {"Structures / types"}else{"Структуры / типы"});
                ui.text_edit_singleline(&mut self.query);
                if ui.add_enabled(root.is_some()&&self.receiver.is_none(),egui::Button::new(tr("обновить"))).clicked(){self.start(root.clone().unwrap());}
            });
            if root.is_none(){ui.label(if crate::language::tr("код")=="code" {"Open an analysis project first"}else{"Сначала открой проект анализа"});}
            if self.receiver.is_some(){ui.spinner();}
            if !self.message.is_empty(){ui.label(&self.message);}
            if self.loaded.limited{ui.label(if crate::language::tr("код")=="code" {"Evidence limits reached; this view is incomplete"}else{"Достигнут лимит данных; список неполный"});}
            for warning in self.loaded.warnings.iter().take(5){ui.weak(warning);}
            self.refresh_filter();
            if self.tab==0 {
                ui.weak(if crate::language::tr("код")=="code" {"Exported static references only. Dynamic/computed calls can be absent. Folded constants are inference, not proof of a data reference."}else{"Только экспортированные статические ссылки. Косвенные вызовы могут отсутствовать. Свёрнутые константы — вывод анализа, не доказанная ссылка на данные."});
                ui.label(format!("{} / {}",self.filtered_rows.len(),self.loaded.references.len()));
                egui::ScrollArea::both().max_height(450.0).show_rows(ui,44.0,self.filtered_rows.len(),|ui,range|{for i in range{
                    let row=&self.loaded.references[self.filtered_rows[i]];ui.horizontal(|ui|{
                        ui.strong(row.kind);ui.monospace(format!("{} → {}",row.from,row.target));
                        if let Some(location)=&row.location {if ui.link(if crate::language::tr("код")=="code" {"code"}else{"код"}).clicked(){jump=Some(location.clone());}}
                        else{ui.weak(if crate::language::tr("код")=="code" {"source location unavailable"}else{"нет позиции в исходнике"});}
                    });ui.label(&row.detail);
                }});
            } else {
                ui.weak(if crate::language::tr("код")=="code" {"Declarations present in recovered C/C++ text. Field offsets, packing and runtime layout are not inferred."}else{"Объявления из восстановленного C/C++ текста. Смещения полей, упаковка и расположение в памяти не выводятся."});
                egui::ScrollArea::vertical().max_height(470.0).show(ui,|ui|{
                    for &index in &self.filtered_rows {
                        let declaration=&self.loaded.declarations[index];
                        egui::CollapsingHeader::new(format!("{} · {}:{}",declaration.name,declaration.location.file.display(),declaration.location.line)).show(ui,|ui|{
                            if ui.link(if crate::language::tr("код")=="code" {"open declaration"}else{"открыть объявление"}).clicked(){jump=Some(declaration.location.clone());}
                            ui.monospace(&declaration.text);
                        });
                    }
                });
            }
        });
        self.open = open;
        if !open {
            self.cancel.store(true, Ordering::Relaxed);
        }
        jump
    }
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
fn relative(text: &str) -> Option<PathBuf> {
    if text.is_empty() || text.contains([':', '\0']) {
        return None;
    }
    let portable = text.replace('\\', "/");
    if portable.starts_with('/')
        || portable
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return None;
    }
    let path = PathBuf::from(portable);
    path.components()
        .all(|c| matches!(c, Component::Normal(_)))
        .then_some(path)
}
fn read(root: &Path, path: &Path, budget: &mut u64) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || linked(&metadata) {
        return Err("linked/non-regular evidence rejected".into());
    }
    let resolved = path.canonicalize().map_err(|e| e.to_string())?;
    if !resolved.starts_with(root) {
        return Err("evidence path escapes project".into());
    }
    if metadata.len() > MAX_FILE || *budget + metadata.len() > MAX_TOTAL {
        return Err("evidence size limit".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| e.to_string())?
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    *budget += bytes.len() as u64;
    if bytes.len() as u64 > MAX_FILE || *budget > MAX_TOTAL {
        return Err("evidence size limit".into());
    }
    String::from_utf8(bytes).map_err(|_| "non-UTF-8 evidence skipped".into())
}
fn address(v: &str) -> String {
    let v = v.trim().trim_start_matches("0x");
    u64::from_str_radix(v, 16)
        .map(|v| format!("{v:x}"))
        .unwrap_or_else(|_| v.to_lowercase())
}
fn short(v: &Value) -> String {
    v.as_str()
        .map(|s| s.chars().take(1024).collect())
        .unwrap_or_default()
}
fn function_locations(report: &Value, parent: &Path) -> BTreeMap<String, Problem> {
    let mut result = BTreeMap::new();
    let Some(source) = report["source_file"].as_str().and_then(relative) else {
        return result;
    };
    for function in report["functions"]
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_ROWS)
    {
        let Some(line) = function["line"]
            .as_u64()
            .filter(|v| *v > 0 && *v <= 10_000_000)
        else {
            continue;
        };
        let location = Problem {
            file: parent.join(&source),
            line: line as usize,
            symbol: short(&function["name"]),
            message: "exported function evidence".into(),
        };
        for key in ["address", "rva"] {
            if let Some(value) = function[key].as_str() {
                result.insert(address(value), location.clone());
            }
        }
    }
    result
}
fn push(loaded: &mut Loaded, row: Reference) {
    if loaded.references.len() < MAX_ROWS {
        loaded.references.push(row);
    } else {
        loaded.limited = true;
    }
}
fn report_rows(report: &Value, parent: &Path, loaded: &mut Loaded) {
    let locations = function_locations(report, parent);
    loaded.limited |= report["xrefs_truncated"].as_bool() == Some(true)
        || report["xref_analysis"]["truncated"].as_bool() == Some(true);
    for row in report["call_xrefs"]
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_ROWS + 1)
    {
        let from = short(&row["from_address"]);
        let target = short(&row["target_address"]);
        if from.is_empty() || target.is_empty() {
            continue;
        }
        push(
            loaded,
            Reference {
                kind: "call",
                from: format!("{} @ {}", short(&row["from_function"]), from),
                target: format!("{} @ {}", short(&row["target_function"]), target),
                detail: format!(
                    "{} · {} · instruction {}",
                    parent.display(),
                    short(&row["kind"]),
                    short(&row["instruction_address"])
                ),
                location: locations.get(&address(&from)).cloned(),
            },
        );
    }
    for row in report["constant_data_xrefs"]
        .as_array()
        .into_iter()
        .flatten()
        .take(MAX_ROWS + 1)
    {
        let function = short(&row["function_address"]);
        let from = short(&row["from"]);
        let to = short(&row["to"]);
        if from.is_empty() || to.is_empty() {
            continue;
        }
        push(
            loaded,
            Reference {
                kind: "data",
                from,
                target: to,
                detail: format!(
                    "{} · {} · {} · {}",
                    parent.display(),
                    short(&row["function"]),
                    short(&row["reference_type"]),
                    short(&row["interpretation"])
                ),
                location: locations.get(&address(&function)).cloned(),
            },
        );
    }
    for string in report["python_string_references"]
        .as_array()
        .into_iter()
        .flatten()
        .take(1024)
    {
        for row in string["references"]
            .as_array()
            .into_iter()
            .flatten()
            .take(64)
        {
            let function = short(&row["address"]);
            push(
                loaded,
                Reference {
                    kind: "string",
                    from: short(&row["from"]),
                    target: short(&string["address"]),
                    detail: format!(
                        "{} · {} · {}",
                        parent.display(),
                        short(&row["function"]),
                        short(&string["value"])
                    ),
                    location: locations.get(&address(&function)).cloned(),
                },
            );
        }
    }
}
fn load(root: &Path, cancel: &AtomicBool) -> Result<Loaded, String> {
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let mut folders = vec![root.clone()];
    let mut files = Vec::new();
    let mut visited = 0;
    let mut loaded = Loaded::default();
    'walk: while let Some(folder) = folders.pop() {
        for entry in fs::read_dir(&folder).map_err(|e| e.to_string())? {
            if cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            visited += 1;
            if visited > MAX_ENTRIES {
                loaded.limited = true;
                break 'walk;
            }
            let entry = entry.map_err(|e| e.to_string())?;
            let meta = fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
            if linked(&meta) {
                loaded.warnings.push(format!(
                    "linked evidence skipped: {}",
                    entry
                        .path()
                        .strip_prefix(&root)
                        .unwrap_or(&entry.path())
                        .display()
                ));
                continue;
            }
            if meta.is_dir() {
                folders.push(entry.path());
            } else if meta.is_file() {
                files.push(entry.path());
            }
        }
    }
    files.sort();
    let mut budget = 0;
    for path in &files {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let filename = path.file_name().unwrap_or_default();
        let is_report =
            filename == "native-report.json" || filename == "native-constants-report.json";
        let is_source = path.extension().is_some_and(|ext| {
            ["c", "cpp", "h", "hpp"]
                .iter()
                .any(|s| ext.eq_ignore_ascii_case(s))
        });
        if !is_report && !is_source {
            continue;
        }
        let text = match read(&root, path, &mut budget) {
            Ok(v) => v,
            Err(e) => {
                loaded.limited = true;
                if loaded.warnings.len() < 16 {
                    loaded.warnings.push(format!(
                        "{}: {e}",
                        path.strip_prefix(&root).unwrap().display()
                    ));
                }
                continue;
            }
        };
        let relative = path.strip_prefix(&root).map_err(|e| e.to_string())?;
        if is_source {
            for declaration in declarations(relative, &text, cancel)? {
                if loaded.declarations.len() >= MAX_TYPES {
                    loaded.limited = true;
                    break;
                }
                loaded.declarations.push(declaration);
            }
        } else {
            let report: Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(e) => {
                    if loaded.warnings.len() < 16 {
                        loaded.warnings.push(format!("{}: {e}", relative.display()));
                    }
                    continue;
                }
            };
            let parent = relative.parent().unwrap_or(Path::new(""));
            if filename == "native-report.json" {
                report_rows(&report, parent, &mut loaded);
            } else {
                loaded.limited |= report["truncated"].as_bool() == Some(true);
                for row in report["annotations"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .take(MAX_ROWS + 1)
                {
                    push(
                        &mut loaded,
                        Reference {
                            kind: "folded constant (inference)",
                            from: format!("RVA {}", short(&row["instruction_rva"])),
                            target: short(&row["location"]),
                            detail: format!(
                                "{} · function RVA {} · {} · {}",
                                parent.display(),
                                short(&row["function_rva"]),
                                short(&row["kind"]),
                                short(&row["value"])
                            ),
                            location: None,
                        },
                    );
                }
            }
        }
    }
    Ok(loaded)
}

// A byte-preserving mask lets braces in comments/literals be ignored without changing line locations.
fn lexical_mask(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut mask = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        let start = i;
        if bytes[i..].starts_with(b"//") {
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
        } else if bytes[i..].starts_with(b"/*") {
            i += 2;
            while i < bytes.len() && !bytes[i..].starts_with(b"*/") {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
        } else if bytes[i] == b'\'' || bytes[i] == b'"' {
            let quote = bytes[i];
            i += 1;
            while i < bytes.len() {
                if bytes[i] == b'\\' {
                    i = (i + 2).min(bytes.len());
                } else if bytes[i] == quote {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
        } else {
            i += 1;
            continue;
        }
        for byte in &mut mask[start..i] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    mask
}
fn ident(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}
fn declarations(path: &Path, text: &str, cancel: &AtomicBool) -> Result<Vec<Declaration>, String> {
    let mask = lexical_mask(text);
    let mut result = Vec::new();
    let mut i = 0;
    while i < mask.len() {
        if i % 4096 == 0 && cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        if !mask[i].is_ascii_alphabetic() && mask[i] != b'_' {
            i += 1;
            continue;
        }
        let start = i;
        while i < mask.len() && ident(mask[i]) {
            i += 1;
        }
        if ![
            b"struct".as_slice(),
            b"union".as_slice(),
            b"enum".as_slice(),
        ]
        .contains(&&mask[start..i])
        {
            continue;
        }
        let keyword = String::from_utf8_lossy(&mask[start..i]);
        let mut at = i;
        while at < mask.len() && mask[at].is_ascii_whitespace() {
            at += 1;
        }
        let name_start = at;
        if at < mask.len() && (mask[at].is_ascii_alphabetic() || mask[at] == b'_') {
            while at < mask.len() && ident(mask[at]) {
                at += 1;
            }
        }
        let name = String::from_utf8_lossy(&mask[name_start..at]).to_string();
        while at < mask.len() && mask[at].is_ascii_whitespace() {
            at += 1;
        }
        if mask.get(at) != Some(&b'{') {
            continue;
        }
        let mut depth = 1;
        at += 1;
        while at < mask.len() && depth > 0 && at - start <= MAX_DECLARATION {
            match mask[at] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                _ => {}
            }
            at += 1;
        }
        if depth != 0 || at - start > MAX_DECLARATION {
            continue;
        }
        while at < mask.len() && mask[at].is_ascii_whitespace() {
            at += 1;
        }
        let alias_start = at;
        while at < mask.len() && ident(mask[at]) {
            at += 1;
        }
        let alias = String::from_utf8_lossy(&mask[alias_start..at]).to_string();
        while at < mask.len() && mask[at].is_ascii_whitespace() {
            at += 1;
        }
        if mask.get(at) != Some(&b';') {
            continue;
        }
        at += 1;
        let mut declaration_start = start;
        let mut previous = start;
        while previous > 0 && mask[previous - 1].is_ascii_whitespace() {
            previous -= 1;
        }
        if previous >= 7
            && &mask[previous - 7..previous] == b"typedef"
            && (previous == 7 || !ident(mask[previous - 8]))
        {
            declaration_start = previous - 7;
        }
        let name = if name.is_empty() {
            if alias.is_empty() {
                "anonymous".into()
            } else {
                alias
            }
        } else {
            name
        };
        result.push(Declaration {
            name: format!("{keyword} {name}"),
            text: text[declaration_start..at].into(),
            location: Problem {
                file: path.into(),
                line: text[..declaration_start]
                    .bytes()
                    .filter(|b| *b == b'\n')
                    .count()
                    + 1,
                symbol: name,
                message: "source declaration; layout unverified".into(),
            },
        });
        if result.len() >= MAX_TYPES {
            break;
        }
        i = at;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filtering_cache_invalidates_only_when_query_tab_or_evidence_changes() {
        let mut view = Inspection::default();
        let mut loaded = Loaded::default();
        loaded.references.push(Reference {
            kind: "call",
            from: "first".into(),
            target: "SECOND".into(),
            detail: "detail".into(),
            location: None,
        });
        loaded.declarations.push(Declaration {
            name: "struct State".into(),
            text: "struct State { int count; };".into(),
            location: Problem {
                file: "source/a.c".into(),
                line: 1,
                symbol: "State".into(),
                message: String::new(),
            },
        });
        view.replace_loaded(loaded);
        assert!(view.refresh_filter());
        assert_eq!(view.filtered_rows, vec![0]);
        assert!(!view.refresh_filter());
        view.query = "second".into();
        assert!(view.refresh_filter());
        assert_eq!(view.filtered_rows, vec![0]);
        assert!(!view.refresh_filter());
        view.tab = 1;
        assert!(view.refresh_filter());
        assert!(view.filtered_rows.is_empty());
        view.query = "COUNT".into();
        assert!(view.refresh_filter());
        assert_eq!(view.filtered_rows, vec![0]);
        assert!(!view.refresh_filter());
        view.replace_loaded(Loaded::default());
        assert!(view.refresh_filter());
        assert!(view.filtered_rows.is_empty());
        assert!(!view.refresh_filter());
    }
    #[test]
    fn portable_paths_reject_windows_and_unix_escape() {
        for p in ["C:/x.c", "../x.c", "/x.c", "a/../x.c", "\\\\server\\x.c"] {
            assert!(relative(p).is_none(), "{p}");
        }
        assert_eq!(relative("source\\a.c"), Some(PathBuf::from("source/a.c")));
    }
    #[test]
    fn declarations_ignore_comments_strings_and_forward_declarations() {
        let source="// struct Fake { int x; };\nconst char *s=\"struct Fake { } ;\";\nstruct Forward;\ntypedef struct Real {\n int x; /* } */\n union { char c; int n; } value;\n} RealAlias;\n";
        let rows = declarations(Path::new("source/a.c"), source, &AtomicBool::new(false)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "struct Real");
        assert_eq!(rows[0].location.line, 4);
        assert!(rows[0].text.starts_with("typedef"));
        assert!(rows[0].text.ends_with("RealAlias;"));
    }
    #[test]
    fn anonymous_types_and_char_braces_are_safe() {
        let rows=declarations(Path::new("a.h"),"typedef struct { char b[sizeof('}')]; } Alias;\nenum Kind { One=1, Two=2 };\nstruct Incomplete {",&AtomicBool::new(false)).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].name, "struct Alias");
        assert_eq!(rows[1].name, "enum Kind");
    }
    #[test]
    fn actual_export_schemas_resolve_only_known_locations() {
        let report = serde_json::json!({"source_file":"source/code.c","functions":[{"address":"0x1000","name":"start","line":3}],"call_xrefs":[{"from_address":"1000","target_address":"2000","from_function":"start","target_function":"helper","instruction_address":"1008","kind":"CALL"}],"constant_data_xrefs":[{"function_address":"1000","from":"1010","to":"3000","function":"start"}],"python_string_references":[{"address":"4000","value":"__main__","references":[{"address":"1000","from":"1020","function":"start"}]}]});
        let mut loaded = Loaded::default();
        report_rows(&report, Path::new("module"), &mut loaded);
        assert_eq!(loaded.references.len(), 3);
        for row in loaded.references {
            let p = row.location.unwrap();
            assert_eq!(p.line, 3);
            assert_eq!(p.file, PathBuf::from("module/source/code.c"));
        }
    }
}
