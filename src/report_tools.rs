//! Bounded report exports and positional comparison of already recovered source.
use eframe::egui::{self, Color32, RichText};
use serde::Serialize;
use serde_json::Value;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};

const MAX_FILE: u64 = 8 * 1024 * 1024;
const MAX_TOTAL: u64 = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 20_000;
const MAX_REPORTS: usize = 128;
const MAX_LINES: usize = 50_000;
const MAX_EXPORT: usize = 96 * 1024 * 1024;

fn label(ru: &str, en: &str) -> String {
    if crate::language::tr("код") == "code" {
        en.into()
    } else {
        ru.into()
    }
}
fn linked(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}
fn bytes(path: &Path, cancel: &AtomicBool) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if linked(&meta) || !meta.is_file() || meta.len() > MAX_FILE {
        return Err(format!(
            "not a regular file within 8 MiB: {}",
            path.display()
        ));
    }
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut result = Vec::with_capacity(meta.len() as usize);
    let mut buffer = [0; 65536];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        if result.len() + count > MAX_FILE as usize {
            return Err("file grew beyond 8 MiB".into());
        }
        result.extend_from_slice(&buffer[..count]);
    }
    Ok(result)
}
fn known_report(name: &str) -> bool {
    [
        "analysis.json",
        "indicators.json",
        "triage-report.json",
        "native-report.json",
        "java-report.json",
        "android-report.json",
        "python-report.json",
        "plugin-report.json",
        "native-lift-report.json",
        "native-constants-report.json",
        "native-tables-report.json",
        "cython-strings-report.json",
        "python-methods-report.json",
        "nuitka-modules-report.json",
        "native-index.json",
        "unpack-report.json",
        "runtime-report.json",
    ]
    .contains(&name)
}
#[derive(Serialize)]
struct Report {
    file: String,
    data: Value,
}
#[derive(Serialize)]
struct Bundle {
    format_version: u32,
    project: String,
    scope: &'static str,
    reports: Vec<Report>,
    warnings: Vec<String>,
    incomplete: bool,
}
fn collect(root: &Path, cancel: &AtomicBool) -> Result<Bundle, String> {
    let meta = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if linked(&meta) || !meta.is_dir() {
        return Err("project root must be a regular directory".into());
    }
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let mut output = Bundle {
        format_version: 1,
        project: root.display().to_string(),
        scope: "existing static analysis reports only; no claim of source or runtime equivalence",
        reports: vec![],
        warnings: vec![],
        incomplete: false,
    };
    let mut queue = vec![(root.clone(), 0usize)];
    let mut entries = 0usize;
    let mut total = 0u64;
    'scan: while let Some((folder, depth)) = queue.pop() {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let read = match fs::read_dir(&folder) {
            Ok(v) => v,
            Err(e) => {
                output.warnings.push(format!("{}: {e}", folder.display()));
                output.incomplete = true;
                continue;
            }
        };
        for entry in read {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    output.warnings.push(e.to_string());
                    output.incomplete = true;
                    continue;
                }
            };
            entries += 1;
            if entries > MAX_ENTRIES {
                output.warnings.push("entry limit reached".into());
                output.incomplete = true;
                break 'scan;
            }
            let path = entry.path();
            let meta = match fs::symlink_metadata(&path) {
                Ok(v) => v,
                Err(e) => {
                    output.warnings.push(e.to_string());
                    output.incomplete = true;
                    continue;
                }
            };
            if linked(&meta) {
                output
                    .warnings
                    .push(format!("link skipped: {}", path.display()));
                output.incomplete = true;
                continue;
            }
            if meta.is_dir() {
                if [
                    "source",
                    "engines",
                    ".git",
                    ".uie-scripts",
                    "scripts",
                    "cache",
                ]
                .iter()
                .any(|n| entry.file_name() == *n)
                {
                    continue;
                }
                if depth >= 16 {
                    output.warnings.push("directory depth limit reached".into());
                    output.incomplete = true;
                } else {
                    queue.push((path, depth + 1));
                }
            } else if meta.is_file() && known_report(&entry.file_name().to_string_lossy()) {
                if output.reports.len() >= MAX_REPORTS {
                    output.warnings.push("report count limit reached".into());
                    output.incomplete = true;
                    break 'scan;
                }
                if total.saturating_add(meta.len()) > MAX_TOTAL {
                    output.warnings.push("report byte budget reached".into());
                    output.incomplete = true;
                    continue;
                }
                match bytes(&path, cancel).and_then(|data| {
                    if total.saturating_add(data.len() as u64) > MAX_TOTAL {
                        return Err("actual report byte budget reached".into());
                    }
                    total += data.len() as u64;
                    serde_json::from_slice(&data).map_err(|e| e.to_string())
                }) {
                    Ok(data) => output.reports.push(Report {
                        file: path
                            .strip_prefix(&root)
                            .map_err(|e| e.to_string())?
                            .to_string_lossy()
                            .into_owned(),
                        data,
                    }),
                    Err(e) => {
                        output.warnings.push(format!("{}: {e}", path.display()));
                        output.incomplete = true;
                    }
                }
            }
            if output.warnings.len() >= 128 {
                output.warnings.push("warning limit reached".into());
                output.incomplete = true;
                break 'scan;
            }
        }
    }
    output.reports.sort_by(|a, b| a.file.cmp(&b.file));
    if output.reports.is_empty() {
        return Err("no supported analysis JSON reports found".into());
    }
    Ok(output)
}
fn escaped(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    for ch in text.chars() {
        match ch {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '"' => result.push_str("&quot;"),
            '\'' => result.push_str("&#39;"),
            _ => result.push(ch),
        }
    }
    result
}
#[derive(Clone, Copy)]
enum Format {
    Json,
    Html,
    Markdown,
}
fn render(bundle: &Bundle, format: Format) -> Result<Vec<u8>, String> {
    let json = serde_json::to_string_pretty(bundle).map_err(|e| e.to_string())?;
    let text=match format{
        Format::Json=>json,
        Format::Html=>format!("<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>UIE analysis report</title><style>body{{background:#191919;color:#ddd;font:15px system-ui;margin:32px;max-width:1200px}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#111;padding:20px}}h1{{font-size:24px}}</style><h1>UIE analysis report</h1><p>Existing static evidence only. Review private paths and indicators before sharing.</p><pre>{}</pre></html>",escaped(&json)),
        Format::Markdown=>format!("# UIE analysis report\n\nExisting static evidence only. Review private paths and indicators before sharing.\n\n```json\n{json}\n```\n"),
    };
    if text.len() > MAX_EXPORT {
        return Err("rendered export exceeds size limit".into());
    }
    Ok(text.into_bytes())
}
fn export(
    root: &Path,
    target: &Path,
    format: Format,
    cancel: &AtomicBool,
) -> Result<PathBuf, String> {
    let bundle = collect(root, cancel)?;
    let data = render(&bundle, format)?;
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)
        .map_err(|e| e.to_string())?;
    let result = (|| {
        for chunk in data.chunks(65536) {
            if cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            file.write_all(chunk).map_err(|e| e.to_string())?;
        }
        file.sync_all().map_err(|e| e.to_string())
    })();
    drop(file);
    if let Err(e) = result {
        let _ = fs::remove_file(target);
        return Err(e);
    }
    Ok(target.into())
}
struct Comparison {
    left: PathBuf,
    right: PathBuf,
    a: Vec<String>,
    b: Vec<String>,
    changed: usize,
}
fn compare(left: &Path, right: &Path, cancel: &AtomicBool) -> Result<Comparison, String> {
    fn lines(path: &Path, cancel: &AtomicBool) -> Result<Vec<String>, String> {
        let data = bytes(path, cancel)?;
        let text = std::str::from_utf8(&data).map_err(|_| "comparison requires UTF-8 text")?;
        if text.contains('\0') {
            return Err("comparison rejects binary text".into());
        }
        let mut lines = Vec::new();
        for line in text.lines() {
            if lines.len() >= MAX_LINES {
                return Err("source comparison exceeds 50000 lines".into());
            }
            lines.push(line.into());
        }
        Ok(lines)
    }
    let a = lines(left, cancel)?;
    let b = lines(right, cancel)?;
    let changed = (0..a.len().max(b.len()))
        .filter(|i| a.get(*i) != b.get(*i))
        .count();
    Ok(Comparison {
        left: left.into(),
        right: right.into(),
        a,
        b,
        changed,
    })
}
enum ResultView {
    Saved(PathBuf),
    Compared(Comparison),
}
pub struct Tools {
    pub open: bool,
    tab: usize,
    comparison: Option<Comparison>,
    message: String,
    receiver: Option<mpsc::Receiver<Result<ResultView, String>>>,
    cancel: Arc<AtomicBool>,
}
impl Default for Tools {
    fn default() -> Self {
        Self {
            open: false,
            tab: 0,
            comparison: None,
            message: String::new(),
            receiver: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl Drop for Tools {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
impl Tools {
    fn start(
        &mut self,
        work: impl FnOnce(Arc<AtomicBool>) -> Result<ResultView, String> + Send + 'static,
    ) {
        self.cancel.store(true, Ordering::Relaxed);
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        self.message.clear();
        thread::spawn(move || {
            let _ = tx.send(work(cancel));
        });
    }
    pub fn show(&mut self, ctx: &egui::Context, root: Option<PathBuf>) {
        if !self.open {
            return;
        }
        if let Some(value) = self.receiver.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(v) => Some(v),
            Err(mpsc::TryRecvError::Disconnected) => Some(Err("report worker stopped".into())),
            Err(_) => None,
        }) {
            self.receiver = None;
            match value {
                Ok(ResultView::Saved(path)) => self.message = path.display().to_string(),
                Ok(ResultView::Compared(value)) => self.comparison = Some(value),
                Err(e) => self.message = e,
            }
        }
        if self.receiver.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        let mut open = self.open;
        egui::Window::new(label("Отчёты и сравнение исходников","Reports and source comparison")).open(&mut open).default_width(1050.0).default_height(650.0).show(ctx,|ui|{
            ui.horizontal(|ui|{ui.selectable_value(&mut self.tab,0,label("Экспорт отчётов","Export reports"));ui.selectable_value(&mut self.tab,1,label("Сравнение декомпиляции","Compare decompiler output"));});ui.separator();let ready=self.receiver.is_none();
            if self.tab==0 {
                ui.label(label("Экспорт существующих JSON отчётов анализа без выполнения входного файла. Проверь личные пути перед публикацией.","Export existing analysis JSON reports without running the input. Review private paths before sharing."));
                if let Some(root)=root.as_ref(){ui.weak(root.display().to_string());}else{ui.label(label("Сначала открой проект анализа","Open an analysis project first"));}
                ui.horizontal(|ui|{for(format,ext)in[(Format::Html,"html"),(Format::Json,"json"),(Format::Markdown,"md")]{if ui.add_enabled(ready&&root.is_some(),egui::Button::new(format!("{} {}",label("Экспорт","Export"),ext.to_uppercase()))).clicked(){if let Some(target)=rfd::FileDialog::new().add_filter(ext,&[ext]).set_file_name(format!("UIE-report.{ext}")).save_file(){let root=root.clone().unwrap();self.start(move|cancel|export(&root,&target,format,&cancel).map(ResultView::Saved));}}}});
            }else{
                ui.label(label("Выбери два исходника от разных движков. Сравниваются строки на одинаковых позициях — это не проверка эквивалентности и не автоматическое выравнивание.","Choose two sources recovered by different engines. Lines are compared by position, without semantic equivalence or automatic alignment."));
                if ui.add_enabled(ready,egui::Button::new(label("Выбрать два исходника","Choose two source files"))).clicked(){if let Some(paths)=rfd::FileDialog::new().add_filter("Source",&["c","cpp","h","hpp","py","cs","java","js","ts","rs","txt"]).pick_files(){if paths.len()!=2{self.message=label("Выбери ровно два файла","Choose exactly two files");}else{self.start(move|cancel|compare(&paths[0],&paths[1],&cancel).map(ResultView::Compared));}}}
                if let Some(value)=&self.comparison{
                    ui.label(format!("{}: {}",label("Различающиеся позиции строк","Changed line positions"),value.changed));
                    ui.columns(2,|cols|{cols[0].label(value.left.display().to_string());cols[1].label(value.right.display().to_string());});
                    egui::ScrollArea::both().max_height(440.0).show_rows(ui,19.0,value.a.len().max(value.b.len()),|ui,rows|{for row in rows{
                        let changed=value.a.get(row)!=value.b.get(row);
                        ui.columns(2,|cols|{for(col,lines)in cols.iter_mut().zip([&value.a,&value.b]){
                            let line=lines.get(row).map(String::as_str).unwrap_or("");let preview:String=line.chars().take(2048).collect();
                            col.add(egui::Label::new(RichText::new(format!("{:>5}  {}{}",row+1,preview,if preview.len()<line.len(){" …"}else{""})).monospace().size(12.0).color(if changed{Color32::WHITE}else{Color32::from_gray(145)}).background_color(if changed{Color32::from_gray(48)}else{Color32::TRANSPARENT})).wrap_mode(egui::TextWrapMode::Truncate));
                        }});
                    }});
                }
            }
            if self.receiver.is_some(){ui.spinner();if ui.button(label("Отменить","Cancel")).clicked(){self.cancel.store(true,Ordering::Relaxed);}}
            if !self.message.is_empty(){ui.label(&self.message);}
        });
        self.open = open;
        if !open {
            self.cancel.store(true, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "uie-report-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }
    #[test]
    fn exports_escape_markup_and_never_replace_existing() {
        let root = fixture("escape");
        fs::write(
            root.join("analysis.json"),
            r#"{"text":"</pre><script>alert('x')</script>&"}"#,
        )
        .unwrap();
        fs::write(root.join("crash-report.log"), "private").unwrap();
        let cancel = AtomicBool::new(false);
        let bundle = collect(&root, &cancel).unwrap();
        assert_eq!(bundle.reports.len(), 1);
        let html = String::from_utf8(render(&bundle, Format::Html).unwrap()).unwrap();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        let target = root.join("report.html");
        export(&root, &target, Format::Html, &cancel).unwrap();
        let before = fs::read(&target).unwrap();
        assert!(export(&root, &target, Format::Html, &cancel).is_err());
        assert_eq!(fs::read(&target).unwrap(), before);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn nested_reports_exclude_sources_and_expose_invalid_json() {
        let root = fixture("nested");
        fs::create_dir_all(root.join("source")).unwrap();
        fs::create_dir_all(root.join("native/module")).unwrap();
        fs::write(root.join("source/analysis.json"), "{\"secret\":true}").unwrap();
        fs::write(root.join("analysis.json"), "{}").unwrap();
        fs::write(root.join("native/module/native-report.json"), "{}").unwrap();
        fs::write(root.join("python-report.json"), "broken").unwrap();
        let bundle = collect(&root, &AtomicBool::new(false)).unwrap();
        assert_eq!(bundle.reports.len(), 2);
        assert!(bundle.incomplete);
        assert_eq!(bundle.warnings.len(), 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn comparison_handles_unicode_line_endings_added_rows_and_limits() {
        let root = fixture("compare");
        let a = root.join("a.py");
        let b = root.join("b.py");
        fs::write(&a, "привет\r\nreturn 1\r\n").unwrap();
        fs::write(&b, "привет\nreturn 2\nadded\n").unwrap();
        let c = compare(&a, &b, &AtomicBool::new(false)).unwrap();
        assert_eq!(c.changed, 2);
        fs::write(&b, "x\n".repeat(MAX_LINES + 1)).unwrap();
        assert!(compare(&a, &b, &AtomicBool::new(false)).is_err());
        fs::write(&b, b"a\0b").unwrap();
        assert!(compare(&a, &b, &AtomicBool::new(false)).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn cancelled_export_does_not_create_output() {
        let root = fixture("cancel");
        fs::write(root.join("analysis.json"), "{}").unwrap();
        let output = root.join("out.json");
        assert!(export(&root, &output, Format::Json, &AtomicBool::new(true)).is_err());
        assert!(!output.exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn tabs_render_without_inputs_and_with_a_source_difference() {
        let ctx = egui::Context::default();
        let mut tools = Tools::default();
        tools.open = true;
        tools.comparison = Some(Comparison {
            left: "left.c".into(),
            right: "right.c".into(),
            a: vec!["return 1;".into()],
            b: vec!["return 2;".into()],
            changed: 1,
        });
        for tab in 0..2 {
            tools.tab = tab;
            let _ = ctx.run(egui::RawInput::default(), |ctx| tools.show(ctx, None));
        }
    }
}
