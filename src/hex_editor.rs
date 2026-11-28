//! Bounded static byte editing. The original is never opened for writing.
use eframe::egui::{self, Color32};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, SystemTime},
};

const MAX_FILE: u64 = 512 * 1024 * 1024;
const PAGE_BYTES: usize = 1024;
const MAX_PATCHES: usize = 65536;
static TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn label(ru: &str, en: &str) -> String {
    if crate::language::tr("код") == "code" {
        en.into()
    } else {
        ru.into()
    }
}

#[derive(Clone)]
struct Source {
    path: PathBuf,
    len: u64,
    modified: Option<SystemTime>,
    hash: [u8; 32],
}

enum ResultView {
    Open(Source, Vec<u8>),
    Page(u64, Vec<u8>),
    Saved(PathBuf),
}

pub struct HexEditor {
    pub open: bool,
    source: Option<Source>,
    page: Vec<u8>,
    page_start: u64,
    patches: BTreeMap<u64, u8>,
    selected: Option<u64>,
    goto: String,
    byte: String,
    message: String,
    receiver: Option<mpsc::Receiver<Result<ResultView, String>>>,
    cancel: Arc<AtomicBool>,
    confirming_open: Option<PathBuf>,
}

impl Default for HexEditor {
    fn default() -> Self {
        Self {
            open: false,
            source: None,
            page: Vec::new(),
            page_start: 0,
            patches: BTreeMap::new(),
            selected: None,
            goto: "0".into(),
            byte: String::new(),
            message: String::new(),
            receiver: None,
            cancel: Arc::new(AtomicBool::new(false)),
            confirming_open: None,
        }
    }
}
impl Drop for HexEditor {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

fn check_file(path: &Path) -> Result<fs::Metadata, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    let linked = {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let linked = meta.file_type().is_symlink();
    if !meta.is_file() || linked {
        return Err("hex input must be a regular file without links".into());
    }
    if meta.len() > MAX_FILE {
        return Err("hex input exceeds 512 MiB limit".into());
    }
    Ok(meta)
}
fn same_metadata(source: &Source, meta: &fs::Metadata) -> bool {
    source.len == meta.len() && source.modified == meta.modified().ok()
}
fn hash_file(file: &mut File, len: u64, cancel: &AtomicBool) -> Result<[u8; 32], String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or("hex length overflow")?;
        if total > len {
            return Err("hex input changed while reading".into());
        }
        hash.update(&buffer[..n]);
    }
    if total != len {
        return Err("hex input changed while reading".into());
    }
    Ok(hash.finalize().into())
}
fn page_from(file: &mut File, start: u64, len: u64) -> Result<Vec<u8>, String> {
    if start > len || !start.is_multiple_of(PAGE_BYTES as u64) {
        return Err("invalid hex page".into());
    }
    file.seek(SeekFrom::Start(start))
        .map_err(|e| e.to_string())?;
    let mut bytes = vec![0; ((len - start).min(PAGE_BYTES as u64)) as usize];
    file.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    Ok(bytes)
}
fn load(path: &Path, cancel: &AtomicBool) -> Result<ResultView, String> {
    check_file(path)?;
    let path = path.canonicalize().map_err(|e| e.to_string())?;
    let before = check_file(&path)?;
    let mut file = File::open(&path).map_err(|e| e.to_string())?;
    let source = Source {
        path,
        len: before.len(),
        modified: before.modified().ok(),
        hash: hash_file(&mut file, before.len(), cancel)?,
    };
    let page = page_from(&mut file, 0, source.len)?;
    if !same_metadata(&source, &file.metadata().map_err(|e| e.to_string())?)
        || !same_metadata(&source, &check_file(&source.path)?)
    {
        return Err("hex input changed while reading".into());
    }
    Ok(ResultView::Open(source, page))
}
fn read_page(source: &Source, start: u64, cancel: &AtomicBool) -> Result<ResultView, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    if !same_metadata(source, &check_file(&source.path)?) {
        return Err("hex input changed; reopen it".into());
    }
    let mut file = File::open(&source.path).map_err(|e| e.to_string())?;
    if !same_metadata(source, &file.metadata().map_err(|e| e.to_string())?) {
        return Err("hex input changed; reopen it".into());
    }
    let bytes = page_from(&mut file, start, source.len)?;
    if !same_metadata(source, &file.metadata().map_err(|e| e.to_string())?) {
        return Err("hex input changed; reopen it".into());
    }
    Ok(ResultView::Page(start, bytes))
}

struct Temporary(PathBuf);
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn patched_copy(
    source: &Source,
    patches: &BTreeMap<u64, u8>,
    destination: &Path,
    cancel: &AtomicBool,
) -> Result<PathBuf, String> {
    if patches.len() > MAX_PATCHES || patches.keys().any(|p| *p >= source.len) {
        return Err("invalid hex patch map".into());
    }
    if !same_metadata(source, &check_file(&source.path)?) {
        return Err("hex input changed; reopen it before saving".into());
    }
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = parent.canonicalize().map_err(|e| e.to_string())?;
    let destination = parent.join(destination.file_name().ok_or("missing patched filename")?);
    if destination == source.path || fs::symlink_metadata(&destination).is_ok() {
        return Err(
            "choose a new filename; existing files and the original are never overwritten".into(),
        );
    }
    let temp_path = parent.join(format!(
        ".uie-hex-{}-{}.tmp",
        std::process::id(),
        TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp_path)
        .map_err(|e| e.to_string())?;
    let temp = Temporary(temp_path);
    let mut output = output;
    let mut input = File::open(&source.path).map_err(|e| e.to_string())?;
    if !same_metadata(source, &input.metadata().map_err(|e| e.to_string())?) {
        return Err("hex input changed; reopen it".into());
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut offset = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let count = input.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        let end = offset
            .checked_add(count as u64)
            .ok_or("hex length overflow")?;
        if end > source.len {
            return Err("hex input changed while saving".into());
        }
        hash.update(&buffer[..count]);
        for (position, byte) in patches.range(offset..end) {
            buffer[(*position - offset) as usize] = *byte;
        }
        output
            .write_all(&buffer[..count])
            .map_err(|e| e.to_string())?;
        offset = end;
    }
    let actual: [u8; 32] = hash.finalize().into();
    if offset != source.len
        || actual != source.hash
        || !same_metadata(source, &input.metadata().map_err(|e| e.to_string())?)
        || !same_metadata(source, &check_file(&source.path)?)
    {
        return Err("hex input changed; patched copy was not published".into());
    }
    output.sync_all().map_err(|e| e.to_string())?;
    drop(output);
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    // A hard link publishes the verified file without an overwrite race.
    fs::hard_link(&temp.0, &destination)
        .map_err(|e| format!("cannot publish new patched copy: {e}"))?;
    Ok(destination)
}

impl HexEditor {
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
    pub fn open_path(&mut self, path: PathBuf) {
        self.open = true;
        if !self.patches.is_empty() {
            self.confirming_open = Some(path);
            return;
        }
        self.start(move |cancel| load(&path, &cancel));
    }
    fn goto_page(&mut self, start: u64) {
        if let Some(source) = self.source.clone() {
            self.start(move |cancel| read_page(&source, start, &cancel));
        }
    }
    fn apply_byte(&mut self) -> Result<(), String> {
        let position = self.selected.ok_or("select a byte first")?;
        let value = self.byte.trim();
        if value.len() != 2 {
            return Err("enter exactly two hexadecimal digits".into());
        }
        let byte = u8::from_str_radix(value, 16).map_err(|_| "invalid hexadecimal byte")?;
        let index = position
            .checked_sub(self.page_start)
            .ok_or("selected byte is outside this page")? as usize;
        let original = *self
            .page
            .get(index)
            .ok_or("selected byte is outside this page")?;
        if byte == original {
            self.patches.remove(&position);
        } else {
            if !self.patches.contains_key(&position) && self.patches.len() >= MAX_PATCHES {
                return Err("hex patch limit reached (65536 bytes)".into());
            }
            self.patches.insert(position, byte);
        }
        Ok(())
    }
    pub fn show(&mut self, ctx: &egui::Context) {
        let completed = self.receiver.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(value) => Some(value),
            Err(mpsc::TryRecvError::Disconnected) => Some(Err("hex worker stopped".into())),
            Err(_) => None,
        });
        if let Some(result) = completed {
            self.receiver = None;
            match result {
                Ok(ResultView::Open(source, page)) => {
                    self.source = Some(source);
                    self.page = page;
                    self.page_start = 0;
                    self.selected = None;
                    self.patches.clear();
                    self.message.clear();
                }
                Ok(ResultView::Page(start, page)) => {
                    self.page_start = start;
                    self.page = page;
                    self.selected = None;
                }
                Ok(ResultView::Saved(path)) => {
                    self.message = format!(
                        "{}: {}",
                        label("копия сохранена", "copy saved"),
                        path.display()
                    )
                }
                Err(error) => self.message = error,
            }
        }
        if !self.open {
            return;
        }
        if self.receiver.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        let mut open = self.open;
        egui::Window::new(label("hex редактор", "hex editor"))
            .open(&mut open)
            .default_size([900.0, 650.0])
            .show(ctx, |ui| {
                let ready = self.receiver.is_none();
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(ready, egui::Button::new(label("открыть файл", "open file")))
                        .clicked()
                    {
                        if let Some(path) = rfd::FileDialog::new().pick_file() {
                            self.open_path(path);
                        }
                    }
                    if ui
                        .add_enabled(
                            ready && self.source.is_some(),
                            egui::Button::new(label(
                                "сохранить изменённую копию",
                                "save patched copy",
                            )),
                        )
                        .clicked()
                    {
                        if let Some(source) = self.source.clone() {
                            let name = format!(
                                "{}_patched{}",
                                source
                                    .path
                                    .file_stem()
                                    .unwrap_or_default()
                                    .to_string_lossy(),
                                source
                                    .path
                                    .extension()
                                    .map(|e| format!(".{}", e.to_string_lossy()))
                                    .unwrap_or_default()
                            );
                            if let Some(path) =
                                rfd::FileDialog::new().set_file_name(name).save_file()
                            {
                                let patches = self.patches.clone();
                                self.start(move |cancel| {
                                    patched_copy(&source, &patches, &path, &cancel)
                                        .map(ResultView::Saved)
                                });
                            }
                        }
                    }
                    if ui
                        .add_enabled(
                            ready && !self.patches.is_empty(),
                            egui::Button::new(label(
                                "отменить все байтовые правки",
                                "discard byte edits",
                            )),
                        )
                        .clicked()
                    {
                        self.patches.clear();
                    }
                });
                if let Some(source) = self.source.as_ref() {
                    ui.label(format!(
                        "{}  |  {} bytes  |  {} {}",
                        source.path.display(),
                        source.len,
                        self.patches.len(),
                        label("правок", "edits")
                    ));
                    ui.weak(format!(
                        "SHA-256: {:x}",
                        sha2::digest::Output::<Sha256>::from(source.hash)
                    ));
                    let len = source.len;
                    ui.horizontal(|ui| {
                        if ui
                            .add_enabled(ready && self.page_start > 0, egui::Button::new("<"))
                            .clicked()
                        {
                            self.goto_page(self.page_start.saturating_sub(PAGE_BYTES as u64));
                        }
                        if ui
                            .add_enabled(
                                ready && self.page_start + (PAGE_BYTES as u64) < len,
                                egui::Button::new(">"),
                            )
                            .clicked()
                        {
                            self.goto_page(self.page_start + PAGE_BYTES as u64);
                        }
                        ui.label(label("смещение hex", "hex offset"));
                        ui.add(egui::TextEdit::singleline(&mut self.goto).desired_width(110.0));
                        if ui
                            .add_enabled(ready, egui::Button::new(label("перейти", "go")))
                            .clicked()
                        {
                            match u64::from_str_radix(
                                self.goto
                                    .trim()
                                    .trim_start_matches("0x")
                                    .trim_start_matches("0X"),
                                16,
                            ) {
                                Ok(position) if position < len || (len == 0 && position == 0) => {
                                    self.goto_page(position / PAGE_BYTES as u64 * PAGE_BYTES as u64)
                                }
                                _ => {
                                    self.message =
                                        label("смещение вне файла", "offset outside the file")
                                }
                            }
                        }
                    });
                    ui.horizontal(|ui| {
                        ui.label(
                            self.selected
                                .map(|p| format!("0x{p:08X}"))
                                .unwrap_or_else(|| label("выбери байт", "select a byte")),
                        );
                        ui.add(
                            egui::TextEdit::singleline(&mut self.byte)
                                .desired_width(42.0)
                                .char_limit(2),
                        );
                        if ui
                            .add_enabled(
                                ready && self.selected.is_some(),
                                egui::Button::new(label("применить байт", "apply byte")),
                            )
                            .clicked()
                        {
                            if let Err(error) = self.apply_byte() {
                                self.message = error;
                            }
                        }
                        if ui
                            .add_enabled(
                                ready
                                    && self.selected.is_some_and(|p| self.patches.contains_key(&p)),
                                egui::Button::new(label("вернуть байт", "revert byte")),
                            )
                            .clicked()
                        {
                            if let Some(p) = self.selected {
                                self.patches.remove(&p);
                            }
                        }
                    });
                    egui::ScrollArea::both().max_height(430.0).show(ui, |ui| {
                        egui::Grid::new("hex-bytes")
                            .spacing([5.0, 3.0])
                            .show(ui, |ui| {
                                for row in 0..self.page.len().div_ceil(16) {
                                    let start = row * 16;
                                    ui.monospace(format!("{:08X}", self.page_start + start as u64));
                                    let mut ascii = String::new();
                                    for col in 0..16 {
                                        let index = start + col;
                                        if let Some(original) = self.page.get(index) {
                                            let position = self.page_start + index as u64;
                                            let byte =
                                                *self.patches.get(&position).unwrap_or(original);
                                            let color = if self.patches.contains_key(&position) {
                                                Color32::from_rgb(245, 130, 130)
                                            } else {
                                                Color32::WHITE
                                            };
                                            let response = ui.add_enabled(
                                                ready,
                                                egui::Button::new(
                                                    egui::RichText::new(format!("{byte:02X}"))
                                                        .monospace()
                                                        .color(color),
                                                )
                                                .selected(self.selected == Some(position))
                                                .min_size(egui::vec2(24.0, 18.0)),
                                            );
                                            if response.clicked() {
                                                self.selected = Some(position);
                                                self.byte = format!("{byte:02X}");
                                            }
                                            ascii.push(if (32..=126).contains(&byte) {
                                                byte as char
                                            } else {
                                                '.'
                                            });
                                        } else {
                                            ui.label("  ");
                                        }
                                    }
                                    ui.monospace(ascii);
                                    ui.end_row();
                                }
                            });
                    });
                    if len == 0 {
                        ui.label(label("пустой файл", "empty file"));
                    }
                }
                if self.receiver.is_some() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        if ui
                            .button(label("отменить операцию", "cancel operation"))
                            .clicked()
                        {
                            self.cancel.store(true, Ordering::Relaxed);
                        }
                    });
                }
                if !self.message.is_empty() {
                    ui.label(&self.message);
                }
                ui.weak(label(
                    "оригинал не изменяется — сохраняется только новая копия",
                    "the original is unchanged; saving creates a new copy only",
                ));
            });
        self.open = open;
        if !open {
            self.cancel.store(true, Ordering::Relaxed);
        }
        if let Some(path) = self.confirming_open.clone() {
            egui::Window::new(label("несохранённые байтовые правки", "unsaved byte edits"))
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.label(label(
                        "открыть другой файл и потерять текущие байтовые правки?",
                        "open another file and discard the current byte edits?",
                    ));
                    if ui
                        .button(label(
                            "открыть и отбросить правки",
                            "open and discard edits",
                        ))
                        .clicked()
                    {
                        self.confirming_open = None;
                        self.patches.clear();
                        self.start(move |cancel| load(&path, &cancel));
                    }
                    if ui
                        .button(label("оставить текущий файл", "keep current file"))
                        .clicked()
                    {
                        self.confirming_open = None;
                    }
                });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "uie-hex-test-{}-{}",
            std::process::id(),
            TEMP_ID.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        path
    }
    fn source(path: &Path) -> Source {
        match load(path, &AtomicBool::new(false)).unwrap() {
            ResultView::Open(source, _) => source,
            _ => panic!("wrong result"),
        }
    }
    #[test]
    fn page_boundaries_and_last_short_page() {
        let root = directory();
        let path = root.join("owned.bin");
        let original: Vec<u8> = (0..1031).map(|i| (i % 256) as u8).collect();
        fs::write(&path, &original).unwrap();
        let src = source(&path);
        match read_page(&src, 1024, &AtomicBool::new(false)).unwrap() {
            ResultView::Page(start, bytes) => {
                assert_eq!(start, 1024);
                assert_eq!(bytes, original[1024..]);
            }
            _ => panic!("wrong result"),
        }
        assert!(read_page(&src, 1025, &AtomicBool::new(false)).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn patches_copy_only_and_refuse_existing_destination() {
        let root = directory();
        let path = root.join("owned.bin");
        let bytes = vec![0x41; 65539];
        fs::write(&path, &bytes).unwrap();
        let src = source(&path);
        let target = root.join("patched.bin");
        let patches = BTreeMap::from([(0, 0x90), (65535, 0x42), (65536, 0), (65538, 0xff)]);
        patched_copy(&src, &patches, &target, &AtomicBool::new(false)).unwrap();
        let changed = fs::read(&target).unwrap();
        for (p, b) in patches {
            assert_eq!(changed[p as usize], b);
        }
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(patched_copy(&src, &BTreeMap::new(), &target, &AtomicBool::new(false)).is_err());
        assert!(patched_copy(&src, &BTreeMap::new(), &path, &AtomicBool::new(false)).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn changed_original_and_cancel_never_publish() {
        let root = directory();
        let path = root.join("owned.bin");
        fs::write(&path, "first").unwrap();
        let mut src = source(&path);
        fs::write(&path, "other").unwrap();
        src.modified = fs::metadata(&path).unwrap().modified().ok();
        let target = root.join("patched.bin");
        assert!(patched_copy(&src, &BTreeMap::new(), &target, &AtomicBool::new(false)).is_err());
        assert!(!target.exists());
        let src = source(&path);
        assert!(patched_copy(&src, &BTreeMap::new(), &target, &AtomicBool::new(true)).is_err());
        assert!(!target.exists());
        assert_eq!(fs::read_dir(&root).unwrap().count(), 1);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn editor_changes_and_reverts_selected_byte() {
        let mut editor = HexEditor::default();
        editor.page = vec![0x41, 0x42];
        editor.selected = Some(1);
        editor.byte = "ff".into();
        editor.apply_byte().unwrap();
        assert_eq!(editor.patches.get(&1), Some(&255));
        editor.byte = "42".into();
        editor.apply_byte().unwrap();
        assert!(editor.patches.is_empty());
        editor.byte = "zz".into();
        assert!(editor.apply_byte().is_err());
    }

    #[test]
    fn size_limit_empty_copy_and_page_ui() {
        let root = directory();
        let path = root.join("empty.bin");
        fs::write(&path, []).unwrap();
        let src = source(&path);
        let target = root.join("empty-copy.bin");
        patched_copy(&src, &BTreeMap::new(), &target, &AtomicBool::new(false)).unwrap();
        assert_eq!(fs::metadata(&target).unwrap().len(), 0);
        let mut editor = HexEditor::default();
        editor.open = true;
        editor.source = Some(src);
        let ctx = egui::Context::default();
        let _ = ctx.run(egui::RawInput::default(), |ctx| editor.show(ctx));
        let oversized = root.join("too-large.bin");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_FILE + 1)
            .unwrap();
        assert!(check_file(&oversized).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
