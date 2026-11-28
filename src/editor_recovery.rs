//! Recovery copies only. Restoring returns text; this module never overwrites source files.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const MAX_TEXT: u64 = 32 * 1024 * 1024;
const MAX_TOTAL: u64 = 128 * 1024 * 1024;
const MAX_HEADER: usize = 16 * 1024;
const MAX_FILES: usize = 1024;
const INTERVAL: Duration = Duration::from_secs(5);
static SERIAL: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct Candidate {
    pub id: String,
    pub path: PathBuf,
    pub baseline_sha256: String,
    pub revision: u64,
    pub bytes: u64,
    /// True also when the original is missing or cannot be checked.
    pub conflict: bool,
}
pub enum Event {
    Candidates(Vec<Candidate>),
    Loaded {
        candidate: Candidate,
        text: String,
    },
    Error {
        path: Option<PathBuf>,
        message: String,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Header {
    version: u32,
    path: PathBuf,
    baseline_sha256: String,
    text_sha256: String,
    revision: u64,
    bytes: u64,
    sequence: u64,
}
enum Command {
    Save {
        path: PathBuf,
        baseline: String,
        revision: u64,
        text: String,
    },
    Remove {
        id: String,
    },
    Scan,
    Load(String),
}
pub struct Controller {
    tx: mpsc::SyncSender<Command>,
    rx: mpsc::Receiver<Event>,
    queued: HashMap<PathBuf, u64>,
    removals: VecDeque<String>,
    next: Instant,
}
impl Default for Controller {
    fn default() -> Self {
        Self::new(crate::engine::config_path().with_file_name("editor-drafts"))
    }
}
impl Controller {
    pub fn new(folder: PathBuf) -> Self {
        let (tx, commands) = mpsc::sync_channel(3);
        let (events, rx) = mpsc::channel();
        thread::spawn(move || worker(folder, commands, events));
        Self {
            tx,
            rx,
            queued: HashMap::new(),
            removals: VecDeque::new(),
            next: Instant::now() + INTERVAL,
        }
    }
    pub fn due(&mut self) -> bool {
        if Instant::now() < self.next {
            return false;
        }
        self.next = Instant::now() + INTERVAL;
        true
    }
    pub fn save(
        &mut self,
        path: &Path,
        revision: u64,
        baseline_sha256: &str,
        text: &str,
    ) -> Result<bool, String> {
        self.flush_removals()?;
        if !self.removals.is_empty() {
            return Ok(false);
        }
        if self.queued.get(path) == Some(&revision) {
            return Ok(false);
        }
        validate_path(path)?;
        if !hash_valid(baseline_sha256) || text.len() as u64 > MAX_TEXT {
            return Err("recovery draft exceeds size limit or has an invalid baseline hash".into());
        }
        let command = Command::Save {
            path: path.into(),
            baseline: baseline_sha256.into(),
            revision,
            text: text.into(),
        };
        match self.tx.try_send(command) {
            Ok(()) => {
                self.queued.insert(path.into(), revision);
                Ok(true)
            }
            Err(mpsc::TrySendError::Full(_)) => Ok(false),
            Err(_) => Err("recovery worker stopped".into()),
        }
    }
    /// FIFO ordering ensures an older queued write cannot recreate a removed saved draft.
    pub fn mark_saved(&mut self, path: &Path) -> Result<(), String> {
        let id = path_id(path)?;
        if !self.removals.contains(&id) {
            self.removals.push_back(id);
        }
        self.queued.remove(path);
        self.flush_removals()
    }
    pub fn refresh(&self) -> Result<(), String> {
        self.tx.try_send(Command::Scan).map_err(|e| e.to_string())
    }
    pub fn load(&self, id: &str) -> Result<(), String> {
        if !hash_valid(id) {
            return Err("invalid recovery id".into());
        }
        self.tx
            .try_send(Command::Load(id.into()))
            .map_err(|e| e.to_string())
    }
    pub fn discard(&mut self, id: &str) -> Result<(), String> {
        if !hash_valid(id) {
            return Err("invalid recovery id".into());
        }
        if !self.removals.iter().any(|value| value == id) {
            self.removals.push_back(id.into());
        }
        self.queued
            .retain(|path, _| path_id(path).as_deref() != Ok(id));
        self.flush_removals()
    }
    fn flush_removals(&mut self) -> Result<(), String> {
        while let Some(id) = self.removals.pop_front() {
            match self.tx.try_send(Command::Remove { id }) {
                Ok(()) => (),
                Err(mpsc::TrySendError::Full(Command::Remove { id })) => {
                    self.removals.push_front(id);
                    break;
                }
                Err(_) => return Err("recovery worker stopped".into()),
            }
        }
        Ok(())
    }
    pub fn poll(&mut self) -> Vec<Event> {
        let mut result = Vec::new();
        if let Err(message) = self.flush_removals() {
            result.push(Event::Error {
                path: None,
                message,
            });
        }
        for _ in 0..32 {
            match self.rx.try_recv() {
                Ok(event) => {
                    if let Event::Error {
                        path: Some(path), ..
                    } = &event
                    {
                        self.queued.remove(path);
                    }
                    result.push(event);
                }
                Err(_) => break,
            }
        }
        result
    }
}
pub fn baseline(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}
fn hash_valid(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|c| c.is_ascii_hexdigit())
}
fn validate_path(path: &Path) -> Result<(), String> {
    if !path.is_absolute() || path.to_str().is_none() {
        return Err("recovery source must have an absolute Unicode path".into());
    }
    Ok(())
}
fn path_id(path: &Path) -> Result<String, String> {
    validate_path(path)?;
    Ok(baseline(path.to_str().unwrap()))
}
fn plain(path: &Path) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("recovery links are not followed".into());
        }
    }
    if metadata.file_type().is_symlink() {
        return Err("recovery links are not followed".into());
    }
    Ok(metadata)
}
fn folder_ready(folder: &Path) -> Result<(), String> {
    fs::create_dir_all(folder).map_err(|e| e.to_string())?;
    if !plain(folder)?.is_dir() {
        return Err("recovery folder is not a directory".into());
    }
    Ok(())
}
fn draft_files(folder: &Path) -> Result<Vec<PathBuf>, String> {
    folder_ready(folder)?;
    let mut files = Vec::new();
    for entry in fs::read_dir(folder).map_err(|e| e.to_string())? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path.extension().is_some_and(|e| e == "draft") {
            if files.len() >= MAX_FILES {
                return Err("recovery draft count limit reached".into());
            }
            if !plain(&path)?.is_file() {
                return Err("recovery draft is not a regular file".into());
            }
            files.push(path);
        }
    }
    Ok(files)
}
fn read_header(path: &Path) -> Result<(Header, File), String> {
    let metadata = plain(path)?;
    if !metadata.is_file() || metadata.len() > MAX_TEXT + MAX_HEADER as u64 + 4 {
        return Err("invalid recovery draft size".into());
    }
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut length = [0; 4];
    file.read_exact(&mut length).map_err(|e| e.to_string())?;
    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_HEADER {
        return Err("recovery header exceeds limit".into());
    }
    let mut data = vec![0; length];
    file.read_exact(&mut data).map_err(|e| e.to_string())?;
    let header: Header = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
    validate_path(&header.path)?;
    if header.version != 1
        || header.bytes > MAX_TEXT
        || !hash_valid(&header.baseline_sha256)
        || !hash_valid(&header.text_sha256)
        || metadata.len() != 4 + length as u64 + header.bytes
    {
        return Err("invalid recovery header".into());
    }
    let expected = format!("{}-{}", path_id(&header.path)?, header.sequence);
    if path.file_stem().and_then(|s| s.to_str()) != Some(&expected) {
        return Err("recovery filename and source disagree".into());
    }
    Ok((header, file))
}
fn current_hash(path: &Path) -> Result<String, String> {
    let metadata = plain(path)?;
    if !metadata.is_file() || metadata.len() > MAX_TEXT {
        return Err("original unavailable or too large".into());
    }
    let mut file = File::open(path)
        .map_err(|e| e.to_string())?
        .take(MAX_TEXT + 1);
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    let mut total = 0;
    loop {
        let n = file.read(&mut bytes).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_TEXT {
            return Err("original grew beyond limit".into());
        }
        hash.update(&bytes[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn candidate(header: &Header) -> Candidate {
    Candidate {
        id: path_id(&header.path).unwrap(),
        path: header.path.clone(),
        baseline_sha256: header.baseline_sha256.clone(),
        revision: header.revision,
        bytes: header.bytes,
        conflict: current_hash(&header.path).as_deref() != Ok(header.baseline_sha256.as_str()),
    }
}
fn latest(folder: &Path) -> Result<HashMap<String, (PathBuf, Header)>, String> {
    let mut result: HashMap<String, (PathBuf, Header)> = HashMap::new();
    let mut total = 0;
    for path in draft_files(folder)? {
        let (header, _) = read_header(&path)?;
        total += plain(&path)?.len();
        if total > MAX_TOTAL {
            return Err("recovery storage exceeds total limit".into());
        }
        let id = path_id(&header.path)?;
        if result
            .get(&id)
            .is_none_or(|(_, previous)| header.sequence > previous.sequence)
        {
            result.insert(id, (path, header));
        }
    }
    Ok(result)
}
fn remove_id(folder: &Path, id: &str) -> Result<(), String> {
    for path in draft_files(folder)? {
        if path
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|name| name.starts_with(&format!("{id}-")))
        {
            fs::remove_file(path).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}
fn write_draft(
    folder: &Path,
    path: PathBuf,
    baseline_hash: String,
    revision: u64,
    text: String,
) -> Result<(), String> {
    let id = path_id(&path)?;
    if text.len() as u64 > MAX_TEXT || !hash_valid(&baseline_hash) {
        return Err("invalid recovery snapshot".into());
    }
    let clock = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos()
        .min(u64::MAX as u128) as u64;
    let previous = loop {
        let previous = SERIAL.load(Ordering::Relaxed);
        if SERIAL
            .compare_exchange_weak(
                previous,
                clock.max(previous.saturating_add(1)),
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            break previous;
        }
    };
    let sequence = clock.max(previous.saturating_add(1));
    let header = Header {
        version: 1,
        path,
        baseline_sha256: baseline_hash,
        text_sha256: baseline(&text),
        revision,
        bytes: text.len() as u64,
        sequence,
    };
    let bytes = serde_json::to_vec(&header).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_HEADER {
        return Err("recovery header exceeds limit".into());
    }
    let existing = draft_files(folder)?;
    let total = existing
        .iter()
        .try_fold(0u64, |sum, p| plain(p).map(|m| sum + m.len()))?;
    let required = 4 + bytes.len() as u64 + text.len() as u64;
    if total + required > MAX_TOTAL {
        return Err("recovery storage limit reached".into());
    }
    let target = folder.join(format!("{id}-{sequence}.draft"));
    let temporary = target.with_extension("tmp");
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|e| e.to_string())?;
        file.write_all(&(bytes.len() as u32).to_le_bytes())
            .and_then(|_| file.write_all(&bytes))
            .and_then(|_| file.write_all(text.as_bytes()))
            .and_then(|_| file.sync_all())
            .map_err(|e| e.to_string())?;
        drop(file);
        fs::rename(&temporary, &target).map_err(|e| e.to_string())?;
        for old in existing {
            if old
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|name| name.starts_with(&format!("{id}-")))
            {
                fs::remove_file(old).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
fn load_draft(folder: &Path, id: &str) -> Result<(Candidate, String), String> {
    let (path, header) = latest(folder)?
        .remove(id)
        .ok_or("recovery draft no longer exists")?;
    let (_, file) = read_header(&path)?;
    let mut text = String::new();
    file.take(MAX_TEXT + 1)
        .read_to_string(&mut text)
        .map_err(|e| e.to_string())?;
    if text.len() as u64 != header.bytes || baseline(&text) != header.text_sha256 {
        return Err("recovery text integrity check failed".into());
    }
    Ok((candidate(&header), text))
}
fn worker(folder: PathBuf, commands: mpsc::Receiver<Command>, events: mpsc::Sender<Event>) {
    let scan = |events: &mpsc::Sender<Event>| match latest(&folder) {
        Ok(items) => {
            let mut values: Vec<_> = items.values().map(|(_, h)| candidate(h)).collect();
            values.sort_by(|a, b| a.path.cmp(&b.path));
            let _ = events.send(Event::Candidates(values));
        }
        Err(message) => {
            let _ = events.send(Event::Error {
                path: None,
                message,
            });
        }
    };
    scan(&events);
    for command in commands {
        let (path, result) = match command {
            Command::Save {
                path,
                baseline,
                revision,
                text,
            } => {
                let copy = path.clone();
                (
                    Some(copy),
                    write_draft(&folder, path, baseline, revision, text),
                )
            }
            Command::Remove { id } => {
                let result = remove_id(&folder, &id);
                if result.is_ok() {
                    scan(&events);
                }
                (None, result)
            }
            Command::Scan => {
                scan(&events);
                continue;
            }
            Command::Load(id) => {
                match load_draft(&folder, &id) {
                    Ok((candidate, text)) => {
                        let _ = events.send(Event::Loaded { candidate, text });
                    }
                    Err(message) => {
                        let _ = events.send(Event::Error {
                            path: None,
                            message,
                        });
                    }
                }
                continue;
            }
        };
        if let Err(message) = result {
            let _ = events.send(Event::Error { path, message });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "uie-draft-{name}-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }
    #[test]
    fn recovery_preserves_original_and_detects_change() {
        let root = fixture("conflict");
        let source = root.join("app.py");
        fs::write(&source, "answer=1\n").unwrap();
        let folder = root.join("drafts");
        write_draft(
            &folder,
            source.clone(),
            baseline("answer=1\n"),
            2,
            "answer=2\n".into(),
        )
        .unwrap();
        let id = path_id(&source).unwrap();
        let (c, text) = load_draft(&folder, &id).unwrap();
        assert!(!c.conflict);
        assert_eq!(text, "answer=2\n");
        assert_eq!(fs::read_to_string(&source).unwrap(), "answer=1\n");
        fs::write(&source, "external change").unwrap();
        assert!(load_draft(&folder, &id).unwrap().0.conflict);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn newest_snapshot_and_remove_are_serial() {
        let root = fixture("serial");
        let source = root.join("app.py");
        fs::write(&source, "original").unwrap();
        let folder = root.join("drafts");
        write_draft(
            &folder,
            source.clone(),
            baseline("original"),
            1,
            "first".into(),
        )
        .unwrap();
        write_draft(
            &folder,
            source.clone(),
            baseline("original"),
            2,
            "second".into(),
        )
        .unwrap();
        let id = path_id(&source).unwrap();
        assert_eq!(load_draft(&folder, &id).unwrap().1, "second");
        assert_eq!(draft_files(&folder).unwrap().len(), 1);
        remove_id(&folder, &id).unwrap();
        assert!(latest(&folder).unwrap().is_empty());
        assert_eq!(fs::read_to_string(source).unwrap(), "original");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn damaged_text_and_header_are_rejected() {
        let root = fixture("corrupt");
        let source = root.join("app.py");
        fs::write(&source, "original").unwrap();
        let folder = root.join("drafts");
        write_draft(
            &folder,
            source.clone(),
            baseline("original"),
            1,
            "edited".into(),
        )
        .unwrap();
        let file = draft_files(&folder).unwrap().pop().unwrap();
        let mut bytes = fs::read(&file).unwrap();
        *bytes.last_mut().unwrap() = b'X';
        fs::write(&file, &bytes).unwrap();
        assert!(load_draft(&folder, &path_id(&source).unwrap()).is_err());
        fs::write(&file, u32::MAX.to_le_bytes()).unwrap();
        assert!(read_header(&file).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
