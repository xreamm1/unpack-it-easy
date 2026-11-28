//! Manifest management only: importing and enabling never executes a plugin.
use eframe::egui;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};
const MAX_BYTES: u64 = 64 * 1024;
const MAX_ENTRIES: usize = 128;
static SERIAL: AtomicU64 = AtomicU64::new(0);
fn text(ru: &str, en: &str) -> String {
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
fn bytes(path: &Path) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || linked(&meta) || meta.len() > MAX_BYTES {
        return Err("manifest must be a regular file of at most 64 KiB".into());
    }
    let mut data = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_BYTES {
        return Err("manifest grew beyond 64 KiB".into());
    }
    Ok(data)
}
fn hash(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}
fn root(folder: &Path, create: bool) -> Result<PathBuf, String> {
    if create {
        fs::create_dir_all(folder).map_err(|e| e.to_string())?;
    }
    let meta = fs::symlink_metadata(folder).map_err(|e| e.to_string())?;
    if !meta.is_dir() || linked(&meta) {
        return Err("plugin directory must be a real directory".into());
    }
    folder.canonicalize().map_err(|e| e.to_string())
}
#[derive(Clone)]
struct Entry {
    path: PathBuf,
    id: String,
    name: String,
    enabled: bool,
    hash: String,
    error: Option<String>,
}
fn entries(folder: &Path) -> Result<Vec<Entry>, String> {
    if !folder.exists() {
        return Ok(vec![]);
    }
    let folder = root(folder, false)?;
    let mut result = Vec::new();
    for item in fs::read_dir(folder).map_err(|e| e.to_string())? {
        let path = item.map_err(|e| e.to_string())?.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }
        if result.len() >= MAX_ENTRIES {
            return Err("more than 128 plugin manifests".into());
        }
        let mut entry = Entry {
            path: path.clone(),
            id: String::new(),
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            enabled: false,
            hash: String::new(),
            error: None,
        };
        match bytes(&path).and_then(|data| {
            entry.hash = hash(&data);
            let value: Value = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
            entry.enabled = value["enabled"].as_bool().unwrap_or(false);
            crate::plugins::validate_manager_manifest(&data, false)
        }) {
            Ok(plugin) => {
                entry.id = plugin.id;
                entry.name = plugin.name;
            }
            Err(error) => entry.error = Some(error),
        }
        result.push(entry);
    }
    result.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(result)
}
fn publish(
    folder: &Path,
    destination: &Path,
    data: &[u8],
    expected: Option<&str>,
) -> Result<(), String> {
    let folder = root(folder, true)?;
    if destination
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .as_ref()
        != Some(&folder)
    {
        return Err("manifest destination escapes plugin directory".into());
    }
    if let Some(expected) = expected {
        if hash(&bytes(destination)?) != expected {
            return Err("manifest changed; refresh before modifying it".into());
        }
    } else if destination.exists() {
        return Err("a manifest with this id already exists".into());
    }
    let temp = folder.join(format!(
        ".manifest-{}-{}.tmp",
        std::process::id(),
        SERIAL.fetch_add(1, Ordering::Relaxed)
    ));
    let outcome = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp)
            .map_err(|e| e.to_string())?;
        file.write_all(data).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        drop(file);
        if let Some(expected) = expected {
            if hash(&bytes(destination)?) != expected {
                return Err("manifest changed during update; refresh first".into());
            }
            fs::rename(&temp, destination).map_err(|e| e.to_string())?;
        } else {
            // Hard-link publication is atomic and cannot replace an existing manifest.
            fs::hard_link(&temp, destination).map_err(|e| e.to_string())?;
            fs::remove_file(&temp).map_err(|e| e.to_string())?;
        }
        Ok(())
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(temp);
    }
    outcome
}
fn toggle(folder: &Path, entry: &Entry, enabled: bool) -> Result<(), String> {
    let data = bytes(&entry.path)?;
    if hash(&data) != entry.hash {
        return Err("manifest changed; refresh first".into());
    }
    let mut value: Value = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
    value
        .as_object_mut()
        .ok_or("manifest must be an object")?
        .insert("enabled".into(), Value::Bool(enabled));
    let data = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
    crate::plugins::validate_manager_manifest(&data, enabled)?;
    if enabled
        && entries(folder)?
            .iter()
            .any(|other| other.path != entry.path && other.enabled && other.id == entry.id)
    {
        return Err("another enabled manifest uses this plugin id".into());
    }
    publish(folder, &entry.path, &data, Some(&entry.hash))
}
fn import(folder: &Path, path: &Path) -> Result<(), String> {
    let mut value: Value = serde_json::from_slice(&bytes(path)?).map_err(|e| e.to_string())?;
    value
        .as_object_mut()
        .ok_or("manifest must be an object")?
        .insert("enabled".into(), Value::Bool(false));
    let data = serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?;
    let plugin = crate::plugins::validate_manager_manifest(&data, false)?;
    let folder = root(folder, true)?;
    if entries(&folder)?.iter().any(|e| e.id == plugin.id) {
        return Err("a plugin with this id is already installed".into());
    }
    publish(
        &folder,
        &folder.join(format!("{}.json", plugin.id)),
        &data,
        None,
    )
}

#[derive(Default)]
pub struct Manager {
    pub open: bool,
    loaded: bool,
    entries: Vec<Entry>,
    receiver: Option<mpsc::Receiver<Result<Vec<Entry>, String>>>,
    message: String,
    confirm: Option<Entry>,
}
impl Manager {
    fn start(&mut self, job: impl FnOnce(&Path) -> Result<(), String> + Send + 'static) {
        let folder = crate::runtime::root().join("plugins");
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        thread::spawn(move || {
            let result = job(&folder).and_then(|_| entries(&folder));
            let _ = tx.send(result);
        });
    }
    pub fn show(&mut self, ctx: &egui::Context) {
        if !self.open {
            return;
        }
        if !self.loaded {
            self.loaded = true;
            self.start(|_| Ok(()));
        }
        if let Some(result) = self.receiver.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(r) => Some(r),
            Err(mpsc::TryRecvError::Disconnected) => {
                Some(Err("plugin manager worker stopped".into()))
            }
            Err(_) => None,
        }) {
            self.receiver = None;
            match result {
                Ok(rows) => {
                    self.entries = rows;
                    self.message.clear();
                }
                Err(e) => self.message = e,
            }
        }
        if self.receiver.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        let mut open = self.open;
        egui::Window::new(text("менеджер плагинов","plugin manager")).open(&mut open).default_width(760.0).show(ctx,|ui|{
            ui.label(text("плагины запускают доверенные внешние программы включай только проверенные инструменты","plugins run trusted external programs; enable only tools you trust"));
            let ready=self.receiver.is_none();
            ui.horizontal(|ui|{
                if ui.add_enabled(ready,egui::Button::new(text("обновить","refresh"))).clicked(){self.start(|_|Ok(()));}
                if ui.add_enabled(ready,egui::Button::new(text("импорт json","import JSON"))).clicked(){if let Some(path)=rfd::FileDialog::new().add_filter("JSON",&["json"]).pick_file(){self.start(move|folder|import(folder,&path));}}
            });
            ui.weak(text("импортированные плагины отключены при включении проверяется sha256 исполняемого файла","imported plugins are disabled; enabling verifies the executable SHA-256"));
            if !self.message.is_empty(){ui.label(&self.message);}
            if !ready{ui.spinner();}
            let mut change=None;
            egui::ScrollArea::vertical().max_height(440.0).show(ui,|ui|{for entry in &self.entries{
                ui.group(|ui|{
                    ui.horizontal(|ui|{let mut enabled=entry.enabled;if ui.add_enabled(ready&&entry.error.is_none(),egui::Checkbox::new(&mut enabled,&entry.name)).changed(){change=Some((entry.clone(),enabled));}ui.weak(&entry.id);});
                    ui.small(entry.path.display().to_string());if let Some(error)=&entry.error{ui.label(error);}
                });
            }});
            if let Some((entry,enabled))=change{if enabled{self.confirm=Some(entry);}else{self.start(move|folder|toggle(folder,&entry,false));}}
        });
        self.open = open;
        if let Some(entry) = self.confirm.clone() {
            egui::Window::new(text("включить плагин","enable plugin")).collapsible(false).resizable(false).show(ctx,|ui|{
                ui.label(format!("{} ({})",entry.name,entry.id));
                ui.label(text("это доверенная внешняя программа sha256 будет проверен включение не запускает её","this is a trusted external program; SHA-256 will be checked; enabling does not run it"));
                ui.horizontal(|ui|{if ui.button(text("включить","enable")).clicked(){self.confirm=None;self.start(move|folder|toggle(folder,&entry,true));}
if ui.button(text("отмена","cancel")).clicked(){self.confirm=None;}});
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn folder() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "uie-plugin-manager-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }
    fn manifest(executable: &Path) -> Value {
        serde_json::json!({"id":"owned","name":"Owned fixture","enabled":true,"executable":executable,"sha256":"00".repeat(32),"extensions":["exe"],"args":["{input}","{output}"]})
    }
    #[test]
    fn imports_disabled_and_never_replaces_existing() {
        let dir = folder();
        let plugins = dir.join("plugins");
        let source = dir.join("incoming.json");
        fs::write(
            &source,
            serde_json::to_vec(&manifest(&dir.join("owned.exe"))).unwrap(),
        )
        .unwrap();
        import(&plugins, &source).unwrap();
        let values = entries(&plugins).unwrap();
        assert_eq!(values.len(), 1);
        assert!(!values[0].enabled);
        assert!(import(&plugins, &source).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn changed_manifest_and_bad_executable_cannot_be_enabled() {
        let dir = folder();
        let source = dir.join("incoming.json");
        let exe = dir.join("owned.exe");
        fs::write(&exe, b"MZ harmless fixture").unwrap();
        fs::write(&source, serde_json::to_vec(&manifest(&exe)).unwrap()).unwrap();
        let plugins = dir.join("plugins");
        import(&plugins, &source).unwrap();
        let entry = entries(&plugins).unwrap().remove(0);
        assert!(toggle(&plugins, &entry, true)
            .unwrap_err()
            .contains("SHA-256"));
        assert!(!entries(&plugins).unwrap()[0].enabled);
        fs::write(&entry.path, b"{}").unwrap();
        assert!(toggle(&plugins, &entry, false)
            .unwrap_err()
            .contains("changed"));
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn verifies_owned_magic_and_pin_without_execution() {
        let dir = folder();
        let source = dir.join("incoming.json");
        let exe = dir.join("owned.exe");
        let data = b"MZ owned static fixture only";
        fs::write(&exe, data).unwrap();
        let mut value = manifest(&exe);
        value["sha256"] = Value::String(hash(data));
        fs::write(&source, serde_json::to_vec(&value).unwrap()).unwrap();
        let plugins = dir.join("plugins");
        import(&plugins, &source).unwrap();
        let entry = entries(&plugins).unwrap().remove(0);
        toggle(&plugins, &entry, true).unwrap();
        let entry = entries(&plugins).unwrap().remove(0);
        assert!(entry.enabled);
        toggle(&plugins, &entry, false).unwrap();
        assert!(!entries(&plugins).unwrap()[0].enabled);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_destination_escape_and_oversized_manifest() {
        let dir = folder();
        let plugins = dir.join("plugins");
        fs::create_dir_all(&plugins).unwrap();
        assert!(publish(&plugins, &dir.join("outside.json"), b"{}", None).is_err());
        assert!(!dir.join("outside.json").exists());
        let source = dir.join("oversized.json");
        fs::write(&source, vec![b' '; MAX_BYTES as usize + 1]).unwrap();
        assert!(import(&plugins, &source).is_err());
        assert!(entries(&plugins).unwrap().is_empty());
        fs::remove_dir_all(dir).unwrap();
    }
}
