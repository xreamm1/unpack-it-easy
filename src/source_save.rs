use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static SERIAL: AtomicU64 = AtomicU64::new(0);
pub struct Request {
    pub index: usize,
    pub path: PathBuf,
    pub text: String,
    pub baseline: String,
    pub recovered: bool,
    pub workspace: Option<PathBuf>,
    pub destination: Option<PathBuf>,
}
pub struct Saved {
    pub index: usize,
    pub original: PathBuf,
    pub path: PathBuf,
    pub baseline: String,
}
pub struct Batch {
    pub saved: Vec<Saved>,
    pub error: Option<String>,
}
fn write_one(request: Request) -> Result<Saved, String> {
    let original = request.path;
    let mut path = original.clone();
    if request.recovered {
        if let Some(root) = request.workspace {
            let root = root.canonicalize().map_err(|e| e.to_string())?;
            let mut directory = root.clone();
            for part in ["source", "recovered"] {
                directory.push(part);
                if !directory.exists() {
                    fs::create_dir(&directory).map_err(|e| e.to_string())?;
                }
                let meta = fs::symlink_metadata(&directory).map_err(|e| e.to_string())?;
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if meta.file_attributes() & 0x400 != 0 {
                        return Err("recovery directory is a reparse point".into());
                    }
                }
                if !meta.is_dir()
                    || meta.file_type().is_symlink()
                    || !directory
                        .canonicalize()
                        .map_err(|e| e.to_string())?
                        .starts_with(&root)
                {
                    return Err("unsafe recovery directory".into());
                }
            }
            let name = original
                .file_name()
                .unwrap_or(std::ffi::OsStr::new("recovered.txt"))
                .to_string_lossy();
            path = directory.join(format!(
                "{}_{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|e| e.to_string())?
                    .as_nanos(),
                name
            ));
        } else {
            path = request
                .destination
                .ok_or("choose a destination for recovered text")?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| e.to_string())?;
        if let Err(e) = file
            .write_all(request.text.as_bytes())
            .and_then(|()| file.sync_all())
        {
            drop(file);
            let _ = fs::remove_file(&path);
            return Err(e.to_string());
        }
    } else {
        let mut bytes = Vec::new();
        fs::File::open(&path)
            .map_err(|e| e.to_string())?
            .take(32 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() > 32 * 1024 * 1024 {
            return Err("source changed beyond save limit".into());
        }
        use sha2::{Digest, Sha256};
        if format!("{:x}", Sha256::digest(&bytes)) != request.baseline {
            return Err(format!("source changed outside editor: {}", path.display()));
        }
        let temporary = path.with_file_name(format!(
            ".uie-save-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| -> Result<(), String> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|e| e.to_string())?;
            file.write_all(request.text.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|e| e.to_string())?;
            drop(file);
            fs::rename(&temporary, &path).map_err(|e| e.to_string())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result?;
    }
    Ok(Saved {
        index: request.index,
        original,
        path,
        baseline: crate::editor_recovery::baseline(&request.text),
    })
}
pub fn write(requests: Vec<Request>) -> Batch {
    let mut batch = Batch {
        saved: Vec::new(),
        error: None,
    };
    for request in requests {
        match write_one(request) {
            Ok(saved) => batch.saved.push(saved),
            Err(error) => {
                batch.error = Some(error);
                break;
            }
        }
    }
    batch
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovered_copy_is_in_project_and_external_edit_is_preserved() {
        let root = std::env::temp_dir().join(format!("uie-source-save-{}", std::process::id()));
        fs::create_dir_all(root.join("source")).unwrap();
        let path = root.join("source/a.py");
        fs::write(&path, "old").unwrap();
        let batch = write(vec![Request {
            index: 0,
            path: path.clone(),
            text: "recovered".into(),
            baseline: crate::editor_recovery::baseline("old"),
            recovered: true,
            workspace: Some(root.clone()),
            destination: None,
        }]);
        assert!(batch.error.is_none());
        assert!(batch.saved[0]
            .path
            .starts_with(root.canonicalize().unwrap().join("source/recovered")));
        assert_eq!(fs::read_to_string(&path).unwrap(), "old");
        assert!(crate::project::source_hashes(&root)
            .unwrap()
            .keys()
            .any(|p| p.starts_with("source/recovered")));
        let batch = write(vec![Request {
            index: 0,
            path: path.clone(),
            text: "edit".into(),
            baseline: crate::editor_recovery::baseline("different"),
            recovered: false,
            workspace: None,
            destination: None,
        }]);
        assert!(batch.error.is_some());
        assert_eq!(fs::read_to_string(path).unwrap(), "old");
        fs::remove_dir_all(root).unwrap();
    }
}
