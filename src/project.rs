use crate::detect::Analysis;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env,
    fs::{self, File},
    io::Read,
    path::{Component, Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
pub struct Project {
    pub input_sha256: String,
    pub output: PathBuf,
    pub all_modules: bool,
    pub analysis: Analysis,
    pub source_sha256: BTreeMap<PathBuf, String>,
    pub verification: String,
}

pub fn app_root() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn sha256(path: &Path) -> Result<String, String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub fn cached(hash: &str, all_modules: bool) -> Result<Option<Project>, String> {
    let primary = app_root().join("projects").join(format!("{hash}.uie"));
    let path = if primary.is_file() {
        primary
    } else {
        app_root().join("projects").join(format!("{hash}.toker"))
    };
    if !path.is_file() {
        return Ok(None);
    }
    let project = open(&path)?;
    if project.input_sha256 != hash
        || project.all_modules != all_modules
        || project.source_sha256.is_empty()
    {
        return Ok(None);
    }
    for (relative, expected) in &project.source_sha256 {
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("небезопасный путь в проекте".into());
        }
        if sha256(&project.output.join(relative)).as_deref() != Ok(expected.as_str()) {
            return Ok(None);
        }
    }
    Ok(Some(project))
}

pub fn save(
    hash: &str,
    output: &Path,
    all_modules: bool,
    analysis: &Analysis,
) -> Result<(), String> {
    let project = capture(hash, output, all_modules, analysis)?;
    let folder = app_root().join("projects");
    fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
    crate::database::export(&folder.join(format!("{hash}.uie")), &project)
}

pub fn capture(
    hash: &str,
    output: &Path,
    all_modules: bool,
    analysis: &Analysis,
) -> Result<Project, String> {
    let mut source_sha256 = BTreeMap::new();
    let mut folders = vec![output.join("source")];
    if let Some(native) = native_source(output) {
        source_sha256.insert(native.file_name().unwrap().into(), sha256(&native)?);
    }
    while let Some(folder) = folders.pop() {
        if let Ok(entries) = fs::read_dir(folder) {
            for entry in entries {
                let entry = entry.map_err(|e| e.to_string())?;
                let kind = entry.file_type().map_err(|e| e.to_string())?;
                if kind.is_dir() {
                    folders.push(entry.path());
                } else if kind.is_file() {
                    source_sha256.insert(
                        entry
                            .path()
                            .strip_prefix(output)
                            .map_err(|e| e.to_string())?
                            .to_path_buf(),
                        sha256(&entry.path())?,
                    );
                }
            }
        }
    }
    let project = Project {
        input_sha256: hash.into(),
        output: output.to_path_buf(),
        all_modules,
        analysis: analysis.clone(),
        source_sha256,
        verification:
            "автоматическая обработка завершена; подробности проверки — в отчётах проекта".into(),
    };
    Ok(project)
}

pub fn native_source(output: &Path) -> Option<PathBuf> {
    fs::read_dir(output)
        .ok()?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.is_file()
                && p.extension().is_some_and(|e| e == "c")
                && p.file_stem().is_some_and(|s| {
                    s == "decompiled" || s.to_string_lossy().ends_with("_decompiled")
                })
        })
}

pub fn open(path: &Path) -> Result<Project, String> {
    let mut project: Project = if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("uie"))
    {
        crate::database::unpack(path)?
    } else {
        serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?
    };
    if project.output.is_relative() {
        project.output = app_root().join(&project.output);
    }
    if project.source_sha256.is_empty() {
        return Err("проект не содержит исходников".into());
    }
    for (relative, expected) in &project.source_sha256 {
        if relative.is_absolute()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("небезопасный путь в проекте".into());
        }
        if sha256(&project.output.join(relative))? != *expected {
            project.verification =
                "изменённый проект: эквивалентность после редактирования не проверена".into();
        }
    }
    Ok(project)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_matches_known_digest() {
        let file = env::temp_dir().join(format!("toker_digest_{}.tmp", std::process::id()));
        fs::write(&file, b"abc").unwrap();
        assert_eq!(
            sha256(&file).unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        fs::remove_file(file).unwrap();
    }
}
