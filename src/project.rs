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
    #[serde(default)]
    pub dependency_sha256: BTreeMap<PathBuf, String>,
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

pub fn cached(
    hash: &str,
    all_modules: bool,
    input: &Path,
    lazy_native: bool,
) -> Result<Option<Project>, String> {
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
    if project.analysis.route == crate::detect::Route::Native {
        let report = fs::read(project.output.join("native-report.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
        if report
            .as_ref()
            .is_some_and(|report| report["lazy"].as_bool().unwrap_or(false) != lazy_native)
        {
            return Ok(None);
        }
        if lazy_native
            && !project.output.join("UIEProject.gpr").is_file()
            && !report
                .as_ref()
                .is_some_and(|value| value["native_input"].is_string())
        {
            return Ok(None);
        }
    }
    if project.input_sha256 != hash
        || project.all_modules != all_modules
        || project.source_sha256.is_empty()
    {
        return Ok(None);
    }
    if source_hashes(&project.output)? != project.source_sha256 {
        return Ok(None);
    }
    let triage_file = project.output.join("triage-report.json");
    if triage_file.is_file() {
        let triage: serde_json::Value =
            serde_json::from_slice(&fs::read(triage_file).map_err(|error| error.to_string())?)
                .map_err(|error| error.to_string())?;
        let plan = triage.get("discovery").unwrap_or(&triage);
        let count = plan["modules"].as_array().map_or(0, Vec::len);
        if plan["truncated"].as_bool() == Some(true) || count != project.dependency_sha256.len() {
            return Ok(None);
        }
    } else if project.analysis.route == crate::detect::Route::Native
        && project
            .source_sha256
            .keys()
            .any(|path| path.starts_with("source/modules"))
    {
        return Ok(None);
    }
    if !dependencies_match(input, &project.dependency_sha256)? {
        return Ok(None);
    }
    Ok(Some(project))
}

pub fn save(
    hash: &str,
    output: &Path,
    all_modules: bool,
    analysis: &Analysis,
    input: &Path,
    dependencies: &BTreeMap<PathBuf, String>,
) -> Result<(), String> {
    if sha256(input)? != hash || !dependencies_match(input, dependencies)? {
        return Err("input files changed during analysis; cache was not saved".into());
    }
    let mut project = capture(hash, output, all_modules, analysis)?;
    project.dependency_sha256 = dependencies.clone();
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
    let source_sha256 = source_hashes(output)?;
    let project = Project {
        input_sha256: hash.into(),
        output: output.to_path_buf(),
        all_modules,
        analysis: analysis.clone(),
        source_sha256,
        dependency_sha256: BTreeMap::new(),
        verification:
            "автоматическая обработка завершена; подробности проверки — в отчётах проекта".into(),
    };
    Ok(project)
}

fn dependency_path(input: &Path, relative: &Path) -> Result<PathBuf, String> {
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("unsafe module dependency path".into());
    }
    let root = input
        .parent()
        .ok_or("input has no parent directory")?
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let path = root
        .join(relative)
        .canonicalize()
        .map_err(|error| format!("dependency {}: {error}", relative.display()))?;
    if !path.starts_with(&root) {
        return Err("module dependency escapes input directory".into());
    }
    Ok(path)
}
pub(crate) fn dependencies_match(
    input: &Path,
    dependencies: &BTreeMap<PathBuf, String>,
) -> Result<bool, String> {
    for (relative, expected) in dependencies {
        if sha256(&dependency_path(input, relative)?)? != *expected {
            return Ok(false);
        }
    }
    Ok(true)
}
pub(crate) fn dependency_snapshot(
    input: &Path,
    modules: &[crate::triage::Module],
) -> Result<BTreeMap<PathBuf, String>, String> {
    modules
        .iter()
        .map(|module| {
            Ok((
                module.relative.clone(),
                sha256(&dependency_path(input, &module.relative)?)?,
            ))
        })
        .collect()
}

pub(crate) fn source_hashes(output: &Path) -> Result<BTreeMap<PathBuf, String>, String> {
    let mut hashes = BTreeMap::new();
    for entry in fs::read_dir(output).map_err(|error| format!("{}: {error}", output.display()))? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path.extension().is_some_and(|ext| ext == "c")
            && path.file_stem().is_some_and(|stem| {
                stem == "decompiled" || stem.to_string_lossy().ends_with("_decompiled")
            })
        {
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if !kind.is_file() {
                return Err(format!("source is not a regular file: {}", path.display()));
            }
            hashes.insert(path.file_name().unwrap().into(), sha256(&path)?);
        }
    }
    let source = output.join("source");
    let mut folders = vec![];
    match fs::symlink_metadata(&source) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => folders.push(source),
        Ok(_) => {
            return Err(format!(
                "source is not a regular directory: {}",
                source.display()
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(format!("{}: {error}", source.display())),
    }
    while let Some(folder) = folders.pop() {
        for entry in
            fs::read_dir(&folder).map_err(|error| format!("{}: {error}", folder.display()))?
        {
            let entry = entry.map_err(|error| format!("{}: {error}", folder.display()))?;
            let kind = entry.file_type().map_err(|error| error.to_string())?;
            if kind.is_symlink() {
                return Err(format!(
                    "source link cannot be integrity-checked: {}",
                    entry.path().display()
                ));
            }
            if kind.is_dir() {
                folders.push(entry.path());
            } else if kind.is_file() {
                if hashes.len() >= 100_000 {
                    return Err("project file limit reached".into());
                }
                let path = entry.path();
                if crate::telemetry::is_base(&path) {
                    return Err(format!(
                        "move project databases outside the source tree before saving: {}",
                        path.display()
                    ));
                }
                hashes.insert(
                    path.strip_prefix(output)
                        .map_err(|error| error.to_string())?
                        .into(),
                    sha256(&path)?,
                );
            } else {
                return Err(format!(
                    "unsupported source entry: {}",
                    entry.path().display()
                ));
            }
        }
    }
    if hashes.is_empty() {
        return Err("project has no source files to integrity-check".into());
    }
    Ok(hashes)
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
    for relative in project.source_sha256.keys() {
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err("unsafe source path in project".into());
        }
    }
    if source_hashes(&project.output)? != project.source_sha256 {
        project.verification =
            "project files changed; equivalence after editing is unverified".into();
    }
    Ok(project)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unchanged_launcher_does_not_validate_a_changed_module() {
        let root = env::temp_dir().join(format!("uie-module-change-{}", std::process::id()));
        fs::create_dir_all(root.join("app")).unwrap();
        let input = root.join("launcher.exe");
        fs::write(&input, "owned fixture launcher").unwrap();
        fs::write(root.join("app/core.pyd"), "version one").unwrap();
        let modules = vec![crate::triage::Module {
            path: root.join("app/core.pyd"),
            relative: "app/core.pyd".into(),
            bytes: 11,
            route: "ghidra".into(),
        }];
        let launcher_hash = sha256(&input).unwrap();
        let snapshot = dependency_snapshot(&input, &modules).unwrap();
        assert!(dependencies_match(&input, &snapshot).unwrap());
        fs::write(root.join("app/core.pyd"), "version two").unwrap();
        assert_eq!(sha256(&input).unwrap(), launcher_hash);
        assert!(!dependencies_match(&input, &snapshot).unwrap());
        assert!(dependency_path(&input, Path::new("../outside.pyd")).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn a_source_directory_read_error_is_not_an_empty_success() {
        let root = env::temp_dir().join(format!("uie-invalid-source-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("sample_decompiled.c"), "void f(void) {}\n").unwrap();
        fs::write(root.join("source"), "not a directory").unwrap();
        assert!(source_hashes(&root)
            .unwrap_err()
            .contains("not a regular directory"));
        let analysis = crate::detect::inspect(b"fixture").unwrap();
        assert!(capture("fixture", &root, false, &analysis).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn nested_and_added_files_are_hashed_and_database_export_does_not_hide_changes() {
        let root = env::temp_dir().join(format!("uie-all-source-{}", std::process::id()));
        fs::create_dir_all(root.join("source/nested")).unwrap();
        fs::write(root.join("source/main.py"), "answer=42\n").unwrap();
        fs::write(root.join("source/nested/helper.py"), "value=1\n").unwrap();
        let analysis = crate::detect::inspect(b"fixture").unwrap();
        let project = capture("fixture", &root, false, &analysis).unwrap();
        assert_eq!(project.source_sha256.len(), 2);
        let manifest = root.join("project.json");
        fs::write(&manifest, serde_json::to_vec(&project).unwrap()).unwrap();
        fs::write(root.join("source/added.py"), "extra=3\n").unwrap();
        assert!(open(&manifest).unwrap().verification.contains("unverified"));
        let base = root.join("saved.uie");
        crate::database::export(&base, &project).unwrap();
        let mut zip = zip::ZipArchive::new(fs::File::open(base).unwrap()).unwrap();
        assert!(zip.by_name("source/nested/helper.py").is_ok());
        assert!(zip.by_name("source/added.py").is_ok());
        drop(zip);
        fs::write(root.join("source/wrong-place.uie"), "fixture").unwrap();
        assert!(crate::database::export(&root.join("bad.uie"), &project).is_err());
        assert!(!root.join("bad.uie").exists());
        fs::remove_dir_all(root).unwrap();
    }
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
