use crate::detect::{inspect_file, Analysis, Route};
use serde::Serialize;
use std::{
    collections::HashSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_SCAN_BYTES: u64 = 16 * 1024 * 1024;
const MAX_MODULE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_MODULES: usize = 64;
const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 4;

#[derive(Clone, Serialize)]
pub struct Module {
    pub path: PathBuf,
    pub relative: PathBuf,
    pub bytes: u64,
    pub route: String,
}

#[derive(Default, Serialize)]
pub struct Plan {
    pub triggers: Vec<String>,
    pub modules: Vec<Module>,
    pub skipped: Vec<String>,
    pub truncated: bool,
}

fn contains(bytes: &[u8], text: &str) -> bool {
    memchr::memmem::find(bytes, text.as_bytes()).is_some()
        || memchr::memmem::find(
            bytes,
            &text
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        )
        .is_some()
}

fn standard_runtime(name: &str) -> bool {
    [
        "kernel32.dll",
        "user32.dll",
        "ntdll.dll",
        "advapi32.dll",
        "gdi32.dll",
        "shell32.dll",
        "ole32.dll",
        "ucrtbase.dll",
        "msvcrt.dll",
    ]
    .contains(&name)
        || name.starts_with("api-ms-")
        || name.starts_with("ext-ms-")
        || name.starts_with("vcruntime")
        || name.starts_with("msvcp")
        || (name.starts_with("python")
            && name.ends_with(".dll")
            && name[6..name.len() - 4].chars().all(|c| c.is_ascii_digit()))
}

pub fn discover(input: &Path, analysis: &Analysis) -> Result<Plan, String> {
    let own_executable = std::env::current_exe()
        .ok()
        .and_then(|path| path.canonicalize().ok());
    let analyzing_self = input
        .canonicalize()
        .ok()
        .zip(own_executable)
        .is_some_and(|(input, own)| input == own);
    discover_with_self(input, analysis, analyzing_self)
}

fn discover_with_self(
    input: &Path,
    analysis: &Analysis,
    analyzing_self: bool,
) -> Result<Plan, String> {
    let mut plan = Plan::default();
    if analysis.route != Route::Native {
        return Ok(plan);
    }
    let root = input.parent().ok_or("нет каталога образца")?;
    let mut bytes = vec![];
    fs::File::open(input)
        .map_err(|e| e.to_string())?
        .take(MAX_SCAN_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    bytes.make_ascii_lowercase();
    for marker in ["runtime\\", "runtime/", "app\\", "app/", ".pyd", "nuitka"] {
        if contains(&bytes, marker) {
            plan.triggers.push(format!("строка/путь: {marker}"));
        }
    }
    let thin = input.metadata().map_err(|e| e.to_string())?.len() < 2 * 1024 * 1024
        && [
            "createprocessw",
            "createprocessa",
            "shellexecutew",
            "shellexecutea",
            "winexec",
        ]
        .iter()
        .any(|marker| contains(&bytes, marker));
    if thin {
        plan.triggers
            .push("тонкий PE с API запуска процессов".into());
    }
    if plan.triggers.is_empty() {
        return Ok(plan);
    }
    let stem = input
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    let directories = [
        "runtime".to_string(),
        "app".into(),
        "modules".into(),
        "lib".into(),
        "libs".into(),
        stem.clone(),
        format!("{stem}.dist"),
    ];
    let application_modules = fs::read_dir(root.join("app")).is_ok_and(|entries| {
        entries.filter_map(Result::ok).any(|e| {
            e.path()
                .extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("pyd"))
        })
    });
    let cargo_layout = contains(&bytes, "rust_eh_personality")
        && root.join(".fingerprint").is_dir()
        && root.join("deps").is_dir();
    let mut queue = vec![(root.to_path_buf(), 0usize)];
    let mut visited = HashSet::new();
    let mut entries = 0;
    let mut total = 0;
    while let Some((directory, depth)) = queue.pop() {
        if !visited.insert(directory.clone()) {
            continue;
        }
        let children_iter = match fs::read_dir(&directory) {
            Ok(found) => found,
            Err(error) => {
                plan.skipped
                    .push(format!("{}: {error}", directory.display()));
                continue;
            }
        };
        let mut children: Vec<_> = children_iter.filter_map(Result::ok).collect();
        children.sort_by_key(|entry| entry.file_name());
        for entry in children {
            entries += 1;
            if entries > MAX_ENTRIES || plan.modules.len() >= MAX_MODULES {
                plan.truncated = true;
                return Ok(plan);
            }
            let kind = match entry.file_type() {
                Ok(kind) => kind,
                Err(_) => continue,
            };
            if kind.is_symlink() {
                plan.skipped
                    .push(format!("{}: ссылка не обходится", entry.path().display()));
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if kind.is_dir() {
                if depth == 0
                    && analyzing_self
                    && ["engines", "results", "projects"].contains(&name.as_str())
                {
                    plan.skipped.push(format!(
                        "{name}: analyzer tools and output are not target application modules"
                    ));
                    continue;
                }
                if depth == 0
                    && cargo_layout
                    && ["deps", "build", "incremental"].contains(&name.as_str())
                {
                    plan.skipped.push(format!(
                        "{name}: Cargo build artifacts excluded from application triage"
                    ));
                    continue;
                }
                if depth == 0 && name == "runtime" && application_modules {
                    plan.skipped.push("runtime: dependency tree excluded because app contains native user modules".into());
                    continue;
                }
                if ["assets", "models", "__pycache__"].contains(&name.as_str()) {
                    continue;
                }

                if depth < MAX_DEPTH
                    && !name.starts_with('.')
                    && (depth > 0
                        || directories.contains(&name)
                        || contains(&bytes, &format!("{name}\\"))
                        || contains(&bytes, &format!("{name}/")))
                {
                    queue.push((entry.path(), depth + 1));
                }
                continue;
            }
            if !kind.is_file() || entry.path() == input {
                continue;
            }
            let path = entry.path();
            let extension = path
                .extension()
                .unwrap_or_default()
                .to_string_lossy()
                .to_ascii_lowercase();
            if !["pyd", "dll", "py", "pyc"].contains(&extension.as_str()) {
                continue;
            }
            if standard_runtime(&name) {
                plan.skipped.push(format!("{name}: стандартный runtime"));
                continue;
            }
            let related = depth > 0
                || extension == "pyd"
                || name.starts_with(&stem)
                || contains(&bytes, &name);
            if !related {
                continue;
            }
            let size = match entry.metadata() {
                Ok(metadata) => metadata.len(),
                Err(error) => {
                    plan.skipped.push(format!("{name}: {error}"));
                    continue;
                }
            };
            if size == 0 || size > MAX_MODULE_BYTES || total + size > MAX_TOTAL_BYTES {
                plan.skipped.push(format!("{name}: лимит размера"));
                plan.truncated = true;
                continue;
            }
            let route = if extension == "py" {
                "source".into()
            } else {
                match inspect_file(&path) {
                    Ok(found) => match found.route {
                        Route::Native => "ghidra",
                        Route::DotNet => "ilspy",
                        Route::PythonArchive | Route::PythonBytecode => "pylingual",
                        Route::Asar => "asar",
                        Route::Java => "cfr",
                        Route::Android => "jadx",
                        Route::Unknown => "unknown",
                    }
                    .to_string(),
                    Err(error) => {
                        plan.skipped.push(format!("{name}: {error}"));
                        continue;
                    }
                }
            };
            if route == "unknown" {
                plan.skipped.push(format!("{name}: формат не распознан"));
                continue;
            }
            total += size;
            plan.modules.push(Module {
                relative: path
                    .strip_prefix(root)
                    .map_err(|e| e.to_string())?
                    .to_path_buf(),
                path,
                bytes: size,
                route,
            });
        }
    }
    plan.modules.sort_by(|a, b| a.relative.cmp(&b.relative));
    plan.modules.sort_by_key(|module| {
        let path = module.relative.to_string_lossy().to_ascii_lowercase();
        (
            if path.starts_with("app") && path.ends_with(".pyd") {
                0
            } else if path.ends_with(".pyd") {
                1
            } else if path.ends_with(".py") {
                2
            } else {
                3
            },
            path,
        )
    });
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn self_analysis_does_not_decompile_its_own_engines() {
        let root = std::env::temp_dir().join(format!("uie-own-engines-{}", std::process::id()));
        fs::create_dir_all(root.join("engines")).unwrap();
        fs::create_dir_all(root.join("app")).unwrap();
        let mut binary = vec![0u8; 64];
        binary[..6].copy_from_slice(b"\x7fELF\x02\x01");
        binary[18..20].copy_from_slice(&62u16.to_le_bytes());
        fs::write(root.join("engines/helper.dll"), &binary).unwrap();
        fs::write(root.join("app/actual.pyd"), &binary).unwrap();
        binary.extend_from_slice(b"engines/ app/ .pyd");
        let input = root.join("sample.exe");
        fs::write(&input, &binary).unwrap();
        let analysis = inspect_file(&input).unwrap();
        let plan = discover_with_self(&input, &analysis, true).unwrap();
        assert_eq!(plan.modules.len(), 1);
        assert!(plan.modules[0].relative.starts_with("app"));
        let plan = discover_with_self(&input, &analysis, false).unwrap();
        assert_eq!(plan.modules.len(), 2);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn rust_build_artifacts_do_not_replace_actual_application_modules() {
        let root = std::env::temp_dir().join(format!("uie-cargo-triage-{}", std::process::id()));
        for folder in ["deps", ".fingerprint", "app"] {
            fs::create_dir_all(root.join(folder)).unwrap();
        }
        let mut binary = vec![0u8; 64];
        binary[..6].copy_from_slice(b"\x7fELF\x02\x01");
        binary[18..20].copy_from_slice(&62u16.to_le_bytes());
        fs::write(root.join("deps/compiler_plugin.dll"), &binary).unwrap();
        fs::write(root.join("app/real.pyd"), &binary).unwrap();
        binary.extend_from_slice(b"rust_eh_personality deps/ app/ .pyd");
        let input = root.join("UIE.exe");
        fs::write(&input, &binary).unwrap();
        let analysis = inspect_file(&input).unwrap();
        let plan = discover(&input, &analysis).unwrap();
        assert_eq!(plan.modules.len(), 1);
        assert_eq!(plan.modules[0].relative, Path::new("app/real.pyd"));
        assert!(plan
            .skipped
            .iter()
            .any(|reason| reason.contains("Cargo build artifacts")));
        fs::remove_dir_all(root.join(".fingerprint")).unwrap();
        let plan = discover(&input, &analysis).unwrap();
        assert!(plan
            .modules
            .iter()
            .any(|module| module.relative.starts_with("deps")));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn hybrid_app_modules_take_priority_over_runtime_tree() {
        let root = std::env::temp_dir().join(format!("uie-hybrid-{}", std::process::id()));
        fs::create_dir_all(root.join("app/core")).unwrap();
        fs::create_dir_all(root.join("runtime")).unwrap();
        let mut elf = vec![0u8; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        fs::write(root.join("app/main.pyd"), &elf).unwrap();
        fs::write(root.join("app/core/worker.pyd"), &elf).unwrap();
        fs::write(root.join("runtime/tcl.dll"), &elf).unwrap();
        elf.extend_from_slice(b"runtime\\ app\\");
        let input = root.join("launcher.exe");
        fs::write(&input, &elf).unwrap();
        let plan = discover(&input, &inspect_file(&input).unwrap()).unwrap();
        assert_eq!(plan.modules.len(), 2);
        assert!(plan.modules.iter().all(|m| m.relative.starts_with("app")));
        assert!(plan.skipped.iter().any(|s| s.starts_with("runtime:")));
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn path_markers_and_runtime_filter() {
        let wide: Vec<_> = "runtime\\core.pyd"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(contains(&wide, "runtime\\"));
        assert!(standard_runtime("python314.dll"));
        assert!(standard_runtime("vcruntime140.dll"));
        assert!(!standard_runtime("app_native.dll"));
    }
}
