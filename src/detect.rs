use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::Path};

pub const MAX_INPUT_BYTES: u64 = 1024 * 1024 * 1024;
const PYINSTALLER_MAGIC: &[u8] = b"MEI\x0c\x0b\x0a\x0b\x0e";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Route {
    Android,
    Asar,
    Java,
    PythonArchive,
    PythonBytecode,
    DotNet,
    Native,
    Unknown,
}

impl Route {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Android => "Android APK / DEX → JADX → Java",
            Self::Asar => "electron ASAR → JavaScript / TypeScript",
            Self::Java => "Java → CFR",
            Self::PythonArchive => "pyinstaller → pyinstxtractor-ng → pylingual",
            Self::PythonBytecode => "python bytecode → pylingual",
            Self::DotNet => ".net → ilspycmd",
            Self::Native => "native → ghidra",
            Self::Unknown => "неизвестный формат — автоматический выбор недоступен",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Analysis {
    pub format: String,
    pub architecture: String,
    pub compiler_hints: Vec<String>,
    pub packer_hints: Vec<String>,
    pub python_version: Option<String>,
    pub route: Route,
    pub sections: Vec<String>,
    pub notes: Vec<String>,
    pub detect_it_easy: Option<serde_json::Value>,
}

fn read16(data: &[u8], offset: usize, big: bool) -> Result<u16, String> {
    let bytes: [u8; 2] = data
        .get(offset..offset.checked_add(2).ok_or("offset overflow")?)
        .ok_or("truncated header")?
        .try_into()
        .unwrap();
    Ok(if big {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    })
}

fn read32(data: &[u8], offset: usize, big: bool) -> Result<u32, String> {
    let bytes: [u8; 4] = data
        .get(offset..offset.checked_add(4).ok_or("offset overflow")?)
        .ok_or("truncated header")?
        .try_into()
        .unwrap();
    Ok(if big {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    })
}

pub fn inspect_file(path: &Path) -> Result<Analysis, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    if size == 0 || size > MAX_INPUT_BYTES {
        return Err(format!(
            "размер файла должен быть 1..{MAX_INPUT_BYTES} байт"
        ));
    }
    let mut data = Vec::with_capacity(size as usize);
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_INPUT_BYTES {
        return Err("файл вырос во время чтения".into());
    }
    let mut analysis = inspect(&data)?;
    let extension = path
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    if extension == "asar" && data.get(..4) == Some(&4u32.to_le_bytes()) {
        analysis.route = Route::Asar;
        analysis.format = "ASAR".into();
        analysis.architecture = "JavaScript".into();
    }
    if (extension == "jar" && data.starts_with(b"PK\x03\x04"))
        || (extension == "class" && data.starts_with(b"\xca\xfe\xba\xbe"))
    {
        analysis.route = Route::Java;
        analysis.format = "Java archive / class".into();
        analysis.architecture = "JVM".into();
    }
    // Contents take precedence over extensions, including renamed APKs.
    if data.starts_with(b"PK\x03\x04") {
        if let Ok(mut archive) = zip::ZipArchive::new(std::io::Cursor::new(&data)) {
            if archive.by_name("AndroidManifest.xml").is_ok() {
                analysis.route = Route::Android;
                analysis.format = "Android APK".into();
                analysis.architecture = "Dalvik / ART".into();
                analysis.notes.push("apk содержит bytecode и ресурсы; нативные JNI библиотеки требуют отдельного анализа".into());
            }
        }
    }
    Ok(analysis)
}

pub fn inspect(data: &[u8]) -> Result<Analysis, String> {
    let mut result = Analysis {
        format: "unknown".into(),
        architecture: "unknown".into(),
        compiler_hints: vec![],
        packer_hints: vec![],
        python_version: None,
        route: Route::Unknown,
        sections: vec![],
        notes: vec![],
        detect_it_easy: None,
    };
    if data.starts_with(b"MZ") {
        let pe = read32(data, 0x3c, false)? as usize;
        if data.get(pe..pe + 4) != Some(b"PE\0\0") {
            return Err("неверная PE-сигнатура".into());
        }
        let machine = read16(data, pe + 4, false)?;
        let count = read16(data, pe + 6, false)? as usize;
        let optional_len = read16(data, pe + 20, false)? as usize;
        let optional = pe + 24;
        let end = optional + optional_len;
        if end > data.len() || optional_len < 2 {
            return Err("обрезанный PE optional header".into());
        }
        let magic = read16(data, optional, false)?;
        let (directory, directory_count) = match magic {
            0x10b => (96, 92),
            0x20b => (112, 108),
            _ => return Err("неизвестный PE optional header".into()),
        };
        if optional_len < directory {
            return Err("обрезанный PE optional header".into());
        }
        result.format = "PE".into();
        result.architecture = match machine {
            0x14c => "x86".into(),
            0x8664 => "x64".into(),
            0xaa64 => "ARM64".into(),
            0x1c4 => "ARM".into(),
            _ => format!("machine 0x{machine:04x}"),
        };
        result.route = Route::Native;
        if optional_len >= directory + 15 * 8
            && read32(data, optional + directory_count, false)? > 14
        {
            let clr = optional + directory + 14 * 8;
            if read32(data, clr, false)? != 0 && read32(data, clr + 4, false)? >= 0x48 {
                result.route = Route::DotNet;
                result.notes.push(
                    "есть CLR data directory; исходный язык .net по нему не определяется".into(),
                );
            }
        }
        for index in 0..count {
            let section = end + index * 40;
            let bytes = data
                .get(section..section + 40)
                .ok_or("обрезанная PE section table")?;
            let name = String::from_utf8_lossy(&bytes[..8])
                .trim_end_matches('\0')
                .to_string();
            if name.to_ascii_uppercase().starts_with("UPX") {
                result
                    .packer_hints
                    .push("UPX: имя секции, эвристика".into());
            }
            if read32(bytes, 8, false)? > 0
                && read32(bytes, 16, false)? == 0
                && read32(bytes, 36, false)? & 0x20000000 != 0
            {
                result.notes.push(format!("исполняемая секция {name}: байты отсутствуют в файле; восстановление кода требует распаковки"));
            }
            result.sections.push(name);
        }
    } else if data.starts_with(b"\x7fELF") {
        if !matches!(data.get(4), Some(1 | 2)) || !matches!(data.get(5), Some(1 | 2)) {
            return Err("неверный ELF identification".into());
        }
        let minimum = if data[4] == 2 { 64 } else { 52 };
        if data.len() < minimum {
            return Err("обрезанный ELF header".into());
        }
        let machine = read16(data, 18, data[5] == 2)?;
        result.format = "ELF".into();
        result.architecture = match machine {
            3 => "x86".into(),
            62 => "x64".into(),
            40 => "ARM".into(),
            183 => "ARM64".into(),
            243 => "RISC-V".into(),
            _ => format!("machine {machine}"),
        };
        result.route = Route::Native;
    } else if data.len() >= 4
        && [
            b"\xfe\xed\xfa\xce".as_slice(),
            b"\xce\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
            b"\xcf\xfa\xed\xfe",
        ]
        .contains(&&data[..4])
    {
        let cpu = read32(data, 4, data[0] == 0xfe)?;
        let minimum = if cpu & 0x1000000 != 0 { 32 } else { 28 };
        if data.len() < minimum {
            return Err("обрезанный Mach-O header".into());
        }
        result.format = "Mach-O".into();
        result.architecture = match cpu {
            7 => "x86".into(),
            0x1000007 => "x64".into(),
            12 => "ARM".into(),
            0x100000c => "ARM64".into(),
            _ => format!("cpu {cpu}"),
        };
        result.route = Route::Native;
    } else if data.len() >= 112
        && data.starts_with(b"dex\n")
        && data[4..7].iter().all(u8::is_ascii_digit)
        && data[7] == 0
    {
        result.format = "Android DEX".into();
        result.architecture = "Dalvik / ART".into();
        result.route = Route::Android;
    } else if data.len() >= 16
        && data.get(2..4) == Some(b"\r\n")
        && matches!(read16(data, 0, false)?, 3370..=3999)
    {
        result.format = "CPython .pyc (magic heuristic)".into();
        result.architecture = "python bytecode".into();
        result.route = Route::PythonBytecode;
    }
    for (signature, label) in [
        (
            b"__pyx_".as_slice(),
            "cython: generated extension marker (heuristic)",
        ),
        (b"Nuitka".as_slice(), "nuitka: runtime marker (heuristic)"),
        (
            b"rust_eh_personality".as_slice(),
            "rust: rust_eh_personality",
        ),
        (b"/rustc/", "rust: build path"),
        (b"Go build ID:", "go: build id"),
        (b"runtime.goexit", "go: runtime symbol"),
        (b"clang version", "clang/llvm: version string"),
        (b"GCC:", "gcc: version string"),
        (b"__mingw", "mingw/gcc: runtime string"),
        (b"Borland", "borland/delphi: vendor string"),
        (b"Embarcadero", "delphi/c++builder: vendor string"),
        (
            b"VCRUNTIME",
            "msvc-compatible runtime; does not prove compiler",
        ),
        (
            b"MSVCP",
            "msvc-compatible c++ runtime; does not prove compiler",
        ),
    ] {
        if memchr::memmem::find(data, signature).is_some() {
            result.compiler_hints.push(label.into());
        }
    }
    if let Some(position) = memchr::memmem::rfind(data, PYINSTALLER_MAGIC) {
        // Validate cookie bounds rather than confusing a bootloader string with an archive.
        if let Some(tail) = data.get(position + 24..position.saturating_add(88)) {
            let cookie_len =
                if memchr::memmem::find(&tail.to_ascii_lowercase(), b"python").is_some() {
                    88
                } else {
                    24
                };
            apply_cookie(data, position, cookie_len, &mut result);
        } else {
            apply_cookie(data, position, 24, &mut result);
        }
    }
    if result.route == Route::Native
        && result
            .compiler_hints
            .iter()
            .any(|hint| hint.contains("nuitka:"))
    {
        result.notes.push("Nuitka compiles Python into native machine code. This output is C pseudocode, not recovered Python source. Original comments, names and some language structures are lost; lossless Python recovery is not supported. A marker alone does not identify the Commercial edition.".into());
    }
    if result.compiler_hints.is_empty() {
        result
            .compiler_hints
            .push("не определён по встроенным сигнатурам".into());
    }
    result.notes.push("строковые признаки компилятора — эвристика, не доказательство; исходный код может восстановиться частично".into());
    if !result.packer_hints.is_empty() && result.route != Route::PythonArchive {
        result.notes.push(
            "упакованный native-код может требовать отдельной распаковки перед ghidra".into(),
        );
    }
    Ok(result)
}

fn apply_cookie(data: &[u8], position: usize, cookie_len: usize, result: &mut Analysis) {
    let values = (
        read32(data, position + 8, true),
        read32(data, position + 12, true),
        read32(data, position + 16, true),
        read32(data, position + 20, true),
    );
    if let (Ok(package), Ok(toc), Ok(length), Ok(version)) = values {
        let end = position + cookie_len;
        if end > data.len() || (package as usize) > end || (package as usize) < cookie_len {
            return;
        }
        if u64::from(toc) + u64::from(length) > u64::from(package) - cookie_len as u64 {
            return;
        }
        let (major, minor) = if version >= 100 {
            (version / 100, version % 100)
        } else {
            (version / 10, version % 10)
        };
        if !(2..=3).contains(&major) || minor > 99 || length == 0 {
            return;
        }
        result.route = Route::PythonArchive;
        result.python_version = Some(format!("{major}.{minor}"));
        result
            .packer_hints
            .push("pyinstaller: CArchive cookie и границы архива".into());
        result.notes.push(
            "python — содержимое архива; компилятор PE может относиться только к загрузчику".into(),
        );
    }
}

pub fn die_summary(value: &serde_json::Value) -> Vec<String> {
    fn visit(v: &serde_json::Value, rows: &mut Vec<String>) {
        if let Some(items) = v.as_array() {
            for item in items {
                visit(item, rows);
            }
        }
        if let Some(object) = v.as_object() {
            if let Some(name) = object.get("name").and_then(serde_json::Value::as_str) {
                let kind = object
                    .get("type")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("signature");
                let version = object
                    .get("version")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let info = object
                    .get("info")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                let line = format!("{kind}: {name} {version} {info}");
                if !rows.contains(&line) {
                    rows.push(line);
                }
            }
            for child in object.values() {
                if child.is_object() || child.is_array() {
                    visit(child, rows);
                }
            }
        }
    }
    let mut rows = vec![];
    visit(value, &mut rows);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn android_dex_and_renamed_apk_use_android_instead_of_java() {
        let mut dex = vec![0u8; 112];
        dex[..8].copy_from_slice(b"dex\n035\0");
        assert_eq!(inspect(&dex).unwrap().route, Route::Android);
        assert_eq!(inspect(&dex[..16]).unwrap().route, Route::Unknown);
        let path = std::env::temp_dir().join(format!("uie-renamed-apk-{}.jar", std::process::id()));
        let mut archive = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
        use std::io::Write;
        archive
            .start_file(
                "AndroidManifest.xml",
                zip::write::SimpleFileOptions::default(),
            )
            .unwrap();
        archive.write_all(b"owned identification fixture").unwrap();
        archive
            .start_file("classes.dex", zip::write::SimpleFileOptions::default())
            .unwrap();
        archive.write_all(&dex).unwrap();
        archive.finish().unwrap();
        let analysis = inspect_file(&path).unwrap();
        assert_eq!(analysis.route, Route::Android);
        assert_eq!(analysis.format, "Android APK");
        std::fs::remove_file(path).unwrap();
    }

    fn pe(managed: bool, x64: bool) -> Vec<u8> {
        let mut data = vec![0; 512];
        data[..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&128u32.to_le_bytes());
        data[128..132].copy_from_slice(b"PE\0\0");
        data[132..134].copy_from_slice(&(if x64 { 0x8664u16 } else { 0x14c }).to_le_bytes());
        data[148..150].copy_from_slice(&(if x64 { 240u16 } else { 224 }).to_le_bytes());
        data[152..154].copy_from_slice(&(if x64 { 0x20bu16 } else { 0x10b }).to_le_bytes());
        if managed {
            let count = 152 + if x64 { 108 } else { 92 };
            data[count..count + 4].copy_from_slice(&16u32.to_le_bytes());
            let clr = 152 + if x64 { 112 } else { 96 } + 14 * 8;
            data[clr..clr + 4].copy_from_slice(&0x2000u32.to_le_bytes());
            data[clr + 4..clr + 8].copy_from_slice(&72u32.to_le_bytes());
        }
        data
    }

    #[test]
    fn pe_native_and_clr_both_widths() {
        for x64 in [false, true] {
            for managed in [false, true] {
                let result = inspect(&pe(managed, x64)).unwrap();
                assert_eq!(
                    result.route,
                    if managed {
                        Route::DotNet
                    } else {
                        Route::Native
                    }
                );
                assert_eq!(result.architecture, if x64 { "x64" } else { "x86" });
            }
        }
    }
    #[test]
    fn unbacked_executable_sections_are_reported_without_treating_bss_as_code() {
        let mut data = pe(false, true);
        data[134..136].copy_from_slice(&1u16.to_le_bytes());
        let section = 152 + 240;
        data[section..section + 5].copy_from_slice(b".text");
        data[section + 8..section + 12].copy_from_slice(&4096u32.to_le_bytes());
        data[section + 36..section + 40].copy_from_slice(&0x60000020u32.to_le_bytes());
        assert!(inspect(&data)
            .unwrap()
            .notes
            .iter()
            .any(|note| note.contains("байты отсутствуют")));
        data[section + 36..section + 40].copy_from_slice(&0xc0000080u32.to_le_bytes());
        assert!(!inspect(&data)
            .unwrap()
            .notes
            .iter()
            .any(|note| note.contains("байты отсутствуют")));
    }

    #[test]
    fn nuitka_is_native_not_python_bytecode() {
        let mut data = pe(false, true);
        data.extend_from_slice(b"Nuitka");
        let result = inspect(&data).unwrap();
        assert_eq!(result.route, Route::Native);
        assert!(result
            .notes
            .iter()
            .any(|note| note.contains("lossless Python recovery is not supported")));
    }

    #[test]
    fn malformed_headers_never_panic() {
        for fixture in [
            pe(true, true),
            b"MZ".to_vec(),
            b"\x7fELF\x02\x01".to_vec(),
            b"\xfe\xed\xfa\xcf".to_vec(),
        ] {
            for length in 0..fixture.len() {
                let _ = inspect(&fixture[..length]);
            }
        }
        let mut huge = pe(false, true);
        huge[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(inspect(&huge).is_err());
    }

    #[test]
    fn pyinstaller_cookie_overrides_bootloader() {
        let mut data = pe(false, true);
        data.extend_from_slice(&[0; 20]);
        data.extend_from_slice(PYINSTALLER_MAGIC);
        for value in [108u32, 0, 20, 312] {
            data.extend_from_slice(&value.to_be_bytes());
        }
        let mut library = [0; 64];
        library[..13].copy_from_slice(b"python312.dll");
        data.extend_from_slice(&library);
        let result = inspect(&data).unwrap();
        assert_eq!(result.route, Route::PythonArchive);
        assert_eq!(result.python_version.as_deref(), Some("3.12"));
        data.truncate(540);
        assert_ne!(inspect(&data).unwrap().route, Route::PythonArchive);
    }

    #[test]
    fn elf_macho_bytecode_and_unknown() {
        let mut elf = vec![0; 64];
        elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        assert_eq!(inspect(&elf).unwrap().architecture, "x64");
        let mut macho = vec![0; 32];
        macho[..4].copy_from_slice(b"\xcf\xfa\xed\xfe");
        macho[4..8].copy_from_slice(&0x100000cu32.to_le_bytes());
        assert_eq!(inspect(&macho).unwrap().architecture, "ARM64");
        let mut pyc = vec![0; 16];
        pyc[..4].copy_from_slice(b"\xa7\x0d\r\n");
        assert_eq!(inspect(&pyc).unwrap().route, Route::PythonBytecode);
        assert_eq!(inspect(b"plain text").unwrap().route, Route::Unknown);
    }
}
