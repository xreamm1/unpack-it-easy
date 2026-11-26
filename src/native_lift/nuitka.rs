use super::{u32_at, Image};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap},
    sync::atomic::{AtomicBool, Ordering},
};

const MAX_SCAN: usize = 16 * 1024 * 1024;
const MAX_NAMES: usize = 8192;
const MAX_ENTRIES: usize = 1024;

#[derive(Serialize)]
pub(super) struct Entry {
    pub name: String,
    pub init_rva: u32,
    init_rva_hex: String,
    loader_rva: String,
    import_rva: Option<String>,
    layout: &'static str,
    flags: u32,
}
#[derive(Serialize)]
pub(super) struct Report {
    pub marker_found: bool,
    interpretation: &'static str,
    pub entries: Vec<Entry>,
    truncated: bool,
}
fn pointer(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}
fn name_valid(bytes: &[u8]) -> bool {
    (2..=256).contains(&bytes.len())
        && bytes.split(|byte| *byte == b'.').all(|part| {
            part.first()
                .is_some_and(|byte| *byte == b'_' || byte.is_ascii_alphabetic())
                && part
                    .iter()
                    .all(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
        })
}
fn executable(image: &Image<'_>, address: u64) -> Option<u32> {
    let rva = u32::try_from(address.checked_sub(image.base)?).ok()?;
    image.code(rva).ok().map(|_| rva)
}
fn data_pointer(image: &Image<'_>, address: u64) -> bool {
    if address == 0 {
        return true;
    }
    let Some(rva) = address.checked_sub(image.base) else {
        return false;
    };
    image.sections.iter().any(|section| {
        !section.executable
            && rva >= u64::from(section.rva)
            && rva - u64::from(section.rva) < section.mapped_size as u64
    })
}
fn modern(image: &Image<'_>, bytes: &[u8]) -> Option<(u32, Option<String>, u32)> {
    let init = executable(image, pointer(bytes, 56)?)?;
    let import = executable(image, pointer(bytes, 64)?)?;
    for offset in [8, 16, 24] {
        let callback = pointer(bytes, offset)?;
        if callback != 0 && executable(image, callback).is_none() {
            return None;
        }
    }
    for offset in [32, 40, 48, 72, 80] {
        if !data_pointer(image, pointer(bytes, offset)?) {
            return None;
        }
    }
    let index = u32_at(bytes, 88).ok()?;
    let size = u32_at(bytes, 92).ok()?;
    let flags = u32_at(bytes, 96).ok()?;
    if index != 0 || size != 0 || flags > 255 || flags & (1 | 4 | 8 | 64) != 0 {
        return None;
    }
    Some((init, Some(format!("0x{import:x}")), flags))
}
fn compact(image: &Image<'_>, bytes: &[u8]) -> Option<(u32, Option<String>, u32)> {
    let init = executable(image, pointer(bytes, 8)?)?;
    let index = u32_at(bytes, 16).ok()?;
    let size = u32_at(bytes, 20).ok()?;
    let flags = u32_at(bytes, 24).ok()?;
    if index != 0 || size != 0 || flags > 255 || flags & (1 | 4 | 8 | 64) != 0 {
        return None;
    }
    Some((init, None, flags))
}
pub(super) fn scan(image: &Image<'_>, cancel: &AtomicBool) -> Result<Report, String> {
    let marker_found = memchr::memmem::find(image.bytes, b"Nuitka").is_some();
    let mut result = Report { marker_found, interpretation: "Validated candidate native module loader entries, not Python source recovery. Expanded x64 entry layout is validated against Nuitka 4.3.5; compact entries require a native init pointer and zero bytecode fields. Names must reference plain module strings and callbacks must reference executable sections. Encrypted names and other layouts can remain unresolved. A runtime marker or layout alone does not establish the Commercial edition.", entries: vec![], truncated: false };
    if !marker_found {
        return Ok(result);
    }
    let mut names = HashMap::new();
    let mut scanned = 0;
    for section in image.sections.iter().filter(|section| !section.executable) {
        let length = section.size.min(MAX_SCAN - scanned);
        let bytes = &image.bytes[section.raw..section.raw + length];
        let mut start = 0;
        for (end, byte) in bytes.iter().enumerate() {
            if end % 65536 == 0 && cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            if *byte != 0 {
                continue;
            }
            let name = &bytes[start..end];
            if name_valid(name) {
                let va = image
                    .base
                    .checked_add(u64::from(section.rva))
                    .and_then(|value| value.checked_add(start as u64))
                    .ok_or("VA overflow")?;
                names.insert(va, String::from_utf8(name.to_vec()).unwrap());
                if names.len() >= MAX_NAMES {
                    result.truncated = true;
                    break;
                }
            }
            start = end + 1;
        }
        scanned += length;
        if scanned >= MAX_SCAN || names.len() >= MAX_NAMES {
            result.truncated = true;
            break;
        }
    }
    let mut entries = BTreeMap::new();
    scanned = 0;
    for section in image.sections.iter().filter(|section| !section.executable) {
        let length = section.size.min(MAX_SCAN - scanned);
        let bytes = &image.bytes[section.raw..section.raw + length];
        for at in (0..bytes.len().saturating_sub(27)).step_by(8) {
            if at % 65536 == 0 && cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            let Some(name) = pointer(bytes, at).and_then(|pointer| names.get(&pointer)) else {
                continue;
            };
            let tail = &bytes[at..];
            let candidate = modern(image, tail)
                .map(|value| (value, "expanded-x64-4.3.5"))
                .or_else(|| compact(image, tail).map(|value| (value, "compact-x64")));
            let Some(((init, import, flags), layout)) = candidate else {
                continue;
            };
            // CPython method/getset tables share the compact pointer prefix.
            // Without a blob-name allowlist, only a main-flagged legacy root is accepted.
            if layout == "compact-x64" && (name != "__main__" || flags & 128 == 0) {
                continue;
            }
            if name == "__main__" && flags & 128 == 0 {
                continue;
            }
            entries
                .entry((name.clone(), init))
                .or_insert_with(|| Entry {
                    name: name.clone(),
                    init_rva: init,
                    init_rva_hex: format!("0x{init:x}"),
                    loader_rva: format!("0x{:x}", u64::from(section.rva) + at as u64),
                    import_rva: import,
                    layout,
                    flags,
                });
            if entries.len() >= MAX_ENTRIES {
                result.truncated = true;
                break;
            }
        }
        scanned += length;
        if scanned >= MAX_SCAN || entries.len() >= MAX_ENTRIES {
            result.truncated = true;
            break;
        }
    }
    let has_expanded = entries
        .values()
        .any(|entry| entry.layout == "expanded-x64-4.3.5");
    result.entries = entries
        .into_values()
        .filter(|entry| !has_expanded || entry.layout == "expanded-x64-4.3.5")
        .collect();
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::super::Section;
    use super::*;
    fn fixture(expanded: bool, bad_callback: bool) -> Vec<u8> {
        let mut bytes = vec![0; 1024];
        bytes[256..263].copy_from_slice(b"Nuitka\0");
        bytes[272..281].copy_from_slice(b"__main__\0");
        let base = 0x140000000u64;
        bytes[512..520].copy_from_slice(&(base + 0x1010).to_le_bytes());
        let function = if expanded { 56 } else { 8 };
        bytes[512 + function..520 + function].copy_from_slice(&(base + 0x2000).to_le_bytes());
        if expanded {
            bytes[576..584].copy_from_slice(
                &(base + if bad_callback { 0x1000 } else { 0x2008 }).to_le_bytes(),
            );
        }
        let flags = if expanded { 96 } else { 24 };
        bytes[512 + flags..516 + flags].copy_from_slice(&128u32.to_le_bytes());
        bytes
    }
    #[test]
    fn modern_and_compact_loader_abis_are_not_confused() {
        for expanded in [false, true] {
            let bytes = fixture(expanded, false);
            let image = Image {
                bytes: &bytes,
                base: 0x140000000,
                export: (0, 0),
                exception: (0, 0),
                sections: vec![
                    Section {
                        rva: 0x1000,
                        raw: 256,
                        size: 512,
                        mapped_size: 512,
                        executable: false,
                    },
                    Section {
                        rva: 0x2000,
                        raw: 768,
                        size: 128,
                        mapped_size: 128,
                        executable: true,
                    },
                ],
            };
            let report = scan(&image, &AtomicBool::new(false)).unwrap();
            assert_eq!(report.entries.len(), 1);
            assert_eq!(report.entries[0].init_rva, 0x2000);
            assert_eq!(report.entries[0].name, "__main__");
            assert_eq!(
                report.entries[0].layout,
                if expanded {
                    "expanded-x64-4.3.5"
                } else {
                    "compact-x64"
                }
            );
        }
    }
    #[test]
    fn a_callback_into_data_is_rejected() {
        let bytes = fixture(true, true);
        let image = Image {
            bytes: &bytes,
            base: 0x140000000,
            export: (0, 0),
            exception: (0, 0),
            sections: vec![
                Section {
                    rva: 0x1000,
                    raw: 256,
                    size: 512,
                    mapped_size: 512,
                    executable: false,
                },
                Section {
                    rva: 0x2000,
                    raw: 768,
                    size: 128,
                    mapped_size: 128,
                    executable: true,
                },
            ],
        };
        assert!(scan(&image, &AtomicBool::new(false))
            .unwrap()
            .entries
            .is_empty());
    }
    #[test]
    fn a_method_like_compact_record_is_not_a_module() {
        let mut bytes = fixture(false, false);
        bytes[272..281].copy_from_slice(b"__doc__\0\0");
        bytes[536..540].copy_from_slice(&0u32.to_le_bytes());
        let image = Image {
            bytes: &bytes,
            base: 0x140000000,
            export: (0, 0),
            exception: (0, 0),
            sections: vec![
                Section {
                    rva: 0x1000,
                    raw: 256,
                    size: 512,
                    mapped_size: 512,
                    executable: false,
                },
                Section {
                    rva: 0x2000,
                    raw: 768,
                    size: 128,
                    mapped_size: 128,
                    executable: true,
                },
            ],
        };
        assert!(scan(&image, &AtomicBool::new(false))
            .unwrap()
            .entries
            .is_empty());
    }
}
