use super::{u32_at, Image};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_SCAN: usize = 16 * 1024 * 1024;
const MAX_METHODS: usize = 4096;
#[derive(Serialize)]
pub(super) struct Method {
    pub name: String,
    pub function_rva: u32,
    function_rva_hex: String,
    table_rva: String,
    flags: String,
    doc: Option<String>,
}
#[derive(Serialize)]
pub(super) struct Report {
    interpretation: &'static str,
    pub methods: Vec<Method>,
    truncated: bool,
}
fn pointer(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}
fn text(image: &Image<'_>, address: u64, limit: usize) -> Option<String> {
    let rva = u32::try_from(address.checked_sub(image.base)?).ok()?;
    let section = image.sections.iter().find(|section| {
        !section.executable
            && rva >= section.rva
            && u64::from(rva - section.rva) < section.size as u64
    })?;
    let offset = (rva - section.rva) as usize;
    let bytes =
        &image.bytes[section.raw + offset..section.raw + (offset + limit + 1).min(section.size)];
    let end = bytes.iter().position(|byte| *byte == 0)?;
    if end > limit {
        return None;
    }
    std::str::from_utf8(&bytes[..end]).ok().map(str::to_owned)
}
fn identifier(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || unicode_ident::is_xid_start(c))
        && chars.all(unicode_ident::is_xid_continue)
}
fn flags_valid(flags: u32) -> bool {
    if flags & 0x30 == 0x30 {
        return false;
    }
    matches!(flags & !0x70, 1 | 3 | 4 | 8 | 128 | 130 | 642)
}
pub(super) fn scan(image: &Image<'_>, cancel: &AtomicBool) -> Result<Report, String> {
    let mut report = Report { interpretation: "Candidate CPython PyMethodDef x64 records. Names, callable pointers, method flags and optional doc pointers are validated statically. These identify wrappers/API entry points, not recovered Python bodies, argument names or proof of Cython/Nuitka edition. No target execution.", methods: vec![], truncated: false };
    let mut scanned = 0;
    for section in image.sections.iter().filter(|section| !section.executable) {
        let length = section.size.min(MAX_SCAN - scanned);
        let bytes = &image.bytes[section.raw..section.raw + length];
        for offset in (0..=bytes.len().saturating_sub(32)).step_by(8) {
            if offset % 65536 == 0 && cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            let Some(record) = bytes.get(offset..offset + 32) else {
                continue;
            };
            let Some(name) = pointer(record, 0)
                .and_then(|va| text(image, va, 256))
                .filter(|name| identifier(name))
            else {
                continue;
            };
            let Some(function_rva) = pointer(record, 8)
                .and_then(|va| va.checked_sub(image.base))
                .and_then(|rva| u32::try_from(rva).ok())
                .filter(|rva| image.code(*rva).is_ok())
            else {
                continue;
            };
            let flags = u32_at(record, 16)?;
            if !flags_valid(flags) || u32_at(record, 20)? != 0 {
                continue;
            }
            let Some(doc_address) = pointer(record, 24) else {
                continue;
            };
            let doc = if doc_address == 0 {
                None
            } else {
                let Some(doc) = text(image, doc_address, 4096) else {
                    continue;
                };
                Some(doc)
            };
            report.methods.push(Method {
                name,
                function_rva,
                function_rva_hex: format!("0x{function_rva:x}"),
                table_rva: format!("0x{:x}", u64::from(section.rva) + offset as u64),
                flags: format!("0x{flags:x}"),
                doc,
            });
            if report.methods.len() >= MAX_METHODS {
                report.truncated = true;
                break;
            }
        }
        scanned += length;
        if scanned >= MAX_SCAN || report.methods.len() >= MAX_METHODS {
            report.truncated = true;
            break;
        }
    }
    Ok(report)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn method_flags_do_not_accept_getset_or_arbitrary_pointer_tables() {
        for flags in [1, 3, 4, 8, 0x82, 0x282] {
            assert!(flags_valid(flags));
        }
        for flags in [0, 2, 5, 0x30, 0x100, 0x14000000, u32::MAX] {
            assert!(!flags_valid(flags));
        }
        assert!(identifier("__init__"));
        assert!(identifier("привет"));
        assert!(!identifier("module.method"));
    }
}
