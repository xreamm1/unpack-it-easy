use super::{u32_at, Image};
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};

const RECORD_SIZE: usize = 16;
const MIN_ENTRIES: usize = 4;
const MAX_ENTRIES: usize = 4096;
const MAX_TABLES: usize = 64;
const MAX_SCAN_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORD_CHECKS: usize = 2 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 1024 * 1024;
const MAX_DECODED_BYTES: usize = 8 * 1024 * 1024;
const MAX_STRING_BYTES: usize = 4096;

#[derive(Serialize)]
pub(super) struct Entry {
    entry_rva: u32,
    pub text_rva: u32,
    text_rva_hex: String,
    length_including_nul: usize,
    flags: String,
    pub text: String,
}

#[derive(Serialize)]
pub(super) struct Table {
    pub table_rva: u32,
    table_rva_hex: String,
    start_boundary_verified: bool,
    pub entries: Vec<Entry>,
}

#[derive(Serialize)]
pub(super) struct Report {
    pub marker_found: bool,
    interpretation: &'static str,
    pub tables: Vec<Table>,
    truncated: bool,
}

fn readonly_sections(image: &Image<'_>) -> Result<Vec<usize>, String> {
    let pe = u32_at(image.bytes, 0x3c)? as usize;
    let optional = pe.checked_add(24).ok_or("offset overflow")?;
    let header_size = super::u16_at(image.bytes, pe + 20)? as usize;
    let mut result = vec![];
    for (index, section) in image.sections.iter().enumerate() {
        let at = optional
            .checked_add(header_size)
            .and_then(|at| at.checked_add(index * 40))
            .ok_or("offset overflow")?;
        let flags = u32_at(image.bytes, at + 36)?;
        if !section.executable && flags & 0xc0000000 == 0x40000000 {
            result.push(index);
        }
    }
    Ok(result)
}

fn literal(
    image: &Image<'_>,
    readonly: &[usize],
    address: u64,
    length: usize,
) -> Option<(u32, String)> {
    let rva = u32::try_from(address.checked_sub(image.base)?).ok()?;
    let section = readonly
        .iter()
        .map(|index| &image.sections[*index])
        .find(|section| {
            rva.checked_sub(section.rva)
                .and_then(|offset| (offset as usize).checked_add(length))
                .is_some_and(|end| end <= section.size)
        })?;
    let raw = section.raw.checked_add((rva - section.rva) as usize)?;
    let bytes = image.bytes.get(raw..raw.checked_add(length)?)?;
    if bytes.last() != Some(&0) {
        return None;
    }
    let text = std::str::from_utf8(&bytes[..length - 1]).ok()?;
    Some((rva, text.to_owned()))
}

fn entry(image: &Image<'_>, readonly: &[usize], record: &[u8], entry_rva: u32) -> Option<Entry> {
    let address = u64::from_le_bytes(record.get(..8)?.try_into().ok()?);
    let length = u16::from_le_bytes(record.get(8..10)?.try_into().ok()?) as usize;
    let padding = u16::from_le_bytes(record.get(10..12)?.try_into().ok()?);
    let flags = u32::from_le_bytes(record.get(12..16)?.try_into().ok()?);
    // This describes only the observed Cython 3 compact UTF-8 Unicode layout.
    if !(1..=MAX_STRING_BYTES).contains(&length) || padding != 0 || !matches!(flags, 0x20 | 0x60) {
        return None;
    }
    let (text_rva, text) = literal(image, readonly, address, length)?;
    Some(Entry {
        entry_rva,
        text_rva,
        text_rva_hex: format!("0x{text_rva:x}"),
        length_including_nul: length,
        flags: format!("0x{flags:x}"),
        text,
    })
}

pub(super) fn scan(image: &Image<'_>, cancel: &AtomicBool) -> Result<Report, String> {
    let marker_found = [b"_cython_".as_slice(), b"__pyx_", b"Cython"]
        .iter()
        .any(|marker| memchr::memmem::find(image.bytes, marker).is_some());
    let mut report = Report {
        marker_found,
        interpretation: "Candidate Cython 3 compact UTF-8 Unicode literal record runs: contiguous x64 <QHHI> records with mapped read-only pointers, bounded NUL-terminated UTF-8 strings, supported flags and a zero terminator. A run may be a suffix of a table containing unsupported byte-string records; its start is not proven without initializer analysis. Literal/table addresses are file evidence; destination Python object slots, initializer assignments and recovered Python function bodies are not inferred. Other Cython layouts and byte-string records can remain unresolved. No target execution.",
        tables: vec![],
        truncated: false,
    };
    if !marker_found {
        return Ok(report);
    }
    let readonly = readonly_sections(image)?;
    let mut scanned = 0usize;
    let mut checks = 0usize;
    let mut text_bytes = 0usize;
    let mut decoded_bytes = 0usize;
    for index in &readonly {
        let section = &image.sections[*index];
        let length = section.size.min(MAX_SCAN_BYTES - scanned);
        let bytes = &image.bytes[section.raw..section.raw + length];
        let mut offset = 0usize;
        while offset + RECORD_SIZE <= bytes.len() {
            if cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            if checks >= MAX_RECORD_CHECKS || report.tables.len() >= MAX_TABLES {
                report.truncated = true;
                return Ok(report);
            }
            let mut entries = vec![];
            let mut cursor = offset;
            let mut terminated = false;
            let mut candidate_bytes = 0usize;
            while let Some(record) = bytes.get(cursor..cursor + RECORD_SIZE) {
                if checks >= MAX_RECORD_CHECKS {
                    report.truncated = true;
                    return Ok(report);
                }
                checks += 1;
                if record.iter().all(|byte| *byte == 0) {
                    terminated = true;
                    break;
                }
                if entries.len() >= MAX_ENTRIES {
                    report.truncated = true;
                    break;
                }
                let Some(entry_rva) = section.rva.checked_add(cursor as u32) else {
                    break;
                };
                let Some(item) = entry(image, &readonly, record, entry_rva) else {
                    break;
                };
                decoded_bytes += item.text.len();
                if decoded_bytes > MAX_DECODED_BYTES {
                    report.truncated = true;
                    return Ok(report);
                }
                candidate_bytes += item.text.len();
                if candidate_bytes + text_bytes > MAX_TEXT_BYTES {
                    report.truncated = true;
                    return Ok(report);
                }
                entries.push(item);
                cursor += RECORD_SIZE;
            }
            if terminated && entries.len() >= MIN_ENTRIES {
                let Some(table_rva) = section.rva.checked_add(offset as u32) else {
                    break;
                };
                text_bytes += candidate_bytes;
                report.tables.push(Table {
                    table_rva,
                    table_rva_hex: format!("0x{table_rva:x}"),
                    start_boundary_verified: false,
                    entries,
                });
                offset = cursor + RECORD_SIZE;
            } else {
                offset += 8;
            }
        }
        scanned += length;
        if scanned == MAX_SCAN_BYTES {
            report.truncated = true;
            break;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x800];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        bytes[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        bytes[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        bytes[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        bytes[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        bytes[0xb0..0xb8].copy_from_slice(&0x180000000u64.to_le_bytes());
        let section = 0x188;
        for (at, value) in [
            (8, 0x600u32),
            (12, 0x1000),
            (16, 0x600),
            (20, 0x200),
            (36, 0x40000040),
        ] {
            bytes[section + at..section + at + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[0x200..0x208].copy_from_slice(b"_cython_");
        for (index, text) in ["cell", "w", "Rect", "привет"].into_iter().enumerate() {
            let string_at = 0x300 + index * 0x20;
            bytes[string_at..string_at + text.len()].copy_from_slice(text.as_bytes());
            let record = 0x400 + index * RECORD_SIZE;
            bytes[record..record + 8].copy_from_slice(
                &(0x180000000u64 + (string_at - 0x200 + 0x1000) as u64).to_le_bytes(),
            );
            bytes[record + 8..record + 10]
                .copy_from_slice(&((text.len() + 1) as u16).to_le_bytes());
            bytes[record + 12..record + 16].copy_from_slice(&0x60u32.to_le_bytes());
        }
        bytes
    }

    fn read(bytes: &[u8]) -> Report {
        scan(&Image::parse(bytes).unwrap(), &AtomicBool::new(false)).unwrap()
    }

    #[test]
    fn compact_cython_table_resolves_literal_addresses_and_unicode_only() {
        let report = read(&fixture());
        assert_eq!(report.tables.len(), 1);
        assert_eq!(report.tables[0].table_rva, 0x1200);
        assert_eq!(report.tables[0].entries.len(), 4);
        assert_eq!(report.tables[0].entries[0].text_rva, 0x1100);
        assert_eq!(report.tables[0].entries[3].text, "привет");
        let serialized = serde_json::to_value(report).unwrap();
        assert!(serialized["tables"][0]["entries"][0].get("slot").is_none());
    }

    #[test]
    fn malformed_or_unproven_records_do_not_become_tables() {
        let original = fixture();
        let mut no_marker = original.clone();
        no_marker[0x200..0x208].fill(0);
        assert!(!read(&no_marker).marker_found);
        for at in [0x400, 0x40a, 0x40c, 0x304, 0x440] {
            let mut broken = original.clone();
            broken[at] = 0xff;
            assert!(read(&broken).tables.is_empty(), "malformation at {at:x}");
        }
        let mut writable = original.clone();
        writable[0x188 + 36..0x188 + 40].copy_from_slice(&0xc0000040u32.to_le_bytes());
        assert!(read(&writable).tables.is_empty());
        let cancelled = scan(&Image::parse(&original).unwrap(), &AtomicBool::new(true));
        assert!(cancelled.is_err());
    }
}
