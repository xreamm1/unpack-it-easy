use super::Image;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_SCAN: usize = 32 * 1024 * 1024;
const MAX_MATCHES: usize = 64;

#[derive(Serialize)]
pub(super) struct Match {
    kind: &'static str,
    rva: String,
    polynomial: &'static str,
    storage_word_xor: String,
}

#[derive(Serialize)]
pub(super) struct Report {
    interpretation: &'static str,
    scanned_bytes: usize,
    truncated: bool,
    matches: Vec<Match>,
}

fn crc_table() -> [u32; 256] {
    std::array::from_fn(|index| {
        let mut value = index as u32;
        for _ in 0..8 {
            value = (value >> 1) ^ if value & 1 != 0 { 0xedb88320 } else { 0 };
        }
        value
    })
}

pub(super) fn scan(image: &Image<'_>, cancel: &AtomicBool) -> Result<Report, String> {
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let expected = crc_table();
    let mut report = Report {
        interpretation: "Static lookup-table patterns only. Four-byte-aligned little-endian DWORDs in file-backed sections, including executable sections. All 256 entries are validated after one constant DWORD XOR. Function usage and CRC initial/final parameters are unverified; this does not establish encryption or recovered application logic.",
        scanned_bytes: 0,
        truncated: false,
        matches: vec![],
    };
    for (index, section) in image.sections.iter().enumerate() {
        let length = section.size.min(MAX_SCAN - report.scanned_bytes);
        if length < section.size {
            report.truncated = true;
        }
        if length >= 1024 {
            let bytes = &image.bytes[section.raw..section.raw + length];
            for offset in (0..=length - 1024).step_by(4) {
                if offset % 16384 == 0 && cancel.load(Ordering::Relaxed) {
                    return Err("cancelled".into());
                }
                let word = |at| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
                let key = word(offset);
                if word(offset + 4) ^ key != expected[1] {
                    continue;
                }
                if !(2..256).all(|index| word(offset + index * 4) ^ key == expected[index]) {
                    continue;
                }
                let Some(rva) = section.rva.checked_add(offset as u32) else {
                    continue;
                };
                report.matches.push(Match {
                    kind: "crc32_reflected_table",
                    rva: format!("0x{rva:x}"),
                    polynomial: "0xedb88320",
                    storage_word_xor: format!("0x{key:08x}"),
                });
                if report.matches.len() == MAX_MATCHES {
                    report.scanned_bytes += offset + 4;
                    report.truncated = true;
                    return Ok(report);
                }
            }
        }
        report.scanned_bytes += length;
        if report.scanned_bytes == MAX_SCAN {
            report.truncated |= image.sections[index + 1..]
                .iter()
                .any(|section| section.size != 0);
            break;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_lift::Section;

    fn fixture(key: u32, corrupt: bool) -> Vec<u8> {
        let mut bytes = vec![0; 12];
        for (index, value) in crc_table().into_iter().enumerate() {
            bytes.extend((value ^ key ^ u32::from(corrupt && index == 255)).to_le_bytes());
        }
        bytes
    }
    fn inspect(bytes: &[u8], cancel: bool) -> Result<Report, String> {
        let image = Image {
            bytes,
            sections: vec![Section {
                rva: 0x2000,
                raw: 0,
                size: bytes.len(),
                mapped_size: bytes.len(),
                executable: true,
            }],
            export: (0, 0),
            exception: (0, 0),
            base: 0x140000000,
        };
        scan(&image, &AtomicBool::new(cancel))
    }
    #[test]
    fn validates_every_entry_and_recovers_a_constant_storage_xor() {
        for key in [0, 0xe9952b25, 0xffffffff] {
            let report = inspect(&fixture(key, false), false).unwrap();
            assert_eq!(report.matches.len(), 1);
            assert_eq!(report.matches[0].rva, "0x200c");
            assert_eq!(report.matches[0].storage_word_xor, format!("0x{key:08x}"));
        }
        assert!(inspect(&fixture(0xe9952b25, true), false)
            .unwrap()
            .matches
            .is_empty());
    }
    #[test]
    fn match_limit_reports_only_the_processed_prefix() {
        let table = fixture(0, false);
        let mut bytes = Vec::new();
        for _ in 0..MAX_MATCHES + 1 {
            bytes.extend_from_slice(&table);
        }
        bytes.resize(bytes.len() + 1024 * 1024, 0);
        let report = inspect(&bytes, false).unwrap();
        assert_eq!(report.matches.len(), MAX_MATCHES);
        assert!(report.truncated);
        assert!(report.scanned_bytes < bytes.len() - 1024 * 1024);
    }
    #[test]
    fn rejects_truncated_tables_and_honors_cancellation() {
        let bytes = fixture(0, false);
        assert!(inspect(&bytes[..bytes.len() - 1], false)
            .unwrap()
            .matches
            .is_empty());
        assert!(inspect(&bytes, true).is_err());
    }
}
