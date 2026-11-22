use md5::Md5;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fs::File,
    io::Read,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

const BLOCK: usize = 1024 * 1024;
const OVERLAP: usize = 4096;
const MAX_HITS: usize = 20_000;
const MAX_RESOURCE_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Report {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub hits: Vec<Hit>,
    pub scanned_files: usize,
    pub truncated: bool,
    pub notes: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Hit {
    pub kind: String,
    pub value: String,
    pub file: String,
    pub offset: u64,
    pub encoding: String,
}

fn pattern() -> Regex {
    Regex::new(r#"(?i)https?://[^\s<>"'\x00]+|(?:[0-9]{1,3}\.){3}[0-9]{1,3}|\b[0-9a-f]{0,4}:[0-9a-f:]{2,}(?:[0-9a-f]{1,4})\b|(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[^\r\n"'\x00]+|[a-z]:\\[^\r\n"'<>|\x00]+|\\\\[a-z0-9_.-]+\\[^\r\n"'<>|\x00]+|/(?:tmp|etc|home|usr|var|opt)/[^\s"'<>\x00]+|\b(?:VirtualAlloc(?:Ex)?|VirtualProtect(?:Ex)?|WriteProcessMemory|ReadProcessMemory|CreateRemoteThread(?:Ex)?|NtCreateThreadEx|OpenProcess|QueueUserAPC|SetWindowsHookEx[AW]?|WinExec|ShellExecute[AW]?|URLDownloadToFile[AW]?|InternetOpen[AW]?|WinHttpConnect|LoadLibrary[AW]?)\b"#).unwrap()
}

fn scan(
    data: &[u8],
    base: u64,
    file: &str,
    report: &mut Report,
    re: &Regex,
    seen: &mut HashSet<(String, String)>,
) {
    for encoding in 0..3 {
        let stride = if encoding == 0 { 1 } else { 2 };
        let mut at = 0;
        while at < data.len() {
            let start = at;
            let mut text = String::new();
            while at < data.len() && text.len() < 16_384 {
                let ch = if encoding == 0 {
                    data[at]
                } else {
                    if at + 1 >= data.len() {
                        break;
                    }
                    let pair = &data[at..at + 2];
                    if pair[if encoding == 1 { 1 } else { 0 }] != 0 {
                        break;
                    }
                    pair[if encoding == 1 { 0 } else { 1 }]
                };
                if !(32..=126).contains(&ch) {
                    break;
                }
                text.push(ch as char);
                at += stride;
            }
            if text.len() >= 4 {
                for found in re.find_iter(&text) {
                    let value = found.as_str().trim_end_matches(['.', ',', ')', ';']);
                    let lower = value.to_ascii_lowercase();
                    let kind = if value.parse::<std::net::IpAddr>().is_ok() {
                        "IP"
                    } else if lower.starts_with("http") {
                        if lower.contains("discord.com/api/webhooks/")
                            || lower.contains("discordapp.com/api/webhooks/")
                        {
                            "Discord webhook"
                        } else if lower.contains("api.telegram.org/bot") {
                            "Telegram bot API"
                        } else {
                            "URL"
                        }
                    } else if lower.starts_with("hkey_")
                        || ["hklm\\", "hkcu\\", "hkcr\\", "hku\\", "hkcc\\"]
                            .iter()
                            .any(|p| lower.starts_with(p))
                    {
                        "Registry"
                    } else if value.contains('\\') || value.starts_with('/') {
                        "File path"
                    } else if value.contains('.') || value.contains(':') {
                        continue;
                    } else {
                        "WinAPI"
                    };
                    if !seen.insert((file.into(), value.into())) {
                        continue;
                    }
                    if report.hits.len() >= MAX_HITS {
                        report.truncated = true;
                        return;
                    }
                    report.hits.push(Hit {
                        kind: kind.into(),
                        value: value.into(),
                        file: file.into(),
                        offset: base + (start + found.start() * stride) as u64,
                        encoding: ["ASCII", "UTF-16LE", "UTF-16BE"][encoding].into(),
                    });
                }
            }
            // Advance one byte after invalid wide characters to cover both alignments.
            at = at.saturating_add(1);
        }
    }
}

fn scan_file(
    path: &Path,
    label: &str,
    report: &mut Report,
    hashing: bool,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let mut file = File::open(path).map_err(|e| e.to_string())?;
    let mut md5 = Md5::new();
    let mut sha1 = Sha1::new();
    let mut sha256 = Sha256::new();
    let mut buf = vec![0; BLOCK];
    let mut tail = vec![];
    let mut offset = 0u64;
    let re = pattern();
    let mut seen = report
        .hits
        .iter()
        .map(|h| (h.file.clone(), h.value.clone()))
        .collect();
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let count = file.read(&mut buf).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        if hashing {
            md5.update(&buf[..count]);
            sha1.update(&buf[..count]);
            sha256.update(&buf[..count]);
        }
        let base = offset - tail.len() as u64;
        tail.extend_from_slice(&buf[..count]);
        scan(&tail, base, label, report, &re, &mut seen);
        offset += count as u64;
        tail = tail[tail.len().saturating_sub(OVERLAP)..].to_vec();
    }
    if hashing {
        report.md5 = format!("{:x}", md5.finalize());
        report.sha1 = format!("{:x}", sha1.finalize());
        report.sha256 = format!("{:x}", sha256.finalize());
    }
    report.scanned_files += 1;
    Ok(())
}
pub fn inspect(path: &Path, cancel: &AtomicBool) -> Result<Report, String> {
    let mut report = Report::default();
    scan_file(path, &path.to_string_lossy(), &mut report, true, cancel)?;
    Ok(report)
}
pub fn resources(root: &Path, report: &mut Report, cancel: &AtomicBool) -> Result<(), String> {
    let mut folders = vec![root.to_path_buf()];
    let mut bytes = 0;
    let mut entries = 0;
    while let Some(folder) = folders.pop() {
        if !folder.exists() {
            continue;
        }
        for entry in std::fs::read_dir(folder).map_err(|e| e.to_string())? {
            if cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            entries += 1;
            if entries > 100_000 {
                report.truncated = true;
                return Ok(());
            }
            let entry = entry.map_err(|e| e.to_string())?;
            let kind = entry.file_type().map_err(|e| e.to_string())?;
            if kind.is_dir() {
                folders.push(entry.path());
            } else if kind.is_file() {
                let size = entry.metadata().map_err(|e| e.to_string())?.len();
                if bytes + size > MAX_RESOURCE_BYTES {
                    report.truncated = true;
                    continue;
                }
                bytes += size;
                let label = entry
                    .path()
                    .strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                if let Err(error) = scan_file(&entry.path(), &label, report, false, cancel) {
                    report.notes.push(format!("{label}: {error}"));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn indicators_validate_addresses_and_wide_offsets() {
        let text="https://discord.com/api/webhooks/123/token 1.2.3.4 999.2.3.4 VirtualAlloc HKEY_CURRENT_USER\\Software\\app";
        let mut report = Report::default();
        let mut seen = HashSet::new();
        scan(
            text.as_bytes(),
            0,
            "test",
            &mut report,
            &pattern(),
            &mut seen,
        );
        assert!(report.hits.iter().any(|h| h.kind == "Discord webhook"));
        assert!(!report.hits.iter().any(|h| h.value == "999.2.3.4"));
        let wide: Vec<u8> = "WriteProcessMemory"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        scan(&wide, 100, "wide", &mut report, &pattern(), &mut seen);
        assert!(report
            .hits
            .iter()
            .any(|h| h.offset == 100 && h.encoding == "UTF-16LE"));
    }
    #[test]
    fn hash_vectors() {
        let path = std::env::temp_dir().join(format!("uie-hash-{}.txt", std::process::id()));
        std::fs::write(&path, b"abc").unwrap();
        let r = inspect(&path, &AtomicBool::new(false)).unwrap();
        assert_eq!(r.md5, "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(r.sha1, "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            r.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let _ = std::fs::remove_file(path);
    }
}
