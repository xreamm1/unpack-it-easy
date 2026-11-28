//! Bounded static comparison. Offset differences are not semantic function matches.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs::File, io::Read, path::Path};
const MAX_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RANGES: usize = 2048;

fn read(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err("comparison requires regular files up to 256 MiB".into());
    }
    let mut data = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_BYTES {
        return Err("comparison input grew beyond limit".into());
    }
    Ok(data)
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
    let value = bytes
        .get(at..at.checked_add(4).ok_or("offset overflow")?)
        .ok_or("truncated PE field")?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}
fn sections(data: &[u8]) -> Result<BTreeMap<String, Value>, String> {
    let mut rows = BTreeMap::new();
    if !data.starts_with(b"MZ") {
        return Ok(rows);
    }
    let pe = u32_at(data, 0x3c)? as usize;
    let count = u16::from_le_bytes(
        data.get(pe + 6..pe + 8)
            .ok_or("truncated sections")?
            .try_into()
            .unwrap(),
    ) as usize;
    let optional = u16::from_le_bytes(
        data.get(pe + 20..pe + 22)
            .ok_or("truncated optional header")?
            .try_into()
            .unwrap(),
    ) as usize;
    for index in 0..count {
        let at = pe + 24 + optional + index * 40;
        let header = data.get(at..at + 40).ok_or("truncated section")?;
        let name = String::from_utf8_lossy(&header[..8])
            .trim_end_matches('\0')
            .to_string();
        let start = u32_at(header, 20)? as usize;
        let size = u32_at(header, 16)? as usize;
        let bytes = if size == 0 {
            &[][..]
        } else {
            data.get(start..start.checked_add(size).ok_or("section overflow")?)
                .ok_or("section raw bytes outside input")?
        };
        let key = if rows.contains_key(&name) {
            format!("{name}#{index}")
        } else {
            name
        };
        rows.insert(key,json!({"rva":u32_at(header,12)?,"file_offset":start,"size":size,"sha256":format!("{:x}",Sha256::digest(bytes))}));
    }
    Ok(rows)
}
fn difference(left: &[u8], right: &[u8]) -> Value {
    let mut changed = 0usize;
    let mut ranges = Vec::new();
    let mut start = None;
    for offset in 0..left.len().max(right.len()) {
        if left.get(offset) != right.get(offset) {
            changed += 1;
            if start.is_none() {
                start = Some(offset);
            }
        } else if let Some(begin) = start.take() {
            if ranges.len() < MAX_RANGES {
                ranges.push(json!({"start":begin,"end_exclusive":offset}));
            }
        }
    }
    if let Some(begin) = start {
        if ranges.len() < MAX_RANGES {
            ranges.push(json!({"start":begin,"end_exclusive":left.len().max(right.len())}));
        }
    }
    json!({"changed_byte_positions":changed,"ranges":ranges,"range_limit":MAX_RANGES,"ranges_may_be_truncated":ranges.len()==MAX_RANGES})
}
pub fn compare(left: &Path, right: &Path) -> Result<Value, String> {
    let old = read(left)?;
    let new = read(right)?;
    let old_analysis = crate::detect::inspect(&old)?;
    let new_analysis = crate::detect::inspect(&new)?;
    if !["PE", "ELF", "Mach-O"].contains(&old_analysis.format.as_str()) {
        return Err("first input is not a recognized executable image".into());
    }
    if !["PE", "ELF", "Mach-O"].contains(&new_analysis.format.as_str()) {
        return Err("second input is not a recognized executable image".into());
    }
    let a = sections(&old)?;
    let b = sections(&new)?;
    let added: Vec<_> = b
        .keys()
        .filter(|name| !a.contains_key(*name))
        .cloned()
        .collect();
    let removed: Vec<_> = a
        .keys()
        .filter(|name| !b.contains_key(*name))
        .cloned()
        .collect();
    let modified: Vec<_> = a
        .iter()
        .filter_map(|(name, value)| {
            b.get(name)
                .filter(|new| new["sha256"] != value["sha256"])
                .map(|_| name.clone())
        })
        .collect();
    Ok(
        json!({"kind":"executable byte and PE section comparison","left":{"file":left,"size":old.len(),"sha256":format!("{:x}",Sha256::digest(&old)),"analysis":old_analysis,"sections":a},"right":{"file":right,"size":new.len(),"sha256":format!("{:x}",Sha256::digest(&new)),"analysis":new_analysis,"sections":b},"bytes":difference(&old,&new),"sections_added":added,"sections_removed":removed,"sections_modified":modified,"semantic_equivalence_verified":false,"target_executed":false,"interpretation":"Offsets are positional differences, not function correspondence. Compare two UIE bases for recovered function changes."}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ranges_include_tail_and_do_not_invent_semantics() {
        let value = difference(b"abcdef", b"aXXdeQz");
        assert_eq!(value["changed_byte_positions"], 4);
        assert_eq!(value["ranges"][0], json!({"start":1,"end_exclusive":3}));
        assert_eq!(value["ranges"][1], json!({"start":5,"end_exclusive":7}));
        assert_eq!(difference(b"same", b"same")["changed_byte_positions"], 0);
    }
}
