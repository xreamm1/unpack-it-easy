//! PE metadata indexing only: no disassembly, target loading or code execution.
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
    fs,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

const MAX_INPUT_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RUNTIME_ROWS: usize = 262_144;
const MAX_EXPORTS: usize = 262_144;
const MAX_FUNCTIONS: usize = 100_000;
const MAX_EXPORT_NAME: usize = 512;
const MAX_XREF_SCAN_BYTES: usize = 8 * 1024 * 1024;
const MAX_XREF_FUNCTION_BYTES: usize = 64 * 1024;
const MAX_XREF_INSTRUCTIONS: usize = 1_000_000;
const MAX_CALL_XREFS: usize = 65_536;

fn word(bytes: &[u8], at: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at.checked_add(2).ok_or("PE offset overflow")?)
            .ok_or("truncated PE field")?
            .try_into()
            .unwrap(),
    ))
}
fn dword(bytes: &[u8], at: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at.checked_add(4).ok_or("PE offset overflow")?)
            .ok_or("truncated PE field")?
            .try_into()
            .unwrap(),
    ))
}
struct Section {
    name: String,
    rva: u32,
    raw: usize,
    size: usize,
    virtual_size: u32,
    executable: bool,
}
struct Pe<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
    base: u64,
    entry: u32,
    exports: (u32, u32),
    runtime: (u32, u32),
}
impl<'a> Pe<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.get(..2) != Some(b"MZ") {
            return Err("native lazy indexing requires an AMD64 PE file".into());
        }
        let pe = dword(bytes, 0x3c)? as usize;
        let optional = pe.checked_add(24).ok_or("PE offset overflow")?;
        if bytes.get(pe..pe.checked_add(4).ok_or("PE offset overflow")?) != Some(b"PE\0\0")
            || word(bytes, pe + 4)? != 0x8664
        {
            return Err("native lazy indexing requires an AMD64 PE file".into());
        }
        let count = word(bytes, pe + 6)? as usize;
        let optional_size = word(bytes, pe + 20)? as usize;
        if count == 0 || count > 96 || optional_size < 112 || word(bytes, optional)? != 0x20b {
            return Err("invalid PE32+ headers".into());
        }
        let header = bytes
            .get(
                optional
                    ..optional
                        .checked_add(optional_size)
                        .ok_or("PE offset overflow")?,
            )
            .ok_or("truncated PE optional header")?;
        let base = u64::from_le_bytes(header[24..32].try_into().unwrap());
        let directory_count = dword(header, 108)? as usize;
        let directory = |index: usize| -> Result<(u32, u32), String> {
            if index >= directory_count {
                return Ok((0, 0));
            }
            let at = 112 + index * 8;
            Ok((dword(header, at)?, dword(header, at + 4)?))
        };
        let section_start = optional
            .checked_add(optional_size)
            .ok_or("PE offset overflow")?;
        let mut sections = Vec::with_capacity(count);
        for index in 0..count {
            let at = section_start + index * 40;
            let rva = dword(bytes, at + 12)?;
            let size = dword(bytes, at + 16)? as usize;
            let raw = dword(bytes, at + 20)? as usize;
            if raw.checked_add(size).is_none_or(|end| end > bytes.len())
                || u64::from(rva) + size as u64 > u64::from(u32::MAX) + 1
                || base.checked_add(u64::from(rva) + size as u64).is_none()
            {
                return Err("PE section is outside mapped file/address bounds".into());
            }
            sections.push(Section {
                name: String::from_utf8_lossy(
                    bytes.get(at..at + 8).ok_or("truncated section name")?,
                )
                .trim_end_matches('\0')
                .to_owned(),
                rva,
                raw,
                size,
                virtual_size: dword(bytes, at + 8)?,
                executable: dword(bytes, at + 36)? & 0x20000000 != 0,
            });
        }
        Ok(Self {
            bytes,
            sections,
            base,
            entry: dword(header, 16)?,
            exports: directory(0)?,
            runtime: directory(3)?,
        })
    }
    fn region(&self, rva: u32, size: usize, executable: bool) -> Option<&'a [u8]> {
        for section in &self.sections {
            let Some(offset) = rva.checked_sub(section.rva).map(|v| v as usize) else {
                continue;
            };
            if executable && !section.executable {
                continue;
            }
            if offset
                .checked_add(size)
                .is_some_and(|end| end <= section.size)
            {
                return self
                    .bytes
                    .get(section.raw + offset..section.raw + offset + size);
            }
        }
        None
    }
    fn export_name(&self, rva: u32) -> Option<String> {
        let mut raw = vec![];
        for offset in 0..MAX_EXPORT_NAME {
            let at = rva.checked_add(offset as u32)?;
            let value = *self.region(at, 1, false)?.first()?;
            if value == 0 {
                let text = std::str::from_utf8(&raw).ok()?;
                if text.is_empty() || text.chars().any(char::is_control) {
                    return None;
                }
                return Some(text.to_owned());
            }
            raw.push(value);
        }
        None
    }
}

#[derive(Serialize)]
struct IndexedFunction {
    name: String,
    address: String,
    end: Option<String>,
    rva: String,
    line: usize,
    lazy: bool,
    success: bool,
    extent_unknown: bool,
    range_conflict: bool,
    evidence: Vec<&'static str>,
}
struct Candidate {
    name: Option<String>,
    end: Option<u32>,
    conflict: bool,
    evidence: Vec<&'static str>,
}
#[derive(Default, Serialize)]
struct Diagnostics {
    runtime_rows_examined: usize,
    invalid_runtime_rows: usize,
    duplicate_runtime_rows: usize,
    merged_chained_fragments: usize,
    noncontiguous_chained_functions: usize,
    invalid_unwind_chains: usize,
    invalid_export_rows: usize,
    forwarded_exports: usize,
    malformed_directories: Vec<&'static str>,
    unbacked_virtual_sections: Vec<UnbackedSection>,
    truncated: bool,
}

#[derive(Serialize)]
struct UnbackedSection {
    name: String,
    rva: String,
    virtual_size: u32,
    executable: bool,
    interpretation: &'static str,
}

#[derive(Serialize)]
struct CallXref {
    from_function_rva: String,
    from_function: String,
    from_address: String,
    instruction_rva: String,
    instruction_address: String,
    target_rva: String,
    target_address: String,
    target_function: String,
    kind: &'static str,
}

#[derive(Serialize)]
struct XrefAnalysis {
    interpretation: &'static str,
    scanned_bytes: usize,
    decoded_instructions: usize,
    truncated: bool,
    indirect_calls_resolved: bool,
}

fn candidate_name(base: u64, rva: u32, candidate: &Candidate) -> String {
    candidate
        .name
        .clone()
        .unwrap_or_else(|| format!("FUN_{:x}", base + u64::from(rva)))
}

fn call_xrefs(
    pe: &Pe<'_>,
    candidates: &BTreeMap<u32, Candidate>,
    cancel: &AtomicBool,
) -> Result<(Vec<CallXref>, XrefAnalysis), String> {
    let mut rows = vec![];
    let mut analysis = XrefAnalysis {
        interpretation: "Static direct CALL rel32 candidates from bounded linear instruction decoding within validated PE runtime ranges. Exact indexed targets only. Metadata and linear decoding do not prove instruction reachability; indirect calls, strings and complete control flow are not resolved.",
        scanned_bytes: 0,
        decoded_instructions: 0,
        truncated: false,
        indirect_calls_resolved: false,
    };
    for (rva, candidate) in candidates {
        let Some(end) = candidate.end else {
            continue;
        };
        if candidate.conflict {
            continue;
        }
        let full_length = (end - rva) as usize;
        let length = full_length
            .min(MAX_XREF_FUNCTION_BYTES)
            .min(MAX_XREF_SCAN_BYTES - analysis.scanned_bytes);
        analysis.truncated |= length < full_length;
        let Some(bytes) = pe.region(*rva, length, true) else {
            continue;
        };
        let mut decoder =
            Decoder::with_ip(64, bytes, pe.base + u64::from(*rva), DecoderOptions::NONE);
        while decoder.can_decode() {
            if analysis.decoded_instructions.is_multiple_of(1024) && cancel.load(Ordering::Relaxed)
            {
                return Err("cancelled".into());
            }
            if analysis.decoded_instructions >= MAX_XREF_INSTRUCTIONS
                || rows.len() >= MAX_CALL_XREFS
            {
                analysis.truncated = true;
                return Ok((rows, analysis));
            }
            let instruction = decoder.decode();
            analysis.decoded_instructions += 1;
            analysis.scanned_bytes += instruction.len();
            if instruction.is_invalid() {
                analysis.truncated = true;
                break;
            }
            if instruction.mnemonic() != Mnemonic::Call
                || instruction.op0_kind() != OpKind::NearBranch64
            {
                continue;
            }
            let Some(target_rva) = instruction
                .near_branch_target()
                .checked_sub(pe.base)
                .and_then(|value| u32::try_from(value).ok())
            else {
                continue;
            };
            let Some(target) = candidates.get(&target_rva) else {
                continue;
            };
            rows.push(CallXref {
                from_function_rva: format!("0x{rva:x}"),
                from_function: candidate_name(pe.base, *rva, candidate),
                from_address: format!("{:x}", pe.base + u64::from(*rva)),
                instruction_rva: format!("0x{:x}", instruction.ip() - pe.base),
                instruction_address: format!("{:x}", instruction.ip()),
                target_rva: format!("0x{target_rva:x}"),
                target_address: format!("{:x}", instruction.near_branch_target()),
                target_function: candidate_name(pe.base, target_rva, target),
                kind: "direct_call_candidate",
            });
        }
        if analysis.scanned_bytes >= MAX_XREF_SCAN_BYTES {
            analysis.truncated = true;
            break;
        }
    }
    Ok((rows, analysis))
}
fn insert<'a>(
    candidates: &'a mut BTreeMap<u32, Candidate>,
    rva: u32,
    diagnostics: &mut Diagnostics,
) -> Option<&'a mut Candidate> {
    if !candidates.contains_key(&rva) && candidates.len() >= MAX_FUNCTIONS {
        diagnostics.truncated = true;
        return None;
    }
    Some(candidates.entry(rva).or_insert_with(|| Candidate {
        name: None,
        end: None,
        conflict: false,
        evidence: vec![],
    }))
}
type RuntimeRow = (u32, u32, u32);
const MAX_UNWIND_CHAIN: usize = 64;

fn unwind_owner(
    pe: &Pe<'_>,
    mut row: RuntimeRow,
    rows: &BTreeSet<RuntimeRow>,
) -> Result<Option<u32>, ()> {
    let mut seen = Vec::new();
    let mut frame = None;
    let mut chained = false;
    for _ in 0..MAX_UNWIND_CHAIN {
        if seen.contains(&row) {
            return Err(());
        }
        seen.push(row);
        let Some(header) = pe.region(row.2, 4, false) else {
            return if chained { Err(()) } else { Ok(None) };
        };
        let version = header[0] & 7;
        if ![1, 2].contains(&version) {
            return if chained { Err(()) } else { Ok(None) };
        }
        let flags = header[0] >> 3;
        if let Some(frame) = frame {
            if header[3] != frame {
                return Err(());
            }
        }
        frame = Some(header[3]);
        if flags & 4 == 0 {
            return Ok(Some(row.0));
        }
        if flags != 4 || row.2 & 3 != 0 {
            return Err(());
        }
        chained = true;
        let offset = 4 + ((u32::from(header[2]) + 1) & !1) * 2;
        let tail = row
            .2
            .checked_add(offset)
            .and_then(|at| pe.region(at, 12, false))
            .ok_or(())?;
        row = (
            dword(tail, 0).map_err(|_| ())?,
            dword(tail, 4).map_err(|_| ())?,
            dword(tail, 8).map_err(|_| ())?,
        );
        if !rows.contains(&row) {
            return Err(());
        }
    }
    Err(())
}

fn merge_unwind_fragments(
    pe: &Pe<'_>,
    rows: &BTreeSet<RuntimeRow>,
    candidates: &mut BTreeMap<u32, Candidate>,
    diagnostics: &mut Diagnostics,
    cancel: &AtomicBool,
) -> Result<(), String> {
    let mut groups: BTreeMap<u32, Vec<(u32, u32)>> = BTreeMap::new();
    for (index, &row) in rows.iter().enumerate() {
        if index % 1024 == 0 && cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        if !candidates.contains_key(&row.0) {
            continue;
        }
        match unwind_owner(pe, row, rows) {
            Ok(Some(owner)) => groups.entry(owner).or_default().push((row.0, row.1)),
            Ok(None) => (),
            Err(()) => {
                diagnostics.invalid_unwind_chains += 1;
                if let Some(item) = candidates.get_mut(&row.0) {
                    item.end = None;
                    item.evidence
                        .push("invalid or unsupported unwind chain; complete extent unknown");
                }
            }
        }
    }
    for (owner, mut parts) in groups {
        if parts.len() < 2 {
            continue;
        }
        parts.sort_unstable();
        parts.dedup();
        if parts
            .iter()
            .any(|part| candidates.get(&part.0).is_some_and(|item| item.conflict))
        {
            for &(begin, _) in &parts {
                if let Some(item) = candidates.get_mut(&begin) {
                    item.end = None;
                    item.evidence
                        .push("conflicting chained fragment; complete owner extent unknown");
                }
            }
            continue;
        }
        let contiguous = parts.first().is_some_and(|part| part.0 == owner)
            && parts.windows(2).all(|pair| pair[0].1 == pair[1].0);
        if !contiguous {
            diagnostics.noncontiguous_chained_functions += 1;
            for &(begin, _) in &parts {
                if let Some(item) = candidates.get_mut(&begin) {
                    item.end = None;
                    item.evidence.push(
                        "noncontiguous chained function; range selection requires all fragments",
                    );
                }
            }
            continue;
        }
        let end = parts.last().unwrap().1;
        if pe.region(owner, (end - owner) as usize, true).is_none() {
            for &(begin, _) in &parts {
                if let Some(item) = candidates.get_mut(&begin) {
                    item.end = None;
                    item.evidence.push(
                        "chained aggregate crosses mapped regions; complete extent unavailable",
                    );
                }
            }
            continue;
        }
        if let Some(item) = candidates.get_mut(&owner) {
            item.end = Some(end);
            item.evidence
                .push("contiguous fragments joined by validated chained UNWIND_INFO");
        }
        for &(begin, _) in parts.iter().skip(1) {
            candidates.remove(&begin);
            diagnostics.merged_chained_fragments += 1;
        }
    }
    Ok(())
}

fn index(
    pe: &Pe<'_>,
    cancel: &AtomicBool,
) -> Result<(BTreeMap<u32, Candidate>, Diagnostics), String> {
    let mut candidates = BTreeMap::new();
    let mut diagnostics = Diagnostics { unbacked_virtual_sections: pe.sections.iter().filter(|section|section.size==0&&section.virtual_size>0).map(|section|UnbackedSection{ name:section.name.clone(),rva:format!("0x{:x}",section.rva),virtual_size:section.virtual_size,executable:section.executable,interpretation:"Virtual range has no raw file bytes; not decoded or filled with invented zero instructions. Executable content may require unpacking; zero-backed data sections alone do not prove packing." }).collect(), ..Diagnostics::default() };
    let mut runtime_rows = BTreeSet::new();
    let (runtime_rva, runtime_size) = pe.runtime;
    if runtime_rva != 0 && runtime_size != 0 {
        let count = runtime_size as usize / 12;
        if runtime_size % 12 != 0 {
            diagnostics
                .malformed_directories
                .push("exception directory trailing bytes");
        }
        diagnostics.truncated |= count > MAX_RUNTIME_ROWS;
        for row in 0..count.min(MAX_RUNTIME_ROWS) {
            if row % 1024 == 0 && cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            diagnostics.runtime_rows_examined += 1;
            let record = runtime_rva
                .checked_add((row * 12) as u32)
                .and_then(|rva| pe.region(rva, 12, false));
            let Some(record) = record else {
                diagnostics.invalid_runtime_rows += 1;
                continue;
            };
            let begin = dword(record, 0)?;
            let end = dword(record, 4)?;
            if end <= begin || pe.region(begin, (end - begin) as usize, true).is_none() {
                diagnostics.invalid_runtime_rows += 1;
                continue;
            }
            runtime_rows.insert((begin, end, dword(record, 8)?));
            if let Some(item) = insert(&mut candidates, begin, &mut diagnostics) {
                if item
                    .evidence
                    .contains(&"PE exception directory RUNTIME_FUNCTION")
                {
                    diagnostics.duplicate_runtime_rows += 1;
                    if item.end != Some(end) {
                        item.conflict = true;
                        item.end = None;
                    }
                } else {
                    item.end = Some(end);
                    item.evidence
                        .push("PE exception directory RUNTIME_FUNCTION");
                }
            }
        }
    }
    merge_unwind_fragments(pe, &runtime_rows, &mut candidates, &mut diagnostics, cancel)?;
    let (export_rva, export_size) = pe.exports;
    if export_rva != 0 && export_size != 0 {
        if let Some(header) = pe.region(export_rva, 40, false) {
            let function_count = dword(header, 20)? as usize;
            let name_count = dword(header, 24)? as usize;
            let functions_rva = dword(header, 28)?;
            let names_rva = dword(header, 32)?;
            let ordinals_rva = dword(header, 36)?;
            diagnostics.truncated |= function_count > MAX_EXPORTS || name_count > MAX_EXPORTS;
            for row in 0..name_count.min(MAX_EXPORTS) {
                if row % 1024 == 0 && cancel.load(Ordering::Relaxed) {
                    return Err("cancelled".into());
                }
                let parse = || -> Option<(u32, String)> {
                    let ordinal_record = ordinals_rva.checked_add((row * 2) as u32)?;
                    let ordinal = word(pe.region(ordinal_record, 2, false)?, 0).ok()? as usize;
                    if ordinal >= function_count || ordinal >= MAX_EXPORTS {
                        return None;
                    }
                    let address_record = functions_rva.checked_add((ordinal * 4) as u32)?;
                    let address = dword(pe.region(address_record, 4, false)?, 0).ok()?;
                    let name_record = names_rva.checked_add((row * 4) as u32)?;
                    let name_rva = dword(pe.region(name_record, 4, false)?, 0).ok()?;
                    Some((address, pe.export_name(name_rva)?))
                };
                let Some((rva, name)) = parse() else {
                    diagnostics.invalid_export_rows += 1;
                    continue;
                };
                if rva >= export_rva
                    && u64::from(rva) < u64::from(export_rva) + u64::from(export_size)
                {
                    diagnostics.forwarded_exports += 1;
                    continue;
                }
                if pe.region(rva, 1, true).is_none() {
                    diagnostics.invalid_export_rows += 1;
                    continue;
                }
                if let Some(item) = insert(&mut candidates, rva, &mut diagnostics) {
                    if item.name.is_none() {
                        item.name = Some(name);
                    }
                    if !item.evidence.contains(&"PE named export") {
                        item.evidence.push("PE named export");
                    }
                }
            }
        } else {
            diagnostics
                .malformed_directories
                .push("unmapped export directory");
        }
    }
    if pe.entry != 0 && pe.region(pe.entry, 1, true).is_some() {
        if let Some(item) = insert(&mut candidates, pe.entry, &mut diagnostics) {
            if item.name.is_none() {
                item.name = Some("entry".into());
            }
            item.evidence.push("PE AddressOfEntryPoint");
        }
    }
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    Ok((candidates, diagnostics))
}

pub fn build(input: &Path, output: &Path, cancel: &AtomicBool) -> Result<usize, String> {
    let input = fs::canonicalize(input).map_err(|e| e.to_string())?;
    if fs::metadata(&input).map_err(|e| e.to_string())?.len() > MAX_INPUT_BYTES {
        return Err("native index input exceeds 256 MiB".into());
    }
    let bytes = fs::read(&input).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("native index input exceeds 256 MiB".into());
    }
    let pe = Pe::parse(&bytes)?;
    let (candidates, diagnostics) = index(&pe, cancel)?;
    if candidates.is_empty() {
        return Err(
            "no executable PE export, entry point or valid runtime function range found".into(),
        );
    }
    let input_sha256 = crate::project::sha256(&input)?;
    if input_sha256 != format!("{:x}", Sha256::digest(&bytes)) {
        return Err("native input changed while metadata was indexed".into());
    }
    let (call_xrefs, xref_analysis) = call_xrefs(&pe, &candidates, cancel)?;
    fs::create_dir_all(output).map_err(|e| e.to_string())?;
    let source_name = "source/native_function_index.c";
    fs::create_dir_all(output.join("source")).map_err(|e| e.to_string())?;
    let mut text = String::from(
        "/* UIE lazy native function index. Function bodies are not decompiled yet. */\n",
    );
    let mut line = 2usize;
    let mut functions = Vec::with_capacity(candidates.len());
    for (rva, item) in candidates {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let address = format!("{:x}", pe.base + u64::from(rva));
        let name = item.name.unwrap_or_else(|| format!("FUN_{address}"));
        let header_name = name.replace("*/", "* /");
        let first_line = line + 1;
        writeln!(text, "\n/* Function at {address}: {header_name} */\n/* Deferred: select this function to request native pseudocode. */").map_err(|e|e.to_string())?;
        line += 3;
        functions.push(IndexedFunction {
            name,
            address,
            end: item
                .end
                .map(|end| format!("{:x}", pe.base + u64::from(end))),
            rva: format!("0x{rva:x}"),
            line: first_line,
            lazy: true,
            success: false,
            extent_unknown: item.end.is_none(),
            range_conflict: item.conflict,
            evidence: item.evidence,
        });
    }
    let count = functions.len();
    let report = serde_json::json!({
        "source_file":source_name,"lazy":true,"indexed":count,"decompiled":0,"failed":0,
        "filtered_runtime":0,"functions":functions,"diagnostics":diagnostics,
        "native_input":input,"native_input_sha256":input_sha256,
        "call_xrefs":call_xrefs,"xref_analysis":xref_analysis,
        "recovery_contract":{
            "output_kind":"PE metadata function index; not decompiled source",
            "original_python_recovered":false,"functional_equivalence_verified":false,
            "range_metadata_is_not_proof_of_valid_code":true,
            "function_extents_not_guessed":true
        }
    });
    fs::write(output.join(source_name), text).map_err(|e| e.to_string())?;
    fs::write(
        output.join("native-report.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires the local static I18n PE fixture via UIE_CHAIN_SAMPLE"]
    fn real_cython_initializer_joins_all_nine_unwind_regions() {
        let input = std::env::var_os("UIE_CHAIN_SAMPLE").expect("UIE_CHAIN_SAMPLE");
        let bytes = fs::read(input).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            "3b9178da9ffd2940ffcba367fa68ed408b43d6cdfb15177a41fbd34b92fbb182"
        );
        let (functions, diagnostics) =
            index(&Pe::parse(&bytes).unwrap(), &AtomicBool::new(false)).unwrap();
        assert_eq!(functions[&0x2eb0].end, Some(0x4e63));
        for begin in [
            0x2f2a, 0x2f32, 0x2f47, 0x2f4f, 0x2f57, 0x2f5f, 0x2f67, 0x2f6f,
        ] {
            assert!(
                !functions.contains_key(&begin),
                "fragment {begin:x} indexed separately"
            );
        }
        assert!(diagnostics.merged_chained_fragments >= 8);
    }

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
        bytes[0xa8..0xac].copy_from_slice(&0x1010u32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&4u32.to_le_bytes());
        bytes[0x120..0x124].copy_from_slice(&0x1300u32.to_le_bytes());
        bytes[0x124..0x128].copy_from_slice(&36u32.to_le_bytes());
        let section = 0x188;
        for (at, value) in [
            (8, 0x600u32),
            (12, 0x1000),
            (16, 0x600),
            (20, 0x200),
            (36, 0x60000020),
        ] {
            bytes[section + at..section + at + 4].copy_from_slice(&value.to_le_bytes());
        }
        for (index, (begin, end)) in [(0x1010u32, 0x1020u32), (0x1030, 0x1020), (0x1040, 0x1060)]
            .into_iter()
            .enumerate()
        {
            let at = 0x500 + index * 12;
            bytes[at..at + 4].copy_from_slice(&begin.to_le_bytes());
            bytes[at + 4..at + 8].copy_from_slice(&end.to_le_bytes());
        }
        bytes
    }
    fn chain_fixture(gap: bool, cycle: bool) -> Vec<u8> {
        let mut bytes = fixture();
        bytes[0x124..0x128].copy_from_slice(&24u32.to_le_bytes());
        for (index, (begin, end, unwind)) in [
            (0x1010u32, 0x1020u32, 0x1400u32),
            (
                if gap { 0x1040 } else { 0x1020 },
                if gap { 0x1050 } else { 0x1030 },
                0x1410,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            for (offset, value) in [(0, begin), (4, end), (8, unwind)] {
                bytes[0x500 + index * 12 + offset..0x504 + index * 12 + offset]
                    .copy_from_slice(&value.to_le_bytes());
            }
        }
        bytes[0x600] = 1;
        bytes[0x610] = 0x21;
        let chained = if cycle {
            (0x1020u32, 0x1030u32, 0x1410u32)
        } else {
            (0x1010, 0x1020, 0x1400)
        };
        for (offset, value) in [(0, chained.0), (4, chained.1), (8, chained.2)] {
            bytes[0x614 + offset..0x618 + offset].copy_from_slice(&value.to_le_bytes());
        }
        bytes
    }
    #[test]
    fn contiguous_chained_unwind_regions_form_one_complete_function() {
        let bytes = chain_fixture(false, false);
        let (functions, diagnostics) =
            index(&Pe::parse(&bytes).unwrap(), &AtomicBool::new(false)).unwrap();
        assert_eq!(functions.len(), 1);
        assert_eq!(functions[&0x1010].end, Some(0x1030));
        assert_eq!(diagnostics.merged_chained_fragments, 1);
    }
    #[test]
    fn conflicting_child_invalidates_its_complete_owner_extent() {
        let mut bytes = chain_fixture(false, false);
        bytes[0x124..0x128].copy_from_slice(&36u32.to_le_bytes());
        for (offset, value) in [(0, 0x1020u32), (4, 0x1040), (8, 0x1410)] {
            bytes[0x518 + offset..0x51c + offset].copy_from_slice(&value.to_le_bytes());
        }
        let (functions, diagnostics) =
            index(&Pe::parse(&bytes).unwrap(), &AtomicBool::new(false)).unwrap();
        assert!(functions[&0x1020].conflict);
        assert_eq!(functions[&0x1010].end, None);
        assert_eq!(diagnostics.merged_chained_fragments, 0);
    }
    #[test]
    fn chained_aggregate_across_sections_is_not_a_complete_fragment() {
        let mut bytes = chain_fixture(false, false);
        bytes[0x86..0x88].copy_from_slice(&2u16.to_le_bytes());
        for offset in [8, 16] {
            bytes[0x188 + offset..0x18c + offset].copy_from_slice(&0x20u32.to_le_bytes());
        }
        for (offset, value) in [
            (8, 0x5e0u32),
            (12, 0x1020),
            (16, 0x5e0),
            (20, 0x220),
            (36, 0x60000020),
        ] {
            bytes[0x1b0 + offset..0x1b4 + offset].copy_from_slice(&value.to_le_bytes());
        }
        let (functions, diagnostics) =
            index(&Pe::parse(&bytes).unwrap(), &AtomicBool::new(false)).unwrap();
        assert_eq!(functions[&0x1010].end, None);
        assert_eq!(functions[&0x1020].end, None);
        assert_eq!(diagnostics.merged_chained_fragments, 0);
    }
    #[test]
    fn cyclic_and_noncontiguous_unwind_chains_do_not_invent_complete_ranges() {
        let bytes = chain_fixture(false, true);
        let (functions, diagnostics) =
            index(&Pe::parse(&bytes).unwrap(), &AtomicBool::new(false)).unwrap();
        assert_eq!(functions[&0x1020].end, None);
        assert_eq!(diagnostics.invalid_unwind_chains, 1);
        let bytes = chain_fixture(true, false);
        let (functions, diagnostics) =
            index(&Pe::parse(&bytes).unwrap(), &AtomicBool::new(false)).unwrap();
        assert_eq!(functions[&0x1010].end, None);
        assert_eq!(functions[&0x1040].end, None);
        assert_eq!(diagnostics.noncontiguous_chained_functions, 1);
    }
    #[test]
    fn metadata_index_keeps_good_ranges_when_another_runtime_row_is_bad() {
        let bytes = fixture();
        let (functions, diagnostics) =
            index(&Pe::parse(&bytes).unwrap(), &AtomicBool::new(false)).unwrap();
        assert_eq!(functions.len(), 2);
        assert_eq!(functions[&0x1010].end, Some(0x1020));
        assert_eq!(functions[&0x1010].name.as_deref(), Some("entry"));
        assert_eq!(diagnostics.invalid_runtime_rows, 1);
        assert_eq!(diagnostics.runtime_rows_examined, 3);
    }
    #[test]
    fn conflicting_ranges_and_unmapped_extents_are_not_guessed() {
        let mut bytes = fixture();
        bytes[0x518..0x51c].copy_from_slice(&0x1010u32.to_le_bytes());
        let (functions, _) = index(&Pe::parse(&bytes).unwrap(), &AtomicBool::new(false)).unwrap();
        assert!(functions[&0x1010].conflict);
        assert_eq!(functions[&0x1010].end, None);
        bytes[0x504..0x508].copy_from_slice(&0x8000u32.to_le_bytes());
        let (_, diagnostics) = index(&Pe::parse(&bytes).unwrap(), &AtomicBool::new(false)).unwrap();
        assert_eq!(diagnostics.invalid_runtime_rows, 2);
        assert!(index(&Pe::parse(&bytes).unwrap(), &AtomicBool::new(true)).is_err());
        bytes[0x188 + 20..0x188 + 24].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Pe::parse(&bytes).is_err());
    }

    #[test]
    fn direct_call_xrefs_keep_instruction_and_function_addresses_distinct() {
        let mut bytes = fixture();
        bytes[0x210] = 0x90;
        bytes[0x211] = 0xe8;
        bytes[0x212..0x216].copy_from_slice(&0x2ai32.to_le_bytes());
        bytes[0x216] = 0xc3;
        bytes[0x240] = 0xc3;
        let pe = Pe::parse(&bytes).unwrap();
        let (functions, _) = index(&pe, &AtomicBool::new(false)).unwrap();
        let (rows, analysis) = call_xrefs(&pe, &functions, &AtomicBool::new(false)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].from_function_rva, "0x1010");
        assert_eq!(rows[0].instruction_rva, "0x1011");
        assert_eq!(rows[0].target_rva, "0x1040");
        assert!(!analysis.indirect_calls_resolved);
    }
}
