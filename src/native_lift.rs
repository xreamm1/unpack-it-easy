use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};
mod constants;
mod cython_strings;
mod methods;
mod nuitka;
mod tables;
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap},
    fs,
    path::Path,
    sync::atomic::{AtomicBool, Ordering},
};

const MAX_FILE: u64 = 256 * 1024 * 1024;
const MAX_FUNCTIONS: usize = 4096;
const MAX_RUNTIME_ROWS: usize = 262_144;
const MAX_FUNCTION_BYTES: usize = 512;
const MAX_INSTRUCTIONS: usize = 128;

#[derive(Serialize)]
struct FunctionResult {
    name: String,
    rva: String,
    python_symbol: String,
    lifted: bool,
    reason: Option<String>,
}

#[derive(Serialize)]
pub struct Report {
    engine: &'static str,
    contract: &'static str,
    pub lifted: usize,
    skipped: usize,
    rejected_runtime_ranges: usize,
    functions: Vec<FunctionResult>,
}

struct Section {
    rva: u32,
    raw: usize,
    size: usize,
    mapped_size: usize,
    executable: bool,
}
struct Image<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
    export: (u32, u32),
    exception: (u32, u32),
    base: u64,
}
fn u16_at(bytes: &[u8], at: usize) -> Result<u16, String> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at.checked_add(2).ok_or("offset overflow")?)
            .ok_or("truncated PE")?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at.checked_add(4).ok_or("offset overflow")?)
            .ok_or("truncated PE")?
            .try_into()
            .unwrap(),
    ))
}
impl<'a> Image<'a> {
    fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.get(..2) != Some(b"MZ") {
            return Err("UIE native lift currently supports PE x64 only".into());
        }
        let pe = u32_at(bytes, 0x3c)? as usize;
        if bytes.get(pe..pe.checked_add(4).ok_or("offset overflow")?) != Some(b"PE\0\0")
            || u16_at(bytes, pe + 4)? != 0x8664
        {
            return Err("not an AMD64 PE".into());
        }
        let count = u16_at(bytes, pe + 6)? as usize;
        if count > 96 {
            return Err("PE section limit".into());
        }
        let optional = pe.checked_add(24).ok_or("offset overflow")?;
        let optional_size = u16_at(bytes, pe + 20)? as usize;
        if optional_size < 144 || u16_at(bytes, optional)? != 0x20b {
            return Err("invalid PE32+ optional header".into());
        }
        let directory_count = u32_at(bytes, optional + 108)?;
        let directory = |index: u32| -> Result<(u32, u32), String> {
            if index >= directory_count || (112 + index as usize * 8 + 8) > optional_size {
                return Ok((0, 0));
            }
            let at = optional + 112 + index as usize * 8;
            Ok((u32_at(bytes, at)?, u32_at(bytes, at + 4)?))
        };
        let mut sections = vec![];
        for index in 0..count {
            let at = optional
                .checked_add(optional_size)
                .and_then(|v| v.checked_add(index * 40))
                .ok_or("offset overflow")?;
            let raw = u32_at(bytes, at + 20)? as usize;
            let size = u32_at(bytes, at + 16)? as usize;
            if raw.checked_add(size).is_none_or(|end| end > bytes.len()) {
                return Err("PE section outside file".into());
            }
            sections.push(Section {
                rva: u32_at(bytes, at + 12)?,
                raw,
                size,
                mapped_size: size.max(u32_at(bytes, at + 8)? as usize),
                executable: u32_at(bytes, at + 36)? & 0x20000000 != 0,
            });
        }
        let base = u64::from_le_bytes(
            bytes
                .get(optional + 24..optional + 32)
                .ok_or("truncated image base")?
                .try_into()
                .unwrap(),
        );
        let image_size = u32_at(bytes, optional + 56)? as u64;
        base.checked_add(image_size)
            .ok_or("PE image address overflow")?;
        for section in &sections {
            let end = u64::from(section.rva)
                .checked_add(section.mapped_size as u64)
                .ok_or("PE section address overflow")?;
            if end > image_size {
                return Err("PE section exceeds image size".into());
            }
            base.checked_add(end).ok_or("PE section address overflow")?;
        }
        Ok(Self {
            bytes,
            sections,
            export: directory(0)?,
            exception: directory(3)?,
            base,
        })
    }
    fn data(&self, rva: u32, length: usize) -> Result<&'a [u8], String> {
        for section in &self.sections {
            if let Some(offset) = rva.checked_sub(section.rva).map(|v| v as usize) {
                if offset
                    .checked_add(length)
                    .is_some_and(|end| end <= section.size)
                {
                    return Ok(&self.bytes[section.raw + offset..section.raw + offset + length]);
                }
            }
        }
        Err("RVA is not backed by file data".into())
    }
    fn code(&self, rva: u32) -> Result<&'a [u8], String> {
        for section in &self.sections {
            if section.executable {
                if let Some(offset) = rva
                    .checked_sub(section.rva)
                    .map(|v| v as usize)
                    .filter(|v| *v < section.size)
                {
                    return Ok(&self.bytes[section.raw + offset
                        ..section.raw + (offset + MAX_FUNCTION_BYTES).min(section.size)]);
                }
            }
        }
        Err("function does not point into an executable section".into())
    }
    fn backed_code_range(&self, begin: u32, end: u32) -> bool {
        end > begin
            && self.sections.iter().any(|section| {
                section.executable
                    && begin.checked_sub(section.rva).is_some_and(|offset| {
                        (offset as usize)
                            .checked_add((end - begin) as usize)
                            .is_some_and(|limit| limit <= section.size)
                    })
            })
    }
    fn functions(&self) -> Result<(BTreeMap<u32, String>, usize), String> {
        let mut functions = BTreeMap::new();
        let mut rejected_runtime_ranges = 0;
        let (rva, size) = self.export;
        if rva != 0 && size != 0 {
            let directory = self.data(rva, 40)?;
            let function_count = u32_at(directory, 20)? as usize;
            let name_count = u32_at(directory, 24)? as usize;
            if function_count > MAX_FUNCTIONS || name_count > MAX_FUNCTIONS {
                return Err("PE export limit".into());
            }
            let addresses = self.data(u32_at(directory, 28)?, function_count * 4)?;
            let names = self.data(u32_at(directory, 32)?, name_count * 4)?;
            let ordinals = self.data(u32_at(directory, 36)?, name_count * 2)?;
            for index in 0..name_count {
                let ordinal = u16_at(ordinals, index * 2)? as usize;
                if ordinal >= function_count {
                    return Err("invalid export ordinal".into());
                }
                let address = u32_at(addresses, ordinal * 4)?;
                if address == 0
                    || (address >= rva && u64::from(address) < u64::from(rva) + u64::from(size))
                    || self.code(address).is_err()
                {
                    continue;
                }
                let name_rva = u32_at(names, index * 4)?;
                let mut name = vec![];
                for offset in 0..256u32 {
                    let byte =
                        self.data(name_rva.checked_add(offset).ok_or("name overflow")?, 1)?[0];
                    if byte == 0 {
                        break;
                    }
                    name.push(byte);
                }
                functions.insert(address, String::from_utf8_lossy(&name).into_owned());
            }
        }
        let (rva, size) = self.exception;
        if rva != 0 && size != 0 {
            if size % 12 != 0 || size as usize / 12 > MAX_RUNTIME_ROWS {
                return Err("PE runtime function table limit".into());
            }
            let table = self.data(rva, size as usize)?;
            for row in table.as_chunks::<12>().0 {
                let begin = u32_at(row, 0)?;
                let end = u32_at(row, 4)?;
                if !self.backed_code_range(begin, end) {
                    rejected_runtime_ranges += 1;
                    continue;
                }
                functions
                    .entry(begin)
                    .or_insert_with(|| format!("sub_{begin:x}"));
                if functions.len() > MAX_FUNCTIONS {
                    return Err("native lift backed function limit".into());
                }
            }
        }
        Ok((functions, rejected_runtime_ranges))
    }
}

fn register(register: Register) -> Result<(Register, u32), String> {
    let width = register.size() as u32 * 8;
    let full = register.full_register();
    if !matches!(width, 8 | 16 | 32 | 64)
        || !matches!(
            full,
            Register::RAX
                | Register::RCX
                | Register::RDX
                | Register::R8
                | Register::R9
                | Register::R10
                | Register::R11
        )
    {
        return Err(format!(
            "unsupported register {register:?}; only volatile scalar integer registers are lifted"
        ));
    }
    Ok((full, width))
}
fn mask(width: u32) -> u64 {
    if width == 64 {
        u64::MAX
    } else {
        (1u64 << width) - 1
    }
}
fn operand(
    instruction: &Instruction,
    index: u32,
    values: &HashMap<Register, String>,
) -> Result<String, String> {
    if instruction.op_kind(index) == OpKind::Register {
        let (full, width) = register(instruction.op_register(index))?;
        let value = values
            .get(&full)
            .ok_or_else(|| format!("read of undefined register {full:?}"))?;
        let shift = if matches!(
            instruction.op_register(index),
            Register::AH | Register::BH | Register::CH | Register::DH
        ) {
            8
        } else {
            0
        };
        return Ok(format!("(({value} >> {shift}) & 0x{:x})", mask(width)));
    }
    match instruction.op_kind(index) {
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to32
        | OpKind::Immediate8to16
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Ok(format!("0x{:x}", instruction.immediate(index))),
        other => Err(format!(
            "unsupported operand {other:?}; memory is not evaluated"
        )),
    }
}

pub fn lift(code: &[u8], rva: u32, symbol: &str) -> Result<String, String> {
    let mut decoder = Decoder::with_ip(64, code, u64::from(rva), DecoderOptions::NONE);
    let mut values: HashMap<_, _> = [
        (Register::RCX, "rcx"),
        (Register::RDX, "rdx"),
        (Register::R8, "r8"),
        (Register::R9, "r9"),
    ]
    .into_iter()
    .map(|(reg, name)| (reg, name.into()))
    .collect();
    let mut source = format!("def {symbol}(rcx=0, rdx=0, r8=0, r9=0):\n");
    for index in 0..MAX_INSTRUCTIONS {
        if !decoder.can_decode() {
            break;
        }
        let instruction = decoder.decode();
        if instruction.is_invalid()
            || instruction.has_lock_prefix()
            || instruction.has_rep_prefix()
            || instruction.has_repne_prefix()
            || instruction.has_segment_prefix()
        {
            return Err(format!(
                "invalid or prefixed instruction at 0x{:x}",
                instruction.ip()
            ));
        }
        match instruction.mnemonic() {
            Mnemonic::Nop | Mnemonic::Endbr64 => continue,
            Mnemonic::Ret if instruction.op_count() == 0 => {
                let value = values
                    .get(&Register::RAX)
                    .ok_or("return value depends on unspecified entry RAX")?;
                source.push_str(&format!("    return {value} & 0xffffffffffffffff\n\n"));
                return Ok(source);
            }
            _ => (),
        }
        if instruction.op0_kind() != OpKind::Register {
            return Err(format!(
                "unsupported {:?} at 0x{:x}",
                instruction.mnemonic(),
                instruction.ip()
            ));
        }
        let (destination, width) = register(instruction.op0_register())?;
        let value = match instruction.mnemonic() {
            Mnemonic::Mov | Mnemonic::Movzx => operand(&instruction, 1, &values)?,
            Mnemonic::Xor
                if instruction.op1_kind() == OpKind::Register
                    && instruction.op0_register() == instruction.op1_register() =>
            {
                "0".into()
            }
            Mnemonic::Add | Mnemonic::Sub | Mnemonic::And | Mnemonic::Or | Mnemonic::Xor => {
                let operation = match instruction.mnemonic() {
                    Mnemonic::Add => "+",
                    Mnemonic::Sub => "-",
                    Mnemonic::And => "&",
                    Mnemonic::Or => "|",
                    _ => "^",
                };
                format!(
                    "{} {operation} {}",
                    operand(&instruction, 0, &values)?,
                    operand(&instruction, 1, &values)?
                )
            }
            Mnemonic::Imul if instruction.op_count() == 3 => format!(
                "{} * {}",
                operand(&instruction, 1, &values)?,
                operand(&instruction, 2, &values)?
            ),
            Mnemonic::Imul if instruction.op_count() == 2 => format!(
                "{} * {}",
                operand(&instruction, 0, &values)?,
                operand(&instruction, 1, &values)?
            ),
            Mnemonic::Neg => format!("-{}", operand(&instruction, 0, &values)?),
            Mnemonic::Not => format!("~{}", operand(&instruction, 0, &values)?),
            Mnemonic::Inc | Mnemonic::Dec => format!(
                "{} {} 1",
                operand(&instruction, 0, &values)?,
                if instruction.mnemonic() == Mnemonic::Inc {
                    "+"
                } else {
                    "-"
                }
            ),
            Mnemonic::Shl | Mnemonic::Shr => format!(
                "{} {} ({} & {})",
                operand(&instruction, 0, &values)?,
                if instruction.mnemonic() == Mnemonic::Shl {
                    "<<"
                } else {
                    ">>"
                },
                operand(&instruction, 1, &values)?,
                if width == 64 { 63 } else { 31 }
            ),
            Mnemonic::Rol | Mnemonic::Ror => {
                let value = operand(&instruction, 0, &values)?;
                let count = format!("({} & {})", operand(&instruction, 1, &values)?, width - 1);
                let reverse = format!("(({width} - {count}) % {width})");
                if instruction.mnemonic() == Mnemonic::Rol {
                    format!("({value} << {count}) | ({value} >> {reverse})")
                } else {
                    format!("({value} >> {count}) | ({value} << {reverse})")
                }
            }
            Mnemonic::Lea => {
                if instruction.is_ip_rel_memory_operand()
                    || !matches!(
                        instruction.memory_size(),
                        iced_x86::MemorySize::Unknown
                            | iced_x86::MemorySize::UInt64
                            | iced_x86::MemorySize::UInt32
                    )
                {
                    return Err("address-dependent LEA is unsupported".into());
                }
                let mut terms = vec![format!("0x{:x}", instruction.memory_displacement64())];
                for (reg, scale) in [
                    (instruction.memory_base(), 1),
                    (instruction.memory_index(), instruction.memory_index_scale()),
                ] {
                    if reg == Register::None {
                        continue;
                    }
                    let (full, bits) = register(reg)?;
                    if bits != 64 {
                        return Err("32-bit address-size LEA is unsupported".into());
                    }
                    let value = values.get(&full).ok_or("LEA reads an undefined register")?;
                    terms.push(format!("({value} * {scale})"));
                }
                terms.join(" + ")
            }
            other => {
                return Err(format!(
                    "unsupported {other:?} at 0x{:x}; no partial Python was emitted",
                    instruction.ip()
                ))
            }
        };
        let variable = format!("v{index}");
        if width < 32 {
            let previous = values
                .get(&destination)
                .ok_or("partial write depends on unspecified upper register bits")?;
            let shift = if matches!(
                instruction.op0_register(),
                Register::AH | Register::BH | Register::CH | Register::DH
            ) {
                8
            } else {
                0
            };
            let retained = !(mask(width) << shift);
            source.push_str(&format!("    {variable} = ({previous} & 0x{retained:x}) | ((({value}) & 0x{:x}) << {shift})\n", mask(width)));
        } else {
            source.push_str(&format!(
                "    {variable} = ({value}) & 0x{:x}\n",
                mask(width)
            ));
        }
        values.insert(destination, variable);
    }
    Err("no complete return within the instruction/byte budget".into())
}

pub fn analyze(input: &Path, output: &Path, cancel: &AtomicBool) -> Result<Report, String> {
    if fs::metadata(input).map_err(|e| e.to_string())?.len() > MAX_FILE {
        return Err("native lift file limit: 256 MiB".into());
    }
    let bytes = fs::read(input).map_err(|e| e.to_string())?;
    let image = Image::parse(&bytes)?;
    let (mut functions, rejected_runtime_ranges) = image.functions()?;
    let entry = u32_at(&bytes, u32_at(&bytes, 0x3c)? as usize + 40)?;
    if entry != 0 && image.code(entry).is_ok() {
        functions
            .entry(entry)
            .or_insert_with(|| "entry_point".into());
    }
    let modules = nuitka::scan(&image, cancel)?;
    let methods = methods::scan(&image, cancel)?;
    for method in &methods.methods {
        functions
            .entry(method.function_rva)
            .or_insert_with(|| format!("py_method_{}_{:x}", method.name, method.function_rva));
    }
    for entry in &modules.entries {
        functions
            .entry(entry.init_rva)
            .or_insert_with(|| format!("modulecode_{}", entry.name.replace('.', "_")));
    }
    let folded = constants::analyze(&image, &functions, cancel)?;
    let tables = tables::scan(&image, cancel)?;
    let mut report = Report { engine: "UIE Rust scalar lifter / iced-x86 decoder", contract: "Partial machine-level reconstruction, not original Python or C source. PE AMD64 Windows register ABI; unsigned scalar register inputs and raw RAX output only. No calls, memory dereferences, branches or implicit entry-register values. Flags and other observable machine state are outside this contract. Static translation, functional equivalence unverified until independently tested.", lifted: 0, skipped: 0, rejected_runtime_ranges, functions: vec![] };
    let mut python = String::from("# UIE machine-level scalar reconstruction; NOT original application source.\n# Inputs: raw Windows x64 RCX, RDX, R8, R9. Output: raw RAX.\n# Only complete supported functions are included. See native-lift-report.json.\n\n");
    for (rva, name) in functions {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let symbol = format!("uie_{rva:x}");
        let result = image.code(rva).and_then(|code| lift(code, rva, &symbol));
        let reason = match result {
            Ok(source) => {
                python.push_str(&format!("# export/function: {}\n", name.escape_default()));
                python.push_str(&source);
                report.lifted += 1;
                None
            }
            Err(error) => {
                report.skipped += 1;
                Some(error)
            }
        };
        report.functions.push(FunctionResult {
            name,
            rva: format!("0x{rva:x}"),
            python_symbol: symbol,
            lifted: reason.is_none(),
            reason,
        });
    }
    fs::create_dir_all(output).map_err(|e| e.to_string())?;
    fs::write(
        output.join("native-tables-report.json"),
        serde_json::to_vec_pretty(&tables).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let cython_literals = cython_strings::scan(&image, cancel)?;
    fs::write(
        output.join("cython-strings-report.json"),
        serde_json::to_vec_pretty(&cython_literals).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        output.join("python-methods-report.json"),
        serde_json::to_vec_pretty(&methods).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if modules.marker_found {
        fs::write(
            output.join("nuitka-modules-report.json"),
            serde_json::to_vec_pretty(&modules).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
    }
    fs::write(
        output.join("native-constants-report.json"),
        serde_json::to_vec_pretty(&folded).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        output.join("native-lift-report.json"),
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if report.lifted > 0 {
        fs::create_dir_all(output.join("source")).map_err(|e| e.to_string())?;
        fs::write(
            output.join("source/native_scalar_reconstruction.py"),
            python,
        )
        .map_err(|e| e.to_string())?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packed_runtime_rows_do_not_hide_the_remaining_backed_functions() {
        let count = MAX_FUNCTIONS + 10;
        let mut bytes = vec![0u8; 16 + count * 12];
        bytes[..5].copy_from_slice(&[0x8b, 0xc1, 0x03, 0xc2, 0xc3]);
        for row in bytes[16..].as_chunks_mut::<12>().0 {
            row[..4].copy_from_slice(&0x5000u32.to_le_bytes());
            row[4..8].copy_from_slice(&0x5005u32.to_le_bytes());
        }
        let last = 16 + (count - 1) * 12;
        bytes[last..last + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        bytes[last + 4..last + 8].copy_from_slice(&0x1005u32.to_le_bytes());
        let mut image = Image {
            bytes: &bytes,
            sections: vec![
                Section {
                    rva: 0x1000,
                    raw: 0,
                    size: 16,
                    mapped_size: 16,
                    executable: true,
                },
                Section {
                    rva: 0x2000,
                    raw: 16,
                    size: count * 12,
                    mapped_size: count * 12,
                    executable: false,
                },
            ],
            export: (0, 0),
            exception: (0x2000, (count * 12) as u32),
            base: 0x180000000,
        };
        let (functions, rejected) = image.functions().unwrap();
        assert_eq!(rejected, count - 1);
        assert_eq!(functions.len(), 1);
        assert!(functions.contains_key(&0x1000));
        assert!(lift(image.code(0x1000).unwrap(), 0x1000, "sum").is_ok());
        image.sections.push(Section {
            rva: 0x1000,
            raw: 16,
            size: 128,
            mapped_size: 128,
            executable: false,
        });
        assert!(image.data(0x1000, 128).is_ok());
        assert!(!image.backed_code_range(0x1000, 0x1080));
    }

    #[test]
    fn unbacked_exports_do_not_consume_the_lifting_budget() {
        let count = MAX_FUNCTIONS;
        let mut bytes = vec![0u8; 16 + 0xb000];
        let mut put = |rva: usize, value: u32| {
            let at = 16 + rva - 0x2000;
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        for (offset, value) in [
            (20, count as u32),
            (24, count as u32),
            (28, 0x2040),
            (32, 0x6040),
            (36, 0xa040),
        ] {
            put(0x2000 + offset, value);
        }
        for index in 0..count {
            put(0x2040 + index * 4, 0x100000 + index as u32 * 16);
            put(0x6040 + index * 4, 0xc040);
        }
        put(0xc060, 0x1000);
        put(0xc064, 0x1005);
        for index in 0..count {
            let at = 16 + 0xa040 - 0x2000 + index * 2;
            bytes[at..at + 2].copy_from_slice(&(index as u16).to_le_bytes());
        }
        bytes[16 + 0xc040 - 0x2000..16 + 0xc046 - 0x2000].copy_from_slice(b"ghost\0");
        let image = Image {
            bytes: &bytes,
            sections: vec![
                Section {
                    rva: 0x1000,
                    raw: 0,
                    size: 16,
                    mapped_size: 16,
                    executable: true,
                },
                Section {
                    rva: 0x2000,
                    raw: 16,
                    size: 0xb000,
                    mapped_size: 0xb000,
                    executable: false,
                },
            ],
            export: (0x2000, 40),
            exception: (0xc060, 12),
            base: 0x180000000,
        };
        let (functions, rejected) = image.functions().unwrap();
        assert_eq!(rejected, 0);
        assert_eq!(functions.len(), 1);
        assert!(functions.contains_key(&0x1000));
    }

    #[test]
    fn arithmetic_is_width_aware_and_no_unknown_code_is_fabricated() {
        let source = lift(&[0x8b, 0xc1, 0x03, 0xc2, 0xc3], 0x1000, "sum").unwrap();
        assert!(source.contains("& 0xffffffff"));
        assert!(source.contains("return v1"));
        for code in [
            &[0xe8, 0, 0, 0, 0, 0xc3][..],
            &[0x48, 0x8b, 0x01, 0xc3],
            &[0x74, 0x00, 0xc3],
            &[0xc3],
            &[0x48, 0x83, 0xc0, 1, 0xc3],
        ] {
            assert!(lift(code, 0x1000, "rejected").is_err());
        }
    }
    #[test]
    fn truncated_images_are_rejected_without_panics() {
        for length in 0..512 {
            let mut data = vec![0; length];
            if length >= 2 {
                data[..2].copy_from_slice(b"MZ");
            }
            assert!(Image::parse(&data).is_err());
        }
    }
}
