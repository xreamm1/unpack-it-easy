use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, Mnemonic, OpKind, Register};
use regex::Regex;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
    fs::File,
    io::Read,
    path::Path,
};

const MAX_INPUT: usize = 256 * 1024 * 1024;
const MAX_C_SOURCE: usize = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 8192;
const MAX_LITERAL: usize = 65536;
const MAX_TEXT: usize = 4 * 1024 * 1024;
const MAX_CFG: usize = 32768;
const MAX_LOOP_STEPS: usize = 256;

struct Section {
    rva: u32,
    raw: usize,
    size: usize,
    mapped: usize,
    flags: u32,
}
struct Image {
    bytes: Vec<u8>,
    base: u64,
    sections: Vec<Section>,
    imports: HashMap<u64, String>,
}
fn number(bytes: &[u8], at: usize, size: usize) -> Result<u64, String> {
    let bytes = bytes
        .get(at..at.checked_add(size).ok_or("offset overflow")?)
        .ok_or("truncated PE")?;
    if size > 8 {
        return Err("invalid integer width".into());
    }
    Ok(bytes.iter().enumerate().fold(0, |value, (index, byte)| {
        value | (u64::from(*byte) << (index * 8))
    }))
}
fn read(path: &Path, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = vec![];
    File::open(path)
        .map_err(|error| error.to_string())?
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > limit {
        return Err(format!("input exceeds {limit} bytes"));
    }
    Ok(bytes)
}
impl Image {
    fn parse(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.get(..2) != Some(b"MZ") {
            return Err("Cython slots require an AMD64 PE file".into());
        }
        let pe = number(&bytes, 0x3c, 4)? as usize;
        if bytes.get(pe..pe.checked_add(4).ok_or("offset overflow")?) != Some(b"PE\0\0")
            || number(&bytes, pe + 4, 2)? != 0x8664
        {
            return Err("not an AMD64 PE".into());
        }
        let count = number(&bytes, pe + 6, 2)? as usize;
        if count > 96 {
            return Err("PE section limit".into());
        }
        let optional = pe.checked_add(24).ok_or("offset overflow")?;
        let optional_size = number(&bytes, pe + 20, 2)? as usize;
        if optional_size < 128 || number(&bytes, optional, 2)? != 0x20b {
            return Err("invalid PE32+ optional header".into());
        }
        let base = number(&bytes, optional + 24, 8)?;
        let import_rva = if number(&bytes, optional + 108, 4)? >= 2 {
            number(&bytes, optional + 120, 4)?
        } else {
            0
        };
        let mut sections = vec![];
        for index in 0..count {
            let at = optional
                .checked_add(optional_size)
                .and_then(|value| value.checked_add(index * 40))
                .ok_or("offset overflow")?;
            let size = number(&bytes, at + 16, 4)? as usize;
            let raw = number(&bytes, at + 20, 4)? as usize;
            if raw.checked_add(size).is_none_or(|end| end > bytes.len()) {
                return Err("section outside PE file".into());
            }
            sections.push(Section {
                rva: number(&bytes, at + 12, 4)? as u32,
                raw,
                size,
                mapped: size.max(number(&bytes, at + 8, 4)? as usize),
                flags: number(&bytes, at + 36, 4)? as u32,
            });
        }
        let mut image = Self {
            bytes,
            base,
            sections,
            imports: HashMap::new(),
        };
        if import_rva != 0 {
            let mut imported = 0;
            for descriptor in 0..256u64 {
                let at = base
                    .checked_add(import_rva)
                    .and_then(|v| v.checked_add(descriptor * 20))
                    .ok_or("import overflow")?;
                let row = image.data(at, 20)?;
                if row.iter().all(|byte| *byte == 0) {
                    break;
                }
                let original = number(row, 0, 4)?;
                let first = number(row, 16, 4)?;
                if first == 0 {
                    return Err("missing import address table".into());
                }
                let lookup = if original == 0 { first } else { original };
                for index in 0..8192u64 {
                    imported += 1;
                    if imported > 32768 {
                        return Err("PE import budget reached".into());
                    }
                    let value = image.integer(
                        base.checked_add(lookup)
                            .and_then(|v| v.checked_add(index * 8))
                            .ok_or("import overflow")?,
                        8,
                    )?;
                    if value == 0 {
                        break;
                    }
                    if value >> 63 != 0 {
                        continue;
                    }
                    let address = base
                        .checked_add(value)
                        .and_then(|v| v.checked_add(2))
                        .ok_or("import name overflow")?;
                    let mut name = vec![];
                    for offset in 0..256 {
                        let byte = image.integer(
                            address.checked_add(offset).ok_or("import name overflow")?,
                            1,
                        )? as u8;
                        if byte == 0 {
                            break;
                        }
                        name.push(byte);
                    }
                    let name = String::from_utf8(name).map_err(|_| "invalid import name")?;
                    image.imports.insert(base + first + index * 8, name);
                }
            }
        }
        Ok(image)
    }
    fn section(&self, address: u64, size: usize, mapped: bool) -> Option<&Section> {
        let rva = address.checked_sub(self.base)?;
        self.sections.iter().find(|section| {
            rva.checked_sub(u64::from(section.rva))
                .and_then(|offset| offset.checked_add(size as u64))
                .is_some_and(|end| end <= if mapped { section.mapped } else { section.size } as u64)
        })
    }
    fn data(&self, address: u64, size: usize) -> Result<&[u8], String> {
        let section = self
            .section(address, size, false)
            .ok_or("address is not backed by file bytes")?;
        let at = section.raw + (address - self.base - u64::from(section.rva)) as usize;
        Ok(&self.bytes[at..at + size])
    }
    fn integer(&self, address: u64, size: usize) -> Result<u64, String> {
        number(self.data(address, size)?, 0, size)
    }
    fn readonly(&self, address: u64, size: usize) -> bool {
        self.section(address, size, false)
            .is_some_and(|section| section.flags & 0xe0000000 == 0x40000000)
    }
    fn writable(&self, address: u64, size: usize) -> bool {
        self.section(address, size, true)
            .is_some_and(|section| section.flags & 0xa0000000 == 0x80000000)
    }
    fn instruction(&self, ip: u64) -> Option<Instruction> {
        let section = self.section(ip, 1, false)?;
        if section.flags & 0x20000000 == 0 {
            return None;
        }
        let at = section.raw + (ip - self.base - u64::from(section.rva)) as usize;
        let end = (at + 15).min(section.raw + section.size);
        let instruction =
            Decoder::with_ip(64, &self.bytes[at..end], ip, DecoderOptions::NONE).decode();
        (!instruction.is_invalid()).then_some(instruction)
    }
    fn cfg(&self, entry: u64) -> Result<BTreeMap<u64, Instruction>, String> {
        let mut result = BTreeMap::new();
        let mut pending = VecDeque::from([entry]);
        while let Some(mut ip) = pending.pop_front() {
            loop {
                if result.contains_key(&ip) {
                    break;
                }
                if result.len() >= MAX_CFG {
                    return Err("initializer CFG budget reached".into());
                }
                let Some(instruction) = self.instruction(ip) else {
                    break;
                };
                let flow = instruction.flow_control();
                result.insert(ip, instruction);
                match flow {
                    FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall => {
                        ip = instruction.next_ip()
                    }
                    FlowControl::ConditionalBranch => {
                        pending.push_back(instruction.near_branch_target());
                        ip = instruction.next_ip();
                    }
                    FlowControl::UnconditionalBranch if instruction.is_jmp_short_or_near() => {
                        ip = instruction.near_branch_target()
                    }
                    _ => break,
                }
            }
        }
        Ok(result)
    }
}

fn mask_c(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut result = bytes.to_vec();
    let mut at = 0;
    while at < bytes.len() {
        let begin = at;
        if bytes[at] == b'/' && bytes.get(at + 1) == Some(&b'/') {
            at += 2;
            while at < bytes.len() && bytes[at] != b'\n' {
                at += 1;
            }
        } else if bytes[at] == b'/' && bytes.get(at + 1) == Some(&b'*') {
            at += 2;
            while at + 1 < bytes.len() && &bytes[at..at + 2] != b"*/" {
                at += 1;
            }
            at = (at + 2).min(bytes.len());
        } else if matches!(bytes[at], b'"' | b'\'') {
            let quote = bytes[at];
            at += 1;
            while at < bytes.len() && bytes[at] != quote {
                if bytes[at] == b'\\' {
                    at += 1;
                }
                at = (at + 1).min(bytes.len());
            }
            at = (at + 1).min(bytes.len());
        } else {
            at += 1;
            continue;
        }
        for byte in &mut result[begin..at] {
            if !matches!(*byte, b'\r' | b'\n') {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(result).unwrap()
}
struct Candidate {
    function: u64,
    table: u64,
    slots: u64,
    line: usize,
}
fn candidates(source: &str) -> Result<Vec<Candidate>, String> {
    let header = Regex::new(r"(?m)^/\* Function at ([0-9a-fA-F]{1,16}): [^\r\n]+ \*/").unwrap();
    let headers: Vec<_> = header.captures_iter(source).collect();
    if headers.len() > 65536 {
        return Err("C function budget reached".into());
    }
    let begin_loop = Regex::new(r"\bdo\s*\{").unwrap();
    let tail = Regex::new(r"([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\+\s*2\s*;\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\+\s*1\s*;\s*$").unwrap();
    let flags = Regex::new(r"([A-Za-z_]\w*)\s*=\s*\*\s*\(\s*uint\s*\*\s*\)\s*\(\s*\(\s*(?:longlong|ulonglong)\s*\)\s*([A-Za-z_]\w*)\s*\+\s*(?:0xc|12)\s*\)\s*;").unwrap();
    let binding =
        Regex::new(r"\b([A-Za-z_]\w*)\s*=\s*&[A-Za-z_]\w*_([0-9A-Fa-f]{8,16})\s*;").unwrap();
    let assign = Regex::new(r"\b([A-Za-z_]\w*)\s*=").unwrap();
    let store = Regex::new(r"\*\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;").unwrap();
    let constructor = Regex::new(r"\b([A-Za-z_]\w*)\s*=\s*(PyBytes_FromStringAndSize|PyUnicode_FromStringAndSize|PyUnicode_Decode|PyUnicode_InternFromString)\s*\(").unwrap();
    let controls = Regex::new(r"\b(?:if|else|goto|while|for|return|switch|case)\b|[{}?:]").unwrap();
    let zero_test =
        Regex::new(r"^\s*while\s*\(\s*\*\s*([A-Za-z_]\w*)\s*!=\s*\([^)]*\)\s*(?:0x0|0)\s*\)\s*;")
            .unwrap();
    let masked = mask_c(source);
    let mut output = vec![];
    let mut attempts = 0usize;
    let mut scanned_braces = 0usize;
    for (index, capture) in headers.iter().enumerate() {
        let start = capture.get(0).unwrap().end();
        let end = headers
            .get(index + 1)
            .map_or(source.len(), |next| next.get(0).unwrap().start());
        let function =
            u64::from_str_radix(&capture[1], 16).map_err(|_| "bad C function address")?;
        let text = &masked[start..end];
        for open in begin_loop.find_iter(text) {
            attempts += 1;
            if attempts > 4096 {
                return Err("initializer loop attempt budget reached".into());
            }
            if output.len() >= 32 {
                return Err("initializer candidate budget reached".into());
            }
            let mut depth = 1usize;
            let mut close = open.end();
            let scan_end = text.len().min(open.end().saturating_add(16385));
            while close < scan_end && depth != 0 {
                scanned_braces += 1;
                if scanned_braces > 4 * 1024 * 1024 {
                    return Err("initializer brace scan budget reached".into());
                }
                if text.as_bytes()[close] == b'{' {
                    depth += 1;
                }
                if text.as_bytes()[close] == b'}' {
                    depth -= 1;
                }
                close += 1;
            }
            if depth != 0 {
                continue;
            }
            let body = &text[open.end()..close - 1];
            if body.len() > 16384 {
                continue;
            }
            let Some(tail) = tail.captures(body) else {
                continue;
            };
            let src = &tail[1];
            let dst = &tail[3];
            if src != &tail[2] || dst != &tail[4] || src == dst {
                continue;
            }
            let Some(condition) = zero_test.captures(&text[close..]) else {
                continue;
            };
            if &condition[1] != src {
                continue;
            }
            let loads: Vec<_> = flags
                .captures_iter(body)
                .filter(|load| &load[2] == src)
                .collect();
            if loads.len() != 1 {
                continue;
            }
            let stores: Vec<_> = store
                .captures_iter(body)
                .filter(|item| &item[1] == dst)
                .collect();
            if stores.len() != 1 {
                continue;
            }
            let value = &stores[0][2];
            let constructors: BTreeSet<_> = constructor
                .captures_iter(body)
                .filter(|call| &call[1] == value)
                .map(|call| call[2].to_string())
                .collect();
            if constructors.len() != 4 {
                continue;
            }
            let mut prelude_start = open.start().saturating_sub(4096);
            while !text.is_char_boundary(prelude_start) {
                prelude_start += 1;
            }
            let prelude = &text[prelude_start..open.start()];
            let src_bindings: Vec<_> = binding
                .captures_iter(prelude)
                .filter(|bind| &bind[1] == src)
                .collect();
            let dst_bindings: Vec<_> = binding
                .captures_iter(prelude)
                .filter(|bind| &bind[1] == dst)
                .collect();
            if src_bindings.len() != 1 || dst_bindings.len() != 1 {
                continue;
            }
            let a = &src_bindings[0];
            let b = &dst_bindings[0];
            let first = a.get(0).unwrap().start().min(b.get(0).unwrap().start());
            if controls.is_match(&prelude[first..]) {
                continue;
            }
            let latest = |name: &str| {
                assign
                    .captures_iter(prelude)
                    .filter(|assignment| &assignment[1] == name)
                    .last()
                    .map(|assignment| assignment.get(0).unwrap().start())
            };
            if latest(src) != Some(a.get(0).unwrap().start())
                || latest(dst) != Some(b.get(0).unwrap().start())
            {
                continue;
            }
            let stmt = &prelude[..first];
            let boundary = stmt.rfind([';', '{', '}']).map_or(0, |at| at + 1);
            if controls.is_match(&stmt[boundary..]) {
                continue;
            }
            output.push(Candidate {
                function,
                table: u64::from_str_radix(&a[2], 16).map_err(|_| "bad table address")?,
                slots: u64::from_str_radix(&b[2], 16).map_err(|_| "bad slot address")?,
                line: source[..start + open.start()]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count()
                    + 1,
            });
        }
    }
    Ok(output)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bytes,
    Unicode,
}
struct Literal {
    address: u64,
    bytes: Vec<u8>,
    flags: u64,
}
fn literals(image: &Image, candidate: &Candidate) -> Result<Vec<Literal>, String> {
    let mut output = vec![];
    let mut total = 0;
    for index in 0..MAX_ENTRIES {
        let at = candidate
            .table
            .checked_add(index as u64 * 16)
            .ok_or("table overflow")?;
        if !image.readonly(at, 16) {
            return Err("string table is not backed by read-only PE data".into());
        }
        let row = image.data(at, 16)?;
        if row.iter().all(|byte| *byte == 0) {
            if output.is_empty() || !image.writable(candidate.slots, output.len() * 8) {
                return Err("invalid destination slot array".into());
            }
            return Ok(output);
        }
        let address = number(row, 0, 8)?;
        let length = number(row, 8, 2)? as usize;
        let flags = number(row, 12, 4)?;
        if length == 0
            || length > MAX_LITERAL
            || number(row, 10, 2)? != 0
            || !matches!(flags, 0 | 0x20 | 0x60)
        {
            return Err("unsupported compact string record".into());
        }
        total += length;
        if total > MAX_TEXT || !image.readonly(address, length) {
            return Err("literal budget or read-only pointer validation failed".into());
        }
        let bytes = image.data(address, length)?;
        if bytes.last() != Some(&0) {
            return Err("literal lacks its declared final NUL".into());
        }
        let bytes = bytes[..length - 1].to_vec();
        if flags != 0 && std::str::from_utf8(&bytes).is_err() {
            return Err("Unicode record is not UTF-8".into());
        }
        if flags == 0x60 && bytes.contains(&0) {
            return Err("interned record contains an interior NUL".into());
        }
        output.push(Literal {
            address,
            bytes,
            flags,
        });
    }
    Err("string table terminator not found within budget".into())
}

#[derive(Clone, Copy)]
enum Abstract {
    Number(u64),
    Object(Kind),
    HashSuccess,
}
fn register(values: &HashMap<Register, Abstract>, reg: Register) -> Option<Abstract> {
    let value = *values.get(&reg.full_register())?;
    match value {
        Abstract::Number(value) => {
            let shift = if matches!(
                reg,
                Register::AH | Register::BH | Register::CH | Register::DH
            ) {
                8
            } else {
                0
            };
            let bits = reg.size() * 8;
            if bits == 0 || bits > 64 {
                return None;
            }
            Some(Abstract::Number(if bits == 64 {
                value
            } else {
                (value >> shift) & ((1u64 << bits) - 1)
            }))
        }
        other if reg.size() == 8 => Some(other),
        _ => None,
    }
}
fn write(
    values: &mut HashMap<Register, Abstract>,
    reg: Register,
    value: Abstract,
) -> Result<(), String> {
    if !matches!(reg.size(), 4 | 8) {
        return Err("unsupported partial initializer write".into());
    }
    let value = match value {
        Abstract::Number(value) if reg.size() == 4 => Abstract::Number(value & 0xffffffff),
        value => value,
    };
    values.insert(reg.full_register(), value);
    Ok(())
}
fn as_number(value: Abstract) -> Result<u64, String> {
    if let Abstract::Number(value) = value {
        Ok(value)
    } else {
        Err("unknown numeric initializer operand".into())
    }
}
fn address(values: &HashMap<Register, Abstract>, instruction: &Instruction) -> Result<u64, String> {
    if instruction.is_ip_rel_memory_operand() {
        return Ok(instruction.ip_rel_memory_address());
    }
    let mut result = instruction.memory_displacement64();
    if instruction.memory_base() != Register::None {
        result = result.wrapping_add(as_number(
            register(values, instruction.memory_base()).ok_or("unknown base")?,
        )?);
    }
    if instruction.memory_index() != Register::None {
        result = result.wrapping_add(
            as_number(register(values, instruction.memory_index()).ok_or("unknown index")?)?
                .wrapping_mul(u64::from(instruction.memory_index_scale())),
        );
    }
    Ok(result)
}
fn operand(
    image: &Image,
    values: &HashMap<Register, Abstract>,
    instruction: &Instruction,
    index: u32,
) -> Result<Abstract, String> {
    match instruction.op_kind(index) {
        OpKind::Register => register(values, instruction.op_register(index))
            .ok_or_else(|| "undefined initializer register".into()),
        OpKind::Memory => Ok(Abstract::Number(image.integer(
            address(values, instruction)?,
            instruction.memory_size().size(),
        )?)),
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Ok(Abstract::Number(instruction.immediate(index))),
        _ => Err("unsupported initializer operand".into()),
    }
}
fn direct_memory(instruction: &Instruction, base: Register, displacement: u64) -> bool {
    instruction.memory_base() == base
        && instruction.memory_index() == Register::None
        && instruction.memory_displacement64() == displacement
}
fn loop_iteration(
    image: &Image,
    instructions: &BTreeMap<u64, Instruction>,
    start: u64,
    registers: (Register, Register),
    candidate: &Candidate,
    index: usize,
    literal: &Literal,
) -> Result<usize, String> {
    let (src, dst) = registers;
    let source = candidate.table + index as u64 * 16;
    let destination = candidate.slots + index as u64 * 8;
    let expected = if literal.flags == 0 {
        Kind::Bytes
    } else {
        Kind::Unicode
    };
    let mut values = HashMap::from([
        (src, Abstract::Number(source)),
        (dst, Abstract::Number(destination)),
    ]);
    let mut zero = None;
    let mut stored = false;
    let mut ip = start;
    for step in 1..=MAX_LOOP_STEPS {
        let instruction = instructions
            .get(&ip)
            .ok_or("initializer jumps outside decoded CFG")?;
        if instruction.has_lock_prefix()
            || instruction.has_segment_prefix()
            || instruction.has_rep_prefix()
            || instruction.has_repne_prefix()
        {
            return Err("unsupported initializer prefix".into());
        }
        let next = instruction.next_ip();
        match instruction.mnemonic() {
            Mnemonic::Mov | Mnemonic::Movzx => {
                let value = operand(image, &values, instruction, 1)?;
                if instruction.op0_kind() == OpKind::Register {
                    write(&mut values, instruction.op0_register(), value)?;
                } else if instruction.op0_kind() == OpKind::Memory
                    && instruction.memory_size().size() == 8
                    && address(&values, instruction)? == destination
                    && matches!(value, Abstract::Object(kind) if kind == expected)
                {
                    if stored {
                        return Err("multiple object slot writes".into());
                    }
                    stored = true;
                } else {
                    return Err("unproven initializer memory write".into());
                }
            }
            Mnemonic::Add | Mnemonic::And | Mnemonic::Dec => {
                let left = as_number(operand(image, &values, instruction, 0)?)?;
                let right = if instruction.mnemonic() == Mnemonic::Dec {
                    1
                } else {
                    as_number(operand(image, &values, instruction, 1)?)?
                };
                let value = match instruction.mnemonic() {
                    Mnemonic::Add => left.wrapping_add(right),
                    Mnemonic::And => left & right,
                    _ => left.wrapping_sub(right),
                };
                let value = if instruction.op0_register().size() == 4 {
                    value & 0xffffffff
                } else {
                    value
                };
                write(
                    &mut values,
                    instruction.op0_register(),
                    Abstract::Number(value),
                )?;
                zero = Some(value == 0);
            }
            Mnemonic::Test | Mnemonic::Cmp => {
                let left = operand(image, &values, instruction, 0)?;
                let right = operand(image, &values, instruction, 1)?;
                zero = match (left, right) {
                    (Abstract::Number(left), Abstract::Number(right)) => {
                        let width = if instruction.op0_kind() == OpKind::Register {
                            instruction.op0_register().size()
                        } else {
                            instruction.memory_size().size()
                        };
                        if !matches!(width, 1 | 2 | 4 | 8) {
                            return Err("unsupported comparison width".into());
                        }
                        let mask = if width == 8 {
                            u64::MAX
                        } else {
                            (1u64 << (width * 8)) - 1
                        };
                        let (left, right) = (left & mask, right & mask);
                        Some(if instruction.mnemonic() == Mnemonic::Test {
                            left & right == 0
                        } else {
                            left == right
                        })
                    }
                    (Abstract::Object(_), Abstract::Object(_))
                        if instruction.mnemonic() == Mnemonic::Test
                            && instruction.op0_register() == instruction.op1_register() =>
                    {
                        Some(false)
                    }
                    (Abstract::HashSuccess, Abstract::Number(value))
                        if instruction.mnemonic() == Mnemonic::Cmp && value == u64::MAX =>
                    {
                        Some(false)
                    }
                    _ => return Err("unresolved initializer condition".into()),
                };
            }
            Mnemonic::Je | Mnemonic::Jne => {
                let taken = zero.ok_or("undefined initializer flags")?
                    == (instruction.mnemonic() == Mnemonic::Je);
                if instruction.near_branch_target() == start {
                    let next_pointer = image.integer(source + 16, 8)?;
                    if !stored
                        || as_number(register(&values, src).ok_or("source lost")?)? != source + 16
                        || as_number(register(&values, dst).ok_or("destination lost")?)?
                            != destination + 8
                        || taken != (next_pointer != 0)
                    {
                        return Err("initializer stride/termination mismatch".into());
                    }
                    return Ok(step);
                }
                ip = if taken {
                    instruction.near_branch_target()
                } else {
                    next
                };
                continue;
            }
            Mnemonic::Jmp if instruction.is_jmp_short_or_near() => {
                ip = instruction.near_branch_target();
                continue;
            }
            Mnemonic::Call => {
                if !instruction.is_ip_rel_memory_operand() {
                    return Err("initializer call is not a named PE import".into());
                }
                let api = image
                    .imports
                    .get(&instruction.ip_rel_memory_address())
                    .ok_or("unresolved initializer import")?;
                let result = if api == "PyObject_Hash" {
                    if !matches!(register(&values, Register::RCX), Some(Abstract::Object(kind)) if kind == expected)
                    {
                        return Err("hash argument is not the constructed object".into());
                    }
                    Abstract::HashSuccess
                } else {
                    let kind = match api.as_str() {
                        "PyBytes_FromStringAndSize" => Kind::Bytes,
                        "PyUnicode_FromStringAndSize" | "PyUnicode_InternFromString" => {
                            Kind::Unicode
                        }
                        _ => return Err(format!("unsupported initializer API {api}")),
                    };
                    if kind != expected
                        || as_number(
                            register(&values, Register::RCX)
                                .ok_or("missing constructor pointer")?,
                        )? != literal.address
                    {
                        return Err("constructor does not use this literal record".into());
                    }
                    if api != "PyUnicode_InternFromString"
                        && as_number(
                            register(&values, Register::RDX).ok_or("missing constructor length")?,
                        )? != literal.bytes.len() as u64
                    {
                        return Err("constructor length mismatch".into());
                    }
                    if api == "PyUnicode_InternFromString" && literal.bytes.contains(&0) {
                        return Err(
                            "interned Unicode constructor would truncate at interior NUL".into(),
                        );
                    }
                    Abstract::Object(kind)
                };
                for reg in [
                    Register::RAX,
                    Register::RCX,
                    Register::RDX,
                    Register::R8,
                    Register::R9,
                    Register::R10,
                    Register::R11,
                ] {
                    values.remove(&reg);
                }
                values.insert(Register::RAX, result);
                zero = None;
            }
            Mnemonic::Nop => (),
            other => return Err(format!("unsupported initializer instruction {other:?}")),
        }
        ip = next;
    }
    Err("initializer iteration budget reached".into())
}
fn native_proof(
    image: &Image,
    candidate: &Candidate,
    records: &[Literal],
) -> Result<Value, String> {
    let instructions = image.cfg(candidate.function)?;
    let bindings: Vec<_> = instructions
        .values()
        .filter(|instruction| {
            instruction.mnemonic() == Mnemonic::Lea
                && instruction.is_ip_rel_memory_operand()
                && instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().size() == 8
        })
        .collect();
    let sources: Vec<_> = bindings
        .iter()
        .filter(|instruction| instruction.ip_rel_memory_address() == candidate.table)
        .collect();
    let destinations: Vec<_> = bindings
        .iter()
        .filter(|instruction| instruction.ip_rel_memory_address() == candidate.slots)
        .collect();
    if sources.len() != 1 || destinations.len() != 1 {
        return Err("ambiguous or missing native base materialization".into());
    }
    let source = sources[0];
    let destination = destinations[0];
    let src = source.op0_register();
    let dst = destination.op0_register();
    let callee_saved = |reg| {
        matches!(
            reg,
            Register::RBX
                | Register::RBP
                | Register::RSI
                | Register::RDI
                | Register::R12
                | Register::R13
                | Register::R14
                | Register::R15
        )
    };
    if src == dst
        || !callee_saved(src)
        || !callee_saved(dst)
        || source.ip().abs_diff(destination.ip()) > 128
    {
        return Err("unsupported initializer base registers".into());
    }
    let starts: Vec<_> = instructions
        .values()
        .filter(|instruction| {
            instruction.mnemonic() == Mnemonic::Mov
                && instruction.op0_kind() == OpKind::Register
                && instruction.op1_kind() == OpKind::Memory
                && instruction.memory_size().size() == 4
                && direct_memory(instruction, src, 12)
                && instruction.ip() > source.ip().max(destination.ip())
                && instruction.ip() - source.ip().max(destination.ip()) <= 128
        })
        .collect();
    if starts.len() != 1 {
        return Err("ambiguous native flags-load loop entry".into());
    }
    let start = starts[0].ip();
    let first = source.ip().min(destination.ip());
    let mut ip = first;
    while ip < start {
        let instruction = instructions
            .get(&ip)
            .ok_or("nonlinear initializer prelude")?;
        if instruction.flow_control() != FlowControl::Next {
            return Err("branch/call between native bindings and loop".into());
        }
        if instruction.op0_kind() == OpKind::Register
            && [src, dst].contains(&instruction.op0_register().full_register())
            && instruction.ip() != source.ip()
            && instruction.ip() != destination.ip()
        {
            return Err("native base overwritten before loop".into());
        }
        ip = instruction.next_ip();
    }
    let mut steps = 0;
    for (index, literal) in records.iter().enumerate() {
        steps += loop_iteration(
            image,
            &instructions,
            start,
            (src, dst),
            candidate,
            index,
            literal,
        )?;
    }
    Ok(
        json!({"function_va":format!("0x{:x}",candidate.function),"source_binding_va":format!("0x{:x}",source.ip()),"destination_binding_va":format!("0x{:x}",destination.ip()),"loop_va":format!("0x{start:x}"),"source_register":format!("{src:?}"),"destination_register":format!("{dst:?}"),"source_stride_bytes":16,"destination_stride_bytes":8,"validated_iterations":records.len(),"abstract_instruction_steps":steps,"entry_reachability_proven":false,"runtime_initialization_observed":false,"assumption":"Conditional loop effects only: loop entry reachability and successful module initialization are not proven. Constructors and hash operations are assumed to succeed on this local path."}),
    )
}

fn recover_data(image: &Image, source: &str) -> Result<(usize, Value), String> {
    let mut tables = vec![];
    let mut rejected = vec![];
    let mut count = 0;
    for candidate in candidates(source)? {
        let result = (|| {
            let records = literals(image, &candidate)?;
            let native = native_proof(image, &candidate, &records)?;
            let entries: Vec<_> = records.iter().enumerate().map(|(index, literal)| {
                let slot = candidate.slots + index as u64 * 8;
                let mut entry = json!({"slot_va":format!("0x{slot:x}"),"slot_rva":format!("0x{:x}",slot-image.base),"entry_rva":format!("0x{:x}",candidate.table-image.base+index as u64*16),"literal_va":format!("0x{:x}",literal.address),"literal_rva":format!("0x{:x}",literal.address-image.base),"length":literal.bytes.len(),"flags":format!("0x{:x}",literal.flags),"kind":if literal.flags==0 {"bytes"} else {"unicode"}});
                if literal.flags == 0 { entry["bytes_hex"] = json!(literal.bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()); }
                else { entry["text"] = json!(std::str::from_utf8(&literal.bytes).unwrap()); }
                entry
            }).collect();
            Ok::<_, String>((
                records.len(),
                json!({"table_va":format!("0x{:x}",candidate.table),"table_rva":format!("0x{:x}",candidate.table-image.base),"destination_va":format!("0x{:x}",candidate.slots),"c_loop_line":candidate.line,"start_boundary_verified":true,"zero_record_terminator_verified":true,"native_evidence":native,"entries":entries}),
            ))
        })();
        match result { Ok((length, table)) => { count += length; tables.push(table); }, Err(error) => rejected.push(json!({"function_va":format!("0x{:x}",candidate.function),"c_loop_line":candidate.line,"reason":error})) }
    }
    Ok((
        count,
        json!({"engine":"UIE bounded Cython initializer slot recovery","interpretation":"Conditional object-slot assignments if the supported initializer loop executes successfully, checked against its local native instruction effects and literal records. Entry reachability, later overwrites and successful module initialization are not proven. No target execution, live object dereferencing or recovered Python bodies.","recovered_slots":count,"tables":tables,"rejected_candidates":rejected}),
    ))
}
pub fn recover(input: &Path, c_file: &Path, output: &Path) -> Result<usize, String> {
    let image = Image::parse(read(input, MAX_INPUT)?)?;
    let source =
        String::from_utf8(read(c_file, MAX_C_SOURCE)?).map_err(|error| error.to_string())?;
    let (count, mut report) = recover_data(&image, &source)?;
    report["input"] = json!(input);
    report["c_file"] = json!(c_file);
    report["input_sha256"] = json!(format!("{:x}", Sha256::digest(&image.bytes)));
    report["source_sha256"] = json!(format!("{:x}", Sha256::digest(source.as_bytes())));
    std::fs::create_dir_all(output).map_err(|error| error.to_string())?;
    std::fs::write(
        output.join("cython-slots-report.json"),
        serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    Ok(count)
}

pub fn annotate_aliases(c_file: &Path, output: &Path) -> Result<usize, String> {
    use std::io::Write;
    let report_path = output.join("cython-slots-report.json");
    let mut report: Value =
        serde_json::from_slice(&read(&report_path, MAX_C_SOURCE)?).map_err(|e| e.to_string())?;
    let source = String::from_utf8(read(c_file, MAX_C_SOURCE)?).map_err(|e| e.to_string())?;
    let source_hash = format!("{:x}", Sha256::digest(source.as_bytes()));
    if report["friendly_pseudocode_sha256"].as_str() == Some(source_hash.as_str()) {
        return Ok(0);
    }
    if report["source_sha256"].as_str() != Some(source_hash.as_str()) {
        return Err("Cython aliases require the exact pseudocode used for slot recovery".into());
    }
    let mut names = BTreeMap::new();
    for entry in report["tables"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|table| table["entries"].as_array().into_iter().flatten())
    {
        if names.len() >= MAX_ENTRIES * 4 {
            return Err("Cython alias budget reached".into());
        }
        let slot = entry["slot_va"]
            .as_str()
            .and_then(|value| value.strip_prefix("0x"))
            .ok_or("invalid object slot")?;
        if slot.is_empty() || slot.len() > 16 || !slot.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("invalid object slot address".into());
        }
        let kind = entry["kind"].as_str().unwrap_or("constant");
        if !matches!(kind, "bytes" | "unicode") {
            return Err("unsupported object constant kind".into());
        }
        let label = entry["text"]
            .as_str()
            .or_else(|| entry["bytes_hex"].as_str())
            .unwrap_or("empty");
        let label: String = label
            .chars()
            .take(24)
            .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
            .collect();
        let alias = format!("uie_candidate_{kind}_{label}_{slot}");
        for prefix in ["DAT_", "_DAT_"] {
            for address in [slot.to_owned(), slot.to_ascii_uppercase()] {
                names.insert(format!("{prefix}{address}"), alias.clone());
            }
        }
    }
    if names.is_empty() {
        return Ok(0);
    }
    let (renamed, count) = crate::rename::replace_many(&source, &names, c_file)?;
    if count == 0 {
        return Ok(0);
    }
    if renamed.len() > MAX_C_SOURCE
        || source.bytes().filter(|byte| *byte == b'\n').count()
            != renamed.bytes().filter(|byte| *byte == b'\n').count()
    {
        return Err("Cython aliases would change line mapping or exceed source limit".into());
    }
    if names.values().any(|alias| source.contains(alias)) {
        return Err("Cython alias collides with existing source text".into());
    }
    let raw = output.join("raw-native-pseudocode.txt");
    let mut original = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&raw)
        .map_err(|e| e.to_string())?;
    original
        .write_all(source.as_bytes())
        .map_err(|e| e.to_string())?;
    drop(original);
    let pending = c_file.with_extension("cython-alias.pending");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .map_err(|e| e.to_string())?;
    file.write_all(renamed.as_bytes())
        .map_err(|e| e.to_string())?;
    drop(file);
    std::fs::rename(&pending, c_file).map_err(|e| e.to_string())?;
    report["aliases"] = json!(names);
    report["aliased_occurrences"] = json!(count);
    report["raw_pseudocode"] = json!("raw-native-pseudocode.txt");
    report["raw_pseudocode_sha256"] = json!(crate::project::sha256(&raw)?);
    report["friendly_pseudocode_sha256"] = json!(crate::project::sha256(c_file)?);
    report["friendly_pseudocode_path"] = json!(c_file);
    report["alias_interpretation"]=json!("Candidate names from conditional initializer-loop effects, not runtime values or recovered Python statements. Identifiers only; C comments, string literals and line numbers are preserved. See entry_reachability_proven and constructor assumptions.");
    std::fs::write(
        report_path,
        serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_preserve_literals_comments_line_numbers_and_original_evidence() {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("uie-slot-alias-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let file = root.join("sample.c");
        let original =
            "void f(){ use(DAT_180004008); } // DAT_180004008\nchar*s=\"DAT_180004008\";\n";
        std::fs::write(&file, original).unwrap();
        let report = json!({"source_sha256":format!("{:x}",Sha256::digest(original.as_bytes())),"tables":[{"entries":[{"slot_va":"0x180004008","kind":"unicode","text":"cell"}]}]});
        std::fs::write(
            root.join("cython-slots-report.json"),
            serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        assert_eq!(annotate_aliases(&file, &root).unwrap(), 1);
        let renamed = std::fs::read_to_string(&file).unwrap();
        assert!(renamed.contains("use(uie_candidate_unicode_cell_180004008)"));
        assert!(renamed.contains("// DAT_180004008") && renamed.contains("\"DAT_180004008\""));
        assert_eq!(renamed.lines().count(), original.lines().count());
        assert_eq!(
            std::fs::read_to_string(root.join("raw-native-pseudocode.txt")).unwrap(),
            original
        );
        assert_eq!(annotate_aliases(&file, &root).unwrap(), 0);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    #[ignore = "requires the original board extension and independently generated static pseudocode"]
    fn real_board_initializer_resolves_known_attribute_slots() {
        let input = std::path::PathBuf::from(
            std::env::var_os("UIE_CYTHON_SLOT_INPUT").expect("set UIE_CYTHON_SLOT_INPUT"),
        );
        let source = std::path::PathBuf::from(
            std::env::var_os("UIE_CYTHON_SLOT_C").expect("set UIE_CYTHON_SLOT_C"),
        );
        let output = std::path::PathBuf::from(
            std::env::var_os("UIE_CYTHON_SLOT_OUTPUT").expect("set UIE_CYTHON_SLOT_OUTPUT"),
        );
        let before = crate::project::sha256(&input).unwrap();
        assert_eq!(recover(&input, &source, &output).unwrap(), 57);
        let report: Value = serde_json::from_slice(
            &std::fs::read(output.join("cython-slots-report.json")).unwrap(),
        )
        .unwrap();
        let entries = report["tables"][0]["entries"].as_array().unwrap();
        for (slot, text) in [
            ("0x18000da08", "w"),
            ("0x18000da18", "x"),
            ("0x18000da20", "y"),
            ("0x18000d938", "h"),
        ] {
            assert!(entries
                .iter()
                .any(|entry| entry["slot_va"] == slot && entry["text"] == text));
        }
        assert_eq!(crate::project::sha256(&input).unwrap(), before);
        let friendly = output.join(format!("friendly-validation-{}", std::process::id()));
        std::fs::create_dir_all(&friendly).unwrap();
        let annotated = friendly.join("board_decompiled.c");
        std::fs::copy(&source, &annotated).unwrap();
        assert_eq!(recover(&input, &annotated, &friendly).unwrap(), 57);
        assert!(annotate_aliases(&annotated, &friendly).unwrap() > 0);
        let text = std::fs::read_to_string(&annotated).unwrap();
        assert!(text.contains("uie_candidate_unicode_w_18000da08"));
        assert_eq!(
            crate::project::sha256(&source).unwrap(),
            crate::project::sha256(&friendly.join("raw-native-pseudocode.txt")).unwrap()
        );
    }
    fn source() -> String {
        "/* Function at 180001000: module_init */\nvoid module_init() {\nlonglong *destination; undefined **source;\ndestination = &DAT_180004000; source = &PTR_s_data_180003000;\ndo { flags = *(uint *)((longlong)source + 0xc); if ((flags & 0x20) == 0) { value = PyBytes_FromStringAndSize(*source); } else if ((flags & 0x40) == 0) { value = PyUnicode_FromStringAndSize(); value = PyUnicode_Decode(*source, length, encoding, 0); } else { value = PyUnicode_InternFromString(); } *destination = value; value = PyObject_Hash(value); source = source + 2; destination = destination + 1; } while (*source != (undefined *)0x0);\n}\n".into()
    }
    fn fixture() -> Image {
        fixture_with_overflow_guard(false)
    }
    fn fixture_with_overflow_guard(blocked: bool) -> Image {
        fixture_with_options(blocked, false)
    }
    fn fixture_with_options(blocked: bool, unreachable: bool) -> Image {
        let base = 0x180000000u64;
        let mut code = vec![];
        if unreachable {
            code.extend([0x31, 0xc0, 0x85, 0xc0, 0x75, 1, 0xc3]);
        }
        let emit_relative = |code: &mut Vec<u8>, prefix: &[u8], target: u64| {
            code.extend(prefix);
            let next = base + 0x1000 + code.len() as u64 + 4;
            code.extend(((target as i64 - next as i64) as i32).to_le_bytes());
        };
        emit_relative(&mut code, &[0x48, 0x8d, 0x35], base + 0x4000);
        emit_relative(&mut code, &[0x48, 0x8d, 0x3d], base + 0x3000);
        let begin = code.len();
        code.extend([
            0x44, 0x8b, 0x47, 0x0c, 0x48, 0x8b, 0x0f, 0x41, 0xf6, 0xc0, 0x20, 0x74, 0,
        ]);
        let to_bytes = code.len() - 1;
        code.extend([0x41, 0xf6, 0xc0, 0x40, 0x74, 0]);
        let to_unicode = code.len() - 1;
        emit_relative(&mut code, &[0xff, 0x15], base + 0x3300);
        code.extend([0xeb, 0]);
        let intern_done = code.len() - 1;
        let unicode = code.len();
        code.extend([0x0f, 0xb7, 0x57, 8, 0x48, 0xff, 0xca]);
        emit_relative(&mut code, &[0xff, 0x15], base + 0x3308);
        code.extend([0xeb, 0]);
        let unicode_done = code.len() - 1;
        let bytes = code.len();
        code.extend([0x0f, 0xb7, 0x57, 8, 0x48, 0xff, 0xca]);
        emit_relative(&mut code, &[0xff, 0x15], base + 0x3310);
        let done = code.len();
        let overflow_branch = if blocked {
            code.extend([
                0x41, 0xba, 0xff, 0xff, 0xff, 0xff, 0x41, 0x83, 0xc2, 1, 0x0f, 0x84, 0, 0, 0, 0,
            ]);
            Some(code.len() - 4)
        } else {
            None
        };
        code.extend([0x48, 0x89, 0x06, 0x48, 0x89, 0xc1]);
        emit_relative(&mut code, &[0xff, 0x15], base + 0x3318);
        code.extend([0x48, 0x83, 0xf8, 0xff, 0x74, 0]);
        let fail = code.len() - 1;
        code.extend([
            0x48, 0x83, 0xc7, 0x10, 0x48, 0x83, 0xc6, 8, 0x48, 0x83, 0x3f, 0, 0x75, 0,
        ]);
        let back = code.len() - 1;
        let ret = code.len();
        code.push(0xc3);
        if let Some(at) = overflow_branch {
            code[at..at + 4].copy_from_slice(&((ret as i64 - at as i64 - 4) as i32).to_le_bytes());
        }
        for (at, target) in [
            (to_bytes, bytes),
            (to_unicode, unicode),
            (intern_done, done),
            (unicode_done, done),
            (fail, ret),
            (back, begin),
        ] {
            code[at] = (target as isize - at as isize - 1) as i8 as u8;
        }
        let code_len = code.len();
        let mut raw = vec![0; 3072];
        raw[..code.len()].copy_from_slice(&code);
        for (index, (payload, flags)) in [
            (vec![0xff], 0u32),
            (b"cell".to_vec(), 0x60),
            (b"w".to_vec(), 0x20),
        ]
        .into_iter()
        .enumerate()
        {
            let literal = 1024 + 256 + index * 32;
            raw[literal..literal + payload.len()].copy_from_slice(&payload);
            let record = 1024 + index * 16;
            raw[record..record + 8]
                .copy_from_slice(&(base + 0x3100 + index as u64 * 32).to_le_bytes());
            raw[record + 8..record + 10]
                .copy_from_slice(&((payload.len() + 1) as u16).to_le_bytes());
            raw[record + 12..record + 16].copy_from_slice(&flags.to_le_bytes());
        }
        Image {
            bytes: raw,
            base,
            sections: vec![
                Section {
                    rva: 0x1000,
                    raw: 0,
                    size: code_len,
                    mapped: code_len,
                    flags: 0x60000020,
                },
                Section {
                    rva: 0x3000,
                    raw: 1024,
                    size: 1024,
                    mapped: 1024,
                    flags: 0x40000040,
                },
                Section {
                    rva: 0x4000,
                    raw: 2048,
                    size: 64,
                    mapped: 256,
                    flags: 0xc0000040,
                },
            ],
            imports: HashMap::from([
                (base + 0x3300, "PyUnicode_InternFromString".into()),
                (base + 0x3308, "PyUnicode_FromStringAndSize".into()),
                (base + 0x3310, "PyBytes_FromStringAndSize".into()),
                (base + 0x3318, "PyObject_Hash".into()),
            ]),
        }
    }
    #[test]
    fn initializer_proves_start_and_preserves_a_leading_non_utf8_bytes_record() {
        let (count, report) = recover_data(&fixture(), &source()).unwrap();
        assert_eq!(count, 3, "{report}");
        assert_eq!(report["tables"][0]["entries"][0]["kind"], "bytes");
        assert_eq!(report["tables"][0]["entries"][0]["bytes_hex"], "ff");
        assert_eq!(report["tables"][0]["entries"][1]["slot_va"], "0x180004008");
        assert_eq!(report["tables"][0]["entries"][1]["text"], "cell");
    }
    #[test]
    fn ambiguous_unrelated_and_string_spoofed_initializers_are_rejected() {
        let source = source();
        for invalid in [
            source.replace(
                "source = &PTR_s_data_180003000;",
                "source = &PTR_s_first_180003010; source = &PTR_s_data_180003000;",
            ),
            source.replace("*destination = value;", "*unrelated = value;"),
            source.replace(
                "value = PyUnicode_Decode(*source, length, encoding, 0);",
                "",
            ),
            format!("/* {} */", source),
        ] {
            assert_eq!(recover_data(&fixture(), &invalid).unwrap().0, 0);
        }
    }
    #[test]
    fn native_stride_corruption_and_a_missing_terminator_are_rejected() {
        let mut image = fixture();
        let at = image
            .bytes
            .windows(4)
            .position(|bytes| bytes == [0x48, 0x83, 0xc7, 0x10])
            .unwrap();
        image.bytes[at + 3] = 8;
        assert_eq!(recover_data(&image, &source()).unwrap().0, 0);
        let mut image = fixture();
        image.bytes[1024 + 48] = 1;
        assert_eq!(recover_data(&image, &source()).unwrap().0, 0);
    }
    #[test]
    fn a_32_bit_overflow_failure_branch_cannot_certify_a_slot_store() {
        let (count, report) = recover_data(&fixture_with_overflow_guard(true), &source()).unwrap();
        assert_eq!(count, 0, "{report}");
        assert!(!report["rejected_candidates"].as_array().unwrap().is_empty());
    }
    #[test]
    fn nul_containing_unicode_cannot_be_certified_through_a_nul_terminated_constructor() {
        let mut image = fixture();
        let test = image
            .bytes
            .windows(4)
            .position(|bytes| bytes == [0x41, 0xf6, 0xc0, 0x40])
            .unwrap();
        image.bytes[test + 3] = 0x20;
        image.bytes[1024 + 16 + 8..1024 + 16 + 10].copy_from_slice(&4u16.to_le_bytes());
        image.bytes[1024 + 16 + 12..1024 + 16 + 16].copy_from_slice(&0x20u32.to_le_bytes());
        image.bytes[1024 + 256 + 32..1024 + 256 + 36].copy_from_slice(b"a\0b\0");
        let (count, report) = recover_data(&image, &source()).unwrap();
        assert_eq!(count, 0, "{report}");
        assert!(report.to_string().contains("interior NUL"), "{report}");
    }
    #[test]
    fn unreachable_loop_is_explicitly_conditional_not_a_proven_runtime_assignment() {
        let (count, report) = recover_data(&fixture_with_options(false, true), &source()).unwrap();
        assert_eq!(count, 3, "{report}");
        let evidence = &report["tables"][0]["native_evidence"];
        assert_eq!(evidence["entry_reachability_proven"], false);
        assert_eq!(evidence["runtime_initialization_observed"], false);
        assert!(evidence["assumption"]
            .as_str()
            .unwrap()
            .contains("not proven"));
    }
    #[test]
    fn unicode_prelude_boundary_does_not_panic() {
        let mut source = source();
        let insertion = source.find("{\n").unwrap() + 2;
        let original_loop = source.find("do {").unwrap();
        let length = 4096 + insertion + 5 - original_loop;
        let mut prefix = String::from("int é = 0;");
        prefix.push_str(&" ".repeat(length - prefix.len()));
        source.insert_str(insertion, &prefix);
        assert!(!source.is_char_boundary(source.find("do {").unwrap() - 4096));
        assert!(candidates(&source).is_ok());
    }
    #[test]
    fn rejected_unclosed_loops_have_a_bounded_scan_budget() {
        let source = format!(
            "/* Function at 180001000: module_init */\nvoid module_init() {{\n{}",
            "do {\n".repeat(100_000)
        );
        assert!(matches!(candidates(&source),Err(error)if error.contains("budget")));
    }
}
