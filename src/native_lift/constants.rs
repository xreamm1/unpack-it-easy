use super::{mask, Image};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess,
    OpKind, Register,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::atomic::{AtomicBool, Ordering},
};

const STACK: u64 = 0x7fff_0000_0000_0000;
const MAX_STEPS: usize = 4096;
const MAX_TOTAL_STEPS: usize = 500_000;
const MAX_ANNOTATIONS: usize = 2048;
const MAX_MEMORY: usize = 8192;

#[derive(Clone, Copy, Default)]
struct Bits {
    value: u64,
    known: u64,
    transformed: bool,
}
#[derive(Default)]
struct State {
    registers: HashMap<Register, Bits>,
    memory: BTreeMap<u64, u8>,
    transformed: BTreeSet<u64>,
    zero: Option<bool>,
    carry: Option<bool>,
    image_reads: bool,
}
#[derive(Serialize)]
pub(super) struct Annotation {
    pub function_rva: String,
    pub instruction_rva: String,
    pub kind: &'static str,
    pub location: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encoding: Option<&'static str>,
}
#[derive(Serialize)]
pub(super) struct Report {
    engine: &'static str,
    interpretation: &'static str,
    steps: usize,
    truncated: bool,
    pub annotations: Vec<Annotation>,
}
fn view(reg: Register) -> Option<(Register, u32, u32)> {
    let bits = reg.size() as u32 * 8;
    let full = reg.full_register();
    if !matches!(
        full,
        Register::RAX
            | Register::RBX
            | Register::RCX
            | Register::RDX
            | Register::RSI
            | Register::RDI
            | Register::RBP
            | Register::RSP
            | Register::R8
            | Register::R9
            | Register::R10
            | Register::R11
            | Register::R12
            | Register::R13
            | Register::R14
            | Register::R15
    ) || !matches!(bits, 8 | 16 | 32 | 64)
    {
        return None;
    }
    Some((
        full,
        bits,
        if matches!(
            reg,
            Register::AH | Register::BH | Register::CH | Register::DH
        ) {
            8
        } else {
            0
        },
    ))
}
impl State {
    fn read(&self, reg: Register) -> Option<u64> {
        let (full, width, offset) = view(reg)?;
        let value = self.registers.get(&full)?;
        if width < 64 && value.known == u64::MAX && value.value.abs_diff(STACK) < 65536 {
            return None;
        }
        let wanted = mask(width) << offset;
        (value.known & wanted == wanted).then_some((value.value >> offset) & mask(width))
    }
    fn write(&mut self, reg: Register, value: Option<u64>) {
        let Some((full, width, offset)) = view(reg) else {
            return;
        };
        let old = self.registers.entry(full).or_default();
        if width >= 32 {
            old.transformed = false;
        }
        let bits = mask(width) << offset;
        old.known &= !bits;
        old.value &= !bits;
        if let Some(value) = value {
            old.value |= (value & mask(width)) << offset;
            old.known |= bits;
        }
        if width == 32 {
            old.value &= 0xffff_ffff;
            old.known |= 0xffff_ffff_0000_0000;
        }
    }
    fn address(&self, instruction: &Instruction) -> Option<u64> {
        if instruction.is_ip_rel_memory_operand() {
            return Some(instruction.ip_rel_memory_address());
        }
        let mut address = instruction.memory_displacement64();
        if instruction.memory_base() != Register::None {
            address = address.wrapping_add(self.read(instruction.memory_base())?);
        }
        if instruction.memory_index() != Register::None {
            address = address.wrapping_add(
                self.read(instruction.memory_index())?
                    .wrapping_mul(u64::from(instruction.memory_index_scale())),
            );
        }
        if instruction.memory_base().size() == 4 || instruction.memory_index().size() == 4 {
            address &= 0xffff_ffff;
        }
        Some(address)
    }
    fn load(&self, image: &Image<'_>, address: u64, size: usize) -> Option<u64> {
        if size == 0 || size > 8 {
            return None;
        }
        let mut result = 0u64;
        for index in 0..size {
            let at = address.checked_add(index as u64)?;
            let value = self.memory.get(&at).copied().or_else(|| {
                if !self.image_reads {
                    return None;
                }
                let rva = u32::try_from(at.checked_sub(image.base)?).ok()?;
                Some(image.data(rva, 1).ok()?[0])
            })?;
            result |= u64::from(value) << (index * 8);
        }
        Some(result)
    }
    fn operand(&self, image: &Image<'_>, instruction: &Instruction, index: u32) -> Option<u64> {
        match instruction.op_kind(index) {
            OpKind::Register => self.read(instruction.op_register(index)),
            OpKind::Memory => self.load(
                image,
                self.address(instruction)?,
                instruction.memory_size().size(),
            ),
            OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64 => Some(instruction.immediate(index)),
            _ => None,
        }
    }
    fn store(&mut self, instruction: &Instruction, value: Option<u64>, transformed: bool) {
        if instruction.op0_kind() == OpKind::Register {
            self.write(instruction.op0_register(), value);
            if value.is_some() && transformed {
                if let Some((full, _, _)) = view(instruction.op0_register()) {
                    if let Some(bits) = self.registers.get_mut(&full) {
                        bits.transformed = true;
                    }
                }
            }
            return;
        }
        if instruction.op0_kind() != OpKind::Memory {
            return;
        }
        let Some(address) = self.address(instruction) else {
            self.memory.clear();
            self.transformed.clear();
            self.image_reads = false;
            return;
        };
        let size = instruction.memory_size().size();
        if size == 0 || size > 8 || self.memory.len() + size > MAX_MEMORY {
            self.memory.clear();
            self.transformed.clear();
            self.image_reads = false;
            return;
        }
        for index in 0..size {
            let Some(at) = address.checked_add(index as u64) else {
                break;
            };
            if let Some(value) = value {
                self.memory.insert(at, (value >> (index * 8)) as u8);
                if transformed {
                    self.transformed.insert(at);
                } else {
                    self.transformed.remove(&at);
                }
            } else {
                self.memory.remove(&at);
                self.transformed.remove(&at);
                self.image_reads = false;
            }
        }
    }
    fn derived(&self, instruction: &Instruction, index: u32) -> bool {
        match instruction.op_kind(index) {
            OpKind::Register => view(instruction.op_register(index))
                .and_then(|(full, _, _)| self.registers.get(&full))
                .is_some_and(|bits| bits.transformed),
            OpKind::Memory => self.address(instruction).is_some_and(|address| {
                (0..instruction.memory_size().size().min(8)).any(|offset| {
                    self.transformed
                        .contains(&address.wrapping_add(offset as u64))
                })
            }),
            _ => false,
        }
    }
    fn forget_effects(&mut self, instruction: &Instruction, factory: &mut InstructionInfoFactory) {
        let info = factory.info(instruction);
        for used in info.used_registers() {
            if matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                if let Some((full, _, _)) = view(used.register()) {
                    self.registers.remove(&full);
                }
            }
        }
        if info.used_memory().iter().any(|used| {
            matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            )
        }) {
            self.memory.clear();
            self.transformed.clear();
            self.image_reads = false;
        }
        if instruction.rflags_modified() != 0 {
            self.zero = None;
            self.carry = None;
        }
    }
}
fn location(address: u64, base: u64) -> String {
    if address.abs_diff(STACK) < 65536 {
        if address >= STACK {
            format!("stack+0x{:x}", address - STACK)
        } else {
            format!("stack-0x{:x}", STACK - address)
        }
    } else if address >= base && address - base <= u64::from(u32::MAX) {
        format!("VA 0x{address:x} / RVA 0x{:x}", address - base)
    } else {
        format!("0x{address:x}")
    }
}
fn strings(
    state: &State,
    image: &Image<'_>,
    function: u32,
    instruction: u64,
    out: &mut Vec<Annotation>,
) {
    let mut run = vec![];
    let mut start = 0;
    let mut transformed = false;
    let flush = |run: &mut Vec<u8>, start: u64, transformed: bool, out: &mut Vec<Annotation>| {
        if run.len() >= 4 && transformed && out.len() < MAX_ANNOTATIONS {
            let text = String::from_utf8_lossy(run).into_owned();
            let loc = location(start, image.base);
            if !out.iter().any(|row| {
                row.kind == "string_candidate"
                    && row.function_rva == format!("0x{function:x}")
                    && row.location == loc
                    && row.value == text
            }) {
                out.push(Annotation {
                    function_rva: format!("0x{function:x}"),
                    instruction_rva: format!("0x{:x}", instruction.saturating_sub(image.base)),
                    kind: "string_candidate",
                    location: loc,
                    value: text,
                    encoding: Some("ASCII"),
                });
            }
        }
        run.clear();
    };
    for (&address, &byte) in &state.memory {
        if !(32..=126).contains(&byte)
            || (!run.is_empty() && address != start + run.len() as u64)
            || run.len() >= 256
        {
            flush(&mut run, start, transformed, out);
            transformed = false;
        }
        if (32..=126).contains(&byte) {
            if run.is_empty() {
                start = address;
            }
            run.push(byte);
            transformed |= state.transformed.contains(&address);
        }
    }
    flush(&mut run, start, transformed, out);
    // A separate scan retains the zero high bytes which terminate the ASCII scan.
    // shortcut: supplementary-plane surrogate pairs are skipped until covered by dedicated fixtures.
    for parity in 0..2 {
        let mut run = String::new();
        let mut count = 0usize;
        let mut start = 0u64;
        let mut transformed = false;
        let flush = |run: &mut String,
                     count: usize,
                     start: u64,
                     transformed: bool,
                     out: &mut Vec<Annotation>| {
            let already_ascii = count != 0
                && (0..count * 2).all(|offset| {
                    state
                        .memory
                        .get(&start.wrapping_add(offset as u64))
                        .is_some_and(|byte| (32..=126).contains(byte))
                });
            if count >= 4 && transformed && !already_ascii && out.len() < MAX_ANNOTATIONS {
                let loc = location(start, image.base);
                let function_rva = format!("0x{function:x}");
                if !out.iter().any(|row| {
                    row.kind == "string_candidate"
                        && row.encoding == Some("UTF-16LE")
                        && row.function_rva == function_rva
                        && row.location == loc
                        && row.value == *run
                }) {
                    out.push(Annotation {
                        function_rva,
                        instruction_rva: format!("0x{:x}", instruction.saturating_sub(image.base)),
                        kind: "string_candidate",
                        location: loc,
                        value: run.clone(),
                        encoding: Some("UTF-16LE"),
                    });
                }
            }
            run.clear();
        };
        for (&address, &low) in &state.memory {
            if address & 1 != parity {
                continue;
            }
            let high_address = address.checked_add(1);
            let high = high_address
                .and_then(|address| state.memory.get(&address))
                .copied();
            let character = high
                .and_then(|high| char::from_u32(u32::from(u16::from_le_bytes([low, high]))))
                .filter(|character| {
                    character.is_alphanumeric()
                        || character.is_ascii_punctuation()
                        || *character == ' '
                });
            if character.is_none()
                || (!run.is_empty() && address != start + count as u64 * 2)
                || count >= 256
            {
                flush(&mut run, count, start, transformed, out);
                count = 0;
                transformed = false;
            }
            if let Some(character) = character {
                if run.is_empty() {
                    start = address;
                }
                run.push(character);
                count += 1;
                transformed |= state.transformed.contains(&address)
                    || high_address.is_some_and(|address| state.transformed.contains(&address));
            }
        }
        flush(&mut run, count, start, transformed, out);
    }
}
fn rotate(value: u64, count: u64, width: u32, left: bool) -> u64 {
    let count = (count & if width == 64 { 63 } else { 31 }) as u32 % width;
    let value = value & mask(width);
    if count == 0 {
        return value;
    }
    if left {
        ((value << count) | (value >> (width - count))) & mask(width)
    } else {
        ((value >> count) | (value << (width - count))) & mask(width)
    }
}

pub(super) fn analyze(
    image: &Image<'_>,
    functions: &BTreeMap<u32, String>,
    cancel: &AtomicBool,
) -> Result<Report, String> {
    let mut report = Report { engine: "UIE Rust bounded constant propagation", interpretation: "Static candidates, not observed execution or recovered application source. Only known branch conditions are followed; unresolved control flow loses tracked state. Calls invalidate volatile registers and memory. Stack addresses are synthetic relative offsets, never runtime addresses. Unknown reads are never replaced with zero. ASCII and BMP UTF-16LE candidates may include false positives.", steps: 0, truncated: false, annotations: vec![] };
    for &function in functions.keys() {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let Ok(code) = image.code(function) else {
            continue;
        };
        let start = image.base + u64::from(function);
        let mut decoder = Decoder::with_ip(64, code, start, DecoderOptions::NONE);
        let mut instructions = BTreeMap::new();
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.is_invalid() {
                break;
            }
            instructions.insert(instruction.ip(), instruction);
        }
        let mut state = State {
            image_reads: true,
            ..Default::default()
        };
        state.write(Register::RSP, Some(STACK));
        let mut ip = start;
        let mut factory = InstructionInfoFactory::new();
        let mut emitted = HashSet::new();
        for step in 0..MAX_STEPS {
            if report.steps >= MAX_TOTAL_STEPS || report.annotations.len() >= MAX_ANNOTATIONS {
                report.truncated = true;
                break;
            }
            if step + 1 == MAX_STEPS {
                report.truncated = true;
            }
            report.steps += 1;
            let Some(instruction) = instructions.get(&ip) else {
                break;
            };
            if cancel.load(Ordering::Relaxed) {
                return Err("cancelled".into());
            }
            let next = instruction.next_ip();
            if instruction.has_lock_prefix()
                || instruction.has_segment_prefix()
                || instruction.has_rep_prefix()
                || instruction.has_repne_prefix()
            {
                state.forget_effects(instruction, &mut factory);
                ip = next;
                continue;
            }
            let mnemonic = instruction.mnemonic();
            if instruction.flow_control() == FlowControl::Return {
                break;
            }
            if matches!(
                instruction.flow_control(),
                FlowControl::Call | FlowControl::IndirectCall
            ) {
                strings(&state, image, function, ip, &mut report.annotations);
                for reg in [
                    Register::RAX,
                    Register::RCX,
                    Register::RDX,
                    Register::R8,
                    Register::R9,
                    Register::R10,
                    Register::R11,
                ] {
                    state.registers.remove(&reg);
                }
                state.memory.clear();
                state.transformed.clear();
                state.image_reads = false;
                state.zero = None;
                state.carry = None;
                ip = next;
                continue;
            }
            if instruction.is_jmp_short_or_near() {
                ip = instruction.near_branch_target();
                continue;
            }
            if instruction.is_jcc_short_or_near() {
                let taken = match mnemonic {
                    Mnemonic::Je => state.zero,
                    Mnemonic::Jne => state.zero.map(|v| !v),
                    Mnemonic::Jb => state.carry,
                    Mnemonic::Jae => state.carry.map(|v| !v),
                    Mnemonic::Jbe => state.carry.zip(state.zero).map(|(c, z)| c || z),
                    Mnemonic::Ja => state.carry.zip(state.zero).map(|(c, z)| !c && !z),
                    _ => None,
                };
                if let Some(taken) = taken {
                    ip = if taken {
                        instruction.near_branch_target()
                    } else {
                        next
                    };
                    continue;
                }
                strings(&state, image, function, ip, &mut report.annotations);
                state = State::default();
                ip = next;
                continue;
            }
            if instruction.flow_control() != FlowControl::Next {
                break;
            }
            if mnemonic == Mnemonic::Push {
                if let Some(rsp) = state
                    .read(Register::RSP)
                    .filter(|_| instruction.stack_pointer_increment() == -8)
                {
                    let address = rsp.wrapping_sub(8);
                    let value = state.operand(image, instruction, 0);
                    let derived = state.derived(instruction, 0);
                    state.write(Register::RSP, Some(address));
                    for byte in 0..8 {
                        let at = address.wrapping_add(byte);
                        if let Some(value) = value {
                            if state.memory.len() < MAX_MEMORY || state.memory.contains_key(&at) {
                                state.memory.insert(at, (value >> (byte * 8)) as u8);
                                if derived {
                                    state.transformed.insert(at);
                                } else {
                                    state.transformed.remove(&at);
                                }
                            } else {
                                state.memory.clear();
                                state.transformed.clear();
                                state.image_reads = false;
                                break;
                            }
                        } else {
                            state.memory.remove(&at);
                            state.transformed.remove(&at);
                        }
                    }
                } else {
                    state.forget_effects(instruction, &mut factory);
                }
                ip = next;
                continue;
            }
            if mnemonic == Mnemonic::Pop
                && instruction.op0_kind() == OpKind::Register
                && instruction.op0_register().size() == 8
                && instruction.op0_register() != Register::RSP
            {
                if let Some(rsp) = state.read(Register::RSP) {
                    let value = state.load(image, rsp, 8);
                    state.write(instruction.op0_register(), value);
                    state.write(Register::RSP, Some(rsp.wrapping_add(8)));
                } else {
                    state.forget_effects(instruction, &mut factory);
                }
                ip = next;
                continue;
            }
            let width = if instruction.op0_kind() == OpKind::Register {
                view(instruction.op0_register()).map(|(_, width, _)| width)
            } else if instruction.op0_kind() == OpKind::Memory {
                Some(instruction.memory_size().size() as u32 * 8)
            } else {
                None
            };
            let a = state.operand(image, instruction, 0);
            let b = if instruction.op_count() >= 2 {
                state.operand(image, instruction, 1)
            } else {
                None
            };
            if matches!(mnemonic, Mnemonic::Cmp | Mnemonic::Test) {
                let same_register = instruction.op0_kind() == OpKind::Register
                    && instruction.op1_kind() == OpKind::Register
                    && instruction.op0_register() == instruction.op1_register();
                state.zero = if mnemonic == Mnemonic::Cmp && same_register
                    || mnemonic == Mnemonic::Test && (a == Some(0) || b == Some(0))
                {
                    Some(true)
                } else {
                    a.zip(b).map(|(a, b)| {
                        if mnemonic == Mnemonic::Cmp {
                            a == (b & mask(width.unwrap_or(64)))
                        } else {
                            a & b == 0
                        }
                    })
                };
                state.carry = if mnemonic == Mnemonic::Test || same_register {
                    Some(false)
                } else {
                    a.zip(b).map(|(a, b)| a < (b & mask(width.unwrap_or(64))))
                };
                ip = next;
                continue;
            }
            let Some(width) = width.filter(|width| matches!(width, 8 | 16 | 32 | 64)) else {
                state.forget_effects(instruction, &mut factory);
                ip = next;
                continue;
            };
            let value = match mnemonic {
                Mnemonic::Mov | Mnemonic::Movzx => b,
                Mnemonic::Lea => state.address(instruction),
                Mnemonic::Xor | Mnemonic::Sub
                    if instruction.op0_kind() == OpKind::Register
                        && instruction.op1_kind() == OpKind::Register
                        && instruction.op0_register() == instruction.op1_register() =>
                {
                    Some(0)
                }
                Mnemonic::Xor => a.zip(b).map(|(a, b)| a ^ b),
                Mnemonic::And if a == Some(0) || b == Some(0) => Some(0),
                Mnemonic::And => a.zip(b).map(|(a, b)| a & b),
                Mnemonic::Or
                    if a == Some(mask(width))
                        || b.is_some_and(|value| value & mask(width) == mask(width)) =>
                {
                    Some(mask(width))
                }
                Mnemonic::Or => a.zip(b).map(|(a, b)| a | b),
                Mnemonic::Add => a.zip(b).map(|(a, b)| a.wrapping_add(b)),
                Mnemonic::Sub => a.zip(b).map(|(a, b)| a.wrapping_sub(b)),
                Mnemonic::Inc => a.map(|a| a.wrapping_add(1)),
                Mnemonic::Dec => a.map(|a| a.wrapping_sub(1)),
                Mnemonic::Neg => a.map(u64::wrapping_neg),
                Mnemonic::Not => a.map(|a| !a),
                Mnemonic::Imul if instruction.op_count() == 3 => b
                    .zip(state.operand(image, instruction, 2))
                    .map(|(a, b)| a.wrapping_mul(b)),
                Mnemonic::Imul if instruction.op_count() == 2 => {
                    a.zip(b).map(|(a, b)| a.wrapping_mul(b))
                }
                Mnemonic::Shl => a
                    .zip(b)
                    .map(|(a, b)| a.wrapping_shl((b & if width == 64 { 63 } else { 31 }) as u32)),
                Mnemonic::Shr => a
                    .zip(b)
                    .map(|(a, b)| a.wrapping_shr((b & if width == 64 { 63 } else { 31 }) as u32)),
                Mnemonic::Rol | Mnemonic::Ror => a
                    .zip(b)
                    .map(|(a, b)| rotate(a, b, width, mnemonic == Mnemonic::Rol)),
                _ => {
                    state.forget_effects(instruction, &mut factory);
                    ip = next;
                    continue;
                }
            }
            .map(|value| value & mask(width));
            if !matches!(
                mnemonic,
                Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Lea | Mnemonic::Not
            ) {
                let shifted = matches!(
                    mnemonic,
                    Mnemonic::Shl | Mnemonic::Shr | Mnemonic::Rol | Mnemonic::Ror
                );
                let zero_shift = shifted
                    && b.is_some_and(|count| count & if width == 64 { 63 } else { 31 } == 0);
                if !zero_shift {
                    if mnemonic == Mnemonic::Imul {
                        state.zero = None;
                    } else if !matches!(mnemonic, Mnemonic::Rol | Mnemonic::Ror) {
                        state.zero = value.map(|value| value == 0);
                    }
                    if !matches!(mnemonic, Mnemonic::Inc | Mnemonic::Dec) {
                        state.carry =
                            if matches!(mnemonic, Mnemonic::And | Mnemonic::Or | Mnemonic::Xor) {
                                Some(false)
                            } else {
                                None
                            };
                    }
                }
            }
            state.store(
                instruction,
                value,
                state.derived(instruction, 0)
                    || (instruction.op_count() >= 2 && state.derived(instruction, 1))
                    || matches!(
                        mnemonic,
                        Mnemonic::Xor
                            | Mnemonic::And
                            | Mnemonic::Or
                            | Mnemonic::Shl
                            | Mnemonic::Shr
                            | Mnemonic::Rol
                            | Mnemonic::Ror
                            | Mnemonic::Add
                            | Mnemonic::Sub
                    ),
            );
            if let Some(value) = value.filter(|_| report.annotations.len() < MAX_ANNOTATIONS) {
                let destination = if instruction.op0_kind() == OpKind::Register {
                    format!("{:?}", instruction.op0_register())
                } else {
                    state
                        .address(instruction)
                        .map(|v| location(v, image.base))
                        .unwrap_or_default()
                };
                let text = if value.abs_diff(STACK) < 65536
                    || value
                        .checked_sub(image.base)
                        .and_then(|rva| u32::try_from(rva).ok())
                        .is_some_and(|rva| image.data(rva, 1).is_ok())
                {
                    location(value, image.base)
                } else {
                    format!("0x{value:x}")
                };
                if emitted.len() < 64 && emitted.insert((ip, destination.clone(), text.clone())) {
                    report.annotations.push(Annotation {
                        function_rva: format!("0x{function:x}"),
                        instruction_rva: format!("0x{:x}", ip - image.base),
                        kind: "constant",
                        location: destination,
                        value: text,
                        encoding: None,
                    });
                }
            }
            ip = next;
        }
        strings(&state, image, function, ip, &mut report.annotations);
        if report.truncated
            && (report.steps >= MAX_TOTAL_STEPS || report.annotations.len() >= MAX_ANNOTATIONS)
        {
            break;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn scan(code: &[u8]) -> Report {
        let image = Image {
            bytes: code,
            sections: vec![super::super::Section {
                rva: 0x1000,
                raw: 0,
                size: code.len(),
                mapped_size: code.len(),
                executable: true,
            }],
            export: (0, 0),
            exception: (0, 0),
            base: 0x140000000,
        };
        analyze(
            &image,
            &BTreeMap::from([(0x1000, "owned_fixture".into())]),
            &AtomicBool::new(false),
        )
        .unwrap()
    }
    #[test]
    fn identities_resolve_unknown_register_inputs_without_inventing_them() {
        for (code, register, value) in [
            (&[0x83, 0xe0, 0x00, 0xc3][..], "EAX", "0x0"),
            (&[0x83, 0xc8, 0xff, 0xc3][..], "EAX", "0xffffffff"),
            (&[0x29, 0xc0, 0xc3][..], "EAX", "0x0"),
        ] {
            let report = scan(code);
            assert!(report
                .annotations
                .iter()
                .any(|row| row.location == register && row.value == value));
        }
        let report = scan(&[
            0x39, 0xc9, 0x75, 0x06, 0xb8, 0x2a, 0, 0, 0, 0xc3, 0xb8, 0x63, 0, 0, 0, 0xc3,
        ]);
        assert!(report
            .annotations
            .iter()
            .any(|row| row.location == "EAX" && row.value == "0x2a"));
        assert!(!report
            .annotations
            .iter()
            .any(|row| row.location == "EAX" && row.value == "0x63"));
    }
    #[test]
    fn a_bounded_xor_loop_recovers_a_stack_string_without_execution() {
        let code = [
            0x48, 0x83, 0xec, 0x20, 0xc7, 0x04, 0x24, 0x7f, 0x72, 0x7b, 0x7b, 0x66, 0xc7, 0x44,
            0x24, 0x04, 0x78, 0x37, 0x31, 0xc0, 0x80, 0x34, 0x04, 0x37, 0xff, 0xc0, 0x83, 0xf8,
            0x06, 0x72, 0xf5, 0x48, 0x83, 0xc4, 0x20, 0xc3,
        ];
        let report = scan(&code);
        assert!(report
            .annotations
            .iter()
            .any(|row| row.kind == "string_candidate"
                && row.value == "HELLO"
                && row.location == "stack-0x20"));
        assert!(!report.truncated);
    }
    #[test]
    fn calls_and_unknown_writes_do_not_leak_stale_constants() {
        let report = scan(&[
            0xbb, 0x78, 0x56, 0x34, 0x12, 0xb9, 0x11, 0x11, 0x11, 0x11, 0xe8, 0, 0, 0, 0, 0x48,
            0x89, 0xc8, 0x48, 0x89, 0xd8, 0xb9, 0x22, 0x22, 0x22, 0x22, 0x0f, 0xc9, 0x89, 0xca,
            0xc3,
        ]);
        assert!(report
            .annotations
            .iter()
            .any(|row| row.location == "RAX" && row.value == "0x12345678"));
        assert!(!report
            .annotations
            .iter()
            .any(|row| row.location == "RAX" && row.value == "0x11111111"));
        assert!(!report.annotations.iter().any(|row| row.location == "EDX"));
    }
    #[test]
    fn transformed_register_values_are_tracked_into_stack_stores() {
        let report = scan(&[
            0xb8, 0x7f, 0x72, 0x7b, 0x7b, 0x35, 0x37, 0x37, 0x37, 0x37, 0x89, 0x44, 0x24, 0xf8,
            0xb9, 0x78, 0, 0, 0, 0x80, 0xf1, 0x37, 0x88, 0x4c, 0x24, 0xfc, 0xc6, 0x44, 0x24, 0xfd,
            0, 0xc3,
        ]);
        assert!(report
            .annotations
            .iter()
            .any(|row| row.kind == "string_candidate"
                && row.value == "HELLO"
                && row.location == "stack-0x8"));
        assert!(scan(&[0x80, 0x31, 0x37, 0xc3]).annotations.is_empty());
    }
    #[test]
    fn an_infinite_loop_exhausts_a_budget_instead_of_hanging() {
        let report = scan(&[0xeb, 0xfe]);
        assert!(report.truncated);
        assert_eq!(report.steps, MAX_STEPS);
    }
    #[test]
    fn partial_registers_and_rotates_follow_x86_widths() {
        let mut state = State::default();
        state.write(Register::AL, Some(0x80));
        assert_eq!(state.read(Register::AL), Some(0x80));
        assert_eq!(state.read(Register::RAX), None);
        state.write(Register::AH, Some(0x12));
        assert_eq!(state.read(Register::AX), Some(0x1280));
        state.write(Register::EAX, Some(0xffff_ffff));
        assert_eq!(state.read(Register::RAX), Some(0xffff_ffff));
        assert_eq!(rotate(0x81, 1, 8, true), 3);
        assert_eq!(rotate(3, 1, 8, false), 0x81);
        assert_eq!(rotate(0x81234567, 32, 32, false), 0x81234567);
        assert_eq!(rotate(0x8123456789abcdef, 65, 64, true), 0x02468acf13579bdf);
    }
    #[test]
    fn address_size_wraps_without_turning_synthetic_stack_bits_into_addresses() {
        let instruction =
            Decoder::with_ip(64, &[0x67, 0x8a, 0x40, 0x20], 0x1000, DecoderOptions::NONE).decode();
        let mut state = State::default();
        state.write(Register::RAX, Some(0xffff_fff0));
        assert_eq!(state.address(&instruction), Some(0x10));
        state.write(Register::RSP, Some(STACK));
        assert_eq!(state.read(Register::ESP), None);
        assert_eq!(state.read(Register::RSP), Some(STACK));
    }
    #[test]
    fn wide_candidates_preserve_known_high_bytes_and_unicode() {
        let image = Image {
            bytes: &[],
            sections: vec![],
            export: (0, 0),
            exception: (0, 0),
            base: 0x140000000,
        };
        for (text, offset) in [("HELLO", 0u64), ("привет", 1)] {
            let mut state = State::default();
            let start = STACK - 0x20 + offset;
            for (index, byte) in text.encode_utf16().flat_map(u16::to_le_bytes).enumerate() {
                let address = start + index as u64;
                state.memory.insert(address, byte);
                state.transformed.insert(address);
            }
            let mut annotations = vec![];
            strings(
                &state,
                &image,
                0x1000,
                image.base + 0x1020,
                &mut annotations,
            );
            assert!(annotations.iter().any(|row| row.value == text
                && row.encoding == Some("UTF-16LE")
                && row.location == location(start, image.base)));
            state.memory.remove(&(start + 3));
            annotations.clear();
            strings(
                &state,
                &image,
                0x1000,
                image.base + 0x1020,
                &mut annotations,
            );
            assert!(!annotations.iter().any(|row| row.value == text));
        }
    }
    #[test]
    fn wide_candidates_require_transformed_bytes_and_do_not_reinterpret_ascii() {
        let image = Image {
            bytes: &[],
            sections: vec![],
            export: (0, 0),
            exception: (0, 0),
            base: 0x140000000,
        };
        let mut state = State::default();
        for (index, byte) in b"PLAIN ASCII STRING".iter().copied().enumerate() {
            state.memory.insert(STACK + index as u64, byte);
            state.transformed.insert(STACK + index as u64);
        }
        let mut annotations = vec![];
        strings(
            &state,
            &image,
            0x1000,
            image.base + 0x1020,
            &mut annotations,
        );
        assert!(annotations
            .iter()
            .any(|row| row.value == "PLAIN ASCII STRING" && row.encoding == Some("ASCII")));
        assert!(!annotations
            .iter()
            .any(|row| row.encoding == Some("UTF-16LE")));
        state.memory.clear();
        state.transformed.clear();
        for (index, byte) in "HELLO"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .enumerate()
        {
            state.memory.insert(STACK + index as u64, byte);
        }
        annotations.clear();
        strings(
            &state,
            &image,
            0x1000,
            image.base + 0x1020,
            &mut annotations,
        );
        assert!(annotations.is_empty());
    }
}
