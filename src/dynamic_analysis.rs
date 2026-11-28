//! Trace-assisted analysis. Parsing traces never launches the target.
//! Native trace specification: https://help.x64dbg.com/en/latest/developers/tracefile.html
use eframe::egui;
use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind, Register};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::Duration,
};
const MAX_FILE: u64 = 128 * 1024 * 1024;
const MAX_ROWS: usize = 200_000;
const MAX_LINE: usize = 64 * 1024;
const MAX_EVIDENCE: usize = 20_000;
fn label(ru: &str, en: &str) -> String {
    if crate::language::tr("код") == "code" {
        en.into()
    } else {
        ru.into()
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub version: u32,
    pub module_sha256: String,
    pub module_base: u64,
    pub module_size: u64,
    pub bitness: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Step {
    ip: u64,
    bytes: String,
    #[serde(default)]
    thread: u32,
    #[serde(default)]
    registers: BTreeMap<String, u64>,
    #[serde(default)]
    writes: Vec<MemoryWrite>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MemoryWrite {
    address: u64,
    bytes: String,
}
#[derive(Serialize)]
struct Edge {
    thread: u32,
    from_rva: String,
    to_rva: Option<String>,
    target_absolute: String,
    kind: String,
    hits: usize,
}
#[derive(Serialize)]
struct Observation {
    thread: u32,
    step: usize,
    rva: String,
    kind: String,
    value: String,
}
#[derive(Serialize)]
struct Report {
    engine: &'static str,
    contract: &'static str,
    module_sha256: String,
    module_base: String,
    steps: usize,
    outside_module: usize,
    unique_instructions: usize,
    edges: Vec<Edge>,
    observations: Vec<Observation>,
    observed_path_pseudocode: Vec<Observation>,
    truncated: bool,
}
fn plain(path: &Path) -> Result<(), String> {
    let m = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err("trace/input reparse point rejected".into());
        }
    }
    if !m.is_file() || m.file_type().is_symlink() || m.len() > MAX_FILE {
        return Err("regular input/trace within 128 MiB required".into());
    }
    Ok(())
}
fn read(path: &Path, cancel: &AtomicBool) -> Result<Vec<u8>, String> {
    plain(path)?;
    let mut file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 65536];
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        if bytes.len() + n > MAX_FILE as usize {
            return Err("input grew beyond limit".into());
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    Ok(bytes)
}
fn hex(s: &str, max: usize) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) || s.len() / 2 > max || !s.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err("invalid/bounded hex bytes".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}
fn pe_size(bytes: &[u8]) -> Result<u64, String> {
    let u32at = |p: usize| -> Result<u32, String> {
        Ok(u32::from_le_bytes(
            bytes
                .get(p..p + 4)
                .ok_or("truncated PE")?
                .try_into()
                .unwrap(),
        ))
    };
    if bytes.get(..2) != Some(b"MZ") {
        return Err("dynamic module binding currently supports PE x64".into());
    }
    let pe = u32at(0x3c)? as usize;
    if bytes.get(pe..pe + 4) != Some(b"PE\0\0") || bytes.get(pe + 4..pe + 6) != Some(&[0x64, 0x86])
    {
        return Err("AMD64 PE required".into());
    }
    if bytes.get(pe + 24..pe + 26) != Some(&[0x0b, 0x02]) {
        return Err("PE32+ required".into());
    }
    Ok(u32at(pe + 24 + 56)? as u64)
}
fn validate(header: &Header, input: &[u8]) -> Result<(), String> {
    if header.version != 1
        || header.bitness != 64
        || header.module_size == 0
        || header.module_size != pe_size(input)?
        || header.module_sha256.len() != 64
        || !header.module_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        || header.module_sha256.to_ascii_lowercase() != format!("{:x}", Sha256::digest(input))
    {
        return Err("trace metadata does not match selected PE x64 binary/SHA-256".into());
    }
    header
        .module_base
        .checked_add(header.module_size)
        .ok_or("module address overflow")?;
    Ok(())
}
fn rva(header: &Header, ip: u64) -> Option<u64> {
    ip.checked_sub(header.module_base)
        .filter(|v| *v < header.module_size)
}
fn registers() -> [(&'static str, Register); 16] {
    [
        ("rax", Register::RAX),
        ("rcx", Register::RCX),
        ("rdx", Register::RDX),
        ("rbx", Register::RBX),
        ("rsp", Register::RSP),
        ("rbp", Register::RBP),
        ("rsi", Register::RSI),
        ("rdi", Register::RDI),
        ("r8", Register::R8),
        ("r9", Register::R9),
        ("r10", Register::R10),
        ("r11", Register::R11),
        ("r12", Register::R12),
        ("r13", Register::R13),
        ("r14", Register::R14),
        ("r15", Register::R15),
    ]
}
struct Analyzer {
    report: Report,
    seen: BTreeMap<u64, Vec<u8>>,
    last: BTreeMap<u32, (u64, FlowControl)>,
    edges: BTreeMap<(u32, u64, u64, String), usize>,
}
impl Analyzer {
    fn new(h: &Header) -> Self {
        Self{report:Report{engine:"UIE observed-path analysis",contract:"Trace observations are path/thread-specific, not global invariants or restored original source. Pseudocode covers observed register operations only, omits flag/alias side effects, and is not compilable original source. Target execution was performed externally; this importer never launches it.",module_sha256:h.module_sha256.clone(),module_base:format!("0x{:x}",h.module_base),steps:0,outside_module:0,unique_instructions:0,edges:Vec::new(),observations:Vec::new(),observed_path_pseudocode:Vec::new(),truncated:false},seen:BTreeMap::new(),last:BTreeMap::new(),edges:BTreeMap::new()}
    }
    fn observe(&mut self, h: &Header, step: Step) -> Result<(), String> {
        if self.report.steps >= MAX_ROWS {
            return Err("trace instruction limit exceeded".into());
        }
        let index = self.report.steps;
        self.report.steps += 1;
        let bytes = hex(&step.bytes, 15)?;
        if bytes.is_empty() {
            return Err("empty instruction".into());
        }
        let mut decoder = Decoder::with_ip(64, &bytes, step.ip, DecoderOptions::NONE);
        let instruction = decoder.decode();
        if instruction.is_invalid() || instruction.len() != bytes.len() {
            return Err("trace contains invalid/inexact x64 instruction".into());
        }
        if step.registers.len() > 32 || step.writes.len() > 256 {
            return Err("trace register/write limit".into());
        }
        if let Some((from, flow)) = self
            .last
            .insert(step.thread, (step.ip, instruction.flow_control()))
        {
            if rva(h, from).is_some()
                && matches!(
                    flow,
                    FlowControl::IndirectCall
                        | FlowControl::IndirectBranch
                        | FlowControl::Call
                        | FlowControl::UnconditionalBranch
                        | FlowControl::ConditionalBranch
                        | FlowControl::Return
                )
            {
                let kind = format!("observed {flow:?}");
                if self.edges.len() < MAX_EVIDENCE
                    || self
                        .edges
                        .contains_key(&(step.thread, from, step.ip, kind.clone()))
                {
                    *self
                        .edges
                        .entry((step.thread, from, step.ip, kind))
                        .or_default() += 1;
                } else {
                    self.report.truncated = true;
                }
            }
        }
        let Some(at) = rva(h, step.ip) else {
            self.report.outside_module += 1;
            return Ok(());
        };
        if self.report.observed_path_pseudocode.len() < MAX_EVIDENCE {
            let operand = |index: u32| -> Option<String> {
                match instruction.op_kind(index) {
                    OpKind::Register => {
                        Some(format!("{:?}", instruction.op_register(index)).to_ascii_lowercase())
                    }
                    OpKind::Immediate8
                    | OpKind::Immediate8_2nd
                    | OpKind::Immediate16
                    | OpKind::Immediate32
                    | OpKind::Immediate64
                    | OpKind::Immediate8to16
                    | OpKind::Immediate8to32
                    | OpKind::Immediate8to64
                    | OpKind::Immediate32to64 => {
                        Some(format!("0x{:x}", instruction.immediate(index)))
                    }
                    _ => None,
                }
            };
            let operation = match instruction.mnemonic() {
                iced_x86::Mnemonic::Mov => Some("="),
                iced_x86::Mnemonic::Xor => Some("^="),
                iced_x86::Mnemonic::And => Some("&="),
                iced_x86::Mnemonic::Or => Some("|="),
                iced_x86::Mnemonic::Add => Some("+="),
                iced_x86::Mnemonic::Sub => Some("-="),
                iced_x86::Mnemonic::Shl => Some("<<="),
                iced_x86::Mnemonic::Shr => Some(">>="),
                _ => None,
            };
            let statement = match (
                operation,
                operand(0),
                if instruction.op_count() > 1 {
                    operand(1)
                } else {
                    None
                },
            ) {
                (Some(operation), Some(left), Some(right))
                    if instruction.op0_kind() == OpKind::Register =>
                {
                    format!("{left} {operation} {right};")
                }
                _ => format!(
                    "/* {:?}: {} ; explicit unsupported/flow instruction */",
                    instruction.mnemonic(),
                    step.bytes
                ),
            };
            self.report.observed_path_pseudocode.push(Observation {
                thread: step.thread,
                step: index,
                rva: format!("0x{at:x}"),
                kind: "observed-path pseudocode".into(),
                value: statement,
            });
        } else {
            self.report.truncated = true;
        }
        if self.seen.len() < MAX_EVIDENCE || self.seen.contains_key(&at) {
            if let Some(previous) = self.seen.insert(at, bytes) {
                if previous != hex(&step.bytes, 15)? {
                    self.note(
                        step.thread,
                        index,
                        at,
                        "runtime code variant",
                        step.bytes.clone(),
                    );
                }
            }
        } else {
            self.report.truncated = true;
        }
        if matches!(
            instruction.flow_control(),
            FlowControl::IndirectCall | FlowControl::IndirectBranch
        ) && instruction.op0_kind() == OpKind::Register
        {
            let wanted = instruction.op0_register().full_register();
            if let Some((name, _)) = registers().iter().find(|(_, r)| *r == wanted) {
                if let Some(target) = step.registers.get(*name) {
                    self.note(
                        step.thread,
                        index,
                        at,
                        "register indirect target",
                        format!("{name}=0x{target:x}"),
                    );
                }
            }
        }
        for write in step.writes {
            let bytes = hex(&write.bytes, 1024)?;
            write
                .address
                .checked_add(bytes.len() as u64)
                .ok_or("memory write address overflow")?;
            if let Ok(text) = std::str::from_utf8(&bytes) {
                let text = text.trim_end_matches('\0');
                if text.len() >= 4
                    && text
                        .chars()
                        .all(|c| !c.is_control() || c == '\t' || c == '\n')
                {
                    self.note(
                        step.thread,
                        index,
                        at,
                        "observed write / UTF-8",
                        format!(
                            "0x{:x}: {}",
                            write.address,
                            text.chars().take(256).collect::<String>()
                        ),
                    );
                }
            }
            if bytes.len() % 2 == 0 {
                let words: Vec<u16> = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                    .take_while(|v| *v != 0)
                    .collect();
                if let Ok(text) = String::from_utf16(&words) {
                    if text.chars().count() >= 4
                        && text.chars().all(|c| c.is_ascii_graphic() || c == ' ')
                    {
                        self.note(
                            step.thread,
                            index,
                            at,
                            "observed write / UTF-16LE",
                            format!(
                                "0x{:x}: {}",
                                write.address,
                                text.chars().take(256).collect::<String>()
                            ),
                        );
                    }
                }
            }
        }
        Ok(())
    }
    fn note(&mut self, thread: u32, step: usize, at: u64, kind: &str, value: String) {
        if self.report.observations.len() < MAX_EVIDENCE {
            self.report.observations.push(Observation {
                thread,
                step,
                rva: format!("0x{at:x}"),
                kind: kind.into(),
                value,
            });
        } else {
            self.report.truncated = true;
        }
    }
    fn finish(mut self, h: &Header) -> Report {
        self.report.unique_instructions = self.seen.len();
        self.report.edges = self
            .edges
            .into_iter()
            .map(|((thread, from, to, kind), hits)| Edge {
                thread,
                from_rva: format!("0x{:x}", from - h.module_base),
                to_rva: rva(h, to).map(|v| format!("0x{v:x}")),
                target_absolute: format!("0x{to:x}"),
                kind,
                hits,
            })
            .collect();
        self.report
    }
}
fn json_trace(bytes: &[u8], input: &[u8], cancel: &AtomicBool) -> Result<Report, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| "JSONL trace must be UTF-8")?;
    let mut lines = text.lines().filter(|l| !l.trim().is_empty());
    let first = lines.next().ok_or("missing trace header")?;
    if first.len() > MAX_LINE {
        return Err("trace header exceeds line limit".into());
    }
    let h: Header = serde_json::from_str(first).map_err(|e| e.to_string())?;
    validate(&h, input)?;
    let mut a = Analyzer::new(&h);
    for line in lines {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        if line.len() > MAX_LINE {
            return Err("trace line exceeds 64 KiB".into());
        }
        a.observe(&h, serde_json::from_str(line).map_err(|e| e.to_string())?)?;
    }
    Ok(a.finish(&h))
}
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).ok_or("trace offset overflow")?;
        let b = self
            .bytes
            .get(self.pos..end)
            .ok_or("truncated native trace")?;
        self.pos = end;
        Ok(b)
    }
    fn byte(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }
    fn word(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn dword(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
}
fn native_trace(
    bytes: &[u8],
    h: &Header,
    input: &[u8],
    cancel: &AtomicBool,
) -> Result<Report, String> {
    validate(h, input)?;
    let mut c = Cursor { bytes, pos: 0 };
    if c.take(4)? != b"TRAC" {
        return Err("not an x64dbg TRAC file".into());
    }
    let size = c.dword()? as usize;
    if size > MAX_LINE {
        return Err("native trace JSON header limit".into());
    }
    let native_header: serde_json::Value =
        serde_json::from_slice(c.take(size)?).map_err(|e| e.to_string())?;
    if native_header["ver"].as_u64() != Some(1)
        || native_header["arch"].as_str() != Some("x64")
        || native_header["compression"].as_str() != Some("")
    {
        return Err("only uncompressed x64dbg trace version 1 / x64 is supported".into());
    }
    let mut regs = [None; 512];
    let mut thread = None;
    let mut a = Analyzer::new(h);
    while c.pos < bytes.len() {
        if cancel.load(Ordering::Relaxed) {
            return Err("cancelled".into());
        }
        let kind = c.byte()?;
        if kind >= 0x80 {
            let size = c.dword()? as usize;
            c.take(size)?;
            continue;
        }
        if kind != 0 {
            return Err("unsupported native trace block".into());
        }
        let changes = c.byte()? as usize;
        let accesses = c.byte()? as usize;
        let flags = c.byte()?;
        if flags & 0x70 != 0 {
            return Err("unsupported native trace flags".into());
        }
        if flags & 0x80 != 0 {
            thread = Some(c.dword()?);
        }
        let opcode = c.take((flags & 15) as usize)?.to_vec();
        let positions = c.take(changes)?.to_vec();
        let mut slot = 0usize;
        for (i, delta) in positions.iter().enumerate() {
            slot = if i == 0 {
                *delta as usize
            } else {
                slot.checked_add(1 + *delta as usize)
                    .ok_or("register index overflow")?
            };
            if slot >= regs.len() {
                return Err("native trace register layout unsupported".into());
            }
            regs[slot] = Some(c.word()?);
        }
        let memoryflags = c.take(accesses)?.to_vec();
        if memoryflags.iter().any(|v| v & !1 != 0) {
            return Err("unsupported memory flags".into());
        }
        let mut addresses = Vec::new();
        for _ in 0..accesses {
            addresses.push(c.word()?);
        }
        for _ in 0..accesses {
            c.word()?;
        }
        let mut writes = Vec::new();
        for (i, flag) in memoryflags.iter().enumerate() {
            if flag & 1 == 0 {
                let value = c.word()?;
                writes.push(MemoryWrite {
                    address: addresses[i],
                    bytes: value
                        .to_le_bytes()
                        .iter()
                        .map(|v| format!("{v:02x}"))
                        .collect(),
                });
            }
        }
        let ip = regs[16].ok_or("native trace starts without instruction-pointer state")?;
        let mut values = BTreeMap::new();
        for (i, (name, _)) in registers().iter().enumerate() {
            if let Some(value) = regs[i] {
                values.insert((*name).into(), value);
            }
        }
        a.observe(
            h,
            Step {
                ip,
                bytes: opcode.iter().map(|v| format!("{v:02x}")).collect(),
                thread: thread.ok_or("native trace starts without thread identity")?,
                registers: values,
                writes,
            },
        )?;
    }
    Ok(a.finish(h))
}
fn analyze(input: &Path, trace: &Path, cancel: &AtomicBool) -> Result<Report, String> {
    let input = read(input, cancel)?;
    let bytes = read(trace, cancel)?;
    if bytes.starts_with(b"TRAC") {
        let metadata = read(&trace.with_extension("uie-trace.json"), cancel)?;
        if metadata.len() > MAX_LINE {
            return Err("trace metadata limit".into());
        }
        let h: Header = serde_json::from_slice(&metadata).map_err(|e| e.to_string())?;
        native_trace(&bytes, &h, &input, cancel)
    } else {
        json_trace(&bytes, &input, cancel)
    }
}
/// Replay a previously captured trace and publish a new evidence report. Never executes input.
pub fn import_trace(
    input: &Path,
    trace: &Path,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<PathBuf, String> {
    let report = analyze(input, trace, cancel)?;
    if cancel.load(Ordering::Relaxed) {
        return Err("cancelled".into());
    }
    let bytes = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .map_err(|e| e.to_string())?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(output);
        return Err(error.to_string());
    }
    Ok(output.to_path_buf())
}
fn guide(input: &Path, trace: &Path, base: u64, cancel: &AtomicBool) -> Result<PathBuf, String> {
    let bytes = read(input, cancel)?;
    let h = Header {
        version: 1,
        module_sha256: format!("{:x}", Sha256::digest(&bytes)),
        module_base: base,
        module_size: pe_size(&bytes)?,
        bitness: 64,
    };
    validate(&h, &bytes)?;
    let path = trace.with_extension("uie-trace.json");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| e.to_string())?;
    file.write_all(&serde_json::to_vec_pretty(&h).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    Ok(path)
}
pub struct DynamicAnalysis {
    pub open: bool,
    trace: Option<PathBuf>,
    base: String,
    report: String,
    message: String,
    receiver: Option<mpsc::Receiver<Result<String, String>>>,
    cancel: Arc<AtomicBool>,
}
impl Default for DynamicAnalysis {
    fn default() -> Self {
        Self {
            open: false,
            trace: None,
            base: String::new(),
            report: String::new(),
            message: String::new(),
            receiver: None,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl Drop for DynamicAnalysis {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}
impl DynamicAnalysis {
    fn start(
        &mut self,
        work: impl FnOnce(Arc<AtomicBool>) -> Result<String, String> + Send + 'static,
    ) {
        self.cancel.store(true, Ordering::Relaxed);
        self.cancel = Arc::new(AtomicBool::new(false));
        let cancel = self.cancel.clone();
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        thread::spawn(move || {
            let _ = tx.send(work(cancel));
        });
    }
    pub fn show(&mut self, ctx: &egui::Context, input: Option<PathBuf>, output: Option<PathBuf>) {
        if !self.open {
            return;
        }
        if let Some(value) = self.receiver.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(v) => Some(v),
            Err(mpsc::TryRecvError::Disconnected) => Some(Err("trace worker stopped".into())),
            Err(_) => None,
        }) {
            self.receiver = None;
            match value {
                Ok(value) if value.starts_with('{') => {
                    self.report = value;
                    self.message.clear();
                }
                Ok(value) => self.message = value,
                Err(error) => self.message = error,
            }
        }
        if self.receiver.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        let mut open = true;
        egui::Window::new(label("динамический анализ / трасса","dynamic analysis / trace")).open(&mut open).default_width(900.0).default_height(620.0).show(ctx,|ui|{
 ui.label(label("импортирует наблюдавшиеся пути выполнения из JSONL или x64dbg .trace64 целевой файл здесь не запускается","imports observed paths from JSONL or x64dbg .trace64; never launches the target here"));
 ui.label(label("для .trace64 нужна соседняя .uie-trace.json с SHA-256 бинарника и фактической базой модуля из отладчика",".trace64 requires a neighboring .uie-trace.json binding binary SHA-256 and the actual debugger module base"));
 egui::CollapsingHeader::new(label("как записать трассу в виртуалке","recording a trace in a VM")).show(ui,|ui|{
     ui.label(label("в отдельной контролируемой VM открой свою тестовую программу в x64dbg и остановись на нужной функции затем выполни команды в консоли отладчика","in a separate controlled VM open your own test program in x64dbg and pause at the desired function, then enter these debugger commands"));
     ui.monospace("StartTraceRecording \"C:\\lab\\sample.trace64\"\nTraceIntoConditional 0, 1000");
     ui.label(label("1000 — шестнадцатеричный лимит 4096 шагов запиши фактическую базу модуля из окна модулей перенеси трассу и исходный бинарник в UIE и создай метаданные с этой базой","1000 is a hexadecimal limit of 4096 steps. Record the actual module base from the debugger modules view. Transfer the trace and original binary to UIE and create metadata with that base."));
 });
 let ready=self.receiver.is_none();ui.horizontal(|ui|{if ui.add_enabled(ready,egui::Button::new(label("открыть трассу","open trace"))).clicked(){if let Some(path)=rfd::FileDialog::new().add_filter("trace",&["jsonl","trace64"]).pick_file(){self.trace=Some(path);self.report.clear();}}
if let Some(path)=&self.trace{ui.label(path.display().to_string());}});
 ui.horizontal(|ui|{ui.label(label("база модуля hex","module base hex"));ui.text_edit_singleline(&mut self.base);if ui.add_enabled(ready&&input.is_some()&&self.trace.is_some(),egui::Button::new(label("создать метаданные trace64","create trace64 metadata"))).clicked(){let input=input.clone().unwrap();let trace=self.trace.clone().unwrap();match u64::from_str_radix(self.base.trim().trim_start_matches("0x"),16){Ok(base)=>self.start(move|cancel|guide(&input,&trace,base,&cancel).map(|p|format!("Metadata: {}",p.display()))),Err(e)=>self.message=e.to_string()}}});
 if ui.add_enabled(ready&&input.is_some()&&self.trace.is_some(),egui::Button::new(label("анализировать трассу","analyze trace"))).clicked(){let input=input.clone().unwrap();let trace=self.trace.clone().unwrap();self.start(move|cancel|analyze(&input,&trace,&cancel).and_then(|r|serde_json::to_string_pretty(&r).map_err(|e|e.to_string())));}
 if !self.report.is_empty(){ui.horizontal(|ui|{if ui.button(label("скопировать отчёт","copy report")).clicked(){ui.ctx().copy_text(self.report.clone());}
if ui.button(label("сохранить отчёт","save report")).clicked(){if let Some(path)=rfd::FileDialog::new().set_directory(output.clone().unwrap_or_default()).set_file_name("dynamic-report.json").save_file(){let report=self.report.clone();self.start(move |_|{let mut file=OpenOptions::new().create_new(true).write(true).open(&path).map_err(|e|e.to_string())?;file.write_all(report.as_bytes()).map_err(|e|e.to_string())?;Ok(format!("Saved: {}",path.display()))});}}});}
 if !self.message.is_empty(){ui.label(&self.message);}
if self.receiver.is_some(){ui.spinner();if ui.button(label("отменить","cancel")).clicked(){self.cancel.store(true,Ordering::Relaxed);}}
 egui::ScrollArea::both().show(ui,|ui|{let lines:Vec<_>=self.report.lines().collect();egui::ScrollArea::vertical().id_salt("dynamic-report-lines").show_rows(ui,18.0,lines.len(),|ui,rows|{for row in rows{ui.monospace(lines[row].chars().take(2048).collect::<String>());}});});
 });
        self.open = open;
        if !open {
            self.cancel.store(true, Ordering::Relaxed);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut b = vec![0; 512];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        b[0x80..0x84].copy_from_slice(b"PE\0\0");
        b[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        b[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        b[0xd0..0xd4].copy_from_slice(&0x2000u32.to_le_bytes());
        b
    }
    fn header(input: &[u8]) -> Header {
        Header {
            version: 1,
            module_sha256: format!("{:x}", Sha256::digest(input)),
            module_base: 0x100000,
            module_size: 0x2000,
            bitness: 64,
        }
    }
    #[test]
    fn binding_and_observed_indirect_edges_are_thread_specific() {
        let input = fixture();
        let h = header(&input);
        let mut trace = serde_json::to_string(&h).unwrap();
        trace.push_str("\n{\"ip\":1048832,\"bytes\":\"ffe0\",\"thread\":1,\"registers\":{\"rax\":1049088}}\n{\"ip\":1049344,\"bytes\":\"90\",\"thread\":2}\n{\"ip\":1049088,\"bytes\":\"c3\",\"thread\":1}\n");
        let r = json_trace(trace.as_bytes(), &input, &AtomicBool::new(false)).unwrap();
        assert_eq!(r.edges.len(), 1);
        assert_eq!(r.edges[0].thread, 1);
        assert_eq!(r.edges[0].to_rva.as_deref(), Some("0x200"));
        assert_eq!(r.observations[0].kind, "register indirect target");
        let mut modified = input;
        modified[500] = 1;
        assert!(json_trace(trace.as_bytes(), &modified, &AtomicBool::new(false)).is_err());
    }
    #[test]
    fn native_trace_reconstructs_rip_and_register_target() {
        let input = fixture();
        let h = header(&input);
        let mut bytes = b"TRAC".to_vec();
        let native_header = br#"{"ver":1,"arch":"x64","compression":""}"#;
        bytes.extend((native_header.len() as u32).to_le_bytes());
        bytes.extend(native_header);
        bytes.extend([0, 2, 0, 0x82]);
        bytes.extend(1u32.to_le_bytes());
        bytes.extend([0xff, 0xe0]);
        bytes.extend([0, 15]);
        bytes.extend(0x100200u64.to_le_bytes());
        bytes.extend(0x100100u64.to_le_bytes());
        bytes.extend([0, 1, 0, 1, 0xc3, 16]);
        bytes.extend(0x100200u64.to_le_bytes());
        let r = native_trace(&bytes, &h, &input, &AtomicBool::new(false)).unwrap();
        assert_eq!(r.steps, 2);
        assert_eq!(r.edges.len(), 1);
        assert_eq!(r.observations.len(), 1);
        bytes.pop();
        assert!(native_trace(&bytes, &h, &input, &AtomicBool::new(false)).is_err());
    }
    #[test]
    fn observed_register_operations_and_written_strings_are_local_evidence() {
        let input = fixture();
        let h = header(&input);
        let trace=format!("{}\n{{\"ip\":1048832,\"bytes\":\"b82a000000\",\"thread\":3,\"writes\":[{{\"address\":1049600,\"bytes\":\"7400650073007400\"}}]}}\n",serde_json::to_string(&h).unwrap());
        let report = json_trace(trace.as_bytes(), &input, &AtomicBool::new(false)).unwrap();
        assert_eq!(report.observed_path_pseudocode[0].value, "eax = 0x2a;");
        assert!(report
            .observations
            .iter()
            .any(|o| o.kind == "observed write / UTF-16LE" && o.value.ends_with("test")));
        assert!(report.edges.is_empty());
    }
    #[test]
    fn reject_invalid_bytes_overflow_and_cancel() {
        let input = fixture();
        let mut h = header(&input);
        h.module_base = u64::MAX;
        assert!(validate(&h, &input).is_err());
        assert!(hex("zz", 15).is_err());
        assert!(hex("a", 15).is_err());
        let h = header(&input);
        let trace = format!(
            "{}\n{{\"ip\":1048832,\"bytes\":\"90\"}}",
            serde_json::to_string(&h).unwrap()
        );
        assert!(json_trace(trace.as_bytes(), &input, &AtomicBool::new(true)).is_err());
    }
}
