use eframe::egui;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, BufRead, Read},
    path::PathBuf,
    sync::{mpsc, OnceLock},
    thread,
};

const MAX_PREVIEW: u64 = 256 * 1024;

fn write_bug_email(report: impl Read, mut output: impl std::io::Write) -> std::io::Result<()> {
    output.write_all(b"To: goygla02@gmail.com\r\nSubject: UIE crash report\r\nX-Unsent: 1\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=UIE_crash_attachment\r\n\r\n--UIE_crash_attachment\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n\r\n--UIE_crash_attachment\r\nContent-Type: text/plain; name=crash.log\r\nContent-Disposition: attachment; filename=crash.log\r\nContent-Transfer-Encoding: base64\r\n\r\n")?;
    let mut report = RedactedReader::new(report, &personal_prefixes());
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    loop {
        let mut bytes = [0u8; 57];
        let mut size = 0;
        while size < bytes.len() {
            match report.read(&mut bytes[size..]) {
                Ok(0) => break,
                Ok(count) => size += count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if size == 0 {
            break;
        }
        for chunk in bytes[..size].chunks(3) {
            let a = chunk[0];
            let b = chunk.get(1).copied().unwrap_or(0);
            let c = chunk.get(2).copied().unwrap_or(0);
            output.write_all(&[
                ALPHABET[(a >> 2) as usize],
                ALPHABET[(((a & 3) << 4) | (b >> 4)) as usize],
                if chunk.len() > 1 {
                    ALPHABET[(((b & 15) << 2) | (c >> 6)) as usize]
                } else {
                    b'='
                },
                if chunk.len() > 2 {
                    ALPHABET[(c & 63) as usize]
                } else {
                    b'='
                },
            ])?;
        }
        output.write_all(b"\r\n")?;
    }
    output.write_all(b"--UIE_crash_attachment--\r\n")?;
    output.flush()
}

struct Report {
    path: PathBuf,
    text: String,
    fingerprint: String,
    truncated: bool,
    acknowledged: bool,
}

fn read_report(path: PathBuf, acknowledgement: &std::path::Path) -> Result<Option<Report>, String> {
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_PREVIEW + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let fingerprint = format!("{:x}", Sha256::digest(&bytes));
    let truncated = bytes.len() as u64 > MAX_PREVIEW;
    bytes.truncate(MAX_PREVIEW as usize);
    let acknowledged = fs::read_to_string(acknowledgement)
        .ok()
        .is_some_and(|old| old == fingerprint);
    Ok(Some(Report {
        path,
        text: String::from_utf8_lossy(&bytes).into_owned(),
        fingerprint,
        truncated,
        acknowledged,
    }))
}

// Bound each diagnostic line, rather than loading the complete log for export.
// Oversized lines fail explicitly; they are never silently truncated or exported raw.
const MAX_REDACTION_LINE: u64 = 8 * 1024 * 1024;

fn personal_prefixes() -> Vec<String> {
    ["USERPROFILE", "HOME", "LOCALAPPDATA", "APPDATA"]
        .into_iter()
        .filter_map(|key| std::env::var(key).ok())
        .collect()
}

struct Redactor {
    prefixes: Vec<regex::Regex>,
    private_key: bool,
}

impl Redactor {
    fn new(prefixes: &[String]) -> Self {
        let mut prefixes = prefixes.to_vec();
        prefixes.sort_by_key(|value| std::cmp::Reverse(value.len()));
        Self {
            prefixes: prefixes
                .into_iter()
                .filter(|prefix| prefix.len() > 3)
                .flat_map(|prefix| [prefix.replace('\\', "/"), prefix.replace('/', "\\")])
                .map(|prefix| {
                    regex::RegexBuilder::new(&regex::escape(&prefix))
                        .case_insensitive(true)
                        .build()
                        .expect("escaped path regex")
                })
                .collect(),
            private_key: false,
        }
    }

    fn line(&mut self, text: &str) -> String {
        static KEY_MARKERS: OnceLock<(regex::Regex, regex::Regex)> = OnceLock::new();
        let (begin, end) = KEY_MARKERS.get_or_init(|| {
            (
                regex::Regex::new(r"(?i)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----").unwrap(),
                regex::Regex::new(r"(?i)-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----").unwrap(),
            )
        });
        let mut remaining = text;
        let mut result = String::new();
        loop {
            if self.private_key {
                if let Some(marker) = end.find(remaining) {
                    result.push_str("<redacted-private-key>");
                    remaining = &remaining[marker.end()..];
                    self.private_key = false;
                } else {
                    result.push_str("<redacted-private-key>");
                    if remaining.ends_with('\n') {
                        result.push('\n');
                    }
                    break;
                }
            } else if let Some(marker) = begin.find(remaining) {
                result.push_str(&remaining[..marker.start()]);
                remaining = &remaining[marker.end()..];
                self.private_key = true;
            } else {
                result.push_str(remaining);
                break;
            }
        }
        static RULES: OnceLock<Vec<(regex::Regex, &'static str)>> = OnceLock::new();
        let rules = RULES.get_or_init(|| [
            (r#"(?i)https?://(?:canary\.|ptb\.)?discord(?:app)?\.com/api(?:/v[0-9]+)?/webhooks/[^\s<>"']+"#, "<redacted-webhook>"),
            (r#"(?i)https?://api\.telegram\.org/(?:file/)?bot[^\s<>"']+"#, "<redacted-telegram-url>"),
            (r#"(?i)\b((?:proxy[-_ ]?)?authorization["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|(?:[a-z][a-z0-9_-]*[ \t]+)?[^\s,;}\]"']+)"#, "${1}<redacted>"),
            (r#"(?i)\b(bearer\s+)[a-z0-9._~+/=-]+"#, "${1}<redacted>"),
            (r#"(?i)(\b[a-z0-9_-]*(?:password|passwd|pwd|token|secret|api[_-]?key|apikey|access[_-]?key|private[_-]?key|credential)(?:[_-][a-z0-9]+)*["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&}\]"']+)"#, "${1}<redacted>"),
            (r#"(?i)(\b(?:accessToken|refreshToken|authToken|clientSecret|privateKey)["']?\s*[:=]\s*)(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;&}\]"']+)"#, "${1}<redacted>"),
            (r#"(?i)[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}"#, "<redacted-email>"),
            (r#"(?i)\b[a-z]:[\\/](?:users|documents and settings)[\\/][^\\/\s<>"':;,]+"#, "<user>"),
            (r#"(?:/home/|/Users/)[^/\s<>"':;,]+|/root\b"#, "<user>"),
        ].into_iter().map(|(pattern, replacement)| (regex::Regex::new(pattern).unwrap(), replacement)).collect());
        for (pattern, replacement) in rules {
            result = pattern.replace_all(&result, *replacement).into_owned();
        }
        for prefix in &self.prefixes {
            result = prefix.replace_all(&result, "<user>").into_owned();
        }
        result
    }
}

struct RedactedReader<R> {
    input: io::BufReader<R>,
    redactor: Redactor,
    pending: io::Cursor<Vec<u8>>,
}

impl<R: Read> RedactedReader<R> {
    fn new(input: R, prefixes: &[String]) -> Self {
        Self {
            input: io::BufReader::new(input),
            redactor: Redactor::new(prefixes),
            pending: io::Cursor::new(Vec::new()),
        }
    }
}

impl<R: Read> Read for RedactedReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        let count = self.pending.read(output)?;
        if count != 0 {
            return Ok(count);
        }
        let mut line = Vec::new();
        (&mut self.input)
            .take(MAX_REDACTION_LINE + 1)
            .read_until(b'\n', &mut line)?;
        if line.len() as u64 > MAX_REDACTION_LINE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Crash report contains a line over 8 MiB; sanitized export stopped without truncating it."));
        }
        if line.is_empty() {
            return Ok(0);
        }
        self.pending = io::Cursor::new(
            self.redactor
                .line(&String::from_utf8_lossy(&line))
                .into_bytes(),
        );
        self.pending.read(output)
    }
}

fn redact(text: &str, prefixes: &[String]) -> String {
    let mut redactor = Redactor::new(prefixes);
    text.split_inclusive('\n')
        .map(|line| redactor.line(line))
        .collect()
}

fn export_report(path: &std::path::Path, output: impl io::Write) -> io::Result<()> {
    let input = fs::File::open(path)?;
    let mut output = io::BufWriter::new(output);
    io::copy(
        &mut RedactedReader::new(input, &personal_prefixes()),
        &mut output,
    )?;
    io::Write::flush(&mut output)
}

fn hint(text: &str, english: bool) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if lower.contains("java heap space") || lower.contains("out of memory") {
        if english {
            "Possible memory exhaustion. Try lazy native analysis or fewer modules, then inspect the engine log."
        } else {
            "Возможно, закончилась память. Попробуй ленивый анализ или меньше модулей и проверь лог движка."
        }
    } else if lower.contains("no such file or directory")
        || lower.contains("required engines are missing")
    {
        if english {
            "A file or engine may be missing. Check the reported path and prepare the required engine while online."
        } else {
            "Возможно, отсутствует файл или движок. Проверь указанный путь и подготовь движок при доступном интернете."
        }
    } else if lower.contains("panicked") || lower.contains("backtrace status:") {
        if english {
            "A Rust panic was recorded. Keep this report and the input hash for a reproducible bug report."
        } else {
            "Сохранён отчёт о Rust panic. Для воспроизведения ошибки пригодятся этот отчёт и хеш входного файла."
        }
    } else if english {
        "The exact cause is unknown. Inspect the first error and nearby log lines; this assistant does not automatically repair files."
    } else {
        "Точная причина неизвестна. Проверь первую ошибку и соседние строки лога; помощник не изменяет файлы автоматически."
    }
}

pub struct Assistant {
    pub open: bool,
    report: Option<Report>,
    receiver: Option<mpsc::Receiver<Result<Option<Report>, String>>>,
    acknowledgement: PathBuf,
    pub error: Option<String>,
    show_raw_preview: bool,
    auto_open: bool,
    mail_receiver: Option<mpsc::Receiver<Result<PathBuf, String>>>,
}

impl Default for Assistant {
    fn default() -> Self {
        let mut assistant = Self {
            open: false,
            report: None,
            receiver: None,
            acknowledgement: crate::engine::config_path().with_file_name("crash-dismissed.sha256"),
            error: None,
            show_raw_preview: false,
            auto_open: true,
            mail_receiver: None,
        };
        assistant.reload(None, false);
        assistant
    }
}

impl Assistant {
    pub fn reload(&mut self, log: Option<PathBuf>, explicit: bool) {
        let path =
            log.unwrap_or_else(|| crate::engine::config_path().with_file_name("crash-report.log"));
        let ack = self.acknowledgement.clone();
        let (tx, rx) = mpsc::channel();
        self.receiver = Some(rx);
        self.auto_open = !explicit;
        if explicit {
            self.open = true;
        }
        self.error = None;
        thread::spawn(move || {
            let _ = tx.send(read_report(path, &ack));
        });
    }

    pub fn show(&mut self, ctx: &egui::Context, english: bool) {
        let label = |en: &'static str, ru: &'static str| if english { en } else { ru };
        if let Some(result) = self.receiver.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                Some(Err("crash report reader stopped".into()))
            }
        }) {
            self.receiver = None;
            match result {
                Ok(report) => {
                    if self.auto_open && report.as_ref().is_some_and(|report| !report.acknowledged)
                    {
                        self.open = true;
                    }
                    self.report = report;
                }
                Err(error) => self.error = Some(error),
            }
        }
        if let Some(result) = self
            .mail_receiver
            .as_ref()
            .and_then(|rx| match rx.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("email preparation stopped".into()))
                }
            })
        {
            self.mail_receiver = None;
            match result {
                Ok(path) => {
                    if let Err(error) = crate::engine::open_folder(&path) {
                        self.error = Some(error);
                    }
                }
                Err(error) => self.error = Some(error),
            }
        }
        if self.receiver.is_some() || self.mail_receiver.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        if !self.open {
            return;
        }
        let mut open = self.open;
        egui::Window::new(label("crash assistant", "помощник сбоев"))
            .id(egui::Id::new("crash-assistant")).anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .default_width(720.0).open(&mut open).show(ctx, |ui| {
                ui.label(label("Reports stay on this computer. Nothing is uploaded automatically.", "Отчёты остаются на этом компьютере. Автоматической отправки нет."));
                if self.receiver.is_some() { ui.spinner(); }
                if let Some(error) = &self.error { ui.colored_label(egui::Color32::LIGHT_RED, error); }
                let Some(report) = &self.report else {
                    ui.label(label("No saved crash report. Rust panics are captured; native crashes and forced termination may not produce a report.", "Сохранённого отчёта нет. Rust panic перехватываются; нативный сбой или принудительное завершение могут не оставить отчёт."));
                    return;
                };
                ui.separator();
                ui.label(hint(&report.text, english));
                ui.small(label("Personal paths and recognized secrets are removed automatically from all copied, saved and attached reports.", "Личные пути и распознанные секреты автоматически удаляются из копий, сохранённых отчётов и вложений."));
                ui.checkbox(&mut self.show_raw_preview, label("Show original locally (exports remain sanitized)", "Показать оригинал локально (экспорт остаётся обезличенным)"));
                let mut text = if self.show_raw_preview { report.text.clone() } else { redact(&report.text, &personal_prefixes()) };
                if report.truncated { text.push_str("\n[preview truncated; copy, save and attachment include the complete sanitized report]\n"); }
                ui.horizontal(|ui| {
                    if ui.add_enabled(self.mail_receiver.is_none(), egui::Button::new(label("Report a bug", "Сообщить об ошибке"))).clicked() {
                        let input = report.path.clone();
                        let (tx, rx) = mpsc::channel();
                        self.mail_receiver = Some(rx);
                        thread::spawn(move || {
                            let result = (|| -> Result<PathBuf, String> {
                                let file = fs::File::open(input).map_err(|e| e.to_string())?;
                                let folder = crate::engine::config_path().with_file_name("bug-reports");
                                fs::create_dir_all(&folder).map_err(|e| e.to_string())?;
                                let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_nanos();
                                let path = folder.join(format!("UIE-crash-{stamp}.eml"));
                                let output = fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(|e| e.to_string())?;
                                write_bug_email(file, std::io::BufWriter::new(output)).map_err(|e| e.to_string())?;
                                Ok(path)
                            })();
                            let _ = tx.send(result);
                        });
                    }
                    if ui.button(label("Copy report", "Скопировать отчёт")).clicked() {
                        let mut complete = Vec::new();
                        match export_report(&report.path, &mut complete) {
                            Ok(()) => ctx.copy_text(String::from_utf8_lossy(&complete).into_owned()),
                            Err(error) => self.error = Some(error.to_string()),
                        }
                    }
                    if ui.button(label("Save report", "Сохранить отчёт")).clicked() {
                        if let Some(path) = rfd::FileDialog::new().set_file_name("UIE-crash-report.txt").save_file() {
                            if let Err(error) = (|| -> io::Result<()> {
                                if path.canonicalize().ok() == report.path.canonicalize().ok() {
                                    return Err(io::Error::new(io::ErrorKind::InvalidInput, "Choose a different file to preserve the original crash log."));
                                }
                                export_report(&report.path, fs::File::create(path)?)
                            })() { self.error = Some(error.to_string()); }
                        }
                    }
                    if ui.button(label("Open log folder", "Открыть папку лога")).clicked() {
                        if let Some(parent) = report.path.parent() { if let Err(error) = crate::engine::open_folder(parent) { self.error = Some(error); } }
                    }
                });
                ui.small(label("Creates an unsent email draft with the complete sanitized crash.log. Review before sending; automatic removal may not recognize every secret. Requires a mail client supporting .eml drafts.", "Создаётся неотправленный черновик с полным обезличенным crash.log. Проверь перед отправкой: автоматическая очистка может распознать не все секреты. Нужен почтовый клиент с поддержкой .eml."));
                egui::ScrollArea::vertical().max_height(350.0).show(ui, |ui| {
                    ui.add(egui::TextEdit::multiline(&mut text).font(egui::TextStyle::Monospace).desired_width(f32::INFINITY).interactive(false));
                });
                if ui.button(label("Do not show this report again", "Больше не показывать этот отчёт")).clicked() {
                    let saved = self.acknowledgement.parent().map_or(Ok(()), fs::create_dir_all)
                        .and_then(|()| fs::write(&self.acknowledgement, &report.fingerprint));
                    match saved {
                        Ok(()) => self.open = false,
                        Err(error) => self.error = Some(error.to_string()),
                    }
                }
            });
        self.open &= open;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn email_attaches_complete_log_without_truncation() {
        let input = vec![b'a'; MAX_PREVIEW as usize + 125];
        let mut email = Vec::new();
        write_bug_email(&input[..], &mut email).unwrap();
        let text = String::from_utf8(email).unwrap();
        assert!(text.starts_with("To: goygla02@gmail.com\r\n"));
        assert!(text.contains("filename=crash.log"));
        let encoded = text
            .split("Content-Transfer-Encoding: base64\r\n\r\n")
            .nth(1)
            .unwrap()
            .split("--UIE_crash_attachment--")
            .next()
            .unwrap()
            .replace("\r\n", "");
        assert_eq!(encoded, "YWFh".repeat(input.len() / 3));
        for (raw, expected) in [("a", "YQ=="), ("ab", "YWI="), ("abc", "YWJj")] {
            let mut output = Vec::new();
            write_bug_email(raw.as_bytes(), &mut output).unwrap();
            assert!(String::from_utf8(output)
                .unwrap()
                .contains(&format!("\r\n{expected}\r\n--UIE_crash_attachment--")));
        }
    }
    fn attachment(email: &[u8]) -> Vec<u8> {
        let email = String::from_utf8_lossy(email);
        let encoded = email
            .split("Content-Transfer-Encoding: base64\r\n\r\n")
            .nth(1)
            .unwrap()
            .split("--UIE_crash_attachment--")
            .next()
            .unwrap();
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut decoded = Vec::new();
        let mut bits = 0u32;
        let mut available = 0;
        for ch in encoded
            .bytes()
            .filter(|ch| !ch.is_ascii_whitespace() && *ch != b'=')
        {
            bits = (bits << 6) | alphabet.iter().position(|value| *value == ch).unwrap() as u32;
            available += 6;
            if available >= 8 {
                available -= 8;
                decoded.push((bits >> available) as u8);
            }
        }
        decoded
    }

    #[test]
    fn removes_recognized_secrets_and_preserves_diagnostics_in_all_exports() {
        let corpus = concat!(
            "panic 0x7ff1234 module::run::h0123abcd sha256=0123456789abcdef\n",
            "C:\\Users\\Alice\\src\\main.rs /home/bob/project.rs /Users/Charlie/app /root/file\n",
            "contact Person.Name+crash@Example.COM\n",
            "Authorization: Bearer authsecret\nPROXY-AUTHORIZATION=Basic basicsecret\n",
            "bearer bearerSecret\nPASSWORD=PassSecret\npwd: pwdSecret\n",
            "{\"Api_Key\": \"keySecret\", \"refreshToken\": \"refreshSecret\"}\n",
            "client-secret='client Secret' access_token=accessSecret token: tokenSecret\n",
            "myApiToken=camelSecret PRIVATE_KEY=privateValue\n",
            "https://api.telegram.org/bot12345:telegramSecret/sendMessage\n",
            "https://discord.com/api/webhooks/123456/discordSecret?wait=true\n",
            "before -----BEGIN RSA PRIVATE KEY-----\nprivateBodyOne\nprivateBodyTwo\n-----END RSA PRIVATE KEY----- after\n",
            "-----begin openssh private key-----inlinePrivate-----end openssh private key-----\n",
            "last diagnostic: backtrace complete\n",
        );
        let clean = redact(corpus, &[]);
        for secret in [
            "Alice",
            "bob",
            "Charlie",
            "/root",
            "Person.Name",
            "authsecret",
            "basicsecret",
            "bearerSecret",
            "PassSecret",
            "pwdSecret",
            "keySecret",
            "refreshSecret",
            "client Secret",
            "accessSecret",
            "camelSecret",
            "privateValue",
            "tokenSecret",
            "telegramSecret",
            "discordSecret",
            "privateBodyOne",
            "privateBodyTwo",
            "inlinePrivate",
        ] {
            assert!(!clean.contains(secret), "leaked {secret}: {clean}");
        }
        assert!(clean.contains("panic 0x7ff1234 module::run::h0123abcd sha256=0123456789abcdef"));
        assert!(clean.contains("before ") && clean.contains(" after\n"));
        assert!(clean.ends_with("last diagnostic: backtrace complete\n"));
        assert_eq!(clean.lines().count(), corpus.lines().count());
        let mut stream = String::new();
        RedactedReader::new(corpus.as_bytes(), &[])
            .read_to_string(&mut stream)
            .unwrap();
        assert_eq!(stream, clean);
        let mut email = Vec::new();
        write_bug_email(corpus.as_bytes(), &mut email).unwrap();
        assert_eq!(attachment(&email), clean.as_bytes());
    }

    #[test]
    fn complete_large_exports_keep_the_last_line_and_redact_secrets_after_preview() {
        let raw = format!(
            "{}\npassword=hiddenAtEnd\nlast diagnostic preserved\n",
            "diagnostic 0x123abc\n".repeat(20000)
        );
        assert!(raw.len() > MAX_PREVIEW as usize);
        let mut email = Vec::new();
        write_bug_email(raw.as_bytes(), &mut email).unwrap();
        let attachment = String::from_utf8(attachment(&email)).unwrap();
        assert!(!attachment.contains("hiddenAtEnd"));
        assert!(attachment.ends_with("last diagnostic preserved\n"));
        assert_eq!(attachment.lines().count(), raw.lines().count());
        let mut output = String::new();
        let raw = format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\nlast\n",
            "secretBody\n".repeat(30000)
        );
        RedactedReader::new(raw.as_bytes(), &[])
            .read_to_string(&mut output)
            .unwrap();
        assert!(!output.contains("secretBody"));
        assert!(output.ends_with("last\n"));
    }

    #[test]
    fn oversized_lines_fail_explicitly_instead_of_truncating_or_leaking() {
        let raw = vec![b'x'; MAX_REDACTION_LINE as usize + 1];
        let error = io::copy(
            &mut RedactedReader::new(raw.as_slice(), &[]),
            &mut io::sink(),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("without truncating"));
    }

    #[test]
    fn reports_are_bounded_and_acknowledgement_is_specific_to_the_content() {
        let root = std::env::temp_dir().join(format!("uie-crash-assistant-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("crash.log");
        let ack = root.join("ack");
        fs::write(&path, vec![b'x'; MAX_PREVIEW as usize + 100]).unwrap();
        let report = read_report(path.clone(), &ack).unwrap().unwrap();
        assert!(
            report.truncated && report.text.len() == MAX_PREVIEW as usize && !report.acknowledged
        );
        fs::write(&ack, &report.fingerprint).unwrap();
        assert!(
            read_report(path.clone(), &ack)
                .unwrap()
                .unwrap()
                .acknowledged
        );
        fs::write(&path, b"a different panic").unwrap();
        assert!(!read_report(path, &ack).unwrap().unwrap().acknowledged);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn redaction_handles_both_path_separators_and_hints_do_not_claim_a_proven_cause() {
        let text = redact(
            "C:\\Users\\demo\\file.rs /home/demo/file.rs",
            &["C:\\Users\\demo".into(), "/home/demo".into()],
        );
        assert_eq!(text, "<user>\\file.rs <user>/file.rs");
        assert!(hint("java heap space", true).starts_with("Possible"));
        assert!(hint("arbitrary failure", true).contains("unknown"));
    }
}
