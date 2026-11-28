# Usage and technical notes

[Back to the project](../README.md)

## Download and run

Download **UIE.exe** from [Releases](https://github.com/xreamm1/unpack-it-easy/releases). Open or drag a file into the window. Required backends are downloaded automatically into `engines` beside the executable. The initial setup requires internet access and several gigabytes of disk space. Keep `UIE.exe` and `engines` together.

English is the default for new installations. Select **English** or **русский** in the toolbar.

For Linux builds and native backend setup see [Linux instructions](linux.md). The automatic PowerShell installer and executable updater are Windows-only.

## Features

- Header, architecture and signature detection, with Detect It Easy compiler/linker/packer details in the stages view.
- PyInstaller extraction and PyLingual decompilation of Python bytecode; bytecode equivalence is reported separately from functional correctness.
- Native PE/ELF/Mach-O analysis through Ghidra; .NET recovery through ILSpy.
- Bounded discovery of related launcher/Nuitka modules, CRT filtering, user-function prioritization, constant initializers, section entropy and data XREF candidates.
- Electron `.asar` source extraction in Rust, including adjacent `.asar.unpacked` files; Java `.jar` and `.class` decompilation through CFR 0.152.
- Android `.apk` and standard `.dex` decompilation through managed JADX 1.5.7. Java appears under `source/java`, decoded manifest/resources under `source/resources`, and diagnostics in `jadx.log` and `android-report.json`. Decompiled Java does not reconstruct original Kotlin source; native JNI `.so` files require separate native analysis. Partial output stays available on decompiler errors. Input code is not executed.
- Android input validation supports standard DEX versions 035 and 037–040. Compact DEX and the 041 container format are explicitly rejected. A failed DEX load is reported as incomplete even when JADX returns resources or exits successfully; Java files bundled as assets are counted as resources.
- Early MD5/SHA-1/SHA-256 and static indicators: URLs, IPv4/IPv6, file/registry paths, Discord webhooks, Telegram bot endpoints and selected WinAPI names. Evidence includes file, byte offset and encoding. VirusTotal/MalwareBazaar links use the hash; files are not automatically uploaded.
- Stage timers, object progress, links to incomplete functions, full-log export/copy.
- Source editor, search, C/Python symbol navigation, virtualized large-file viewing and a clickable minimap.
- **N** or **F2** opens file-wide identifier rename. Comments and string literals are preserved. This is lexical renaming, without scope/type inference. Rename history and edited files are saved in `.uie`.
- Portable `.uie` project databases with resources, reports and rename history; legacy `.toker` loading.
- New result directories and the primary output use `<application>_decompiled`.

## Updates and responsiveness

### Analysis tools and settings

The compact toolbar keeps open/load/save actions visible; other actions are in
**more**. The language selector remains in the toolbar. **more → tools** includes
the HEX editor, XREF/types viewer, plugin manager, and report/source comparison.

The HEX editor pages through files up to 512 MiB, supports offset navigation and
staged byte changes, and saves a verified new copy. It never writes the original.
Source undo/redo covers edits and renames; history is bounded and session-local.
Dirty text is saved to separate recovery drafts approximately every five seconds
when autosave is enabled. Recovery opens a draft in memory. Saving recovered text
creates a new copy inside the project's source/recovered directory so it is
included in subsequent .uie exports; without a loaded project a new destination
must be selected. Original files remain unchanged. This recovers editor drafts,
not a crashed third-party decompiler's internal state. Source saving runs in a
worker and rejects an original changed outside the editor.

The XREF viewer uses exported call/data/string references and labels folded
constants as inference. Missing source locations remain explicit. The types view
shows struct/union/enum declarations present in recovered C/C++ text; it does not
infer ABI packing or field offsets. Report export supports static HTML, JSON and
Markdown. The source comparison view compares two existing decompiler outputs
positionally; differences do not establish semantic equivalence.

Plugin manifests can be imported disabled, inspected, enabled after executable
SHA-256 verification, and disabled again. Enabling a manifest does not run it;
select it explicitly in engine settings and refresh that list after manager
changes. Appearance settings save a configurable monochrome theme. Defaults keep
the code background black.

The **settings** button opens **engines and limits**. Choose automatic routing or
an explicitly enabled [external decompiler plugin](plugins.md), include related
modules, enable lazy native decompilation, or bypass the result cache. Changes
are saved between sessions and apply to subsequent analysis jobs.

On Windows, optional Job Object limits cover the analysis process tree: combined
committed memory (128–65536 MiB) and active processes (1–128). Defaults are 2048 MiB
and 32 processes. Exceeding these limits can produce a partial result. Processes
are assigned before execution and descendants are terminated on cleanup. These
limits are not a filesystem or network sandbox. They are unavailable on other
platforms and disabled there by default.

The **background** tab has a **disable background** button that restores the
plain dark background; **enable background** restores the waves. It also selects adaptive refresh and sets
minimum/maximum frame rates. Minimized windows stop background animation.
Without desktop OpenGL 3.3, a static egui background is used. The animated field
is rendered into a bounded half-resolution texture and reused between animation
frames; the presentation pass remains at window resolution. Adaptive refresh
accounts for idle input and asynchronously measured field rendering time.

**analysis tools** also provides search across recovered source files (including
unsaved editor changes), a static call graph with clickable source locations,
and comparison of two executables or two `.uie` databases. Executable comparison
reports byte offsets and PE section hashes, not semantic equivalence. Call graphs
require a native report containing call XREFs; computed or dynamic calls may be
absent. Search and graph sizes are bounded and truncation is reported.

Owned program round-trip checks are described in [quality tests](quality.md).

Crash Assistant exports, clipboard copies and email attachments redact common
credentials, home paths, email addresses, webhooks and private keys. Local raw
preview is opt-in and does not disable export redaction. Full log lines are
retained; an oversized single line is rejected explicitly. Redaction is pattern
based, so review reports before sharing. Email export creates a draft with a
sanitized log attachment; it does not silently send mail.

On startup UIE checks the latest stable GitHub release in a background worker with a timeout. The centered dialog displays the GitHub release notes before offering **update**, **later** and **do not show again**. Notes are shown as plain text, with a link to the full release page. Missing notes have a fallback message; long notes are bounded. The last choice disables automatic checks; the toolbar still allows a manual check. Offline mode skips checks and downloads.

An accepted update is downloaded in the background and checked against the release asset SHA-256. Unsaved edits must be saved before restarting. A helper waits for UIE to exit and atomically replaces the executable, preserving a backup and the engines/projects folders.

Result discovery, source reading and symbol indexing run in background workers. Event processing is limited per frame and log writes are batched. Files initially use virtualized viewing; select edit to modify the source. Very long lines show their first 8192 characters in viewing mode; complete source is retained on disk and in project databases.

## Native Python builds and debugger

### Trace-assisted reconstruction

**Analysis → dynamic trace analysis** imports a recorded execution trace; it does
not start the input program. PE AMD64 inputs can be bound to a native x64dbg
`.trace64` recording using its actual runtime module base and an adjacent
`.uie-trace.json` metadata file. SHA-256 and image-size checks prevent accidental
association with a different binary. The UI also accepts the explicit JSONL
format implemented in `src/dynamic_analysis.rs`.

The report separates per-thread observed execution edges, register-based indirect
targets, and partial pseudocode for the recorded instruction path. Runtime code
bytes can differ from file bytes; the observations describe that recording only.
Unsupported instructions remain marked, unvisited branches are not recovered,
and trace evidence is not proof of full functional equivalence. Recording a
target is a separate debugger operation in a controlled VM. Native trace parsing
currently supports uncompressed x64 version-1 recordings, not every debugger
trace format.

The Rust constant pass also merges agreed known register bits and memory across
bounded forward branch joins, while conflicting values become unknown. Known
indirect call/jump targets are emitted as static candidates; concrete bounded
loop recovery remains available. This does not replace general CFG recovery or
automatically reconstruct original Python from arbitrary native code.

Nuitka and Cython compile Python to native code. UIE routes these files to Ghidra, not to a Python-bytecode decompiler. Output is C pseudocode and supporting evidence; original Python reconstruction is not guaranteed.

- User/module initializers and Python-related string XREF candidates are prioritized.
- Failed functions get a conservative retry and then an explicitly marked disassembly fallback.
- Entropy, constants initialization and data XREF reports help locate candidate processing sites. They do not automatically decrypt Nuitka Commercial constants.
- Hybrid launcher builds containing `app/*.pyd` prioritize application modules and exclude the separate `runtime` dependency tree from automatic decompilation. The discovery report records this exclusion.
- The Windows **x64dbg / x32dbg** toolbar button downloads a pinned official snapshot with a SHA-256 check. Select an empty debugger or explicitly start the selected PE executable under the debugger. This is a separate action that starts a target process; static analysis does not launch targets. ARM64 and non-PE debugging are unsupported by this integration.
- Offline bundle preparation includes x64dbg on Windows. Linux uses native analysis backends and does not offer the Windows debugger integration.

The known-source test in `tests/fixtures/nuitka_sample.py` was compiled with Nuitka 4.3.5 / CPython 3.12 and analyzed: 488 functions emitted, no decompilation failures. This validates the native analysis route, not Python source equivalence. A supplied hybrid application showed Cython markers in its extension modules; it is not evidence of Nuitka Commercial support.

## About and donations

The About dialog shows author information, version, repository and the purpose of donations: UIE development, new formats and bug fixes. BTC, LTC, USDT on TRC20, TON and TRX addresses are embedded in `assets/donations.json`; the selected address has a QR code and copy button. No payment is submitted by the application. XMR is not listed.

## Offline preparation and diagnostics

Each preparation attempt gets a fresh directory under `engines/offline-preparation`, so existing log files no longer break retries. Downloads retry transient failures and record successful Python versions individually. Errors launching the GUI are recorded in `startup-error.log` beside the settings file, including on Windows without a visible console. A reported startup failure on a customized Windows VM has not been reproduced.

UIE's own log messages and reports are translated for display and log export. Raw per-backend log files retain original diagnostic text; arbitrary output from external tools and operating systems may remain in its original language.

## Offline mode

While online, select a Python version or **all python versions**, then click **download offline bundle**. This prepares DIE, Python/PyLingual, Ghidra/Java, ILSpy, CFR and JADX, plus the selected Python interpreters and model snapshots under `engines`. Keep `engines/jadx/jadx-1.5.7.zip` as well as the extracted JARs: UIE verifies the installed files against that authenticated archive. The all-versions option prepares Python **3.8–3.14** and requires multiple gigabytes. Preparation can be cancelled and rerun; successful version preparations are recorded in `engines/offline-ready.json`.

After successful preparation, the GUI enables **offline**. This blocks automatic engine downloads and enables offline flags for Hugging Face, Transformers and uv. Missing components produce an error instead of downloading. External hash lookup links are disabled in this mode. Copy the whole `engines` directory alongside the executable when moving the offline installation.

Command line preparation:

```cmd
UIE.exe --prepare-offline all
UIE.exe --prepare-offline 3.14
```

Logs: `engines/offline-preparation/`. Offline Python 3.14 preparation and decompilation are tested; the remaining selectable Python versions require their corresponding downloads. Python 3.6/3.7 and experimental 3.15 offline bundles are not supported by this packaging.

## Limits and verification

Decompilation does not guarantee the original source or a runnable project. Native output is C pseudocode. Failed Ghidra functions stay marked incomplete and include an address-labelled disassembly fallback. Entropy/XREFs identify candidates, not proof of encryption or decryption. Static indicators do not prove executed network activity or process injection.

Protected Nuitka Commercial reconstruction has not been validated on a real protected sample. Archive extraction is bounded and rejects traversal paths; external decompilers run with the current user's permissions.

## Build

Windows with Rust and the MSVC C++ build tools:

```cmd
cargo build --release --locked
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

Output: `target\release\UIE.exe`. GUI runtime does not require a system Python installation.

## Русский

Откройте или перетащите файл в UIE. Программа определит формат, покажет этапы и откроет доступные исходники. Язык переключается в верхней панели. Кнопка подготовки офлайн-комплекта заранее скачивает движки и модели в `engines`; режим «офлайн» запрещает автоматические загрузки. Переименование — `N`/`F2`, сохранение проекта — `.uie`. Полная эквивалентность и восстановление оригинального кода не гарантируются.

See [third-party components](../THIRD_PARTY.md) for backend licenses and sources.

## Crash reports and backtraces

For Rust panic diagnostics, enable the environment variable before launching UIE.

PowerShell:

```powershell
$env:RUST_BACKTRACE = "1"
.\UIE.exe
```

Command Prompt:

```cmd
set RUST_BACKTRACE=1
UIE.exe
```

Linux:

```sh
RUST_BACKTRACE=1 ./UIE
```

Use `RUST_BACKTRACE=full` for the expanded stack. UIE writes the latest Rust panic, backtrace status, version, OS, architecture and thread name to `crash-report.log` next to the settings file. The standard stderr panic output is also preserved. On Windows the default location is `%LOCALAPPDATA%\UnpackItEasy\crash-report.log`; on Linux it is `$XDG_CONFIG_HOME/UnpackItEasy/crash-report.log` or `$HOME/.config/UnpackItEasy/crash-report.log`.

GUI initialization errors remain in `startup-error.log` in the same directory. Release builds may have limited symbols. For source-level traces use a development build (`cargo run`). Backtraces diagnose Rust panics; they do not capture all native crashes, access violations, hangs or forced process termination. Review logs for private paths and sensitive data before attaching them to an issue.
