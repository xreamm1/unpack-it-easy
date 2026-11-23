# Unpack It Easy (UIE)

Rust desktop application with a Windows x64 release for static binary triage, source extraction and decompilation. Written in Rust with egui. Input executables are not launched.

## Download and run

Download **UIE.exe** from [Releases](https://github.com/xreamm1/unpack-it-easy/releases). Open or drag a file into the window. Required backends are downloaded automatically into `engines` beside the executable. The initial setup requires internet access and several gigabytes of disk space. Keep `UIE.exe` and `engines` together.

English is the default for new installations. Select **English** or **русский** in the toolbar.

For Linux builds and native backend setup see [Linux instructions](docs/linux.md). The automatic PowerShell installer and executable updater are Windows-only.

## Features

- Header, architecture and signature detection, with Detect It Easy compiler/linker/packer details in the stages view.
- PyInstaller extraction and PyLingual decompilation of Python bytecode; bytecode equivalence is reported separately from functional correctness.
- Native PE/ELF/Mach-O analysis through Ghidra; .NET recovery through ILSpy.
- Bounded discovery of related launcher/Nuitka modules, CRT filtering, user-function prioritization, constant initializers, section entropy and data XREF candidates.
- Electron `.asar` source extraction in Rust, including adjacent `.asar.unpacked` files; Java `.jar` and `.class` decompilation through CFR 0.152.
- Early MD5/SHA-1/SHA-256 and static indicators: URLs, IPv4/IPv6, file/registry paths, Discord webhooks, Telegram bot endpoints and selected WinAPI names. Evidence includes file, byte offset and encoding. VirusTotal/MalwareBazaar links use the hash; files are not automatically uploaded.
- Stage timers, object progress, links to incomplete functions, full-log export/copy.
- Source editor, search, C/Python symbol navigation, virtualized large-file viewing and a clickable minimap.
- **N** or **F2** opens file-wide identifier rename. Comments and string literals are preserved. This is lexical renaming, without scope/type inference. Rename history and edited files are saved in `.uie`.
- Portable `.uie` project databases with resources, reports and rename history; legacy `.toker` loading.
- New result directories and the primary output use `<application>_decompiled`.

## Updates and responsiveness

On startup UIE checks the latest stable GitHub release in a background worker with a timeout. The dialog offers **update**, **later** and **do not show again**. The last choice disables automatic checks; the toolbar still allows a manual check. Offline mode skips checks and downloads.

An accepted update is downloaded in the background and checked against the release asset SHA-256. Unsaved edits must be saved before restarting. A helper waits for UIE to exit and atomically replaces the executable, preserving a backup and the engines/projects folders.

Result discovery, source reading and symbol indexing run in background workers. Event processing is limited per frame and log writes are batched. Files initially use virtualized viewing; select edit to modify the source. Very long lines show their first 8192 characters in viewing mode; complete source is retained on disk and in project databases.

## Offline mode

While online, select a Python version or **all python versions**, then click **download offline bundle**. This prepares DIE, Python/PyLingual, Ghidra/Java, ILSpy and CFR, plus the selected Python interpreters and model snapshots under `engines`. The all-versions option prepares Python **3.8–3.14** and requires multiple gigabytes. Preparation can be cancelled and rerun; successful version preparations are recorded in `engines/offline-ready.json`.

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

See [third-party components](THIRD_PARTY.md) for backend licenses and sources.
