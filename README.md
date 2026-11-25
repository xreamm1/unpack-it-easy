<div align="center">

<img src="assets/uie.png" alt="Unpack It Easy icon" width="80" height="80">

# Unpack It Easy

### Open a binary. Follow the analysis. Explore the code.

A desktop workspace for binary analysis, unpacking and decompilation, written in Rust.

[![Download UIE for Windows x64](https://img.shields.io/badge/Download-UIE.exe-2ea44f?style=for-the-badge)](https://github.com/xreamm1/unpack-it-easy/releases/latest/download/UIE.exe)
[![Latest release](https://img.shields.io/github/v/release/xreamm1/unpack-it-easy?style=for-the-badge&label=latest)](https://github.com/xreamm1/unpack-it-easy/releases/latest)

[![Build status](https://img.shields.io/github/actions/workflow/status/xreamm1/unpack-it-easy/build.yml?branch=main&style=flat-square&label=build)](https://github.com/xreamm1/unpack-it-easy/actions/workflows/build.yml)
[![Release asset downloads](https://img.shields.io/github/downloads/xreamm1/unpack-it-easy/total?style=flat-square&label=release%20downloads)](https://github.com/xreamm1/unpack-it-easy/releases)
[![GitHub stars](https://img.shields.io/github/stars/xreamm1/unpack-it-easy?style=flat-square&label=stars)](https://github.com/xreamm1/unpack-it-easy/stargazers)
[![MIT license](https://img.shields.io/github/license/xreamm1/unpack-it-easy?style=flat-square)](LICENSE)

[![Quick start](https://img.shields.io/badge/Quick_start-24292f?style=for-the-badge)](#quick-start)
[![Supported formats](https://img.shields.io/badge/Supported_formats-24292f?style=for-the-badge)](#what-can-i-open)
[![Linux setup](https://img.shields.io/badge/Linux_setup-24292f?style=for-the-badge)](docs/linux.md)
[![Report a bug](https://img.shields.io/badge/Report_a_bug-24292f?style=for-the-badge)](https://github.com/xreamm1/unpack-it-easy/issues/new)

</div>

## What is UIE?

UIE connects detection, extraction and decompilation in one window. Drop in a file, watch the stages, then browse the available source or pseudocode with its analysis report. The backends do the decompilation; UIE handles routing, setup and the workspace around them.

It is useful when you want to inspect an unfamiliar application without manually connecting a separate tool for every format.

[![UIE code viewer and analysis workspace](assets/workspace.png)](https://github.com/xreamm1/unpack-it-easy/releases/latest)

## Quick start

1. **[Download UIE.exe](https://github.com/xreamm1/unpack-it-easy/releases/latest/download/UIE.exe)** for Windows x64 and place it in a writable folder.
2. Launch it and drop a file into the window, or choose **open file**.
3. Let UIE prepare the required analysis engines. First-time setup needs internet access and can take several gigabytes of disk space.
4. Follow the stages, open the results and save your work as a **`.uie` project**.

Keep the downloaded `engines` folder beside `UIE.exe`. You do not need to install a system Python for the GUI. English is the default; Russian is available in the toolbar.

**Linux:** build from source and configure native backends using the [Linux guide](docs/linux.md). Compilation is checked in CI; Linux runtime coverage is still limited. The `.exe` download, automatic dependency installer and x64dbg integration are for Windows.

## What can I open?

| Input | Available output |
| --- | --- |
| PyInstaller executables and Python `.pyc` | Extracted resources and recovered Python, with bytecode-equivalence reporting where available |
| Native PE, ELF and Mach-O binaries | C pseudocode and native-analysis reports |
| Nuitka and Cython builds, including launcher + `.pyd` layouts | Native C pseudocode, related modules, initialization and XREF candidates |
| .NET assemblies | C# source |
| Java `.jar` and `.class` | Java source |
| Electron `.asar` | Extracted JavaScript, TypeScript and resources present in the archive |
| UIE `.uie` projects | Saved code, resources, reports and rename history |

**Recovery depends on the input.** Native pseudocode is not the original source, and full Python recovery or decryption of Nuitka Commercial builds is not verified. Incomplete results stay marked incomplete. [Details and limits](docs/usage.md#limits-and-verification).

## Inside the workspace

- **See what is happening.** Stage timers, object counters, logs and links from reported problems to the affected code.
- **Get an early picture.** Compiler and packer signatures, MD5/SHA-1/SHA-256, URLs, IPs, paths, webhook strings and selected WinAPI indicators. External hash lookups are optional; files are not automatically uploaded.
- **Browse larger outputs.** Virtualized viewing, a clickable minimap, search and a function tree. Rename identifiers with **N / F2** and keep the history in your project.
- **Inspect native Python builds.** Related-module discovery, CRT filtering, constant-initializer candidates, section entropy and Python-string XREFs.
- **Keep your work.** Save portable `.uie` databases, copy or export logs, and reopen edited files with their resources.
- **Use a debugger when needed.** Optional x64dbg/x32dbg integration on Windows. Starting a sample under the debugger is an explicit action; normal static analysis does not run input executables.

UIE currently routes work through Detect It Easy, Ghidra, PyLingual, ILSpy and CFR. See [third-party components and licenses](THIRD_PARTY.md).

## Prepare once, work offline

While online, choose the Python version you need and click **download offline bundle**. Once preparation finishes, enable **offline** to stop automatic downloads and update checks.

Copy `UIE.exe` together with `engines` to move the prepared installation. Python 3.8–3.14 can be selected; the all-versions option needs multiple gigabytes. Missing components are reported instead of fetched while offline.

[Offline setup and command-line usage](docs/usage.md#offline-mode) · [Troubleshooting and crash reports](docs/usage.md#crash-reports-and-backtraces)

## Help improve UIE

UIE is still being actively tested. If it saves you time, **[give the repo a star](https://github.com/xreamm1/unpack-it-easy/stargazers)** so more people can find it.

Found a crash, a failed extraction or an incorrect result? [Open an issue](https://github.com/xreamm1/unpack-it-easy/issues/new) with your OS, UIE version, the failing stage and the exported log. Include a small reproducible sample when you can share it, and remove private paths, tokens and other sensitive data from logs before posting.

You can also support new-format work and bug fixes through **about → support development** in the app. Contributions and reproducible bug reports are welcome too.

## Build from source

On Windows, install Rust and the MSVC C++ build tools:

```cmd
cargo build --release --locked
```

Output: `target\release\UIE.exe`. For Linux prerequisites, see [the Linux guide](docs/linux.md).

<details>
<summary>Development checks</summary>

```cmd
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
```

</details>

[Technical notes](docs/usage.md) · [Backend evaluation](docs/backend-evaluation.md) · [MIT license](LICENSE)
