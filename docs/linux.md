# Linux setup

UIE can be built on Linux. Automatic dependency installation through PowerShell and executable self-updates are Windows-only. Linux uses native tools configured below; it never invokes the Windows installer. Detect It Easy is optional when the chosen backend is already available.

## Build

On Ubuntu install Rust and the development libraries used by egui/rfd:

```sh
sudo apt-get install build-essential pkg-config libssl-dev libx11-dev libxkbcommon-dev libwayland-dev libegl1-mesa-dev
cargo build --release --locked
```

Run `target/release/UIE` from a writable directory. Run in a graphical desktop session (X11/Wayland). The GitHub Releases `UIE.exe` is a Windows executable, not a Linux binary.

## Native dependencies

Install only the backends you need:

- Native binaries: [Ghidra](https://github.com/NationalSecurityAgency/ghidra/releases) and a compatible JDK; set `JAVA_HOME` and use `support/analyzeHeadless`, without `.bat`.
- Python: a Python 3.12 virtual environment with the pinned PyLingual/xdis revisions in `src/install-engines.ps1`, plus pyinstxtractor-ng and their dependencies. Use that environment's Python for all three manifest Python entries. Install uv and put it on PATH for managed target interpreters. Model downloads use `engines/models`.
- .NET: .NET SDK/runtime and native `ilspycmd` (for example `dotnet tool install --global ilspycmd`); add `$HOME/.dotnet/tools` to PATH.
- JAR/class: Java and curl; CFR downloads to `engines/cfr`, with a checksum check.
- ASAR: no external extraction backend.
- Optional signatures: native `diec` on PATH or in the manifest.

Create `engines/engines.json` alongside UIE, or point `UIE_ENGINES_DIR` at a writable engines folder. Example (replace these paths with installed locations):

```json
{
  "ghidra": "/opt/ghidra/support/analyzeHeadless",
  "java_home": "/usr/lib/jvm/java-21-openjdk-amd64",
  "python": "/home/user/uie-venv/bin/python",
  "pylingual": "/home/user/uie-venv/bin/python",
  "extractor": "/home/user/uie-venv/bin/python",
  "ilspy": "/home/user/.dotnet/tools/ilspycmd"
}
```

Omit unused entries. Ghidra's JDK requirement depends on its version. Native ELF/Mach-O analysis refers to the input format, not necessarily the host operating system.

Linux settings use `XDG_CONFIG_HOME/UnpackItEasy/settings.json`, falling back to `$HOME/.config/UnpackItEasy/settings.json`. English is the default for new installations; existing language choices are retained.

Linux runtime behaviour has not been validated in the maintainer's Windows environment. An Ubuntu compilation check is included in CI. Missing Linux tools produce setup instructions instead of a Windows PowerShell error.
