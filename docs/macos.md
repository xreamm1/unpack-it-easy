# macOS setup

The Windows `UIE.exe` cannot run natively on macOS. Build UIE on the target Mac using stable Rust and Xcode command line tools:

```sh
xcode-select --install
cargo build --release --locked
./target/release/UIE
```

Run in a graphical desktop session. This is an unsigned executable, not a signed/notarized `.app` bundle. The current local development host is Windows; macOS GUI execution is unverified. The prepared desktop workflow builds/tests ARM64 and Intel macOS on separate runners when published.

Use native Ghidra with its required JDK, native `ilspycmd`, Java/CFR and a Python environment for PyLingual as described in [Linux setup](linux.md). Configure macOS paths in `engines/engines.json` next to the executable, or set `UIE_ENGINES_DIR` to an engines directory. The backend manifest has the same fields. No Windows PowerShell dependency installer or Windows executable self-update is invoked on macOS. Missing engines produce a setup error.

`open` is used for the result directory on macOS. Install UPX separately on PATH if needed; there is no automatic official UPX macOS binary download in this build. x64dbg is Windows-only. Cross-platform binary analysis does not make a Windows debugger portable.

Settings use `XDG_CONFIG_HOME/UnpackItEasy/settings.json` when set, otherwise `$HOME/.config/UnpackItEasy/settings.json`. Keep the executable and engines in a writable application directory.
