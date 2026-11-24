# Backend evaluation

Examined snapshots:

- HEXPYRION: `DimaReverse/hexpyrion@4daa534c8f21f63510a8a375279a8bfe6c3dd95f`
- RESX: `Ryftenius/RESX@ef7aae84cdd9c40ef19dcd2d99e552b323635156`

Both repositories declare the MIT license. Any future redistribution must retain their copyright and license notices. No code from either project is vendored into UIE by this change.

## HEXPYRION

Useful components: static onefile extraction, constants/blob and module-table analysis, Python ABI discovery, recovery-quality reports. Runtime capture modes are separate from static processing and must not be enabled implicitly by UIE.

The current `detect_nuitka_edition` uses string hints and a structural extra-16-byte blob-header heuristic. Its label is not by itself proof that a binary is a Nuitka Commercial build.

On UIE's actual Nuitka 4.3.5/CPython 3.12 fixture, `--ndx --dev-only --strict` extracted a module/blob description but exited 2 with **zero sources** and one unrecovered module (`No native entry point or usable bytecode`). The Ghidra route independently emitted 488 functions. These are different outcomes: C pseudocode is not original Python.

On the supplied hybrid launcher's executable, NDX exited 1 because its Python ABI was unknown/conflicting. On the main extension with `--target-python 3.12`, it exited 1 because no Nuitka constants blob was found. The standalone edition detector without an extracted blob returned `unknown` for both files, and `opensource` for the known Nuitka fixture. A different HEXPYRION version/mode may behave differently.

Recommendation: evaluate its static extraction and ABI outputs as an optional experimental stage. Retain strict gap reporting and the Ghidra fallback. Do not present speculative output as verified source recovery.

## RESX

RESX is a Rust PE-analysis toolkit with JSON outputs, disassembly/CFG reconstruction, API-resolution evidence, behavior reports and bounded string analysis. Its `SystemExports` provider uses local Windows DLL export data for some API resolution, so feature coverage depends on the host and configured providers.

Built the examined source on Windows. `peinfo --json --no-pdb` and `behavior --json --no-pdb` both returned success for the supplied launcher. `peinfo` exposed the paths to `runtime/pythonw.exe` and `app/main.py`. The behavior report contained 49 static findings. A finding is evidence from analysis, not proof of execution or maliciousness.

Recommendation: a separately invoked, bounded JSON provider for the report/IOC/CFG views. Keep its results labelled as static candidates; it does not replace Ghidra or recover Nuitka Python source on its own.
