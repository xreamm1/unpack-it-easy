# Third-party components

UIE orchestrates separate backends. Their code and models retain their own licenses; UIE's MIT license does not relicense them. Backends are downloaded separately and are not included in the application source repository or the standalone executable.

- [Detect It Easy](https://github.com/horsicq/DIE-engine)
- [pyinstxtractor-ng](https://github.com/pyinstxtractor/pyinstxtractor-ng)
- [PyLingual](https://github.com/syssec-utd/pylingual), including the pinned upstream revision in the installer
- [PyLingual models](https://huggingface.co/syssec-utd): see each model card
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [RetDec 5.0](https://github.com/avast/retdec/tree/v5.0), MIT with separately licensed bundled dependencies. The Windows offline installer retains `LICENSE`, `LICENSE-PELIB`, `LICENSE-THIRD-PARTY` and runtime support files. Archive SHA-256 is pinned in `src/install-engines.ps1`.
- [ILSpy](https://github.com/icsharpcode/ILSpy)
- [CFR 0.152](https://www.benf.org/other/cfr/), MIT; pinned SHA-256 in `src/archives.rs`
- [JADX 1.5.7](https://github.com/skylot/jadx/tree/v1.5.7), Apache-2.0 with separately licensed dependencies; official distribution SHA-256 is pinned in `src/android.rs`. The authenticated ZIP is retained with the managed installation as its integrity anchor.
- [uv](https://github.com/astral-sh/uv), [python-build-standalone](https://github.com/astral-sh/python-build-standalone), [CPython](https://github.com/python/cpython)
- [Eclipse Temurin](https://adoptium.net/)

The Windows RetDec installation also uses the OpenSSL 1.1 runtime from managed CPython 3.8. The installer retains the CPython distribution license and the OpenSSL/SSLeay license text in `engines/retdec/licenses`.

Rust dependency versions are recorded in Cargo.lock. Consult each dependency's package metadata for its license.

- [iced-x86](https://github.com/icedland/iced), MIT; instruction decoder used by UIE's own bounded scalar lifter.
- [UPX](https://github.com/upx/upx/tree/v5.3.0), GPL-2.0-or-later with UPX exceptions; official executable downloaded separately with pinned archive SHA-256. Source and license: https://github.com/upx/upx/tree/v5.3.0

- [x64dbg](https://github.com/x64dbg/x64dbg), GPL-3.0; official snapshot downloaded separately with its distribution files. Source: https://github.com/x64dbg/x64dbg/tree/2026.05.27
