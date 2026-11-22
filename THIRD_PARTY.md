# Third-party components

UIE orchestrates separate backends. Their code and models retain their own licenses; UIE's MIT license does not relicense them. Backends are downloaded separately and are not included in the application source repository or the standalone executable.

- [Detect It Easy](https://github.com/horsicq/DIE-engine)
- [pyinstxtractor-ng](https://github.com/pyinstxtractor/pyinstxtractor-ng)
- [PyLingual](https://github.com/syssec-utd/pylingual), including the pinned upstream revision in the installer
- [PyLingual models](https://huggingface.co/syssec-utd): see each model card
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- [ILSpy](https://github.com/icsharpcode/ILSpy)
- [CFR 0.152](https://www.benf.org/other/cfr/), MIT; pinned SHA-256 in `src/archives.rs`
- [uv](https://github.com/astral-sh/uv), [python-build-standalone](https://github.com/astral-sh/python-build-standalone), [CPython](https://github.com/python/cpython)
- [Eclipse Temurin](https://adoptium.net/)

Rust dependency versions are recorded in Cargo.lock. Consult each dependency's package metadata for its license.
