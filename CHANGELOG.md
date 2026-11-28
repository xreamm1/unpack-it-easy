# UIE v0.4.3

## Added
- Android APK/DEX analysis through managed JADX.
- HEX editor with paged viewing, staged byte edits and verified save-to-copy.
- Editor draft recovery, undo/redo, XREF and recovered type declaration views.
- Project-wide source search, call graph navigation and executable/source comparison.
- HTML, JSON and Markdown report export; external decompiler plugin manager.
- Configurable Windows analysis process/memory limits and monochrome appearance.
- x64dbg trace import with binary identity checks and partial observed-path pseudocode.

## Improved
- Bounded forward constant propagation across branch joins and static indirect-target candidates.
- Background rendering at reduced resolution, adaptive refresh, minimized-window pause and static fallback.
- Source/database saves run in workers; recovered sources are included in project exports.
- Crash report exports redact common secrets, paths, addresses and private keys.
- Dark theme remains consistent with light system settings; save-and-close waits for both save stages.
- Engine completion no longer chases an indefinitely growing child-process log.
- Archive size/path validation and lazy-analysis retry handling.

## Downloads
`UIE.exe` is the Windows x64 application. Analysis engines are downloaded separately when required; the first setup needs internet access. `SHA256SUMS.txt` verifies the release asset.

## Validation and limits
Windows unit tests and an owned Java/Android round-trip corpus were run before publication. Platform CI results are available in Actions. Native output is partial reconstruction, not guaranteed original source. Trace analysis imports recordings and does not automatically run targets or recover unvisited paths. Full Nuitka Commercial/ChessAnalyzer recovery and behavior in VMware are not verified.
