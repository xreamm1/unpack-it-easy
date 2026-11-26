# Native backend research and implemented changes

This note separates tested implementation changes from experimental source reconstruction. All target analysis described here was static. The original ChessAnalyzer executable/extensions and generated whole Python modules were not executed.

## Existing projects

[HEXPYRION](https://github.com/DimaReverse/hexpyrion) (`4daa534c8f21f63510a8a375279a8bfe6c3dd95f`) and [REVENANT](https://github.com/DimaReverse/nuitka-revenant) (`501592270bce75828394630580bb6ae9cb0c7334`) both declare MIT licensing. They provide constants/module discovery, native-to-Python experiments and recovery audits. Their original static source-emission paths returned incomplete results on UIE's owned Nuitka 4.3.5/CPython 3.12 fixture. Unmodified strict NDX found no usable native entry and emitted no recovered Python source.

These projects are useful research references, not proof of universal recovery. Their source-healing paths include name/constant-driven templates; parseable Python alone does not establish equivalence. UIE does not silently promote those templates to verified application source. Neither external Python decompiler is integrated as the production Nuitka-to-Python backend by these changes.

## Nuitka loader compatibility

The authoritative layout is [Nuitka's `unfreezing.h`](https://github.com/Nuitka/Nuitka/blob/4.3.5/nuitka/build/include/nuitka/unfreezing.h). The tested 4.3.5 x64 entry is expanded: native initializer at byte offset56, importer at64, bytecode index/size at88/92 and flags at96. Earlier parsers assumed a compact layout with initializer at8 and flags at24. Individually emitted entries can be referenced through a pointer table; a contiguous compact-array assumption misses them.

UIE now has an independently written, bounded Rust loader scanner. It validates plain module names, executable callbacks/initializer/importer pointers, mapped data pointers, native bytecode fields and flags before using an entry. Compact entries are accepted only for a `__main__` root with the main flag, avoiding common method/getset-table false positives. Expanded matches take precedence. A runtime marker/layout does not prove Nuitka Commercial, and encrypted names or unrecognized layouts remain unresolved.

## Research-only ABI and metadata patches

A separate HEXPYRION research copy adds the expanded loader ABI plus constants metadata kinds `K`, `W` and `Y`. This follows [Nuitka's `constants_blob_spec.h`](https://github.com/Nuitka/Nuitka/blob/4.3.5/nuitka/build/include/nuitka/constants_blob_spec.h) and [constants reader](https://github.com/Nuitka/Nuitka/blob/4.3.5/nuitka/build/static_src/HelpersConstantsBlob.c): module/class/generator-expression descriptors omit fields that ordinary function descriptors carry. No research-copy patch is being represented as an integrated product source-recovery backend.

The patched owned fixture exposes15 private constants and3 code-object descriptions. Two recovered functions, `score_position` and `describe`, have ASTs identical to their known original definitions. Extracting only those owned definitions passed1,160 input comparisons. The generated whole module was not executed: it still drops a value assignment and printing, then references an undefined value. Strict recovery remains incomplete. Synthetic `C/K/W/Y` grammar tests passed; compiled coverage for `W/Y` remains missing.

The plain hello-world research fixture also remains incomplete. Its blocker is concrete: tuple allocation/item storage, builtin lookup and generic Python-call helper semantics must be proven and connected. Per-fixture addresses are evidence, not portable signatures, and are not hardcoded into UIE as a substitute for recovery.

## ChessAnalyzer and Cython

The supplied layout includes a launcher and CPython 3.12 extensions with Cython evidence. [Cython 3.1.4 function utilities](https://github.com/cython/cython/blob/3.1.4/Cython/Utility/CythonFunction.c) and [CPython 3.12 method definitions](https://github.com/python/cpython/blob/v3.12.0/Include/methodobject.h) explain the surviving function names, wrapper flags and metadata. They do not imply surviving Python bytecode.

UIE's own Rust Cython pass verifies traceback helpers through actual `PyCode_NewEmpty`, `PyFrame_New` and `PyTraceBack_Here` calls, excluding comments/string lookalikes. On a copy of the main app extension's Ghidra output, it maps109 native functions to78 distinct Python-qualified names. It changes header comments and report metadata only; native bodies/identifiers and line counts are retained. Traceback line numbers are error sites, not necessarily function-definition lines. Idempotence, ambiguity rejection and spoof rejection are tested. This is metadata recovery, not full Python reconstruction.

## Static string analysis

[FLOSS](https://github.com/mandiant/flare-floss) distinguishes stack, decoded, tight-loop and ordinary strings, including separate [UTF-16LE extraction](https://github.com/mandiant/flare-floss/blob/master/floss/strings.py). Its Apache-2.0 implementation was studied but not copied into UIE.

UIE independently adds bounded BMP UTF-16LE candidate recovery over known transformed bytes at either alignment. Missing high bytes are never assumed zero; original instruction/function RVAs and synthetic stack offsets remain attached. Tests cover ASCII preservation, wide Latin/Cyrillic text, odd alignment, absent bytes and untransformed text. Surrogate-pair recovery is not established. These results remain static candidates, with limits and possible false positives, rather than observations of execution.

No universal decryptor, full native-source guarantee or automatic heavy-protector bypass has been established by this research. Runtime behavior on Linux/macOS is a separate validation requirement.
