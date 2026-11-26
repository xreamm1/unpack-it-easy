# Native recovery and its limits

UIE does not promise original Python source from a Nuitka executable. Nuitka compiles Python through C into native code. A successful native decompilation is not a Python source-equivalence test. Commercial protection is not inferred from entropy alone. Cython markers in a hybrid launcher must be reported separately from Nuitka evidence.

## UIE Rust scalar lifter

The new in-process Rust lifter uses iced-x86 only to decode instructions. UIE implements register tracking, instruction translation, width masks and Python emission. It does not invoke Ghidra, Python or a model for this pass.

The supported subset is complete straight-line AMD64 integer functions in PE files, discovered through named exports and the exception table. Inputs are the raw Windows x64 `RCX`, `RDX`, `R8`, `R9` values; output is raw `RAX`. Arithmetic wraps at the actual 32/64-bit destination width. Original signatures, signedness and names are not inferred. Calls, memory dereferences, branches, floating point, stack frames and reads of undefined entry registers are rejected. The output models the integer return value, not flags, timing or other machine state.

```powershell
UIE.exe --lift-native owned-fixture.dll result
```

`native-lift-report.json` lists every attempted function, its RVA, Python symbol and any unsupported instruction. `source/native_scalar_reconstruction.py` is emitted only if at least one complete function is translated. It is a partial analysis artifact, not recovered application source. This pass runs before Ghidra on native inputs; Ghidra remains the general native backend. Both reports and generated Python are preserved in `.uie` projects.

The owned `tests/fixtures/native_scalar.c` fixture covered nine integer functions and rejected two unsupported functions. `tests/check_native_scalar.py` compared 5,397 return values against the compiled fixture, including overflow edge cases. This verifies that fixture, not arbitrary binaries.

## Constants and string candidates

A separate Rust pass tracks known register bits across 8/16/32/64-bit writes, including high-byte registers and 32-bit zero extension. Supported operations include XOR, AND, OR, SHL, SHR, ROL and ROR, integer arithmetic, loads/stores and known address calculations. Simple loops are followed only when their branch condition is known. Register-derived bytes and stack XOR loops can produce ASCII string candidates; no input executable is run.

Calls invalidate volatile registers and memory. Unknown instructions invalidate the registers/memory they may write using decoder instruction-effect metadata; unrelated known registers survive. An unresolved branch discards state before continuing a linear candidate scan. Unknown values are never filled with zero. These are static candidates, not observed runtime results.

The pass is bounded to 512 bytes per discovered function, 4,096 steps per function, 500,000 total steps, 8,192 tracked memory bytes and 2,048 annotations per file. Limits are reported. `native-constants-report.json` retains constants, instruction RVAs and string candidates. The Ghidra report embeds the annotations; the report tab and the current function's editor panel show them with navigation to the containing function. Synthetic stack offsets are explicitly labelled as stack offsets, not real runtime addresses.

The owned `tests/fixtures/native_strings.asm` fixture recovered `HELLO` through a bounded XOR loop. The full offline Ghidra pipeline retained the string and its address in the `.uie` database. Separate tests cover calls, unknown writes, partial registers, rotated values and infinite-loop limits.

## UPX

UPX signatures trigger `upx -d` on a staged copy. UIE never executes the target. The original hash, output hash, unpacked-format analysis and failures are recorded in `unpack-report.json`; `packed-analysis.json` preserves the initial identification. Successful unpacking selects the next backend from the unpacked file. A failed unpack remains an incomplete result even if Ghidra produces output from the packed file.

Official UPX 5.3.0 archives are downloaded with pinned SHA-256 values on Windows x86/x64 and Linux x64/ARM64. An installed `upx` on PATH is also supported. macOS requires an installed UPX. Offline mode does not download missing tools. The offline preparation includes UPX on supported automatic-download platforms. Altered or unsupported packers are reported rather than forced.

```powershell
UIE.exe --unpack owned-packed.exe result
```

The local owned Nuitka fixture was packed with UPX `--exact`; decompression restored its SHA-256 exactly. This is an unpacking check, not a Nuitka-to-Python recovery result.

No automatic VMProtect, Themida, Denuvo, anti-debug bypass or guaranteed deobfuscation is implemented. Antivirus compatibility and code signing are not validated by these tests.

## Platform validation

The local validation host is Windows x64. The prepared desktop workflow builds and tests Windows x64, Linux x64 and macOS ARM64/x64 separately. Preparing the workflow does not establish successful CI or GUI operation on those hosts. No cross-platform release has been published for these changes.
