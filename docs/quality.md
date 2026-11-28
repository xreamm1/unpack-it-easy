# Owned fixture round-trip checks

From the source directory, run Python 3 and pass an existing UIE executable,
engine cache, JDK home (both `java` and `javac`), and a new results directory:

```powershell
python tests/quality/run_quality.py --uie C:/path/UIE.exe --engines C:/path/engines --java-home C:/path/jdk --output C:/path/quality-run-001
```

The suite compiles the bundled Java sources and runs their independent assertion
programs against fixed baselines first. It then sends the authored class and JAR
through UIE/CFR and the authored DEX and APK through UIE/JADX. Each successful
recovery with Java sources is compiled with the explicit JDK and runs the same
assertion program if compilation succeeds, including partial backend output.
Only these owned, harmless fixtures are executed; no arbitrary input option exists.
DEX bytes are authored directly using the bundled standard-library builder;
Dalvik code and APKs are never executed or installed. Recovered Java is executed.

Coverage is deliberately small: Java branches, for/while loops, negative and zero
inputs, trimmed/repeated strings and a Unicode string (12 assertions per case);
Android integer addition including overflow and one string literal (7 assertions
per case). The Android Java source records the intended behavior of the DEX.
This is a regression corpus, not a claim of general functional equivalence or
a decompilation accuracy percentage.

Offline is the default. Missing cached external engines produce explicit skips;
the harness does not download them. `--online` explicitly permits UIE engine
preparation. Cached CFR/JADX artifacts are copied into a private engine directory
under the new output; existing results and the supplied cache are not overwritten.
JAR/APK entry timestamps are fixed. Compiled Java bytes may differ across JDKs;
the report records JDK versions, executable and fixture hashes.

`quality-report.json` separates UIE backend success, emitted files, javac results,
fixture assertion results, errors, unsupported cases and skips. Original sources,
verifiers, baselines, settings, backend reports and recovered files are retained
in the output. No unsupported cases are currently specified. A failed case does
not become a skip. Exit codes: 0 all passed, 1 failed, 2 incomplete/skipped (or
invalid invocation). Time limits: 15 seconds for version/builder commands,
60 for javac, 30 for fixture execution, 180 for each UIE invocation; timed-out
process trees are terminated. Nothing is published.
