# Nuitka native fixture

The source is owned by this project and contains no external activity.

```cmd
python -m pip install nuitka ordered-set zstandard
python -m nuitka --msvc=latest --output-dir=build --report=compilation-report.xml nuitka_sample.py
```

On Linux omit `--msvc=latest`. Open the emitted binary in UIE. When the generated launch script is run, expected output is `UIE_NUITKA_FIXTURE 42 winning`. This is not an equivalence test for Ghidra C pseudocode. Nuitka Commercial requires a licensed compiler and a separate protected sample; this fixture uses standard Nuitka.
