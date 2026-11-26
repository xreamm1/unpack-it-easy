"""Compare only the owned native_scalar.c fixture against UIE-generated Python.

Usage: python tests/check_native_scalar.py fixture.dll lifted-output-directory
Never pass an untrusted library: ctypes loads and executes the supplied DLL.
"""
import ctypes
import importlib.util
import json
from pathlib import Path
import random
import sys


def main():
    library_path = Path(sys.argv[1]).resolve()
    output = Path(sys.argv[2]).resolve()
    library = ctypes.CDLL(str(library_path))
    spec = importlib.util.spec_from_file_location(
        "uie_owned_fixture", output / "source/native_scalar_reconstruction.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    report = json.loads((output / "native-lift-report.json").read_text())
    arities = {"scalar_sum": 2, "scalar_mix": 2, "scalar_wrap": 2,
               "scalar_neg": 1, "scalar_shift": 1,
               "scalar_rotate_left": 1, "scalar_rotate_right32": 1,
               "scalar_rotate_variable": 2, "scalar_mask": 2}
    randomizer = random.Random(7193)
    edge_cases = [0, 1, 31, 32, 63, 64, 65, 2**31 - 1, 2**31, 2**32 - 1, 2**32, 2**63, 2**64 - 1]
    comparisons = 0
    verified = []
    for row in report["functions"]:
        name = row["name"]
        if name.startswith("unsupported_"):
            assert not row["lifted"], row
            assert not hasattr(module, row["python_symbol"]), row
            continue
        assert name in arities and row["lifted"], row
        arity = arities[name]
        scalar = ctypes.c_uint32 if name in {"scalar_wrap", "scalar_rotate_right32"} else ctypes.c_uint64
        native = getattr(library, name)
        native.argtypes = [scalar] * arity
        native.restype = scalar
        python = getattr(module, row["python_symbol"])
        cases = [(a,) if arity == 1 else (a, b)
                 for a in edge_cases for b in (edge_cases if arity == 2 else [0])]
        cases += [tuple(randomizer.getrandbits(64) for _ in range(arity)) for _ in range(500)]
        for values in cases:
            expected = native(*values)
            actual = python(*values)
            assert actual == expected, (name, values, expected, actual)
            comparisons += 1
        verified.append(name)
    assert len(verified) == 9
    result = {"owned_fixture": str(library_path), "functions": verified,
              "comparisons": comparisons, "passed": True,
              "scope": "raw integer return values of the owned fixture only"}
    (output / "validation.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
