"""Round-trip only this directory's authored fixtures; never accepts target inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import zipfile


HERE = Path(__file__).resolve().parent


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def run(command, cwd, env, timeout):
    started = time.monotonic()
    result = {"command": [str(item) for item in command], "timeout_seconds": timeout}
    try:
        options = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
        process = subprocess.Popen(result["command"], cwd=cwd, env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, **options)
        stdout, stderr = process.communicate(timeout=timeout)
        result.update(returncode=process.returncode,
                      stdout=stdout.decode("utf-8", errors="replace"),
                      stderr=stderr.decode("utf-8", errors="replace"))
        result["success"] = process.returncode == 0
    except subprocess.TimeoutExpired:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
        else:
            os.killpg(process.pid, signal.SIGKILL)
        process.kill()
        process.communicate(timeout=10)
        result.update(success=False, error="process timed out")
    except OSError as error:
        result.update(success=False, error=str(error))
    result["seconds"] = round(time.monotonic() - started, 3)
    return result


def compile_and_check(sources, verifier, classes, java, javac, cwd, env, baseline):
    classes.mkdir()
    syntax = run([javac, "-encoding", "UTF-8", "--release", "8", "-proc:none",
                  "-d", classes, *sources, verifier], cwd, env, 60)
    behavior = {"status": "skipped", "reason": "javac did not succeed"}
    if syntax["success"]:
        behavior = run([java, "-cp", classes, verifier.stem], cwd, env, 30)
        behavior["expected_stdout"] = baseline
        behavior["stdout_matches_baseline"] = behavior.get("stdout", "").replace("\r\n", "\n") == baseline
        behavior["success"] = behavior["success"] and behavior["stdout_matches_baseline"]
        behavior["status"] = "passed" if behavior["success"] else "failed"
    return syntax, behavior


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uie", type=Path, required=True)
    parser.add_argument("--engines", type=Path, required=True, help="existing UIE engine cache")
    parser.add_argument("--java-home", type=Path, required=True, help="JDK containing java and javac")
    parser.add_argument("--output", type=Path, required=True, help="new, nonexistent results directory")
    parser.add_argument("--online", action="store_true", help="explicitly allow UIE to obtain missing engines")
    args = parser.parse_args()
    uie, engines, java_home, output = [path.resolve() for path in
                                       (args.uie, args.engines, args.java_home, args.output)]
    if output.exists():
        parser.error("--output must not already exist; existing results are never overwritten")
    suffix = ".exe" if os.name == "nt" else ""
    java, javac = [java_home / "bin" / (name + suffix) for name in ("java", "javac")]
    for path in (uie, java, javac):
        if not path.is_file():
            parser.error("required executable is missing: " + str(path))
    output.mkdir(parents=True)
    report = {"schema_version": 1, "scope": "owned fixtures and listed assertions only; not general equivalence",
              "offline": not args.online, "uie": str(uie), "engines": str(engines),
              "java_home": str(java_home), "cases": [], "errors": [], "unsupported": [], "skips": []}
    env = os.environ.copy()
    for name in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(name, None)
    env["JAVA_HOME"] = str(java_home)
    env["PATH"] = str(java_home / "bin") + os.pathsep + env.get("PATH", "")
    # Stage cached artifacts privately: UIE can prepare them without changing the supplied cache.
    stage = output / "engines"
    stage.mkdir()
    env["UIE_ENGINES_DIR"] = str(stage)
    manifest_path = engines / "engines.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig")) if manifest_path.is_file() else {}
    staged_manifest = {"java_home": str(java_home)}
    diec = manifest.get("diec", "")
    diec = (engines / diec).resolve() if diec else engines / "die" / ("diec" + suffix)
    if diec.is_file():
        staged_manifest["diec"] = str(diec)
    write_json(stage / "engines.json", staged_manifest)
    for relative in ("cfr/cfr-0.152.jar", "jadx/jadx-1.5.7.zip"):
        source = engines / relative
        if source.is_file():
            destination = stage / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
    report["tools"] = {"java": run([java, "-version"], output, env, 15),
                       "javac": run([javac, "-version"], output, env, 15)}
    report["uie_sha256"] = hashlib.sha256(uie.read_bytes()).hexdigest()
    fixture_copy = output / "corpus"
    shutil.copytree(HERE / "fixtures", fixture_copy / "fixtures")
    shutil.copytree(HERE / "verifiers", fixture_copy / "verifiers")
    shutil.copytree(HERE / "baselines", fixture_copy / "baselines")
    shutil.copy2(HERE / "build_android_fixture.py", fixture_copy / "build_android_fixture.py")
    report["android_generation"] = run([sys.executable, fixture_copy / "build_android_fixture.py",
                                         output / "android-input"], output, env, 15)
    try:
        java_source = fixture_copy / "fixtures/uie/quality/JavaFixture.java"
        android_source = fixture_copy / "fixtures/uie/fixture/Hello.java"
        baseline_classes = {}
        for name, source, verifier in (("java", java_source, "VerifyJava"),
                                        ("android", android_source, "VerifyAndroid")):
            baseline = (fixture_copy / "baselines" / (name + ".stdout.txt")).read_text(encoding="utf-8")
            check_source = fixture_copy / "verifiers" / (verifier + ".java")
            classes = output / (name + "-original-classes")
            syntax, behavior = compile_and_check([source], check_source, classes, java, javac, output, env, baseline)
            baseline_classes[name] = (classes, check_source, baseline)
            report[name + "_baseline"] = {"javac_syntax": syntax, "functional_fixture_checks": behavior}
            if not syntax["success"] or not behavior.get("success"):
                raise RuntimeError(name + " authored source baseline failed")
        java_classes = baseline_classes["java"][0]
        class_file = java_classes / "uie/quality/JavaFixture.class"
        jar_file = output / "owned-java.jar"
        with zipfile.ZipFile(jar_file, "x", zipfile.ZIP_DEFLATED) as archive:
            entry = zipfile.ZipInfo("uie/quality/JavaFixture.class", (2020, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, class_file.read_bytes())
        cases = [("java-class", class_file, "java", "CFR"),
                 ("java-jar", jar_file, "java", "CFR"),
                 ("android-dex", output / "android-input/hello.dex", "android", "JADX"),
                 ("android-apk", output / "android-input/hello.apk", "android", "JADX")]
        for name, target, family, backend in cases:
            case = {"name": name, "backend": backend, "input": str(target),
                    "status": "failed",
                    "backend_success": None, "emitted_files": [], "emitted_java_files": [],
                    "javac_syntax": {"status": "skipped"}, "functional_fixture_checks": {"status": "skipped"},
                    "errors": [], "unsupported": [], "skips": []}
            report["cases"].append(case)
            required = stage / ("cfr/cfr-0.152.jar" if family == "java" else "jadx/jadx-1.5.7.zip")
            missing = []
            if not required.is_file():
                missing.append(str(required.relative_to(stage)))
            if os.name == "nt" and family == "java" and not diec.is_file():
                missing.append("DIE detector")
            if missing and not args.online:
                case["status"] = "skipped"
                case["skips"].append("offline; missing cached engine: " + ", ".join(missing))
                report["skips"].append({"case": name, "reason": case["skips"][0]})
                continue
            if not target.is_file():
                case["status"] = "failed"
                case["errors"].append("authored fixture generation failed")
                continue
            case["input_sha256"] = hashlib.sha256(target.read_bytes()).hexdigest()
            case_dir = output / name
            case_dir.mkdir()
            settings = {"output": str(case_dir / "recovered"), "offline": not args.online,
                        "english": True, "all_modules": True, "force_rebuild": True,
                        "hide_updates": True, "diec": staged_manifest.get("diec", "")}
            write_json(case_dir / "settings.json", settings)
            invocation = run([uie, "--decompile", target, case_dir / "settings.json", case_dir / "report.json"],
                             case_dir, env, 180)
            case["uie_process"] = invocation
            backend_report = case_dir / "report.json"
            if backend_report.is_file():
                case["backend_report"] = json.loads(backend_report.read_text(encoding="utf-8-sig"))
            else:
                case["errors"].append("UIE did not produce report.json")
            case["backend_success"] = bool(case.get("backend_report", {}).get("success"))
            recovered = case_dir / "recovered"
            files = sorted(path for path in recovered.rglob("*") if path.is_file())
            sources = [path for path in files if path.suffix == ".java"]
            case["emitted_files"] = [str(path.relative_to(case_dir)) for path in files]
            case["emitted_java_files"] = [str(path.relative_to(case_dir)) for path in sources]
            # Source extraction is reported separately even if the backend returned partial output.
            if sources:
                _, verifier, baseline = baseline_classes[family]
                syntax, behavior = compile_and_check(sources, verifier, case_dir / "recompiled", java, javac,
                                                    case_dir, env, baseline)
                case["javac_syntax"], case["functional_fixture_checks"] = syntax, behavior
            if not sources:
                case["errors"].append("no Java source emitted")
            if not case["backend_success"]:
                case["errors"].append(case.get("backend_report", {}).get("error") or "backend failed")
            case["status"] = "passed" if (invocation["success"] and case["backend_success"]
                                               and case["javac_syntax"].get("success")
                                               and case["functional_fixture_checks"].get("success")) else "failed"
    except (OSError, ValueError, RuntimeError) as error:
        report["errors"].append(str(error))
    report["status"] = "failed" if report["errors"] or any(case["status"] == "failed" for case in report["cases"]) else (
        "incomplete" if report["skips"] else "passed")
    write_json(output / "quality-report.json", report)
    print(json.dumps({"status": report["status"], "report": str(output / "quality-report.json")}, indent=2))
    return 1 if report["status"] == "failed" else (2 if report["status"] == "incomplete" else 0)


if __name__ == "__main__":
    sys.exit(main())
