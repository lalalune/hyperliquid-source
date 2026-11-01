#!/usr/bin/env python3
"""Compile the existing component and compare its input-only field example.

Expected records are independent static-native-derived observations, not target
execution. Source mutations test this qualified relation, not a native ABI.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENT = ROOT / "src/node94-consensus-admission"
FIELD = "src/qc_recovery_byte.rs"
INPUT_SHA = "543593d9b4c23e919f95b5bd37e860e3eee783b814f4fa582285e8d3db1aac6c"
EXPECTED_SHA = "90c44eb754ad03cec387b6da73353c1b57b66c666cc37bce17e87d592a2cc901"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def mutations():
    limit = """        state.charge = incremented;
        if incremented > state.limit {
            return Err(FieldError::ChargeRejected);
        }"""
    return {
        "discard-limit-charge": (limit, """        if incremented > state.limit {
            return Err(FieldError::ChargeRejected);
        }
        state.charge = incremented;"""),
        "eof-before-charge": ("    if state.mode == 1 {", """    if input.is_empty() {
        return Err(FieldError::EmptyInput);
    }
    if state.mode == 1 {"""),
        "admit-limit-equality": ("if incremented > state.limit", "if incremented - 1 > state.limit"),
        "wrap-overflow": ("""        let incremented = state
            .charge
            .checked_add(1)
            .ok_or(FieldError::ChargeRejected)?;""",
                          "        let incremented = state.charge.wrapping_add(1);"),
        "consume-two": ("    *input = suffix;", "    *input = if suffix.is_empty() { suffix } else { &suffix[1..] };"),
        "reject-high-byte": (
            "    *input = suffix;",
            """    if value > 1 {
        return Err(FieldError::ChargeRejected);
    }
    *input = suffix;"""),
    }


def command(argv, cwd, stem, *, env=None, stdin=None):
    result = subprocess.run(argv, cwd=cwd, env=env, input=stdin,
                            capture_output=True, timeout=90)
    stem.with_suffix(".stdout").write_bytes(result.stdout)
    stem.with_suffix(".stderr").write_bytes(result.stderr)
    record = {"argv": list(map(str, argv)), "exit": result.returncode,
              "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)}
    require(result.returncode == 0, f"command failed: {record}; {result.stderr.decode(errors='replace')}")
    return result, record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rustc = args.rustc.resolve(strict=True)
    cargo = (args.cargo or rustc.with_name("cargo")).resolve(strict=True)
    tool_hashes = {str(path): sha(path.read_bytes()) for path in (rustc, cargo)}
    output = args.out.resolve()
    require(not output.exists(), "refuse an existing output directory")
    output.mkdir(parents=True)
    version, _ = command([str(rustc), "-vV"], output, output / "rustc-version")
    require(b"release: 1.94.1\n" in version.stdout, "require pinned rustc1.94.1")
    require(b"host: x86_64-unknown-linux-gnu\n" in version.stdout, "require reviewed host")
    cargo_version, _ = command([str(cargo), "-vV"], output, output / "cargo-version")

    spec = importlib.util.spec_from_file_location("qc_field_independent_oracle", HERE / "oracle.py")
    oracle = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = oracle
    spec.loader.exec_module(oracle)
    cases = oracle.corpus()
    require(len(cases) == 2572, "corpus changed")
    inputs = ("\n".join(case.input_line() for case in cases) + "\n").encode()
    expected = ("\n".join(case.expected_line() for case in cases) + "\n").encode()
    require(sha(inputs) == INPUT_SHA and sha(expected) == EXPECTED_SHA, "frozen stream changed")
    expected_lines = expected.splitlines()
    (output / "inputs.tsv").write_bytes(inputs)
    (output / "expected.tsv").write_bytes(expected)
    (output / "inputs.tsv").chmod(0o444)
    (output / "expected.tsv").chmod(0o444)

    names = ["Cargo.toml", "Cargo.lock"]
    names += sorted(path.relative_to(COMPONENT).as_posix()
                    for directory in ("src", "examples")
                    for path in (COMPONENT / directory).rglob("*.rs"))
    sources = {name: (COMPONENT / name).read_bytes() for name in names}
    baseline = sources[FIELD].decode()
    source_sets = {"baseline": sources}
    recipes = mutations()
    for name, (old, new) in recipes.items():
        require(baseline.count(old) == 1 and old != new, f"ambiguous mutation {name}")
        source_sets[name] = sources | {FIELD: baseline.replace(old, new, 1).encode()}
    snapshots = {}
    for name, content in source_sets.items():
        location = output / "sources" / name
        for relative, data in content.items():
            path = location / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o444)
        snapshots[name] = {relative: sha(data) for relative, data in content.items()}
    freeze = {"source_snapshots": snapshots, "input_sha256": INPUT_SHA,
              "expected_sha256": EXPECTED_SHA, "oracle_sha256": sha((HERE / "oracle.py").read_bytes())}
    frozen = (json.dumps(freeze, sort_keys=True, indent=2) + "\n").encode()
    (output / "freeze.json").write_bytes(frozen)
    results = []
    for name, content in source_sets.items():
        location = output / "sources" / name
        for opt in (0, 3):
            run = output / f"{name}-opt{opt}"
            run.mkdir()
            env = os.environ.copy()
            env.update({"RUSTC": str(rustc), "RUSTDOC": str(rustc.with_name("rustdoc")),
                        "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": "",
                        "CARGO_HOME": str(output / "cargo-home"), "CARGO_TARGET_DIR": str(run / "target"),
                        "RUSTFLAGS": "-D warnings -C overflow-checks=yes", "CARGO_NET_OFFLINE": "true"})
            argv = [str(cargo), "build", "--offline", "--locked", "--manifest-path",
                    str(location / "Cargo.toml"), "--example", "qc_recovery_byte_input_only"]
            if opt == 3:
                argv.append("--release")
            _, compile_record = command(argv, run, run / "compile", env=env)
            binary = run / "target" / ("release" if opt == 3 else "debug") / "examples/qc_recovery_byte_input_only"
            binary_hash = sha(binary.read_bytes())
            dependencies = set()
            pattern = re.escape(str(location)) + r"/[^\s\\]+\.rs"
            for dep_info in (run / "target").rglob("*.d"):
                dependencies.update(re.findall(pattern, dep_info.read_text()))
            wanted = {str(location / relative) for relative in content if relative.endswith(".rs")}
            require(dependencies == wanted, "compiler project-source closure changed")
            result, run_record = command([str(binary)], run, run / "run", env=env, stdin=inputs)
            require(result.stderr == b"", "unexpected driver diagnostic")
            require(sha(binary.read_bytes()) == binary_hash, "driver executable changed")
            actual_lines = result.stdout.splitlines()
            require(len(actual_lines) == len(cases), "driver output count changed")
            differences = [i for i, (actual, wanted) in enumerate(zip(actual_lines, expected_lines)) if actual != wanted]
            require(bool(differences) == (name != "baseline"), f"unexpected comparison {name}")
            for relative, digest in snapshots[name].items():
                require(sha((location / relative).read_bytes()) == digest, "compiler-read source changed")
            results.append({"source": name, "opt_level": opt, "compile": compile_record,
                            "run": run_record, "binary_sha256": binary_hash,
                            "compiler_project_sources": len(dependencies),
                            "matched": len(cases) - len(differences), "different": len(differences),
                            "witnesses": [cases[i].name for i in differences[:3]]})
            print(f"{name} opt{opt}: compile/run0; {len(differences)}/{len(cases)} different")
    require(all(sha((COMPONENT / name).read_bytes()) == sha(data) for name, data in sources.items()),
            "working component changed during comparison")
    require(all(sha(Path(path).read_bytes()) == digest for path, digest in tool_hashes.items()),
            "compiler or Cargo changed during comparison")
    require(sha((output / "inputs.tsv").read_bytes()) == INPUT_SHA
            and sha((output / "expected.tsv").read_bytes()) == EXPECTED_SHA, "fixture files changed")
    report = {"rustc": version.stdout.decode(), "cargo": cargo_version.stdout.decode(),
              "rustc_sha256": sha(rustc.read_bytes()), "cargo_sha256": sha(cargo.read_bytes()),
              "freeze_sha256": sha(frozen), "inputs": INPUT_SHA, "expected": EXPECTED_SHA,
              "qualified_cases": 2572, "frozen_boundaries": 12, "all_byte_cases": 2560,
              "source_mutants": 6, "results": results, "target_executed": False,
              "limits": "Static-derived field-entry relation; no native execution, original ABI/store-order or crypto equivalence"}
    (output / "results.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
