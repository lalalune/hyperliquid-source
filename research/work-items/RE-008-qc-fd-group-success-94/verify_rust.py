#!/usr/bin/env python3
"""Compile a real component's input-only projection and compare frozen outputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
COMPONENT = ROOT / "src/node94-consensus-admission"
FIELD = "src/qc_fd_group.rs"
EXAMPLE = "qc_fd_group_input_only"
INPUT_SHA = "85a8eaf0bd17f8a15315cf739d353f3a4e51dc7141c25d3923f7906149c533ec"
EXPECTED_SHA = "5478a322a78b060ae8915a1de6ee344f4dee205192c29c9669fd52227551cb82"


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def mutations():
    return {
        "word0-shift-16": ("&word0.to_le_bytes()", "&(((word0 >> 16) << 8) | (word0 & 0xff)).to_le_bytes()"),
        "word1-to-word2-slot": ("output[16..24].copy_from_slice(&word1", "output[24..32].copy_from_slice(&word1"),
        "word2-to-word1-slot": ("output[24..32].copy_from_slice(&word2", "output[16..24].copy_from_slice(&word2"),
        "word3-to-word2-slot": ("output[32..40].copy_from_slice(&word3", "output[24..32].copy_from_slice(&word3"),
        "second-refund-16": ("*charge = final_charge;", "*charge = final_charge - 8;"),
        "word3-uses-word2": ("output[32..40].copy_from_slice(&word3.to_le_bytes());",
                             "let _ = word3;\n    output[32..40].copy_from_slice(&word2.to_le_bytes());"),
    }


def command(argv, cwd, stem, *, env=None, stdin=None):
    result = subprocess.run(list(map(str, argv)), cwd=cwd, env=env, input=stdin,
                            capture_output=True, timeout=90)
    stem.with_suffix(".stdout").write_bytes(result.stdout)
    stem.with_suffix(".stderr").write_bytes(result.stderr)
    record = {"argv": list(map(str, argv)), "exit": result.returncode,
              "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)}
    require(result.returncode == 0, f"command failed: {record}; {result.stderr.decode(errors='replace')}")
    return result, record


def read_result(line):
    """Independent byte/word reader for the input-only program's stdout."""
    fields = line.decode("ascii").split("\t")
    require(len(fields) == 5, "result record shape")
    charge, consumed = int(fields[1]), int(fields[2])
    require(0 <= charge < 1 << 64 and consumed >= 0, "result numeric domain")
    suffix = b"" if fields[3] == "-" else bytes.fromhex(fields[3])
    output = bytes.fromhex(fields[4])
    require(len(output) == 40, "complete40-byte helper result")
    return fields[0], charge, consumed, suffix, struct.unpack("<5Q", output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", type=Path, required=True)
    parser.add_argument("--cargo", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    rustc = args.rustc.resolve(strict=True)
    cargo = (args.cargo or rustc.with_name("cargo")).resolve(strict=True)
    output = args.out.resolve()
    require(not output.exists(), "refuse an existing output directory")
    output.mkdir(parents=True)
    tool_hashes = {str(p): sha(p.read_bytes()) for p in (rustc, cargo)}
    comparator_sha = sha(Path(__file__).read_bytes())
    version, _ = command([rustc, "-vV"], output, output / "rustc-version")
    require(b"release: 1.94.1\n" in version.stdout and b"host: x86_64-unknown-linux-gnu\n" in version.stdout, "require reviewed rustc1.94.1 host")
    cargo_version, _ = command([cargo, "-vV"], output, output / "cargo-version")
    inputs = (HERE / "inputs.tsv").read_bytes()
    expected = (HERE / "expected.tsv").read_bytes()
    require(sha(inputs) == INPUT_SHA and sha(expected) == EXPECTED_SHA, "pre-Rust fixtures changed")
    wanted_lines = expected.splitlines()[1:]
    require(len(wanted_lines) == 8, "qualified case count")
    wanted_records = list(map(read_result, wanted_lines))
    for name, content in [("inputs.tsv", inputs), ("expected.tsv", expected)]:
        (output / name).write_bytes(content)
        (output / name).chmod(0o444)
    names = ["Cargo.toml", "Cargo.lock", f"examples/{EXAMPLE}.rs"]
    names += sorted(p.relative_to(COMPONENT).as_posix() for p in (COMPONENT / "src").rglob("*.rs"))
    sources = {name: (COMPONENT / name).read_bytes() for name in names}
    original = sources[FIELD].decode()
    variants = {"baseline": sources}
    for name, (old, new) in mutations().items():
        require(original.count(old) == 1 and old != new, "ambiguous source mutation " + name)
        variants[name] = sources | {FIELD: original.replace(old, new, 1).encode()}
    snapshots = {}
    for name, content in variants.items():
        for relative, data in content.items():
            path = output / "sources" / name / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(0o444)
        snapshots[name] = {relative: sha(data) for relative, data in content.items()}
    freeze = {"source_snapshots": snapshots, "input_sha256": INPUT_SHA, "expected_sha256": EXPECTED_SHA}
    frozen = (json.dumps(freeze, indent=2, sort_keys=True) + "\n").encode()
    (output / "freeze.json").write_bytes(frozen)
    results = []
    for name, content in variants.items():
        location = output / "sources" / name
        for opt in (0, 3):
            run = output / f"{name}-opt{opt}"
            run.mkdir()
            env = os.environ.copy()
            env.update({"RUSTC": str(rustc), "RUSTDOC": str(rustc.with_name("rustdoc")),
                        "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": "",
                        "CARGO_HOME": str(output / "cargo-home"), "CARGO_TARGET_DIR": str(run / "target"),
                        "RUSTFLAGS": "-D warnings -C overflow-checks=yes", "CARGO_NET_OFFLINE": "true"})
            argv = [cargo, "build", "--offline", "--locked", "--manifest-path", location / "Cargo.toml", "--example", EXAMPLE]
            if opt == 3:
                argv.append("--release")
            _, compiled = command(argv, run, run / "compile", env=env)
            binary = run / "target" / ("release" if opt == 3 else "debug") / "examples" / EXAMPLE
            binary_hash = sha(binary.read_bytes())
            dependencies, dep_pins = set(), {}
            # Check every compiler-recorded project input, not just .rs names:
            # an included expected-data file must also fail this closure check.
            pattern = re.escape(str(location)) + r"/[^\s\\:]+"
            for path in (run / "target").rglob("*.d"):
                dependencies.update(re.findall(pattern, path.read_text()))
                dep_pins[path.relative_to(run).as_posix()] = sha(path.read_bytes())
            require(dependencies == {str(location / r) for r in content if r.endswith(".rs")}, "exact compiler-read project source set")
            actual, ran = command([binary], run, run / "run", env=env, stdin=inputs)
            require(not actual.stderr and sha(binary.read_bytes()) == binary_hash, "unexpected run diagnostic/executable drift")
            actual_lines = actual.stdout.splitlines()
            require(len(actual_lines) == len(wanted_lines), "driver output count")
            actual_records = list(map(read_result, actual_lines))
            different = [i for i, (a, w) in enumerate(zip(actual_records, wanted_records, strict=True)) if a != w]
            require(bool(different) == (name != "baseline"), "unexpected comparison " + name)
            require(all(sha((location / r).read_bytes()) == d for r, d in snapshots[name].items()), "snapshot changed after compilation")
            results.append({"source": name, "opt_level": opt, "compile": compiled, "run": ran,
                            "binary_sha256": binary_hash, "dep_info": dep_pins,
                            "compiler_project_sources": len(dependencies),
                            "matched": len(wanted_lines) - len(different), "different": len(different),
                            "witnesses": [wanted_lines[i].split(b"\t", 1)[0].decode() for i in different[:2]]})
            print(f"{name} opt{opt}: compile/run0; {len(different)}/8 different")
    require(all(sha((COMPONENT / r).read_bytes()) == sha(d) for r, d in sources.items()), "working source changed")
    require(all(sha(Path(p).read_bytes()) == h for p, h in tool_hashes.items()), "compiler/Cargo changed")
    require(sha(Path(__file__).read_bytes()) == comparator_sha, "comparator changed")
    require(sha((HERE / "inputs.tsv").read_bytes()) == INPUT_SHA
            and sha((HERE / "expected.tsv").read_bytes()) == EXPECTED_SHA, "fixtures changed")
    report = {"rustc": version.stdout.decode(), "cargo": cargo_version.stdout.decode(), "tools": tool_hashes,
              "source_snapshot": snapshots["baseline"], "freeze_sha256": sha(frozen), "comparator_sha256": comparator_sha,
              "input_sha256": INPUT_SHA, "expected_sha256": EXPECTED_SHA, "cases": 8,
              "source_mutants": 6, "results": results, "captured_execution": False,
              "limits": "Final-state FD-only mode1 projection against static-derived expectations; no native ABI, failure or execution equivalence"}
    (output / "results.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
