"""Recheck the frozen static oracle, then build/run only newly authored Rust."""
import argparse
import base64
import gzip
import hashlib
import json
from pathlib import Path
import platform
import subprocess
import sys

import oracle
from verify_static import check as check_static

ROOT, PACKET = oracle.ROOT, oracle.PACKET
SOURCE = ROOT / "src/node94-thirty-step-matrix"
FROZEN = PACKET / "frozen"
RUSTC_DEFAULT = "/opt/homebrew/opt/rustup/bin/rustc"
MUTATIONS = {
    "twenty_nine_steps": [("for _ in 0..30 {", "for _ in 0..29 {")],
    "even_instead_of_odd": [("if first & 1 != 0 {", "if first & 1 == 0 {")],
    "signed_pair_comparison": [("if first < second {", "if (first as i64) < (second as i64) {"), ("first -= second;", "first = first.wrapping_sub(second);")],
    "swap_on_equality": [("if first < second {", "if first <= second {")],
    "omit_matrix_swap": [("rows.swap(0, 1);", "rows.swap(0, 0);")],
    "omit_row_doubling": [("rows[1][0] *= 2;", "rows[1][0] *= 1;"), ("rows[1][1] *= 2;", "rows[1][1] *= 1;")],
    "add_matrix_rows": [("rows[0][0] -= rows[1][0];", "rows[0][0] += rows[1][0];"), ("rows[0][1] -= rows[1][1];", "rows[0][1] += rows[1][1];")],
    "omit_swap_accumulator": [("accumulator.wrapping_add((first & second) >> 1)", "accumulator.wrapping_add(((first & second) >> 1) * 0)")],
    "xor_swap_accumulator": [("(first & second) >> 1", "(first ^ second) >> 1")],
    "widen_second_plus_two": [("second.wrapping_add(2) >> 2", "((u128::from(second) + 2) >> 2) as u64")],
    "parity_only_return": [("rbp: accumulator,", "rbp: accumulator & 1,")],
    "zero_extend_coefficients": [("rax: rows[0][0] as u64,", "rax: u64::from(rows[0][0] as u32),"), ("rbx: rows[0][1] as u64,", "rbx: u64::from(rows[0][1] as u32),"), ("rcx: rows[1][1] as u64,", "rcx: u64::from(rows[1][1] as u32),"), ("rdx: rows[1][0] as u64,", "rdx: u64::from(rows[1][0] as u32),")],
    "return_current_packed_row": [("r13: encoded(before_rows[1]),", "r13: encoded(rows[1]),")],
    "return_final_accumulator_snapshot": [("r14: before_accumulator,", "r14: accumulator ^ (before_accumulator & 0),")],
    "return_final_pair_snapshot": [("r10: before_pair[0],", "r10: first ^ (before_pair[0] & 0),")],
    "reverse_packed_fields": [("((BIAS + row[0]) as u64) | (((BIAS + row[1]) as u64) << 32)", "((BIAS + row[1]) as u64) | (((BIAS + row[0]) as u64) << 32)")],
}



def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", default=RUSTC_DEFAULT)
    parser.add_argument("--objdump", default="/opt/homebrew/opt/binutils/bin/objdump")
    parser.add_argument("--output", type=Path, default=ROOT / "work/node94-thirty-step-matrix/recheck")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build = ROOT / "work/node94-thirty-step-matrix/build"
    build.mkdir(parents=True, exist_ok=True)
    commands = []
    streams = {}

    def clean(text):
        return text.replace(str(ROOT), "/repo")

    def run(label, command):
        process = subprocess.run(list(map(str, command)), cwd=ROOT,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for stream in ("stdout", "stderr"):
            streams[f"{label}.{stream}"] = getattr(process, stream)
        commands.append({"label": label, "argv": [clean(str(x)) for x in command],
                         "cwd": "/repo", "returncode": process.returncode,
                         "stdout_sha256": hashlib.sha256(process.stdout).hexdigest(),
                         "stderr_sha256": hashlib.sha256(process.stderr).hexdigest()})
        if process.returncode != 0:
            failure = {"commands": commands, "streams": [
                {"key": key, "sha256": hashlib.sha256(raw).hexdigest(),
                 "base64": base64.b64encode(raw).decode("ascii")}
                for key, raw in streams.items()]}
            (output / "failure-streams.json.gz").write_bytes(
                gzip.compress((json.dumps(failure) + "\n").encode(), mtime=0))
            raise ValueError(f"{label} failed: {process.stderr.decode(errors='replace')}")
        return process.stdout

    frozen = json.loads((FROZEN / "ORACLE-FREEZE.json").read_text())
    require(oracle.digest(PACKET / "oracle.py") == frozen["oracle_source_sha256"], "Frozen oracle source changed")
    archived = {}
    for filename, key in (("inputs.tsv", "inputs_sha256"), ("expected.txt", "expected_sha256")):
        raw = gzip.decompress((FROZEN / (filename + ".gz")).read_bytes())
        require(hashlib.sha256(raw).hexdigest() == frozen[key], f"Frozen {filename} changed")
        archived[filename] = raw
    write_json(output / "static-controls.json", check_static())
    inputs, expected, coverage = oracle.fixture_bytes()
    require(inputs == archived["inputs.tsv"], "Input regeneration changed")
    require(expected == archived["expected.txt"], "Arithmetic oracle regeneration changed")
    require(json.loads(json.dumps(coverage)) == frozen["coverage"], "Coverage changed")
    input_path = build / "inputs.tsv"
    input_path.write_bytes(inputs)
    compiler = [args.rustc, "+1.94.1"]
    version = run("rustc-version", compiler + ["-Vv"]).decode()
    require("release: 1.94.1\n" in version and
            "commit-hash: e408947bfd200af42db322daf0fadfe7e26d3bd1\n" in version,
            "Compiler is not the pinned rustc 1.94.1")
    run("objdump-version", [args.objdump, "--version"])
    facts = frozen["static_facts"]
    for index, item in enumerate(facts["bodies"]):
        label = "target-disassembly" if index == 0 else f"caller-{index}-disassembly"
        run(label, [args.objdump, "-d", f"--start-address={item['start']:#x}",
                    f"--stop-address={item['end']:#x}", "artifacts/node/94/hl-node"])
    frame_command = [args.objdump, "--dwarf=frames", "artifacts/node/94/hl-node"]
    frame_process = subprocess.Popen(frame_command, cwd=ROOT, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
    secs, _ = oracle.mapping(oracle.TARGET.read_bytes())
    eh = next(s for s in secs if s["name"] == ".eh_frame")["address"]
    offsets = sorted({record["va"] - eh for item in facts["bodies"] for record in item["frames"].values()})
    selected, capture = [], False
    for line in frame_process.stdout:
        if any(line.startswith(f"{offset:08x} ") for offset in offsets):
            capture = True
        if capture:
            selected.append(line)
        if not line.strip():
            capture = False
    error = frame_process.stderr.read()
    require(frame_process.wait() == 0 and not error, "GNU frame read failed")
    frames = "".join(selected)
    for item in facts["bodies"]:
        require(f"pc={item['start']:016x}..{item['end']:016x}" in frames, "GNU FDE extent changed")
    (output / "target.frames.txt").write_text(frames.rstrip("\n") + "\n")
    commands.append({"label": "target-frames", "argv": frame_command, "cwd": "/repo",
                     "returncode": 0, "retention": "CIE/FDE records " + ",".join(hex(x) for x in offsets)})

    def compile_run(label, lib_source, optimization):
        directory = build / label
        directory.mkdir(exist_ok=True)
        library = directory / "libnode94_thirty_step_matrix.rlib"
        client = directory / "client"
        flags = ["--edition=2021", "-Dwarnings", "-C", f"opt-level={optimization}",
                 "-C", "overflow-checks=yes", "-C", "panic=abort", "-C", "debuginfo=0",
                 "-C", "codegen-units=1", "--remap-path-prefix", f"{ROOT}=/repo"]
        run(label + "-library", compiler + [lib_source, "--crate-name", "node94_thirty_step_matrix",
                                           "--crate-type", "rlib", *flags, "-o", library])
        run(label + "-client", compiler + [SOURCE / "input_only_driver.rs", *flags,
                                          "--extern", f"node94_thirty_step_matrix={library}", "-o", client])
        actual = run(label + "-run", [client, input_path])
        lines, truth = actual.decode().splitlines(), expected.decode().splitlines()
        require(len(lines) == len(truth), f"{label}: incomplete native output")
        mismatches = [i for i, (a, b) in enumerate(zip(lines, truth)) if a != b]
        input_rows = inputs.decode().splitlines()
        record = {
            "cases": len(truth), "mismatches": len(mismatches),
            "library_sha256": oracle.digest(library), "client_sha256": oracle.digest(client),
            "output_sha256": hashlib.sha256(actual).hexdigest(),
            "first_mismatches": [{"row_zero_based": i, "input": input_rows[i],
                                   "expected": truth[i], "actual": lines[i]}
                                  for i in mismatches[:5]],
        }
        return record

    results = {}
    for optimization in (0, 3):
        for repeat in (1, 2):
            label = f"opt{optimization}-build{repeat}"
            results[label] = compile_run(label, SOURCE / "lib.rs", optimization)
            require(results[label]["mismatches"] == 0, f"{label} differs from frozen oracle")
        first, second = (results[f"opt{optimization}-build{n}"] for n in (1, 2))
        for key in ("library_sha256", "client_sha256", "output_sha256"):
            require(first[key] == second[key], f"opt{optimization} repeat {key} changed")

    original = (SOURCE / "lib.rs").read_text()
    controls = {}
    for name, changes in MUTATIONS.items():
        changed = original
        for before, after in changes:
            require(changed.count(before) == 1, f"{name}: mutation is not unique")
            changed = changed.replace(before, after)
        mutant = build / f"{name}.rs"
        mutant.write_text(changed)
        controls[name] = compile_run("mutant-" + name, mutant, 3)
        controls[name]["source_change"] = [{"before": before, "after": after} for before, after in changes]
        controls[name]["source_sha256"] = oracle.digest(mutant)
        require(controls[name]["mismatches"] > 0, f"{name}: control was not detected")

    # Repeat mismatch counting against a deliberately corrupted expectation.
    # This exercises the real native-output comparison independently of mutants.
    altered = expected.splitlines()
    altered[0] = b"deliberately-corrupt"  # The frozen archive is untouched.
    actual = streams["opt3-build1-run.stdout"].splitlines()
    comparator_mismatches = sum(a != b for a, b in zip(actual, altered))
    require(comparator_mismatches == 1, "Corrupted expectation did not produce exactly one mismatch")
    report = {
        "target_sha256": frozen["static_facts"]["target_sha256"],
        "source_base_commit": "56c0ec672bd8fdcfaa80f2db700a61e6240b3663",
        "platform": platform.platform(), "python_version": sys.version.split()[0],
        "python_optimization": sys.flags.optimize,
        "rustc": version, "coverage": coverage, "builds": results, "compiled_controls": controls,
        "corrupted_expectation_mismatches": comparator_mismatches,
        "source_sha256": {name: oracle.digest(SOURCE / name)
                          for name in ("lib.rs", "input_only_driver.rs")},
        "oracle_freeze_sha256": oracle.digest(FROZEN / "ORACLE-FREEZE.json"),
        "validator_sha256": oracle.digest(__file__),
        "static_verifier_sha256": oracle.digest(PACKET / "verify_static.py"),
        "static_target_rechecked": True, "captured_binary_executed": False,
        "original_abi_reproduced": False, "target_code_byte_comparison": "not measured",
        "progress_gate_requested": False,
    }
    write_json(output / "commands.json", commands)
    write_json(output / "results.json", report)
    stream_records = []
    basis = None
    basis_label = None
    for command in commands:
        if command["label"] == "target-frames":
            continue
        for stream in ("stdout", "stderr"):
            label = command["label"]
            raw = streams[f"{label}.{stream}"]
            sha = hashlib.sha256(raw).hexdigest()
            require(sha == command[f"{stream}_sha256"], "Raw command stream hash changed")
            record = {"label": label, "stream": stream, "sha256": sha, "bytes": len(raw)}
            if stream == "stdout" and label.endswith("-run"):
                if basis is None:
                    basis, basis_label = raw, label
                    record["base64"] = base64.b64encode(raw).decode("ascii")
                else:
                    require(len(raw) == len(basis), "Native stream width changed")
                    delta = bytes(a ^ b for a, b in zip(raw, basis))
                    record["xor_base64"] = base64.b64encode(delta).decode("ascii")
                    record["basis_label"] = basis_label
            else:
                record["base64"] = base64.b64encode(raw).decode("ascii")
            stream_records.append(record)
    archive = json.dumps({"encoding": "base64-or-xor-base64", "streams": stream_records},
                         indent=2).encode() + b"\n"
    (output / "raw-streams.json.gz").write_bytes(gzip.compress(archive, mtime=0))
    print(json.dumps({"cases_per_build": coverage["cases"], "builds": len(results),
                      "compiled_controls": {key: value["mismatches"] for key, value in controls.items()},
                      "results": clean(str(output / "results.json"))}, indent=2))


if __name__ == "__main__":
    main()
