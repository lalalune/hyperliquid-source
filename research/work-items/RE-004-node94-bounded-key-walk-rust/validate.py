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
SOURCE = ROOT / "src/node94-bounded-key-walk"
FROZEN = PACKET / "frozen"
RUSTC_DEFAULT = "/opt/homebrew/opt/rustup/bin/rustc"
MUTATIONS = {
    "initial_equality_stops": ("if key < u64::from(current.word_e6)", "if key <= u64::from(current.word_e6)", 1),
    "initial_key_narrowed": ("if key < u64::from(current.word_e6)", "if (key as u16) < current.word_e6", 1),
    "initial_signed_compare": ("if key < u64::from(current.word_e6)", "if (key as i64) < i64::from(current.word_e6)", 1),
    "signed_gate_compare": ("if gate < next.word_e6", "if (gate as i16) < (next.word_e6 as i16)", 1),
    "gate_equality_stops": ("if gate < next.word_e6", "if gate <= next.word_e6", 1),
    "retain_input_key_on_later_stop": ("Ok([next.id, index, u64::from(gate)])", "Ok([next.id, index, key])", 1),
    "saturating_index": ("index.wrapping_add(1)", "index.saturating_add(1)", 1),
    "advance_initial_index": ("Ok([current.id, index, key])", "Ok([current.id, index.wrapping_add(1), key])", 1),
    "exhausted_first_node": ("Ok([0, current.id, index])", "Ok([0, start, index])", 1),
    "exhausted_key_instead_of_index": ("Ok([0, current.id, index])", "Ok([0, current.id, key])", 1),
    "reject_closing_edge_before_gate": (
        "let next = lookup(nodes, current.next)?;",
        "let next = lookup(nodes, current.next)?;\n        if next.id == start { return Err(Refusal::NonterminatingCycle); }", 1),
    "precheck_unread_successors": (
        "let mut current = lookup(nodes, start)?;",
        "for node in nodes { if node.next != 0 { lookup(nodes, node.next)?; } }\n    let mut current = lookup(nodes, start)?;", 1),
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
    parser.add_argument("--output", type=Path, default=ROOT / "work/node94-bounded-key-walk/recheck")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build = ROOT / "work/node94-bounded-key-walk/build"
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
        require(process.returncode == 0, f"{label} failed: {process.stderr.decode(errors='replace')}")
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
    run("target-disassembly", [args.objdump, "-d", "--start-address=0x1b26100",
                                "--stop-address=0x1b2616a", "artifacts/node/94/hl-node"])
    run("caller-1-disassembly", [args.objdump, "-d", "--start-address=0x25767b0",
                                 "--stop-address=0x2576b6d", "artifacts/node/94/hl-node"])
    # Retain the CIE and function/caller FDEs from a complete GNU frame read.
    frame_command = [args.objdump, "--dwarf=frames", "artifacts/node/94/hl-node"]
    frame_process = subprocess.Popen(frame_command, cwd=ROOT, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
    selected, capture = [], False
    for line in frame_process.stdout:
        if line.startswith("00000000 ") or line.startswith("0002e56c ") or line.startswith("003eb2cc ") or line.startswith("002dc714 "):
            capture = True
        if capture:
            selected.append(line)
        if not line.strip():
            capture = False
    error = frame_process.stderr.read()
    require(frame_process.wait() == 0 and not error, "GNU frame read failed")
    frames = "".join(selected)
    require("pc=0000000001b26100..0000000001b2616a" in frames, "GNU FDE extent changed")
    require("pc=00000000025767b0..0000000002576b6d" in frames, "GNU first caller FDE extent changed")
    (output / "target.frames.txt").write_text(frames.rstrip("\n") + "\n")
    commands.append({"label": "target-frames", "argv": frame_command, "cwd": "/repo",
                     "returncode": 0, "retention": "CIEs 0/0x2dc714 and FDEs 0x2e56c/0x3eb2cc only"})

    def compile_run(label, lib_source, optimization):
        directory = build / label
        directory.mkdir(exist_ok=True)
        library = directory / "libnode94_bounded_key_walk.rlib"
        client = directory / "client"
        flags = ["--edition=2021", "-Dwarnings", "-C", f"opt-level={optimization}",
                 "-C", "overflow-checks=yes", "-C", "panic=abort", "-C", "debuginfo=0",
                 "-C", "codegen-units=1", "--remap-path-prefix", f"{ROOT}=/repo"]
        run(label + "-library", compiler + [lib_source, "--crate-name", "node94_bounded_key_walk",
                                           "--crate-type", "rlib", *flags, "-o", library])
        run(label + "-client", compiler + [SOURCE / "input_only_driver.rs", *flags,
                                          "--extern", f"node94_bounded_key_walk={library}", "-o", client])
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
    for name, (before, after, count) in MUTATIONS.items():
        require(original.count(before) == count, f"{name}: mutation is not unique")
        mutant = build / f"{name}.rs"
        mutant.write_text(original.replace(before, after))
        controls[name] = compile_run("mutant-" + name, mutant, 3)
        controls[name]["source_change"] = {"before": before, "after": after}
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
    for command in commands:
        if command["label"] == "target-frames":
            continue
        for stream in ("stdout", "stderr"):
            label = command["label"]
            raw = streams[f"{label}.{stream}"]
            sha = hashlib.sha256(raw).hexdigest()
            require(sha == command[f"{stream}_sha256"], "Raw command stream hash changed")
            stream_records.append({"label": label, "stream": stream, "sha256": sha,
                                   "base64": base64.b64encode(raw).decode("ascii")})
    archive = json.dumps({"encoding": "base64", "streams": stream_records},
                         indent=2).encode() + b"\n"
    (output / "raw-streams.json.gz").write_bytes(gzip.compress(archive, mtime=0))
    print(json.dumps({"cases_per_build": coverage["cases"], "builds": len(results),
                      "compiled_controls": {key: value["mismatches"] for key, value in controls.items()},
                      "results": clean(str(output / "results.json"))}, indent=2))


if __name__ == "__main__":
    main()
