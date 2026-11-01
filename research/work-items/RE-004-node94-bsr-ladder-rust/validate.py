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

ROOT, PACKET = oracle.ROOT, oracle.PACKET
SOURCE = ROOT / "src/node94-bsr-ladder"
FROZEN = PACKET / "frozen"
RUSTC_DEFAULT = "/opt/homebrew/opt/rustup/bin/rustc"
MUTATIONS = {
    "reverse_inner_order": ("value.min(upper).max(lower)", "value.max(lower).min(upper)"),
    "saturating_upper": (".wrapping_sub(fourth)", ".saturating_sub(fourth)"),
    "signed_upper_comparison": (
        "Some(value.min(upper).max(lower).min(12).max(5))",
        "let chosen = if (value as i32) < (upper as i32) { value } else { upper };\n"
        "    Some(chosen.max(lower).min(12).max(5))"),
    "zero_default": ("if value == 0 { 11 }", "if value == 0 { 0 }"),
    "maximum_lower_bound": (
        "(bit_index(second) + 1).min(bit_index(third) + 2)",
        "(bit_index(second) + 1).max(bit_index(third) + 2)"),
    "omit_predecessor": ("bit_index(second - 1)", "bit_index(second)"),
    "move_outer_cap_early": (
        "value.min(upper).max(lower).min(12).max(5)",
        "value.min(upper).min(12).max(lower).max(5)"),
    "invent_excluded_return": ("return None;", "return Some(5);"),
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
    parser.add_argument("--output", type=Path, default=ROOT / "work/node94-bsr-ladder/recheck")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build = ROOT / "work/node94-bsr-ladder/build"
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
    amendment = frozen["post_freeze_admission_hardening"]
    require(oracle.digest(FROZEN / amendment["original_source_archive"]) == frozen["oracle_source_sha256"],
            "Original frozen oracle source changed")
    require(oracle.digest(PACKET / "oracle.py") == amendment["current_oracle_sha256"],
            "Amended oracle source changed")
    archived = {}
    for filename, key in (("inputs.tsv", "inputs_sha256"), ("expected.txt", "expected_sha256")):
        raw = gzip.decompress((FROZEN / (filename + ".gz")).read_bytes())
        require(hashlib.sha256(raw).hexdigest() == frozen[key], f"Frozen {filename} changed")
        archived[filename] = raw
    require(oracle.admit() == frozen["static_facts"], "Static target admission changed")
    inputs, expected, coverage = oracle.fixture_bytes()
    require(inputs == archived["inputs.tsv"], "Input regeneration changed")
    require(expected == archived["expected.txt"], "Threshold oracle regeneration changed")
    require(json.loads(json.dumps(coverage)) == frozen["coverage"], "Coverage changed")
    input_path = build / "inputs.tsv"
    input_path.write_bytes(inputs)
    compiler = [args.rustc, "+1.94.1"]
    version = run("rustc-version", compiler + ["-Vv"]).decode()
    require("release: 1.94.1\n" in version and
            "commit-hash: e408947bfd200af42db322daf0fadfe7e26d3bd1\n" in version,
            "Compiler is not the pinned rustc 1.94.1")
    run("objdump-version", [args.objdump, "--version"])
    run("target-disassembly", [args.objdump, "-d", "--start-address=0x556e980",
                                "--stop-address=0x556e9d8", "artifacts/node/94/hl-node"])
    # Retain only the CIE and selected FDE from a complete GNU frame read.
    frame_command = [args.objdump, "--dwarf=frames", "artifacts/node/94/hl-node"]
    frame_process = subprocess.Popen(frame_command, cwd=ROOT, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True)
    selected, capture = [], False
    for line in frame_process.stdout:
        if line.startswith("00000000 ") or line.startswith("002d110c "):
            capture = True
        if capture:
            selected.append(line)
        if not line.strip():
            capture = False
    error = frame_process.stderr.read()
    require(frame_process.wait() == 0 and not error, "GNU frame read failed")
    frames = "".join(selected)
    require("pc=000000000556e980..000000000556e9d8" in frames, "GNU FDE extent changed")
    (output / "target.frames.txt").write_text(frames.rstrip("\n") + "\n")
    commands.append({"label": "target-frames", "argv": frame_command, "cwd": "/repo",
                     "returncode": 0, "retention": "CIE 0 and FDE 0x2d110c only"})

    def compile_run(label, lib_source, optimization):
        directory = build / label
        directory.mkdir(exist_ok=True)
        library = directory / "libnode94_bsr_ladder.rlib"
        client = directory / "client"
        flags = ["--edition=2021", "-Dwarnings", "-C", f"opt-level={optimization}",
                 "-C", "overflow-checks=yes", "-C", "panic=abort", "-C", "debuginfo=0",
                 "-C", "codegen-units=1", "--remap-path-prefix", f"{ROOT}=/repo"]
        run(label + "-library", compiler + [lib_source, "--crate-name", "node94_bsr_ladder",
                                           "--crate-type", "rlib", *flags, "-o", library])
        run(label + "-client", compiler + [SOURCE / "input_only_driver.rs", *flags,
                                          "--extern", f"node94_bsr_ladder={library}", "-o", client])
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
    for name, (before, after) in MUTATIONS.items():
        require(original.count(before) == 1, f"{name}: mutation is not unique")
        mutant = build / f"{name}.rs"
        mutant.write_text(original.replace(before, after))
        controls[name] = compile_run("mutant-" + name, mutant, 3)
        controls[name]["source_change"] = {"before": before, "after": after}
        controls[name]["source_sha256"] = oracle.digest(mutant)
        require(controls[name]["mismatches"] > 0, f"{name}: control was not detected")

    # Repeat mismatch counting against a deliberately corrupted expectation.
    # This exercises the real native-output comparison independently of mutants.
    altered = expected.splitlines()
    altered[0] = b"5"  # Frozen row zero is 6; outside the actual expectation file.
    actual = streams["opt3-build1-run.stdout"].splitlines()
    comparator_mismatches = sum(a != b for a, b in zip(actual, altered))
    require(comparator_mismatches == 1, "Corrupted expectation did not produce exactly one mismatch")
    report = {
        "target_sha256": frozen["static_facts"]["target_sha256"],
        "source_base_commit": "56c0ec672bd8fdcfaa80f2db700a61e6240b3663",
        "platform": platform.platform(), "python_version": sys.version.split()[0],
        "rustc": version, "coverage": coverage, "builds": results, "compiled_controls": controls,
        "corrupted_expectation_mismatches": comparator_mismatches,
        "source_sha256": {name: oracle.digest(SOURCE / name)
                          for name in ("lib.rs", "input_only_driver.rs")},
        "oracle_freeze_sha256": oracle.digest(FROZEN / "ORACLE-FREEZE.json"),
        "validator_sha256": oracle.digest(__file__),
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
    for record in stream_records:
        # Remove the older per-stream packaging, if reproducing in place.
        (output / f"{record['label']}.{record['stream']}.gz").unlink(missing_ok=True)
    print(json.dumps({"cases_per_build": coverage["cases"], "builds": len(results),
                      "compiled_controls": {key: value["mismatches"] for key, value in controls.items()},
                      "results": clean(str(output / "results.json"))}, indent=2))


if __name__ == "__main__":
    main()
