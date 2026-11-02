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
SOURCE = ROOT / "src/node94-calendar-constructor"
FROZEN = PACKET / "frozen"
RUSTC_DEFAULT = "/opt/homebrew/opt/rustup/bin/rustc"
MUTATIONS = {
    'upper_dword_input': [('input as u32 as i32', '(input >> 32) as u32 as i32')],
    'epoch_one_early': [('day.checked_add(365)', 'day.checked_add(364)')],
    'epoch_one_late': [('day.checked_add(365)', 'day.checked_add(366)')],
    'truncate_negative_cycle': [('.div_euclid(146_097)', ' / 146_097')],
    'cycle_one_day_short': [('.div_euclid(146_097)', '.div_euclid(146_096)'), ('.rem_euclid(146_097)', '.rem_euclid(146_096)')],
    'ignore_century_exception': [('- (year + 99) / 100', '- (year + 99) / 100 * 0')],
    'omit_four_century_restore': [('+ (year + 399) / 400', '+ (year + 399) / 400 * 0')],
    'inclusive_year_correction': [('if residual < leap_prefix(year_in_cycle)', 'if year_in_cycle > 0 && residual <= leap_prefix(year_in_cycle)')],
    'zero_based_ordinal': [('leap_prefix(year_in_cycle) + 1;', 'leap_prefix(year_in_cycle) + 0;')],
    'exclude_first_year': [('-262_143..=262_142', '-262_142..=262_142')],
    'include_extra_last_year': [('-262_143..=262_142', '-262_143..=262_143')],
    'weekday_one_late': [('leap_prefix(year_in_cycle) + 3) % 7', 'leap_prefix(year_in_cycle) + 4) % 7')],
    'invert_leap_flag': [('if leap { 0 } else { 8 }', 'if leap { 8 } else { 0 }')],
    'year_shift_twelve': [('(year as u32) << 13', '(year as u32) << 12')],
    'sign_extend_rax': [('u64::from(packed)', 'packed as i32 as i64 as u64')],
    'truncate_saved_rax': [('rcx: entry_rax,', 'rcx: u64::from(entry_rax as u32),')],
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
    parser.add_argument("--output", type=Path, default=ROOT / "work/node94-calendar-constructor/recheck")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build = ROOT / "work/node94-calendar-constructor/build"
    build.mkdir(parents=True, exist_ok=True)
    commands = []
    streams = {}

    def clean(text):
        return text.replace(str(ROOT), "/repo")

    def run(label, command, expected_exit=0):
        process = subprocess.run(list(map(str, command)), cwd=ROOT,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for stream in ("stdout", "stderr"):
            streams[f"{label}.{stream}"] = getattr(process, stream)
        commands.append({"label": label, "argv": [clean(str(x)) for x in command],
                         "cwd": "/repo", "returncode": process.returncode, "expected_returncode": expected_exit,
                         "stdout_sha256": hashlib.sha256(process.stdout).hexdigest(),
                         "stderr_sha256": hashlib.sha256(process.stderr).hexdigest()})
        if process.returncode != expected_exit:
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
    require(oracle.certificates() == frozen["certificates"], "Arithmetic certificate changed")
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
    compiler_path = run("rustc-path", ["/opt/homebrew/opt/rustup/bin/rustup", "which", "--toolchain", "1.94.1", "rustc"]).decode().strip()
    compiler_hash = oracle.digest(compiler_path)
    require(compiler_hash == "b69cbcffa5e990057035d53ccc8163e8392ce784f6abb114c19ceb61528ba9f6", "Compiler file changed")
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
        library = directory / "libnode94_calendar_constructor.rlib"
        client = directory / "client"
        flags = ["--edition=2021", "-Dwarnings", "-C", f"opt-level={optimization}",
                 "-C", "overflow-checks=yes", "-C", "panic=abort", "-C", "debuginfo=0",
                 "-C", "codegen-units=1", "--remap-path-prefix", f"{ROOT}=/repo"]
        run(label + "-library", compiler + [lib_source, "--crate-name", "node94_calendar_constructor",
                                           "--crate-type", "rlib", *flags, "-o", library])
        run(label + "-client", compiler + [SOURCE / "input_only_driver.rs", *flags,
                                          "--extern", f"node94_calendar_constructor={library}", "-o", client])
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

    malformed = build / "malformed.tsv"
    malformed.write_text("0\t1\t2\n")
    bad = run("driver-malformed", [build / "opt3-build1/client", malformed], expected_exit=2)
    require(not bad, "Malformed driver input produced output")
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
        "rustc": version, "compiler_sha256": compiler_hash, "coverage": coverage, "builds": results, "compiled_controls": controls,
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
