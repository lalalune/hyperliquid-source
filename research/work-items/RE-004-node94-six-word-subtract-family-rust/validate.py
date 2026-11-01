"""Recheck the frozen static oracle, then build/run only newly authored Rust."""
import argparse
import atexit
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
SOURCE = ROOT / "src/node94-six-word-subtract-family"
FROZEN = PACKET / "frozen"
RUSTC_DEFAULT = "/opt/homebrew/opt/rustup/bin/rustc"
MUTATIONS = {'reverse_subtraction': [('a[i].overflowing_sub(b[i])', 'b[i].overflowing_sub(a[i])')], 'discard_limb_borrow': [('difference.overflowing_sub(u64::from(borrow))', 'difference.overflowing_sub(u64::from(borrow) & 0)')], 'conjoin_borrows': [('borrow = first || second;', 'borrow = first && second;')], 'signed_limb_borrow': [('let (difference, first) = a[i].overflowing_sub(b[i]);', 'let difference = a[i].wrapping_sub(b[i]);\n        let first = (a[i] as i64) < (b[i] as i64);')], 'always_correct': [('let mask = 0_u64.wrapping_sub(u64::from(borrow));', 'let mask = 0_u64.wrapping_sub(u64::from(borrow)) | u64::MAX;')], 'never_correct': [('let mask = 0_u64.wrapping_sub(u64::from(borrow));', 'let mask = 0_u64.wrapping_sub(u64::from(borrow)) & 0;')], 'truncate_mask32': [('let mask = 0_u64.wrapping_sub(u64::from(borrow));', 'let mask = u64::from((0_u64.wrapping_sub(u64::from(borrow))) as u32);')], 'discard_correction_carry': [('+ u128::from(masked[i]) + carry;', '+ u128::from(masked[i]) + (carry & 0);')], 'retain_final_carry': [('    for (i, value) in result.iter().enumerate() {', '    result[5] = result[5].wrapping_add(carry as u64);\n    for (i, value) in result.iter().enumerate() {')], 'early_store_before_b': [('    let b = words(image, b_start);', '    image[output..output+48].fill(0);\n    let b = words(image, b_start);')], 'early_store_before_m': [('    let correction = words(image, m_start);', '    image[output..output+48].fill(0);\n    let correction = words(image, m_start);')], 'pair_low_first': [('    if member == Member::HighFirstPair {\n        let high_a = words(image, a_start + 48);\n        execute(image, high_a, b_start + 48, m_start, output + 48);\n    }', '    if member == Member::HighFirstPair {\n        let low_a = words(image, a_start);\n        let mut low = execute(image, low_a, b_start, m_start, output);\n        let high_a = words(image, a_start + 48);\n        execute(image, high_a, b_start + 48, m_start, output + 48);\n        low.callee = saved;\n        return Some(low);\n    }')], 'pair_early_low_a': [('    if member == Member::HighFirstPair {\n        let high_a = words(image, a_start + 48);\n        execute(image, high_a, b_start + 48, m_start, output + 48);\n    }', '    let early_a = words(image, a_start);\n    if member == Member::HighFirstPair {\n        let high_a = words(image, a_start + 48);\n        execute(image, high_a, b_start + 48, m_start, output + 48);\n    }'), ('        words(image, a_start)\n    };', '        if member == Member::HighFirstPair { early_a } else { words(image, a_start) }\n    };')], 'pair_early_low_b': [('    output: usize,\n) -> Registers {', '    output: usize,\n    early: Option<[u64; 6]>,\n) -> Registers {'), ('let b = words(image, b_start);', 'let b = early.unwrap_or_else(|| words(image, b_start));'), ('    if member == Member::HighFirstPair {\n        let high_a = words(image, a_start + 48);\n        execute(image, high_a, b_start + 48, m_start, output + 48);\n    }', '    let early_b = words(image, b_start);\n    if member == Member::HighFirstPair {\n        let high_a = words(image, a_start + 48);\n        execute(image, high_a, b_start + 48, m_start, output + 48, None);\n    }'), ('execute(image, a, b_start, m_start, output);', 'execute(image, a, b_start, m_start, output, if member == Member::HighFirstPair { Some(early_b) } else { None });')], 'pair_early_m': [('    output: usize,\n) -> Registers {', '    output: usize,\n    early: Option<[u64; 6]>,\n) -> Registers {'), ('let correction = words(image, m_start);', 'let correction = early.unwrap_or_else(|| words(image, m_start));'), ('    if member == Member::HighFirstPair {\n        let high_a = words(image, a_start + 48);\n        execute(image, high_a, b_start + 48, m_start, output + 48);\n    }', '    let early_m = words(image, m_start);\n    if member == Member::HighFirstPair {\n        let high_a = words(image, a_start + 48);\n        execute(image, high_a, b_start + 48, m_start, output + 48, None);\n    }'), ('execute(image, a, b_start, m_start, output);', 'execute(image, a, b_start, m_start, output, if member == Member::HighFirstPair { Some(early_m) } else { None });')], 'pair_wrong_high_destination': [('execute(image, high_a, b_start + 48, m_start, output + 48);', 'execute(image, high_a, b_start + 48, m_start, output);')], 'raw_restores_callee': [('if matches!(member, Member::Saved | Member::HighFirstPair) {', 'if true {')], 'saved_does_not_restore': [('if matches!(member, Member::Saved | Member::HighFirstPair) {', 'if false {')], 'prepared_wrong_high_word': [('        prepared\n    } else {', '        let mut wrong = prepared; wrong[5] = wrong[4]; wrong\n    } else {')], 'prepared_requires_a': [('let a_start = if member == Member::Prepared {\n        0', 'let a_start = if member == Member::Prepared {\n        span(base, image.len(), a_address, width)?')], 'rax_result_not_masked': [('rax: masked[2]', 'rax: result[2]')], 'rsi_result_not_masked': [('rsi: masked[5]', 'rsi: result[5]')], 'raw_r12_masked_not_result': [('masked[3], masked[4], result[4], result[5], masked[0], masked[1]', 'masked[3], masked[4], masked[4], result[5], masked[0], masked[1]')], 'raw_r13_masked_not_result': [('masked[3], masked[4], result[4], result[5], masked[0], masked[1]', 'masked[3], masked[4], result[4], masked[5], masked[0], masked[1]')], 'raw_r14_result_not_masked': [('masked[3], masked[4], result[4], result[5], masked[0], masked[1]', 'masked[3], masked[4], result[4], result[5], result[0], masked[1]')], 'refusal_changes_image': [('        return None;', '        image.fill(0);\n        return None;')]}

def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rustc", default=RUSTC_DEFAULT)
    parser.add_argument("--objdump", default="/opt/homebrew/opt/binutils/bin/objdump")
    parser.add_argument("--output", type=Path, default=ROOT / "work/node94-six-word-subtract-family/recheck")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    build = ROOT / "work/node94-six-word-subtract-family/build"
    build.mkdir(parents=True, exist_ok=True)
    commands = []
    streams = {}

    def retain():
        write_json(output / "commands.json", commands)
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
                    elif len(raw) == len(basis):
                        delta = bytes(a ^ b for a, b in zip(raw, basis))
                        record["xor_base64"] = base64.b64encode(delta).decode("ascii")
                        record["basis_label"] = basis_label
                    else:
                        record["base64"] = base64.b64encode(raw).decode("ascii")
                else:
                    record["base64"] = base64.b64encode(raw).decode("ascii")
                stream_records.append(record)
        archive = json.dumps({"encoding": "base64-or-xor-base64", "streams": stream_records},
                             indent=2).encode() + b"\n"
        (output / "raw-streams.json.gz").write_bytes(gzip.compress(archive, mtime=0))

    atexit.register(retain)

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
    for filename, key in (("inputs.bin", "inputs_sha256"), ("expected.bin", "expected_sha256")):
        raw = gzip.decompress((FROZEN / (filename + ".gz")).read_bytes())
        require(hashlib.sha256(raw).hexdigest() == frozen[key], f"Frozen {filename} changed")
        archived[filename] = raw
    write_json(output / "static-controls.json", check_static())
    inputs, expected, coverage = oracle.fixture_bytes()
    require(inputs == archived["inputs.bin"], "Input regeneration changed")
    require(expected == archived["expected.bin"], "Arithmetic oracle regeneration changed")
    require(json.loads(json.dumps(coverage)) == frozen["coverage"], "Coverage changed")
    input_path = build / "inputs.bin"
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
        label = f"body-{index}-disassembly"
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
        library = directory / "libnode94_six_word_subtract_family.rlib"
        client = directory / "client"
        flags = ["--edition=2021", "-Dwarnings", "-C", f"opt-level={optimization}",
                 "-C", "overflow-checks=yes", "-C", "panic=abort", "-C", "debuginfo=0",
                 "-C", "codegen-units=1", "--remap-path-prefix", f"{ROOT}=/repo"]
        run(label + "-library", compiler + [lib_source, "--crate-name", "node94_six_word_subtract_family",
                                           "--crate-type", "rlib", *flags, "-o", library])
        run(label + "-client", compiler + [SOURCE / "input_only_driver.rs", *flags,
                                          "--extern", f"node94_six_word_subtract_family={library}", "-o", client])
        actual = run(label + "-run", [client, input_path])
        require(len(actual) == len(expected), f"{label}: incomplete native output")
        truth = [expected[i:i+oracle.OUTPUT_SIZE] for i in range(0,len(expected),oracle.OUTPUT_SIZE)]
        lines = [actual[i:i+oracle.OUTPUT_SIZE] for i in range(0,len(actual),oracle.OUTPUT_SIZE)]
        mismatches = [i for i,(a,b) in enumerate(zip(lines,truth)) if a != b]
        admitted = [i for i in mismatches if truth[i][:8] == (1).to_bytes(8,'little')]
        record = {
            "cases": len(truth), "mismatches": len(mismatches), "admitted_mismatches": len(admitted),
            "library_sha256": oracle.digest(library), "client_sha256": oracle.digest(client),
            "output_sha256": hashlib.sha256(actual).hexdigest(),
            "first_mismatches": [{"row_zero_based": i,
                                   "input_hex": inputs[i*oracle.INPUT_SIZE:(i+1)*oracle.INPUT_SIZE].hex(),
                                   "expected_hex": truth[i].hex(), "actual_hex": lines[i].hex()}
                                  for i in mismatches[:3]],
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

    malformed = build / "malformed.bin"
    malformed.write_bytes(b"partial")
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
        if controls[name]["mismatches"] == 0:
            write_json(output / "ineffective-control.json", {"name": name, "result": controls[name]})
            failure = {"commands": commands, "streams": [
                {"key": key, "sha256": hashlib.sha256(raw).hexdigest(),
                 "base64": base64.b64encode(raw).decode("ascii")}
                for key, raw in streams.items()]}
            (output / "failure-streams.json.gz").write_bytes(gzip.compress(
                (json.dumps(failure) + "\n").encode(), mtime=0))
        require(controls[name]["mismatches"] > 0, f"{name}: control was not detected")

    # Repeat mismatch counting against a deliberately corrupted expectation.
    # This exercises the real native-output comparison independently of mutants.
    altered = bytearray(expected)
    altered[0] ^= 1
    actual = streams["opt3-build1-run.stdout"]
    comparator_mismatches = sum(actual[i:i+oracle.OUTPUT_SIZE] != altered[i:i+oracle.OUTPUT_SIZE]
                                for i in range(0,len(actual),oracle.OUTPUT_SIZE))
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
    print(json.dumps({"cases_per_build": coverage["cases"], "builds": len(results),
                      "compiled_controls": {key: value["mismatches"] for key, value in controls.items()},
                      "results": clean(str(output / "results.json"))}, indent=2))


if __name__ == "__main__":
    main()
