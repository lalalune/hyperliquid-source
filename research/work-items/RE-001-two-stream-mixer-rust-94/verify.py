#!/usr/bin/env python3
"""Static checks plus execution of newly authored Rust only, never the target."""

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess

from oracle import check as check_fixtures
from static_evidence import HERE, ROOT, TARGET, START, END, sections, view, inspect, collect, require

SOURCE = ROOT / "src/node94-two-stream-mixer"
FIXTURES = HERE / "fixtures"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def check_archive():
    result = json.loads((HERE / "native/result.json").read_text())
    expected = {f"opt{r['opt']}-build{r['build']}.tsv": r["output_sha256"] for r in result["runs"]}
    expected.update({f"mutants-{m['name']}.tsv": m["output_sha256"] for m in result["compiled_mutants"]})
    raw = (HERE / "native/raw-streams.json.gz").read_bytes()
    require(raw[4:8] == bytes(4), "archive timestamp must be zero")
    streams = json.loads(gzip.decompress(raw))["streams"]
    require(len(streams) == len(expected) and {s["name"] for s in streams} == set(expected), "archive stream labels/count")
    for stream in streams:
        data = stream["text"].encode("ascii")
        require(len(data) == stream["bytes"], "archive stream length")
        require(sha(data) == stream["sha256"] == expected[stream["name"]], "archive stream hash")
    print(f"PASS retained archive: {len(streams)} lossless native output streams")


def compare(actual, expected):
    def rows(raw):
        lines = raw.decode("ascii").splitlines()
        parsed = [line.split("\t") for line in lines]
        require(all(len(row) == 2 and re.fullmatch(r"[0-9a-f]{16}", row[1]) for row in parsed), "output format")
        require(len({row[0] for row in parsed}) == len(parsed), "duplicate output ID")
        return parsed
    got, want = rows(actual), rows(expected)
    require([row[0] for row in got] == [row[0] for row in want], "output IDs/order/count")
    return [{"id": g[0], "actual": g[1], "expected": w[1]} for g, w in zip(got, want) if g != w]


def static_controls(data):
    secs = sections(data)
    sec = {row["name"]: row for row in secs}
    record = inspect(data)
    cases = [("whole-target-authentication", 0, "target SHA-256", True)]
    # These go below the whole-target digest gate to exercise local witnesses.
    for label, offset in (("seed-a", 1), ("seed-b", 4), ("mask-bit63", 15),
                          ("zero-branch", 19), ("length-residue", 23),
                          ("unsigned-meeting-guard", 39), ("forward-high", 44),
                          ("backward-high", 49), ("multiply-a", 55),
                          ("forward-low", 61), ("backward-low", 66),
                          ("multiply-b", 75), ("high-limb-b", 79),
                          ("high-limb-a", 82), ("forward-step", 88),
                          ("backward-step", 92), ("loop-branch", 93),
                          ("return-xor", 95), ("return", 101)):
        cases.append((label, view(data, secs, START + offset, 1)[1], "selected body", False))
    cases.extend([
        ("padding", view(data, secs, END, 1)[1], "padding", False),
        ("cie-encoding", sec[".eh_frame"]["offset"] + 15, "CIE", False),
        ("fde-range", sec[".eh_frame"]["offset"] + 0x20BF4 + 12, "FDE", False),
        ("slot-value", int(record["slot"]["file_offset"], 16), "zero-in-file relocation slot contents", False),
    ])
    rel = int(record["relocation"]["file_offset"], 16)
    for label, offset in (("relocation-slot", 0), ("relocation-type", 8),
                          ("relocation-symbol", 12), ("relocation-addend", 16)):
        cases.append((label, rel + offset, "R_X86_64_RELATIVE naming slot", False))
    results = []
    for label, offset, message, authenticate in cases:
        copy = bytearray(data)
        copy[offset] ^= 1
        try:
            inspect(copy, authenticate=authenticate)
        except ValueError as exc:
            require(str(exc) == message, f"unexpected rejection for {label}: {exc}")
            results.append({"name": label, "rejected_by": str(exc)})
        else:
            raise ValueError(f"static corruption survived: {label}")
    return results


MUTANTS = {
    "discard-high-a": ("a = product_a as u64 ^ (product_a >> 64) as u64;", "a = product_a as u64;"),
    "discard-high-b": ("b = product_b as u64 ^ (product_b >> 64) as u64;", "b = product_b as u64;"),
    "seed-order": ("let mut a = seed_a;\n    let mut b = seed_b;", "let mut a = seed_b;\n    let mut b = seed_a;"),
    "big-endian": ("u64::from_le_bytes(bytes)", "u64::from_be_bytes(bytes)"),
    "drop-length-residue": ("let mut back = input.len();", "let mut back = input.len() & !15;"),
    "drop-overlap-round": ("while front < back && back >= 16", "while back >= 16 && front + 16 <= back - 16"),
    "omit-meeting-guard": ("while front < back && back >= 16", "while back >= 16"),
    "omit-key-a": ("word(back - 8) ^ key", "word(back - 8)"),
    "omit-key-b": ("word(back - 16) ^ key", "word(back - 16)"),
    "forward-lane-order": ("u128::from(a ^ word(front + 8))", "u128::from(a ^ word(front))"),
    "backward-lane-order": ("word(back - 8) ^ key", "word(back - 16) ^ key"),
    "return-a-only": ("    a ^ b\n}", "    a\n}"),
}


def build(rustc, source, directory, opt, commands):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "lib.rs").write_text(source)
    shutil.copyfile(SOURCE / "client.rs", directory / "client.rs")
    flags = ["--edition=2024", "-C", f"opt-level={opt}", "-C", "codegen-units=1",
             "-C", "overflow-checks=yes", "-C", "panic=abort", "-C", "debuginfo=0",
             "--remap-path-prefix", f"{directory}=/component", "-D", "warnings"]
    calls = [
        [rustc, "+1.94.1", "--crate-name", "node94_two_stream_mixer", "--crate-type=rlib", "lib.rs", *flags, "-o", "libnode94_two_stream_mixer.rlib"],
        [rustc, "+1.94.1", "--crate-name", "two_stream_input_client", "client.rs", *flags,
         "--extern", "node94_two_stream_mixer=libnode94_two_stream_mixer.rlib", "-o", "client"],
    ]
    for command in calls:
        completed = subprocess.run(command, cwd=directory, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        commands.append({"cwd": str(directory.relative_to(ROOT)), "argv": command,
                         "exit": completed.returncode, "output": completed.stdout})
        require(completed.returncode == 0, f"Rust build failed: {completed.stdout}")
    return {name: sha((directory / name).read_bytes()) for name in ("libnode94_two_stream_mixer.rlib", "client")}


def run(out, rustc):
    require(not out.exists(), "use a fresh output directory")
    out.mkdir(parents=True)
    check_archive()
    freeze = check_fixtures(FIXTURES)
    collect(out / "static")
    for file in (HERE / "static").iterdir():
        require((out / "static" / file.name).read_bytes() == file.read_bytes(), f"static export drift: {file.name}")
    controls = static_controls(TARGET.read_bytes())
    inputs, expected = (FIXTURES / "inputs.tsv").read_bytes(), (FIXTURES / "expected.tsv").read_bytes()
    source = (SOURCE / "lib.rs").read_text()
    commands, builds, runs, mutants = [], {}, [], []
    for opt in (0, 3):
        hashes = []
        for repeat in (1, 2):
            directory = out / f"opt{opt}-build{repeat}"
            hashes.append(build(rustc, source, directory, opt, commands))
            actual = subprocess.check_output([str(directory / "client")], input=inputs, cwd=directory)
            (directory / "actual.tsv").write_bytes(actual)
            require(compare(actual, expected) == [], f"native disagreement: opt{opt}, build{repeat}")
            runs.append({"opt": opt, "build": repeat, "cases": freeze["cases"],
                         "mismatches": 0, "output_sha256": sha(actual)})
        require(hashes[0] == hashes[1], f"nonreproducible artifacts: opt{opt}")
        builds[f"opt{opt}"] = hashes[0]
    for label, (old, new) in MUTANTS.items():
        require(source.count(old) == 1, f"mutation anchor: {label}")
        directory = out / "mutants" / label
        build(rustc, source.replace(old, new), directory, 3, commands)
        actual = subprocess.check_output([str(directory / "client")], input=inputs, cwd=directory)
        (directory / "actual.tsv").write_bytes(actual)
        mismatches = compare(actual, expected)
        require(mismatches, f"compiled mutant survived: {label}")
        mutants.append({"name": label, "cases": freeze["cases"], "mismatches": len(mismatches),
                        "first_witness": mismatches[0], "output_sha256": sha(actual)})
    comparator = []
    lines = expected.splitlines(keepends=True)
    changed = lines[0].split(b"\t")[0] + b"\t0000000000000000\n"
    for label, corrupted in (("value", changed + b"".join(lines[1:])),
                             ("omitted-row", b"".join(lines[:-1])),
                             ("duplicate-row", expected + lines[0]),
                             ("reordered-rows", lines[1] + lines[0] + b"".join(lines[2:]))):
        try:
            require(compare(corrupted, expected) == [], "output values")
        except ValueError as exc:
            comparator.append({"name": label, "rejected_by": str(exc)})
        else:
            raise ValueError(f"comparator corruption survived: {label}")
    compiler = subprocess.check_output([rustc, "+1.94.1", "-vV"], text=True)
    result = {"target_sha256": freeze["target_sha256"], "freeze": freeze, "compiler": compiler,
              "platform": platform.platform(), "python": platform.python_version(),
              "source_sha256": {name: sha((SOURCE / name).read_bytes()) for name in
                                ("lib.rs", "client.rs", "Cargo.toml", "Cargo.lock", "rust-toolchain.toml")},
              "build_hashes": builds, "reproducible_two_builds_per_opt": True,
              "runs": runs, "compiled_mutants": mutants, "static_controls": controls,
              "comparator_controls": comparator, "captured_execution": False,
              "instruction_emulation": False, "target_native_differential": False}
    (out / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
    (out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(f"PASS: {freeze['cases']} fixtures x 4 native runs; {len(mutants)} compiled mutants killed; {len(controls)} static and {len(comparator)} comparator controls; identical repeated build hashes")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--check-archive", action="store_true", help="Verify retained raw output packaging without rebuilding")
    parser.add_argument("--rustc", default=os.environ.get("RUSTC", "/opt/homebrew/opt/rustup/bin/rustc"))
    args = parser.parse_args()
    if args.check_archive:
        check_archive()
    elif args.out:
        run(args.out.resolve(), args.rustc)
    else:
        parser.error("provide --out or --check-archive")
