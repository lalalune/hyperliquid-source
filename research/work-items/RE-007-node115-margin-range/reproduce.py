#!/usr/bin/env python3
"""Build only authored Rust; compare input-only runs with frozen linear results."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
SOURCE = ROOT / "src/node115-margin-range"
SOURCE_FILES = {"Cargo.toml", "Cargo.lock", "README.md", "src/lib.rs", "src/main.rs"}


def sha(value):
    return hashlib.sha256(value).hexdigest()


def parse_output(value, ids):
    if not value.isascii() or b"\r" in value or not value.endswith(b"\n"):
        raise ValueError("noncanonical output transport")
    rows = value[:-1].split(b"\n")
    if len(rows) != len(ids):
        raise ValueError("output row count")

    def number(text, maximum=(1 << 64) - 1):
        if not re.fullmatch(rb"0|[1-9][0-9]*", text) or int(text) > maximum:
            raise ValueError("noncanonical output integer")
        return int(text)

    for identifier, line in zip(ids, rows):
        fields = line.split(b"\t")
        if fields[0] != identifier:
            raise ValueError("output identifier/order")
        if len(fields) == 3 and fields[1] == b"err" and fields[2] in [b"bounds", b"order"]:
            continue
        if len(fields) != 12 or fields[1] != b"ok":
            raise ValueError("output field/tag")
        count, first, second = [number(x) for x in fields[2:5]]
        if count != first + second:
            raise ValueError("output segment count")
        if count:
            for text in fields[5:9]:
                number(text)
            number(fields[9], 255)
        elif fields[5:10] != [b"-"] * 5:
            raise ValueError("empty output has selected fields")
        for text, length in zip(fields[10:], [first, second]):
            if not length:
                if text != b"-":
                    raise ValueError("noncanonical empty segment")
            elif len(text.split(b",")) != length or any(
                    not re.fullmatch(rb"[0-9a-f]{80}", row) for row in text.split(b",")):
                raise ValueError("invalid segment encoding")
    return rows


def compare(actual, expected, ids):
    actual_rows = parse_output(actual, ids)
    expected_rows = parse_output(expected, ids)
    differences = sum(a != b for a, b in zip(actual_rows, expected_rows))
    if (differences == 0) != (actual == expected):
        raise ValueError("raw-byte comparator inconsistency")
    return differences


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cargo", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.is_relative_to(ROOT) or out.exists():
        raise ValueError("out must be new and outside the repository")
    # Cargo must not discover inherited configuration outside the copied crate.
    for ancestor in (out.parent, *out.parent.parents):
        for relative in [".cargo/config", ".cargo/config.toml"]:
            if (ancestor / relative).exists():
                raise ValueError(f"ancestor Cargo configuration: {ancestor / relative}")
    cargo = args.cargo.resolve(strict=True)
    pins = json.loads((PACKET / "validation/SOURCE-PINS.json").read_text())
    if set(pins) != SOURCE_FILES:
        raise ValueError("source pin allowlist")
    for relative, digest in pins.items():
        if sha((SOURCE / relative).read_bytes()) != digest:
            raise ValueError(f"source pin mismatch: {relative}")
    corpus = json.loads((PACKET / "corpus/CORPUS.json").read_text())
    inputs = gzip.decompress((PACKET / "corpus/inputs.tsv.gz").read_bytes())
    expected = gzip.decompress((PACKET / "corpus/expected.tsv.gz").read_bytes())
    if sha(inputs) != corpus["files"]["inputs.tsv"] or sha(expected) != corpus["files"]["expected.tsv"]:
        raise ValueError("corpus pin mismatch")
    ids = [line.split(b"\t", 1)[0] for line in inputs.splitlines()]
    if len(ids) != corpus["cases"] or len(set(ids)) != len(ids):
        raise ValueError("invalid corpus identifiers")
    mutations = json.loads((PACKET / "validation/MUTATIONS.json").read_text())
    seen_mutations = set()
    for mutation in mutations:
        if (not re.fullmatch(r"M[0-9]{2}", mutation["id"])
                or mutation["id"] in seen_mutations or mutation["file"] != "src/lib.rs"):
            raise ValueError("mutation path/id allowlist")
        seen_mutations.add(mutation["id"])
    out.mkdir()
    (out / "empty").mkdir()
    (out / "cargo-home").mkdir()
    env = {"PATH": str(cargo.parent) + os.pathsep + "/usr/bin:/bin",
           "CARGO_HOME": str(out / "cargo-home"), "LC_ALL": "C"}
    records = []
    results = {"scope": "authored host value implementation, not target runtime equivalence",
               "cases": len(ids), "commands": records, "variants": []}

    def save():
        (out / "RESULTS.json").write_text(json.dumps(results, indent=2) + "\n")

    def run(name, argv, data=None, environment=None):
        failure = None
        kind = "completed"
        try:
            proc = subprocess.run(argv, input=data, cwd=out / "empty",
                                  env=environment if environment is not None else {},
                                  capture_output=True, timeout=120)
        except subprocess.TimeoutExpired as error:
            failure = error
            kind = "timeout-partial-streams"
            proc = subprocess.CompletedProcess(argv, None, error.stdout or b"", error.stderr or b"")
        except OSError as error:
            failure = error
            kind = "spawn-error-no-child-streams"
            proc = subprocess.CompletedProcess(argv, None, b"", b"")
        index = f"{len(records):03}-{name}"
        for stream, value in [("stdout", proc.stdout), ("stderr", proc.stderr)]:
            (out / f"{index}.{stream}.gz").write_bytes(gzip.compress(value, mtime=0))
        records.append({"name": name,
                        "argv": [str(x).replace(str(out), "<OUT>") for x in argv],
                        "cwd": "<OUT>/empty", "input_sha256": sha(data) if data is not None else None,
                        "exit_code": proc.returncode, "termination": kind,
                        "error_type": type(failure).__name__ if failure else None,
                        "stdout_sha256": sha(proc.stdout), "stdout_bytes": len(proc.stdout),
                        "stderr_sha256": sha(proc.stderr), "stderr_bytes": len(proc.stderr),
                        "stdout": f"{index}.stdout.gz", "stderr": f"{index}.stderr.gz"})
        save()
        if failure:
            raise failure
        return proc

    def build(name, mutation=None, release=True):
        directory = out / name
        directory.mkdir()
        for relative in pins:
            target = directory / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((SOURCE / relative).read_bytes())
        if mutation:
            target = directory / mutation["file"]
            text = target.read_text()
            if text.count(mutation["before"]) != 1:
                raise ValueError("mutation anchor is not unique: " + mutation["id"])
            target.write_text(text.replace(mutation["before"], mutation["after"]))
        argv = [str(cargo), "build", "--offline", "--locked", "--manifest-path",
                str(directory / "Cargo.toml"), "--target-dir", str(directory / "target")]
        if release:
            argv.append("--release")
        built = run(name + "-build", argv, environment=env)
        if built.returncode:
            raise ValueError(name + " build failed; this is not a semantic result")
        binary = directory / "target" / ("release" if release else "debug") / "margin-range"
        proc = run(name + "-driver", [str(binary)], inputs)
        if proc.returncode or proc.stderr:
            raise ValueError(name + " abnormal or incomplete run")
        mismatches = compare(proc.stdout, expected, ids)
        result = {"name": name, "source_mutation": mutation["id"] if mutation else None,
                  "binary_sha256": sha(binary.read_bytes()), "mismatches": mismatches,
                  "qualified_normal_complete_run": True}
        results["variants"].append(result)
        save()
        if (mismatches == 0) != (mutation is None):
            raise ValueError(name + " unexpected comparison result")
        return binary, result

    run("cargo-version", [str(cargo), "--version"], environment=env)
    run("rustc-version", [str(cargo.parent / "rustc"), "--version"], environment=env)
    build("debug", release=False)
    baseline, first = build("release")
    _, repeat = build("release-repeat")
    results["repeat_binary_equal"] = first["binary_sha256"] == repeat["binary_sha256"]
    if not results["repeat_binary_equal"]:
        raise ValueError("repeat release binary differs")
    for mutation in mutations:
        build(mutation["id"], mutation)
    # Exact comparison corruption controls are separate from compiled semantic variants.
    damaged = [expected[:-1], expected + b"\n", b"!" + expected[1:], b"",
               expected.replace(b"\n", b"\r\n"),
               expected.replace(b"\tok\t0\t", b"\tok\tnan\t", 1),
               expected.replace(b"\tok\t0\t", b"\tok\t00\t", 1)]
    rejected = 0
    for value in damaged:
        try:
            compare(value, expected, ids)
        except ValueError:
            rejected += 1
    # M01 has a real selected row; change its offset while preserving syntax.
    changed = expected.replace(b"M01\tok\t1\t1\t0\t0\t0\t9\t2\t0\t",
                               b"M01\tok\t1\t1\t0\t0\t0\t9\t3\t0\t", 1)
    results["comparator_controls"] = {"valid_equal": compare(expected, expected, ids) == 0,
                                       "rejected_corruptions": rejected,
                                       "valid_value_change_differences": compare(changed, expected, ids)}
    if rejected != len(damaged) or results["comparator_controls"]["valid_value_change_differences"] != 1:
        raise ValueError("production comparator controls failed")
    malformed = [b"x\t0\t0\t0\t-", b"x\t0\t0\t0\t-\r\n", b"\xff\n",
                 b"x\t00\t0\t0\t-\n", b"x\t0\t0\t18446744073709551616\t-\n",
                 b"x\t0\t0\t0\t-\textra\n", b"x\t0\t0\t0\tff\n",
                 b"x\t0\t0\t0\t-\nx\t0\t0\t0\t-\n",
                 b"x\t0\t0\t0\t-\nbad\n", b"x\t0\t0\t0\t" + b"AB" * 40 + b"\n",
                 b"x\t-1\t0\t0\t-\n", b"x\t0\t+0\t0\t-\n",
                 b"x\t0\t0\t0\t" + b",".join([b"00" * 40] * 4097) + b"\n",
                 b"x" * (16 * 1024 * 1024 + 1)]
    results["transport"] = []
    for i, value in enumerate(malformed):
        proc = run(f"bad-{i}", [str(baseline)], value)
        okay = proc.returncode == 2 and proc.stdout == b""
        results["transport"].append({"case": i, "passed": okay})
        save()
        if not okay:
            raise ValueError(f"malformed input control failed: {i}")
    extra = run("extra-argument", [str(baseline), "unexpected"], b"")
    if extra.returncode != 2 or extra.stdout:
        raise ValueError("extra-argument control failed")
    empty = run("empty-input", [str(baseline)], b"")
    if empty.returncode or empty.stdout or empty.stderr:
        raise ValueError("empty input control failed")
    results["passed"] = True
    save()
    print(json.dumps({"passed": True, "cases": len(ids), "variants": results["variants"],
                      "commands": len(records)}))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"reproduce: {error}", file=sys.stderr)
        sys.exit(1)
