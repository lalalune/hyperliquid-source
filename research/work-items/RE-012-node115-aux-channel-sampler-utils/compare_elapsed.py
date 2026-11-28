#!/usr/bin/env python3
"""Compare the compiled sampler's public results to the two captured split-duration projections."""
import argparse
from fractions import Fraction
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import entry_start_static as elf

NS = 1_000_000_000
U64_MAX = (1 << 64) - 1
WINDOWS = {
    0x5B2992D: "f5f1ac30799c1f90329bba228b159db851796921914c4bf7fd60aee224a8419d",
    0x5B2A18E: "b5c4fb1722a8138bd8eb2f391326b3d365813cf4885969a0b3329ecf6538a676",
}


def check_projection():
    record = json.loads((HERE / "records.json").read_text())
    data = (ROOT / record["target"]["path"]).read_bytes()
    assert hashlib.sha256(data).hexdigest() == record["target"]["sha256"]
    for call, digest in WINDOWS.items():
        assert hashlib.sha256(elf.read(data, call, 94)[1]).hexdigest() == digest
        assert elf.rip_target(data, call, 1) == 0x5C84210
        # The two sites share instructions and operands, with distinct RIP displacements.
        for delta, op_len, target in [(35, 3, 0x451210), (42, 4, 0x450170),
                                      (62, 4, 0x458D50), (74, 4, 0x459010)]:
            assert elf.rip_target(data, call + delta, op_len) == target
    assert struct.unpack("<II", elf.read(data, 0x451210, 8)[1]) == (0x43300000, 0x45300000)
    assert struct.unpack("<dd", elf.read(data, 0x450170, 16)[1]) == (2.0**52, 2.0**84)
    assert struct.unpack("<d", elf.read(data, 0x458D50, 8)[1]) == (NS,)
    assert struct.unpack("<d", elf.read(data, 0x459010, 8)[1]) == (float("inf"),)


def corpus():
    for sec in range(61):
        for millis in range(1000):
            yield sec, sec * NS + millis * 1_000_000
    # Long samples and exact neighbours of binary and decimal boundaries.
    for power in range(64):
        for near in (-1, 0, 1):
            nanos = (1 << power) + near
            yield 100 + power, nanos
    for power in range(35):
        for subsec in (0, 1, 117_999_999, 118_000_000, 118_000_001, NS - 1):
            yield 200 + power, (1 << power) * NS + subsec
    for nanos in (U64_MAX - 1, U64_MAX):
        yield 300, nanos


def observe(source, payload):
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        manifest = root / "Cargo.toml"
        manifest.write_text(
            '[package]\nname="group-sampler-observe"\nversion="0.0.0"\nedition="2024"\n'
            '[[bin]]\nname="observe"\npath="observe.rs"\n[dependencies]\nnode-runtime={path='
            + json.dumps(str(source / "src/node-runtime")) + '}\n')
        (root / "observe.rs").write_bytes((HERE / "observe.rs").read_bytes())
        return subprocess.run(["cargo", "run", "--release", "--offline", "--quiet",
                               "--manifest-path", manifest], check=True, input=payload,
                              stdout=subprocess.PIPE).stdout


def bits(value):
    return int.from_bytes(struct.pack("<d", value), "little")


def compare(source):
    rows = list(corpus())
    payload = b"".join(struct.pack("<QQ", *row) for row in rows)
    observed = observe(source, payload)
    assert len(observed) == len(rows) * 32
    groups = {}
    names = ("sample", "group_count", "running_total", "running_max")
    mismatches = dict.fromkeys(names, 0)
    examples = []
    for (group, elapsed), actual in zip(rows, struct.iter_unpack("<QQQQ", observed), strict=True):
        seconds, nanos = divmod(elapsed, NS)
        # Round division and addition independently, using exact rational intermediate values.
        fraction = float(Fraction(nanos, NS))
        sample = float(Fraction(seconds) + Fraction.from_float(fraction))
        count, total, maximum = groups.get(group, (0, 0.0, 0.0))
        groups[group] = count + 1, total + sample, max(maximum, sample)
        count, total, maximum = groups[group]
        expected = bits(sample), count, bits(total), bits(maximum)
        for name, got, want in zip(names, actual, expected, strict=True):
            mismatches[name] += got != want
        if actual[0] != expected[0] and len(examples) < 2:
            examples.append({"nanos": elapsed, "observed_bits": hex(actual[0]),
                             "expected_bits": hex(expected[0])})
    return {"samples": len(rows), "groups": len(groups), "mismatches": mismatches,
            "first_sample_differences": examples,
            "input_sha256": hashlib.sha256(payload).hexdigest(),
            "observed_sha256": hashlib.sha256(observed).hexdigest()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=ROOT)
    parser.add_argument("--expect", choices=("base", "fixed"))
    args = parser.parse_args()
    check_projection()
    result = compare(args.source_root.resolve())
    print(json.dumps(result, indent=2))
    if args.expect:
        retained = json.loads((HERE / "elapsed-results.json").read_text())
        if result != retained[args.expect]:
            raise SystemExit("observation differs from retained " + args.expect)
