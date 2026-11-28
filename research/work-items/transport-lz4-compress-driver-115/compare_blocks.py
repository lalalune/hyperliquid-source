#!/usr/bin/env python3
"""Compare the integrated compressor, the recovered driver model and public lz4_flex."""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import shutil
import subprocess
import sys
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
import byte_progress
import entry_start_static as elf
from fde_extents import eh_frame_records
import transport_lz4_compress_115 as driver

BASE = "2da45cb0a761cff6b478e40421699857d87a94df"


def qualified_drivers():
    data = driver.BINARY.read_bytes()
    if hashlib.sha256(data).hexdigest() != driver.SHA256:
        raise ValueError("wrong node 115 artifact")
    fdes = {(row["start"], row["end"]) for row in eh_frame_records(data)[1]}
    vendor = ROOT / "research/work-items/RE-002-node115-vendor-overflow-census"
    records = json.loads((vendor / "census.json").read_text())["records"]
    compiled = (vendor / "bodies.bin").read_bytes()
    evidence = {}
    for start in (driver.SMALL, driver.LARGE):
        row, = [r for r in records if r["start"] == start]
        end = row["end"]
        if ((start, end) not in fdes or row["crate"] != "lz4_flex"
                or row["candidate_versions"] != ["0.14.0"] or "compress_internal" not in row["symbol"]):
            raise ValueError("public source attribution changed")
        offset = row["source_offset"]
        source = compiled[offset:offset + end - start]
        _, target = elf.read(data, start, end - start)
        if (hashlib.sha256(source).hexdigest() != row["source_body_sha256"]
                or hashlib.sha256(target).hexdigest() != row["target_body_sha256"]):
            raise ValueError("driver body digest changed")
        matched = byte_progress.compare(source, target, row["relocations"])
        if not matched["relocation_qualified"]:
            raise ValueError("driver fixed bytes differ from the public build")
        evidence[hex(start)] = {"body_bytes": len(target), "fixed_bytes": matched["non_relocation_bytes"],
                                "source_sha256": row["source_body_sha256"], "target_sha256": row["target_body_sha256"]}
    return evidence


def corpus():
    rng = random.Random(0x477E950)
    for length in range(33):
        yield bytes(range(length))
        yield b"x" * length
    for length in (64, 128, 269, 270, 271, 525, 1024, 4096, 65534, 65535, 65536, 65537, 80000):
        yield rng.randbytes(length)
        yield (b"ABCDBCDABCDEBCDC" * length)[:length]
        seed = rng.randbytes(251)
        yield (seed * ((length + 250) // 251))[:length]
        # The same source with sparse edits exercises both skip and match-chain paths.
        data = bytearray((seed * ((length + 250) // 251))[:length])
        for idx in range(57, length, 83):
            data[idx] ^= 0x5a
        yield bytes(data)
    for seq in range(1, 65):
        source = bytearray(rng.randbytes(85 + seq * 5))
        for _ in range(24):
            cut = rng.randrange(len(source) - 15)
            length = rng.randrange(5, 16)
            source.extend(source[cut:cut + length])
            source.extend(rng.randbytes(rng.randrange(8)))
        yield bytes(source)


def record(data):
    return struct.pack("<I", len(data)) + data


def read_block(stream, offset):
    size, = struct.unpack_from("<I", stream, offset)
    start = offset + 4
    end = start + size
    if end > len(stream):
        raise ValueError("truncated comparison output")
    return stream[start:end], end


def model(data, flags=None):
    kind = driver.SMALL if len(data) < 65_535 else driver.LARGE
    status, encoded = driver.model_compress(kind, data, 0, 0, len(data) * 110 // 100 + 20,
                                            0, [0] * 4096, flags)
    if status:
        raise ValueError("unexpected driver refusal")
    return struct.pack("<I", len(data)) + encoded


def compare(inputs, stream):
    offset = 0
    counts = Counter()
    corpus_hash, reference_hash = hashlib.sha256(), hashlib.sha256()
    witnesses = []
    flags = {
        "single_byte_probe_step": driver.Flags(step_start=1 << 20, step_shift=20),
        "omit_backward_extension": driver.Flags(backward=False),
        "change_match_end_seed": driver.Flags(store_back=3),
    }
    controls = Counter({k: 0 for k in flags})
    for data in inputs:
        local, offset = read_block(stream, offset)
        public, offset = read_block(stream, offset)
        expected = model(data)
        if expected != public:
            raise ValueError(f"public lz4_flex and driver model differ at row {counts['rows']}")
        large = len(data) >= 65_535
        counts["rows"] += 1
        counts["large" if large else "small"] += 1
        if local != expected:
            counts["different_large" if large else "different_small"] += 1
            if len(witnesses) < 2:
                witnesses.append({"row": counts["rows"], "input_bytes": len(data),
                                  "expected_sha256": hashlib.sha256(public).hexdigest(),
                                  "actual_sha256": hashlib.sha256(local).hexdigest()})
        for name, changed in flags.items():
            controls[name] += int(model(data, changed) != public)
        corpus_hash.update(record(data))
        reference_hash.update(record(public))
    if offset != len(stream) or not all(controls.values()):
        raise ValueError("unexpected trailing outputs or non-discriminating control")
    return {
        "table_cases": {"small": counts["small"], "large": counts["large"]},
        "mismatches": {"small": counts["different_small"], "large": counts["different_large"]},
        "first_differences": witnesses, "rows": counts["rows"],
        "changed_driver_outputs": dict(controls), "input_sha256": corpus_hash.hexdigest(),
        "reference_sha256": reference_hash.hexdigest(),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", action="store_true")
    parser.add_argument("--baseline", action="store_true", help="rebuild the pinned base instead of the current source")
    args = parser.parse_args()
    recorded = json.loads((HERE / "block-results.json").read_text())
    if qualified_drivers() != recorded["source_drivers"]:
        raise ValueError("recorded driver evidence changed")
    inputs = list(corpus())
    wire = b"".join(map(record, inputs))
    rustc = subprocess.check_output(["rustup", "which", "--toolchain", "1.95.0", "rustc"], text=True).strip()
    cargo = subprocess.check_output(["rustup", "which", "--toolchain", "1.95.0", "cargo"], text=True).strip()
    with tempfile.TemporaryDirectory(prefix="lz4-blocks-") as tmp:
        work = Path(tmp)
        manifest = HERE / "reference/Cargo.toml"
        if args.baseline:
            archive = work / "source.tar"
            subprocess.run(["git", "-C", ROOT, "archive", "--format=tar", "-o", archive, BASE, "src"], check=True)
            with tarfile.open(archive) as tar:
                tar.extractall(work, filter="data")
            old_reference = work / HERE.relative_to(ROOT) / "reference"
            old_reference.mkdir(parents=True)
            for name in ("Cargo.toml", "Cargo.lock", "main.rs"):
                shutil.copyfile(HERE / "reference" / name, old_reference / name)
            manifest = old_reference / "Cargo.toml"
        env = dict(os.environ, RUSTC=rustc, CARGO_TARGET_DIR=str(work / "target"))
        outputs = []
        for profile in ([], ["--release"]):
            outputs.append(subprocess.check_output(
                [cargo, "run", "--frozen", "--quiet", *profile, "--manifest-path",
                 manifest], input=wire, env=env))
    if outputs[0] != outputs[1]:
        raise ValueError("debug and release blocks differ")
    report = compare(inputs, outputs[0])
    key = "baseline" if args.baseline else "corrected"
    if not args.record and report != recorded[key]:
        raise ValueError(f"recorded block results differ: {report}")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
