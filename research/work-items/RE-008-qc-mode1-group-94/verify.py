#!/usr/bin/env python3
"""Authenticate mode1 native anchors and frozen state algebra; never run node."""
import argparse
import csv
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PREVIOUS = ROOT / "research/work-items/RE-008-qc-mode0-group-94/verify.py"
SPEC = importlib.util.spec_from_file_location("credited_mode0_native", PREVIOUS)
MODE0 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODE0)
FREEZE = "5fa1a8a08792fda65f42923033315ed16533ce8d51755bd01fd67c945c97e209"
MAX = (1 << 64) - 1


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def freeze():
    raw = (HERE / "pre-rust/PRE-MODE1-RUST-FREEZE.json").read_bytes()
    need(sha(raw) == FREEZE, "pre-mode1-Rust freeze")
    frozen = json.loads(raw)
    for name, digest in frozen["fixtures"].items():
        need(sha((HERE / "pre-rust" / name).read_bytes()) == digest, "pre-source fixture " + name)
    return frozen


def relation(row):
    """Independent bounded state algebra; credited scalar kernel stays separate."""
    need(int(row["mode_word"]) == 1, "full mode word one")
    c, limit = int(row["charge"]), int(row["limit"])
    wire = b"" if row["wire_hex"] == "-" else bytes.fromhex(row["wire_hex"])
    before = bytes.fromhex(row["group_before_hex"])
    need(len(before) == 40, "provided group memory width")
    if c > MAX - 32 or c + 32 > limit:
        final = c if c > MAX - 32 else c + 32
        image = bytearray(before)
        image[:8] = (1).to_bytes(8, "little")
        image[8] = 2
        return [row["id"], str(final), "0", str(len(wire)), wire.hex() or "-",
                "1", "2", "-", "1", "2", "-", "-", image.hex()]
    # Accepted scalar/cursor data are already separately proved. The new
    # group invariant retains originalC+32 at each scalar return/first short.
    inner = MODE0.relation(row | {"mode_word": "0", "charge": "0", "limit": "0"})
    inner[1] = str(c + 32)
    memory = (bytes(8) + bytes.fromhex(inner[11])).hex() if inner[5] == "0" else "-"
    return inner + [memory]


def verify_vectors():
    freeze()
    inputs = list(csv.DictReader(io.StringIO((HERE / "pre-rust/inputs.tsv").read_text()), delimiter="\t"))
    expected = list(csv.reader(io.StringIO((HERE / "pre-rust/expected.tsv").read_text()), delimiter="\t"))[1:]
    need(len(inputs) == len(expected) == 128, "case count")
    need([relation(row) for row in inputs] == expected, "all128 target-derived frozen states")
    return inputs, expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--llvm", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    need(not args.out.exists(), "refuse existing output")
    args.out.mkdir(parents=True)
    frozen = freeze()
    data = args.binary.read_bytes()
    need(sha(data) == frozen["target"]["sha256"] and len(data) == frozen["target"]["size"], "authenticated node94")
    image = MODE0.Image(data)
    for anchor in frozen["anchors"]:
        expected = bytes.fromhex(anchor["hex"])
        need(image.read(int(anchor["va"], 16), len(expected)) == expected, "mode1 native anchor " + anchor["va"])
    for control in frozen["native_controls"]:
        for change in control["changes"]:
            before, after = bytes.fromhex(change["before"]), bytes.fromhex(change["after"])
            need(before != after and len(before) == len(after), "distinct static control bytes")
            need(image.read(int(change["va"], 16), len(before)) == before, "authenticated static site")
    verify_vectors()
    argv = [sys.executable, "-B", str(PREVIOUS), "--binary", str(args.binary), "--llvm", str(args.llvm),
            "--out", str(args.out / "credited-complete-native-auth")]
    process = subprocess.run(argv, capture_output=True)
    (args.out / "native-auth.stdout").write_bytes(process.stdout)
    (args.out / "native-auth.stderr").write_bytes(process.stderr)
    need(process.returncode == 0, process.stderr.decode(errors="replace"))
    report = {"target_sha256": sha(data), "vectors": 128, "static_site_controls": 10,
              "credited_full_native_auth": {"argv": argv, "exit": process.returncode,
                                            "stdout_sha256": sha(process.stdout), "stderr_sha256": sha(process.stderr)},
              "dependency_pins": {str(PREVIOUS.relative_to(ROOT)): sha(PREVIOUS.read_bytes())},
              "captured_execution": False, "captured_emulation": False,
              "limits": "active final fields;supplied-prefill denial memory only;no inactive need/ABI/fullQC/runtime claim"}
    (args.out / "results.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("128 frozen states;10 static sites;credited4body/FDE/dual-tool authentication:pass")


if __name__ == "__main__":
    main()
