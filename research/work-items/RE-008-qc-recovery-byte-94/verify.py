#!/usr/bin/env python3
"""Regenerate bounded static evidence and corrupt native branch/field relations."""
import argparse
import csv
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("qc_recovery_evidence", HERE / "evidence.py")
e = importlib.util.module_from_spec(spec); spec.loader.exec_module(e)


def reject(action, reason):
    try: action()
    except ValueError as error:
        e.require(reason in str(error), "unexpected rejection: " + str(error))
        return str(error)
    raise ValueError("corruption accepted: " + reason)


def contents(path):
    return {f.name: f.read_bytes() for f in path.iterdir() if f.is_file()}


def check_windows(image, frozen):
    for site in frozen["windows"]:
        raw = bytes.fromhex(site["hex"])
        e.require(image.read(int(site["va"], 16), len(raw)) == raw, "frozen window " + site["name"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=e.ROOT / "artifacts/node/94/hl-node")
    parser.add_argument("--llvm", default=os.environ.get("LLVM_OBJDUMP") or shutil.which("llvm-objdump"))
    parser.add_argument("--report", type=Path); args = parser.parse_args()
    if not args.llvm: parser.error("pass --llvm, set LLVM_OBJDUMP, or add llvm-objdump to PATH")
    image = e.Image(args.binary.read_bytes()); params = e.derive(image)
    frozen = json.loads((HERE / "freeze.json").read_text())
    checks = []
    checks.append(reject(lambda: e.Image(b"wrong target"), "target SHA-256 mismatch"))
    checks.append(reject(lambda: image.read(0xFFFFFFFFFFFFFFF0, 32), "file-backed"))
    class Overlay:
        def __init__(self, at, raw): self.at, self.raw = at, raw
        def read(self, va, size):
            data = bytearray(image.read(va, size)); lo = max(va, self.at); hi = min(va + size, self.at + len(self.raw))
            if lo < hi: data[lo-va:hi-va] = self.raw[lo-self.at:hi-self.at]
            return bytes(data)
    for site in frozen["windows"]:
        at = int(site["va"], 16); raw = bytearray.fromhex(site["hex"]); raw[-1] ^= 1
        checks.append(reject(lambda at=at, raw=raw: check_windows(Overlay(at, raw), frozen), "frozen window"))
    cases = []
    with (HERE / "boundaries.csv").open() as file:
        for row in csv.DictReader(file):
            actual = e.project_field(params, *(int(row[k]) for k in ("mode", "charge", "limit", "remaining", "byte")))
            expected = [row["status"], int(row["charge_after"]), int(row["consumed"]),
                        None if row["kind"] == "-" else int(row["kind"]), None if row["value"] == "-" else int(row["value"])]
            e.require([actual[k] for k in ("status", "charge_after", "consumed", "kind", "value")] == expected, "frozen boundary " + row["name"])
            cases.append(row["name"])
    native_controls = []
    with tempfile.TemporaryDirectory(prefix="qc-recovery-static-") as temporary:
        tmp = Path(temporary)
        expected = contents(HERE / "observed")
        for generation in ("first", "second"):
            result = e.collect(args.binary, args.llvm, tmp / generation)
            e.require(contents(tmp / generation) == expected, "fresh evidence differs")
        mutations = [
            ("EOF-success-bypass", 0x4C7E52B, b"\x0f\x84" + struct.pack("<i", e.SUCCESS-0x4C7E531), "success bypasses"),
            ("unreachable-success", 0x4C7E4F3, b"\xc3", "vacuous field success"),
            ("charge-aliases-remaining", 0x4C7E51A, b"\x18", "charge state-field agreement"),
            ("two-byte-input-load", 0x4C7E536, b"\xb7", "field width/cursor direction"),
            ("empty-needs-two", 0x4C7E602, b"\x02", "empty shortfall/field width"),
            ("limit-allows-equality", 0x4C7E51F, b"\x87", "limit comparison must reject equality"),
        ]
        for name, va, raw, reason in mutations:
            data = bytearray(image.data); off = image.offset(va, len(raw)); before = bytes(data[off:off+len(raw)])
            data[off:off+len(raw)] = raw; binary = tmp / (name + ".elf"); binary.write_bytes(data); binary.chmod(0o600)
            def audit():
                changed = e.Image(binary.read_bytes(), identity=False)
                texts, rows = e.native(binary, *e.RANGES["row-field-owner"], args.llvm)
                cursor = e.RANGES["row-field-owner"][0]
                for at, code, _ in rows:
                    e.require(at == cursor and changed.read(at, len(code)) == code, "mutant native bytes")
                    cursor += len(code)
                e.require(cursor == e.RANGES["row-field-owner"][1], "mutant complete body")
                e.check_graph(rows)  # Checked before operand constraints, below identity/frozen-window guards.
                e.derive(changed)
            message = reject(audit, reason)
            native_controls.append({"name": name, "va": hex(va), "before": before.hex(), "after": raw.hex(), "rejection": message})
    report = {"target_sha256": e.SHA, "captured_execution": False, "instruction_evaluation": False,
              "identity_and_mapping_rejections": 2, "window_byte_identity_rejections": len(frozen["windows"]),
              "native_controls": native_controls, "native_mutant_mode": "0600",
              "native_controls_below_identity_and_window_guards": True, "frozen_boundary_cases": cases,
              "fresh_generations": 2, "all_exports_byte_identical": True, "native_summary": result["summary"],
              "tools": {"python": sys.version.split()[0],
                        "gnu": subprocess.check_output(["objdump", "--version"], text=True).splitlines()[0],
                        "llvm": subprocess.check_output([args.llvm, "--version"], text=True).splitlines()[0]}}
    if args.report: args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print("PASS: 12 boundary cases; 14 identity/mapping/window guards; 6 native controls; two identical generations")
