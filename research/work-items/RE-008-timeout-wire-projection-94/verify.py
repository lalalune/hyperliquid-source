#!/usr/bin/env python3
"""Reproduce native static evidence and attack its guards; no captured execution."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("timeout_wire_build", HERE / "build.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)


def reject(action, expected):
    try:
        action()
    except ValueError as error:
        b.require(expected in str(error), f"wrong rejection: {error}; expected {expected}")
        return str(error)
    raise ValueError(f"control was accepted: {expected}")


def files(path):
    return {f.relative_to(path).as_posix(): f.read_bytes() for f in path.rglob("*") if f.is_file()}


class Overlay:
    """A changed target witness, below whole-image/body digest checks."""
    def __init__(self, image, va, raw):
        self.image, self.va, self.raw = image, va, raw

    def read(self, va, size):
        result = bytearray(self.image.read(va, size))
        lo, hi = max(va, self.va), min(va + size, self.va + len(self.raw))
        if lo < hi:
            result[lo - va:hi - va] = self.raw[lo - self.va:hi - self.va]
        return bytes(result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=b.ROOT / "artifacts/node/94/hl-node")
    parser.add_argument("--llvm", default=os.environ.get("LLVM_OBJDUMP") or shutil.which("llvm-objdump"))
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    if not args.llvm:
        parser.error("LLVM objdump is required; pass --llvm, set LLVM_OBJDUMP, or add llvm-objdump to PATH")
    image = b.Image(args.binary.read_bytes())
    pins = json.loads((HERE / "pins.json").read_text())
    report = {"target_sha256": b.SHA, "captured_execution": False, "instruction_evaluation": False,
              "native_controls": [], "native_mutant_identity_and_witness_checks_disabled": True,
              "witness_control_scope": "byte identity only; these are not semantic mutation proofs"}
    controls = []

    def record(name, expected, action, native=None):
        reason = reject(action, expected)
        item = {"name": name, "result": "rejected", "reason": reason}
        controls.append(item)
        if native:
            report["native_controls"].append(dict(item, **native))

    record("wrong-image", "target SHA-256 mismatch", lambda: b.Image(b"wrong image"))
    record("non-file-backed-va", "non-file-backed", lambda: image.read(0xFFFFFFFFFFFFFFF0, 32))
    for pin in pins["witnesses"]:
        va, raw = int(pin["va"], 16), bytearray.fromhex(pin["hex"])
        # Changing the final byte reaches displacement/immediate operands in
        # most selected rows, rather than only checking an opcode marker.
        raw[-1] ^= 1
        record(pin["name"], "witness", lambda va=va, raw=raw: b.check_witnesses(Overlay(image, va, bytes(raw)), pins))
    for table in b.TABLES:
        for index in range(5):
            va = table + 4 * index
            raw = bytearray(image.read(va, 4)); raw[0] ^= 1
            record(f"table-{table:x}-entry-{index}", "dispatch table",
                   lambda va=va, raw=raw: b.check_witnesses(Overlay(image, va, bytes(raw)), pins))
    record("tag2-data", "tag2 literal", lambda: b.check_witnesses(Overlay(image, 0x209EDC, b"\x01\0\0\0"), pins))

    with tempfile.TemporaryDirectory(prefix="timeout-wire-static-") as temporary:
        tmp = Path(temporary)
        expected = files(HERE / "observed")
        for generation in ("first", "second"):
            out = tmp / generation
            result = b.collect(args.binary, args.llvm, pins, out)
            actual = files(out)
            b.require(actual == expected, f"regeneration differs: {generation}")
        report["reproductions"] = {"generations": 2, "files_per_generation": len(actual),
            "all_byte_identical_to_committed": True, "summary": result["summary"]}

        # These controls are actual mutated ELF copies, passed to both native
        # disassemblers. Whole-image and witness/body equality checks are OFF.
        # They must fail the local graph theorem independently of frozen bytes.
        cases = [
            ("writer-success-bypass", 0x4778853, 0x47789C7, "success bypass timeout-write"),
            ("sizer-success-bypass", 0x4778AB9, 0x4778B58, "success bypass timeout-size"),
            ("signature-write-success-bypass", 0x4DF2101, 0x4DF21F8, "success bypass signature-write"),
            ("signature-size-success-bypass", 0x4DF227E, 0x4DF235C, "success bypass signature-size"),
        ]
        for name, va, target, reason in cases:
            raw = image.read(va, 6)
            b.require(raw[:2] == b"\x0f\x85", f"control requires native JNE {va:#x}")
            mutant = bytearray(image.data)
            off = image.offset(va + 2, 4)
            mutant[off:off + 4] = struct.pack("<i", target - va - 6)
            path = tmp / f"{name}.elf"
            path.write_bytes(mutant)
            path.chmod(0o600)
            record(name, reason, lambda path=path, name=name: b.collect(path, args.llvm, pins, tmp / name,
                   identity=False, witnesses=False),
                   {"va": hex(va), "original": raw.hex(), "mutated": bytes(mutant[off-2:off+4]).hex(),
                    "new_target": hex(target)})
        mutant = bytearray(image.data)
        mutant[image.offset(0x4778820)] = 0xC3
        path = tmp / "vacuous.elf"; path.write_bytes(mutant); path.chmod(0o600)
        record("vacuous-writer-success", "vacuous success timeout-write",
               lambda: b.collect(path, args.llvm, pins, tmp / "vacuous", identity=False, witnesses=False),
               {"va": "0x4778820", "original": image.read(0x4778820, 1).hex(), "mutated": "c3"})

        frozen = json.loads((HERE / "observed/records.json").read_text())
        fde_va = int(next(f for f in frozen["functions"] if f["name"] == "timeout-write")["fde"]["va"], 16)
        mutant = bytearray(image.data)
        off = image.offset(fde_va + 12, 4)
        mutant[off] ^= 1
        path = tmp / "fde-range.elf"; path.write_bytes(mutant); path.chmod(0o600)
        record("fde-range", "FDE extent timeout-write",
               lambda: b.collect(path, args.llvm, pins, tmp / "fde-range", identity=False, witnesses=False),
               {"va": hex(fde_va + 12), "original": image.read(fde_va + 12, 4).hex(),
                "mutated": bytes(mutant[off:off+4]).hex()})

    # The theorem checker itself must reject a vacuous graph and a success
    # path that skips a mandatory native operation. These do not model x86.
    success, mandatory = b.SUCCESS_GATES["timeout-write"]
    record("checker-vacuity", "vacuous success", lambda: b.gate_contract("timeout-write", {0: []}, 0))
    graph = {0: [success], success: []}
    graph.update({site: [] for site in mandatory})
    record("checker-skipped-operation", "success bypass", lambda: b.gate_contract("timeout-write", graph, 0))
    report["control_count"] = len(controls)
    report["all_controls_rejected"] = True
    report["control_trace_sha256"] = b.digest(b.dump(controls).encode())
    report["native_mutant_controls"] = 6
    report["native_mutant_file_mode"] = "0600, no execute bits"
    report["control_classes"] = {"identity_and_mapping": 2, "instruction_byte_identity": len(pins["witnesses"]),
                                 "table_and_tag_data": 11, "native_cfg": 5, "native_fde": 1, "graph_checker": 2}
    report["tool_versions"] = {
        "gnu": __import__("subprocess").check_output(["objdump", "--version"], text=True).splitlines()[0],
        "llvm": __import__("subprocess").check_output([args.llvm, "--version"], text=True).splitlines()[0],
        "python": __import__("sys").version.split()[0],
    }
    if args.report:
        args.report.write_text(b.dump(report))
    print(f"PASS: {report['control_count']} controls; two fresh native exports identical; no captured execution")


if __name__ == "__main__":
    main()
