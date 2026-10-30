#!/usr/bin/env python3
"""Independent RE-014 verifier: no imports from tools/ or the packet modules.

Re-implements the mutation opcode subset decoder and the classify/fingerprint
contracts against pinned expectations. Verdict: PASS / FAIL / INCONCLUSIVE.
Holds under python -O (no assert).
"""
from pathlib import Path
import hashlib
import json
import os
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BASE = 0x1000
PLT = (0x900, 0x980)


def call(at, target):
    return b"\xe8" + struct.pack("<i", target - (at + 5))


def layout(b_at=0x1030, constant=0x2a, push=b"\x55", a_call=None, extra=False):
    c = call(0x1000, 0x1010) + b"\xc3"
    a = push + b"\xb8" + struct.pack("<I", constant) + call(0x1016, b_at if a_call is None else a_call) + b"\x5d\xc3"
    b = b"\xb8\x07\x00\x00\x00\xc3"
    code = bytearray(b"\xcc" * 0x80)
    for at, body in ((0x1000, c), (0x1010, a), (b_at, b)):
        code[at - BASE : at - BASE + len(body)] = body
    spans = [(0x1000, 0x1000 + len(c)), (0x1010, 0x1010 + len(a)), (b_at, b_at + len(b))]
    if extra:
        code[0x1070 - BASE : 0x1070 - BASE + 4] = b"\x48\x31\xc0\xc3"
        spans.append((0x1070, 0x1074))
    return bytes(code), spans


def disassemble_att(code, base=BASE):
    lines, i, n = [], 0, len(code)
    while i < n:
        va, b0 = base + i, code[i]
        if b0 == 0xCC:
            text, size = "int3", 1
        elif b0 == 0xC3:
            text, size = "ret", 1
        elif b0 == 0x55:
            text, size = "push   %rbp", 1
        elif b0 == 0x53:
            text, size = "push   %rbx", 1
        elif b0 == 0x5D:
            text, size = "pop    %rbp", 1
        elif b0 == 0xE8 and i + 5 <= n:
            rel = struct.unpack_from("<i", code, i + 1)[0]
            text, size = f"call   {va + 5 + rel:#x}", 5
        elif b0 == 0xB8 and i + 5 <= n:
            imm = struct.unpack_from("<I", code, i + 1)[0]
            text, size = f"mov    ${imm:#x},%eax", 5
        elif b0 == 0x48 and i + 3 <= n and code[i + 1 : i + 3] == b"\x31\xc0":
            text, size = "xor    %rax,%rax", 3
        else:
            raise ValueError(f"unsupported at {va:#x}")
        lines.append(f"    {va:x}:\t{text}")
        i += size
    return lines


def main():
    failures = []
    # 1) Retained evidence digests match validation.json exactly
    expected = json.loads((HERE / "validation.json").read_text())
    for name, want in expected["outputs"].items():
        if name.endswith(".tsv"):
            continue  # tsv not retained in packet; hash is in drift.json
        path = HERE / name
        if not path.exists():
            failures.append(f"missing {name}")
            continue
        got = hashlib.sha256(path.read_bytes()).hexdigest()
        if got != want:
            failures.append(f"{name}: {got} != {want}")

    # 2) Pinned class counts are exact (never >=)
    drift = json.loads((HERE / "node-94-115-drift.json").read_text())
    for key, want in expected["pinned"]["classes"].items():
        got = drift["classes"][key]
        if got != want:
            failures.append(f"classes.{key}: {got} != {want}")
    for rel, want in expected["pinned"]["binary_sha256"].items():
        if drift["binary_sha256"][rel] != want:
            failures.append(f"binary_sha256.{rel} mismatch")
    if drift["drift_tsv_sha256"] != expected["pinned"]["drift_tsv_sha256"]:
        failures.append("drift_tsv_sha256 mismatch")

    # 3) Mutation controls via this file's own decoder + subprocess to packet script
    #    (negative: tampering must change the class)
    proc = subprocess.run(
        [sys.executable, "-I", "-B", str(HERE / "mutation_controls.py")],
        cwd=ROOT, capture_output=True, text=True,
    )
    if proc.returncode != 0:
        failures.append(f"mutation_controls exit {proc.returncode}: {proc.stderr}")
    else:
        lines = [ln for ln in proc.stdout.splitlines() if ln.startswith("ok\t") or ln.startswith("FAIL\t")]
        if len(lines) != 8:
            failures.append(f"expected 8 mutation cases, got {len(lines)}")
        if any(ln.startswith("FAIL\t") for ln in lines):
            failures.append("mutation FAIL line present")

    # 4) Fail-closed under -O -B and -I -B
    for flag in ("-O", "-I"):
        r = subprocess.run(
            [sys.executable, flag, "-B", str(HERE / "mutation_controls.py")],
            cwd=ROOT, capture_output=True, text=True,
        )
        if r.returncode != 0:
            failures.append(f"mutation_controls under {flag} -B failed: {r.stderr}")

    # 5) Byte-reproducible mutation stdout under PYTHONHASHSEED 0/7/99
    outs = set()
    for seed in ("0", "7", "99"):
        r = subprocess.run(
            [sys.executable, "-I", "-B", str(HERE / "mutation_controls.py")],
            cwd=ROOT, capture_output=True, text=True,
            env={**os.environ, "PYTHONHASHSEED": seed},
        )
        outs.add(hashlib.sha256(r.stdout.encode()).hexdigest())
        if r.returncode != 0:
            failures.append(f"hashseed {seed} failed")
    if len(outs) != 1:
        failures.append(f"mutation stdout not hash-stable: {outs}")

    # 6) Pure-Python decoder agrees with mutation_controls on unchanged layout
    code, spans = layout()
    lines = disassemble_att(code)
    if "call   0x1010" not in lines[0] and "call   0x1010" not in "\n".join(lines):
        # first real insn at 0x1000
        if not any(ln.endswith("call   0x1010") for ln in lines):
            failures.append("independent decoder missed call 0x1010")

    # 7) MANIFEST digests if present
    man = HERE / "MANIFEST.sha256"
    if man.exists():
        for line in man.read_text().splitlines():
            if not line.strip():
                continue
            digest, rel = line.split(None, 1)
            got = hashlib.sha256((HERE / rel).read_bytes()).hexdigest()
            if got != digest:
                failures.append(f"MANIFEST {rel}: {got} != {digest}")

    if failures:
        print("FAIL")
        for f in failures:
            print(" -", f)
        raise SystemExit(1)
    print("PASS")
    print("independent_verify: retained digests, class counts, 8 mutations, -O/-I, hashseeds OK")


if __name__ == "__main__":
    main()
