#!/usr/bin/env python3
"""Re-derive the RE-001 spot scale round-up wrapper packet
(0x5a00fc0) from the pinned node #115 binary.

Run from the repository root:

    python3 research/work-items/RE-001-spot-scale-roundup-fc0-115/verify.py

Checks, in order: the binary digest against
provenance/artifacts.json; the packet manifest; the objdump
excerpts for the wrapper and the round leaf (regenerated, and
the committed files' raw instruction bytes compared against
the binary); the wrapper's and the leaf's spot instruction
bytes; the FDE ranges in the live frame dump and in
frames.txt; the round leaf's slot relocation; the named
constants' bytes and values; the whole-binary census against
callers.tsv (direct calls, tail jumps, stored qwords,
RELATIVE addends, and each call site's smallest enclosing
FDE); the records.json semantics; and the model test suite.
"""

import ast
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
PROVENANCE_KEY = "artifacts/node/115/hl-node"

EXCERPTS = {
    "main.txt": (0x5A00FC0, 0x5A01101, "5a00fc0:"),
    "round.txt": (0x63EFE40, 0x63EFEB1, "63efe40:"),
}

MANIFEST_FILES = [
    "README.md", "records.json", "main.txt", "round.txt",
    "frames.txt", "relocations.txt", "callers.tsv",
    "export_excerpts.py", "census.py", "verify.py",
]

SPOT = [
    # the wrapper's front
    (0x5A00FD0, "85d2", "test edx,edx (the flag test)"),
    (0x5A00FD4, "660f5705e449a5fa", "xorpd against the -0.0 pair"),
    (0x5A00FDC, "66480f6ec9", "movq xmm1,rcx (conversion start)"),
    (0x5A00FE1, "660f620d2702a5fa", "punpckldq against the bias dwords"),
    (0x5A00FE9, "660f5c0d7ff1a4fa", "subpd against the bias pair"),
    (0x5A00FF5, "660f15d1", "unpckhpd (conversion halves)"),
    (0x5A00FF9, "f20f58d1", "addsd (conversion sum)"),
    (0x5A00FFD, "f20f5805ab82a5fa", "addsd against 1.0"),
    (0x5A01005, "f20f59c2", "mulsd (the product)"),
    (0x5A01009, "ff158108ae00", "call through slot 0x64e1890"),
    (0x5A01013, "f20f5fc1", "maxsd against +0.0"),
    # the saturating cast
    (0x5A0101C, "48b9ffffffffffffff7f", "movabs rcx, abs mask"),
    (0x5A01029, "48b8ffffffffffffef7f", "movabs rax, DBL_MAX bits"),
    (0x5A01037, "4839c1", "cmp rcx,rax (absolute bits)"),
    (0x5A0103A, "7f16", "jg to the cast (+inf scratch path)"),
    (0x5A0103C, "660f2e054c80a5fa", "ucomisd against 2^64"),
    (0x5A01044, "660f28d0", "movapd xmm2,xmm0 (clamp value)"),
    (0x5A01048, "7608", "jbe to the cast"),
    (0x5A0104A, "f20f10153e80a5fa", "movsd xmm2, 2^64 (clamp)"),
    (0x5A01052, "f2480f2cc2", "cvttsd2si rax,xmm2"),
    (0x5A0105E, "f20f5c05fa82a5fa", "subsd against 2^63"),
    (0x5A01066, "f2480f2cd0", "cvttsd2si rdx,xmm0"),
    (0x5A0106B, "48c1f93f", "sar rcx,63 (sign mask)"),
    (0x5A0106F, "4821ca", "and rdx,rcx"),
    (0x5A01072, "4809c2", "or rdx,rax (cast combine)"),
    (0x5A01077, "660f2ed1", "ucomisd against 0.0 (sign guard)"),
    (0x5A0107B, "480f43c2", "cmovae rax,rdx"),
    (0x5A0107F, "660f2e15d17ca5fa", "ucomisd against 2^64-2048"),
    (0x5A01087, "49c7c4ffffffff", "mov r12,-1 (saturation value)"),
    (0x5A0108E, "4c0f46e0", "cmovbe r12,rax"),
    (0x5A01092, "4983fc01", "cmp r12,1 (raise-to-1 test)"),
    (0x5A01096, "4983d400", "adc r12,0 (raise to 1)"),
    # the selector call and the rounding
    (0x5A010A3, "e868020000", "direct call to the selector 0x5a01310"),
    (0x5A010B1, "48c1e820", "shr rax,32 (division width test)"),
    (0x5A010BC, "48f7f1", "div rcx (64-bit division)"),
    (0x5A010C6, "f7f1", "div ecx (32-bit division)"),
    (0x5A010CB, "48ffc2", "inc rdx (the q+1 candidate)"),
    (0x5A010CE, "48c7c6ffffffff", "mov rsi,-1 (increment saturation)"),
    (0x5A010D5, "480f44d6", "cmove rdx,rsi"),
    (0x5A010D9, "84db", "test bl,bl (the flag choice)"),
    (0x5A010DB, "480f44d0", "cmove rdx,rax (flag clear keeps q)"),
    (0x5A010E2, "48f7e1", "mul rcx (multiply back by scale)"),
    (0x5A010E5, "7003", "jo past the result move (overflow keeps -1)"),
    (0x5A010EA, "4883fe01", "cmp rsi,1 (product raise test)"),
    (0x5A010EE, "4883d600", "adc rsi,0 (product raised to 1)"),
    # the round leaf
    (0x63EFE40, "660f28c8", "leaf: movapd xmm1,xmm0 (save x)"),
    (0x63EFE44, "660f2805745b06fa", "leaf: movapd of the sign pair"),
    (0x63EFE4C, "660f54c1", "leaf: andpd (sign of x)"),
    (0x63EFE50, "660f5605081006fa", "leaf: orpd of the round constant"),
    (0x63EFE58, "f20f58c1", "leaf: addsd (x + copysign)"),
    (0x63EFE64, "48c1ea34", "leaf: shr rdx,52 (exponent)"),
    (0x63EFE68, "81e2ff070000", "leaf: and edx,0x7ff"),
    (0x63EFE6E, "81fa32040000", "leaf: cmp edx,0x432 (exponent gate)"),
    (0x63EFE74, "773a", "leaf: ja to ret (large/inf/NaN)"),
    (0x63EFE76, "8d8a01fcffff", "leaf: lea ecx,[rdx-0x3ff] (shift)"),
    (0x63EFE7C, "48be000000000000f0ff", "leaf: movabs rsi, trunc mask"),
    (0x63EFE86, "48d3fe", "leaf: sar rsi,cl"),
    (0x63EFE89, "81faff030000", "leaf: cmp edx,0x3ff (|s| < 1 test)"),
    (0x63EFE8F, "48b90000000000000080", "leaf: movabs rcx, sign mask"),
    (0x63EFE99, "480f43ce", "leaf: cmovae rcx,rsi (mask choice)"),
    (0x63EFEA0, "48f7d2", "leaf: not rdx (fraction test)"),
    (0x63EFEA3, "4885c2", "leaf: test rdx,rax"),
    (0x63EFEA8, "4821c1", "leaf: and rcx,rax (truncate)"),
    (0x63EFEAB, "66480f6ec1", "leaf: movq xmm0,rcx (result)"),
    (0x63EFEB0, "c3", "leaf: ret"),
]

FRAMES = [
    (0x5A00FC0, 0x5A01101),
    (0x63EFE40, 0x63EFEB1),
    (0x517AF50, 0x517B75D),
    (0x517C040, 0x517C84D),
    (0x54EFCA0, 0x54F126D),
    (0x54F1270, 0x54F283D),
]

EXPECTED_SLOTS = {0x64E1890: 0x63EFE40}

CONSTANTS = [
    (0x4559C0, "0000000000000080" * 2, "the (-0.0, -0.0) pair"),
    (0x451210, "00003043000030450000000000000000",
     "the conversion dword pair"),
    (0x450170, "00000000000030430000000000003045",
     "the conversion bias pair (2^52, 2^84)"),
    (0x4592B0, "000000000000f03f", "the 1.0 constant"),
    (0x459090, "000000000000f043", "the 2^64 constant"),
    (0x459360, "000000000000e043", "the 2^63 constant"),
    (0x458D58, "ffffffffffffef43", "the 2^64-2048 constant"),
    (0x450E60, "ffffffffffffdf3f" * 2,
     "the round constant pair (0.49999999999999994)"),
    (0x4593E0, "9a9999999999b93f", "the callers' 0.1 constant"),
]

EXPECTED_CALLS = {
    0x5A00FC0: ["0x517b48f", "0x517c57f", "0x54f0797", "0x54f1d67"],
}
EXPECTED_JUMPS = {0x5A00FC0: []}


def fail(msg):
    raise SystemExit("FAIL: %s" % msg)


def load_segments(data):
    segs = []
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type != 1:
            continue
        p_offset, p_vaddr = struct.unpack_from("<QQ", data, off + 0x08)
        p_filesz = struct.unpack_from("<Q", data, off + 0x20)[0]
        segs.append((p_offset, p_vaddr, p_filesz))
    return segs


def v2o(segs, addr):
    for off, va, size in segs:
        if va <= addr < va + size:
            return off + (addr - va)
    fail("address %#x not in any load segment" % addr)


def provenance_digest():
    prov = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    for entry in prov["files"]:
        if entry["path"] == PROVENANCE_KEY:
            return entry["sha256"]
    fail("provenance has no %s entry" % PROVENANCE_KEY)


def check_digest():
    import hashlib
    if not BINARY.exists():
        fail("binary not materialised at %s" % BINARY)
    digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    if digest != provenance_digest():
        fail("binary digest %s != provenance %s"
             % (digest, provenance_digest()))
    return digest


def check_manifest():
    import hashlib
    lines = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    listed = {}
    for line in lines:
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        listed[name.strip().lstrip("*")] = digest
    if sorted(listed) != sorted(MANIFEST_FILES):
        fail("manifest file set mismatch: %s" % sorted(listed))
    for name, want in listed.items():
        got = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if got != want:
            fail("manifest hash mismatch for %s" % name)


def objdump_window(start, stop):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%#x" % start,
         "--stop-address=%#x" % stop, str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    lines = out.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.startswith("Disassembly of section"):
            return "".join(lines[i:])
    fail("objdump output has no disassembly section")


def parse_excerpt(text, marker):
    rows = []
    for line in text.splitlines():
        if marker in line and "\t" in line:
            head, _, rest = line.partition("\t")
            addr = int(head.strip().rstrip(":"), 16)
            hexpart = rest.split("\t")[0].strip().replace(" ", "")
            rows.append((addr, hexpart))
    return rows


def check_excerpts():
    data = BINARY.read_bytes()
    segs = load_segments(data)
    for name, (start, stop, marker) in EXCERPTS.items():
        want_text = objdump_window(start, stop)
        got_text = (PACKET / name).read_text()
        if got_text != want_text:
            fail("%s does not match a fresh objdump window" % name)
        for addr, hexpart in parse_excerpt(got_text, marker):
            off = v2o(segs, addr)
            raw = data[off:off + len(hexpart) // 2].hex()
            if raw != hexpart:
                fail("%s: bytes at %#x: file %s vs binary %s"
                     % (name, addr, hexpart, raw))


def check_spots():
    data = BINARY.read_bytes()
    segs = load_segments(data)
    for addr, want, label in SPOT:
        off = v2o(segs, addr)
        got = data[off:off + len(want) // 2].hex()
        if got != want:
            fail("spot mismatch at %#x (%s): %s != %s"
                 % (addr, label, got, want))


def frame_ranges():
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    ranges = []
    for match in re.finditer(r"pc=([0-9a-f]+)\.\.([0-9a-f]+)", text):
        ranges.append((int(match.group(1), 16), int(match.group(2), 16)))
    return ranges


def check_frames():
    ranges = set(frame_ranges())
    stored = (PACKET / "frames.txt").read_text()
    for start, stop in FRAMES:
        if (start, stop) not in ranges:
            fail("FDE %#x..%#x missing from the frame dump" % (start, stop))
        if "pc=%016x..%016x" % (start, stop) not in stored:
            fail("frames.txt missing FDE %#x..%#x" % (start, stop))


def relative_slots():
    out = subprocess.run(["readelf", "-rW", str(BINARY)],
                         capture_output=True, text=True, check=True).stdout
    slots = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "R_X86_64_RELATIVE":
            try:
                slots[int(parts[0], 16)] = int(parts[3], 16)
            except ValueError:
                pass
    return slots, out


def check_relocations():
    slots, _text = relative_slots()
    stored = (PACKET / "relocations.txt").read_text()
    for slot, addend in EXPECTED_SLOTS.items():
        if slots.get(slot) != addend:
            fail("relocation mismatch for slot %#x: %r" % (slot, slots.get(slot)))
        if ("%016x" % slot) not in stored or ("%x" % addend) not in stored:
            fail("relocations.txt missing slot %#x" % slot)
    if 0x5A00FC0 in slots.values():
        fail("unexpected RELATIVE addend for the wrapper address")


def check_constants():
    data = BINARY.read_bytes()
    segs = load_segments(data)
    for addr, want_hex, label in CONSTANTS:
        off = v2o(segs, addr)
        got = data[off:off + len(want_hex) // 2].hex()
        if got != want_hex:
            fail("constant mismatch at %#x (%s): %s != %s"
                 % (addr, label, got, want_hex))
    off = v2o(segs, 0x4593E0)
    if struct.unpack_from("<d", data, off)[0] != 0.1:
        fail("caller constant at 0x4593e0 is not 0.1")


def check_census():
    out = subprocess.run(
        [sys.executable, str(PACKET / "census.py")],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    rows = (PACKET / "callers.tsv").read_text().splitlines()[1:]
    tsv_calls = {}
    tsv_jumps = {}
    tsv_callers = {}
    for row in rows:
        site, target, caller, kind = row.split("\t")[0:4]
        tsv_callers[site] = caller
        if kind == "call":
            tsv_calls.setdefault(target, []).append(site)
        elif kind == "tail jump":
            tsv_jumps.setdefault(target, []).append(site)
        else:
            fail("unknown callers.tsv kind: %s" % kind)
    for target, want_calls in EXPECTED_CALLS.items():
        match = re.search(
            r"routine %#x: direct calls: (\[.*\])" % target, out)
        if not match:
            fail("census output has no direct-calls list for %#x" % target)
        calls = ast.literal_eval(match.group(1))
        if sorted(calls) != sorted(want_calls):
            fail("census calls mismatch for %#x: %s vs %s"
                 % (target, calls, want_calls))
        if sorted(calls) != sorted(tsv_calls.get("%#x" % target, [])):
            fail("callers.tsv calls do not match census for %#x" % target)
        want_jumps = EXPECTED_JUMPS[target]
        match = re.search(
            r"routine %#x: tail jumps: (\[.*\])" % target, out)
        if not match:
            fail("census jumps mismatch for %#x" % target)
        jumps = ast.literal_eval(match.group(1))
        if sorted(jumps) != sorted(want_jumps):
            fail("census jumps mismatch for %#x: %s vs %s"
                 % (target, jumps, want_jumps))
        if sorted(jumps) != sorted(tsv_jumps.get("%#x" % target, [])):
            fail("callers.tsv jumps do not match census for %#x" % target)
    for target in EXPECTED_CALLS:
        for want in ("routine %#x: stored qwords: []" % target,
                     "routine %#x: RELATIVE addends: 0" % target):
            if want not in out:
                fail("census mismatch, missing %r" % want)
    ranges = frame_ranges()
    for site, caller in tsv_callers.items():
        value = int(site, 16)
        cands = [(a, b) for a, b in ranges if a <= value < b]
        if not cands:
            fail("no enclosing FDE for site %s" % site)
        a, b = min(cands, key=lambda ab: ab[1] - ab[0])
        if caller != "%#x..%#x" % (a, b):
            fail("caller mismatch for %s: %s vs %#x..%#x"
                 % (site, caller, a, b))


def check_records():
    records = json.loads((PACKET / "records.json").read_text())
    if records["task"] != "RE-001":
        fail("records task mismatch")
    if records["artifact_sha256"] != provenance_digest():
        fail("records digest mismatch")
    if records["routine"]["address"] != "0x5a00fc0":
        fail("records routine address mismatch")
    if records["routine"]["fde"] != "0x5a00fc0..0x5a01101":
        fail("records routine FDE mismatch")
    if records["routine"]["size_bytes"] != 321:
        fail("records routine size mismatch")
    if records["round_leaf"]["address"] != "0x63efe40":
        fail("records leaf address mismatch")
    if records["round_leaf"]["fde"] != "0x63efe40..0x63efeb1":
        fail("records leaf FDE mismatch")
    if records["round_leaf"]["size_bytes"] != 113:
        fail("records leaf size mismatch")
    if records["selector_call"]["site"] != "0x5a010a3":
        fail("records selector site mismatch")
    if records["selector_call"]["target"] != "0x5a01310":
        fail("records selector target mismatch")
    census = records["census"]
    if census["direct_call_count"] != 4:
        fail("records call count mismatch")
    if census["tail_jump_count"] != 0:
        fail("records census jump count mismatch")
    if census["stored_qword_count"] != 0:
        fail("records census stored count mismatch")
    if census["relative_addend_count"] != 0:
        fail("records census addend count mismatch")
    if census["direct_call_sites"] != EXPECTED_CALLS[0x5A00FC0]:
        fail("records call sites mismatch")
    if census["caller_constant"]["value"] != 0.1:
        fail("records caller constant mismatch")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_spot_scale_roundup_fc0_115.py"],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    if "checks pass" not in out:
        fail("model tests did not pass: %s" % out)


def main():
    check_digest()
    check_manifest()
    check_excerpts()
    check_spots()
    check_frames()
    check_relocations()
    check_constants()
    check_census()
    check_records()
    check_model_tests()
    print("ALL CHECKS PASSED")


if __name__ == "__main__":
    main()
