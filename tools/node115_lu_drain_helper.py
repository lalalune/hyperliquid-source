#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-drain-helper.

Reads only bytes from the node #115 binary; never executes it.
Checks: binary size + SHA-256, excerpt regeneration, strict
instruction counts, key bytes, whole-.text census for the drain /
accumulator / predicate, .rela.dyn GOT absence, the .rodata weight
table shape, disjointness from prior packets' exhibits, and
MANIFEST hashes. Exits 0 only if every check passes.
"""

import hashlib
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET = os.path.join(ROOT, "research", "work-items",
                      "RE-001-node115-lu-drain-helper")
BINARY = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
EXPECT_SHA = ("a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
EXPECT_SIZE = 105896032

# (name, start VA, end VA, strict instrs) — .text file offset = VA - 0x1000
EXHIBITS = [
    ("drain", 0x63697A0, 0x63697D2, 15),
    ("accum", 0x63A9712, 0x63A9742, 12),
    ("stub", 0x63BFB90, 0x63BFB98, 3),
]

# Prior packets' claimed ranges (must not overlap ours).
PRIOR = [
    (0x635DE30, 0x635DEC6),   # #202 fast-path exhibit
    (0x635C6D0, 0x635C886),   # #203 dispatch
    (0x635CDF8, 0x635CE47),   # #203 full
    (0x635CCE8, 0x635CD7F),   # #203 page
    (0x63EAEF0, 0x63EAF7E),   # #204 small_lock
    (0x63EB9D0, 0x63EBA48),   # #204 large_gate
    (0x63BD640, 0x63BD687),   # #204 push_large
    (0x63EC019, 0x63EC068),   # #204 large_tail
    (0x63C0340, 0x63C03E8),   # #205 push
    (0x63BD687, 0x63BD6B3),   # #205 flag_large
    (0x63612E6, 0x6361313),   # #205 flag_small
    (0x6360610, 0x636063A),   # #205 fallback_gate
    (0x635FB50, 0x635FB90),   # #206 inner_head
    (0x635FC30, 0x635FC76),   # #206 inner_branch
    (0x635FBAD, 0x635FBE5),   # #206 inner_call
    (0x636063A, 0x636066F),   # #206 gate_cont
    (0x6360680, 0x636069A),   # #206 gate_tail
    (0x635F4E0, 0x635F50B),   # #207 tail_lookup
    (0x635F523, 0x635F53E),   # #207 tail_pred
    (0x635F678, 0x635F68D),   # #207 tail_accum
    (0x635F610, 0x635F637),   # #207 tail_drain
    (0x635FBE5, 0x635FC1E),   # #207 tail_callsite
]

# (VA, expected bytes) — key-byte spot checks.
KEY_BYTES = [
    (0x63697A0, bytes.fromhex("f30f1efa")),   # drain endbr64
    (0x63697AB, bytes.fromhex("7410")),       # drain je -> signal path
    (0x63697B0, bytes.fromhex("e8db630500")),  # drain call -> stub
    (0x63697B5, bytes.fromhex("483dffe0f505")),  # cmp $0x5f5e0ff
    (0x63697BB, bytes.fromhex("7613")),       # jbe -> silent ret
    (0x63697BD, bytes.fromhex("488d7b08")),   # lea entry+8
    (0x63697C2, bytes.fromhex("e939800800")),  # jmp -> cond_signal@plt
    (0x63697D1, bytes.fromhex("c3")),         # drain ret
    (0x63A9714, bytes.fromhex("48f7f5")),     # accum div %rbp
    (0x63A9717, bytes.fromhex("483dc7000000")),  # cmp $0xc7
    (0x63A9724, bytes.fromhex("488d0d154a7ffa")),  # lea table
    (0x63A9737, bytes.fromhex("480fafc3")),   # imul %rbx,%rax
    (0x63A973B, bytes.fromhex("48c1e818")),   # shr $0x18
    (0x63BFB94, bytes.fromhex("488b07")),     # stub mov (%rdi),%rax
    (0x63BFB97, bytes.fromhex("c3")),         # stub ret
]

CENSUS = {
    0x63697A0: {"e8": [0x635F632, 0x635F645], "e9": [], "lea": []},
    0x63A96F0: {"e8": [0x635F681], "e9": [], "lea": []},
    0x6369790: {"e8": [0x635F526], "e9": [], "lea": []},
}

TABLE_VA = 0xB9E140  # .rodata: VA == file offset


def fail(msg):
    print(f"verifier: FAIL: {msg}")
    sys.exit(1)


def text_blob():
    out = subprocess.run(["readelf", "-SW", BINARY], capture_output=True,
                         text=True, check=True).stdout
    for line in out.splitlines():
        m = re.search(r"\.text\s+\w+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
                      line)
        if m:
            va, off, size = (int(x, 16) for x in m.groups())
            with open(BINARY, "rb") as f:
                f.seek(off)
                return va, f.read(size)
    fail("no .text section found")


def strict_count(objdump_lines):
    # address + byte field + tab + mnemonic; byte-continuation lines out
    pat = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S+")
    return sum(1 for ln in objdump_lines if pat.match(ln))


def main():
    if not os.path.exists(BINARY):
        fail(f"binary missing: {BINARY}")
    size = os.path.getsize(BINARY)
    if size != EXPECT_SIZE:
        fail(f"binary size {size} != {EXPECT_SIZE}")
    h = hashlib.sha256()
    with open(BINARY, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != EXPECT_SHA:
        fail("binary SHA-256 mismatch")

    text_va, blob = text_blob()

    def read(va, n):
        off = va - 0x1000
        out = subprocess.run(["od", "-An", "-tx1", "-j", str(off),
                              "-N", str(n), BINARY],
                             capture_output=True, text=True, check=True).stdout
        return bytes.fromhex(out.replace(" ", "").replace("\n", ""))

    for name, start, end, want_strict in EXHIBITS:
        with open(os.path.join(PACKET, f"{name}.hex"),
                  encoding="utf-8") as f:
            claimed = bytes.fromhex("".join(f.read().split()))
        if claimed != read(start, end - start):
            fail(f"{name}.hex does not match binary bytes")
        out = subprocess.run(
            ["objdump", "-d", f"--start-address={hex(start)}",
             f"--stop-address={hex(end)}", BINARY],
            capture_output=True, text=True, check=True).stdout
        lines = [ln for ln in out.splitlines()
                 if re.match(r"^\s*[0-9a-f]+:\t", ln)
                 and start <= int(ln.split(":")[0].strip(), 16) < end]
        with open(os.path.join(PACKET, f"{name}.objdump.txt"),
                  encoding="utf-8") as f:
            shipped = f.read().splitlines()
        if lines != shipped:
            fail(f"{name}.objdump.txt does not match objdump output")
        if strict_count(lines) != want_strict:
            fail(f"{name} strict count {strict_count(lines)} "
                 f"!= {want_strict}")

    for va, want in KEY_BYTES:
        if read(va, len(want)) != want:
            fail(f"key bytes mismatch at {hex(va)}")

    # Whole-.text census: one E8/E9 pass + one LEA pass per target set.
    targets = set(CENSUS)
    e8_found = {t: [] for t in targets}
    e9_found = {t: [] for t in targets}
    i = 0
    while True:
        i = blob.find(b"\xe8", i)
        if i < 0:
            break
        if i + 5 <= len(blob):
            disp = struct.unpack("<i", blob[i + 1:i + 5])[0]
            tgt = text_va + i + 5 + disp
            if tgt in targets:
                e8_found[tgt].append(text_va + i)
        i += 1
    i = 0
    while True:
        i = blob.find(b"\xe9", i)
        if i < 0:
            break
        if i + 5 <= len(blob):
            disp = struct.unpack("<i", blob[i + 1:i + 5])[0]
            tgt = text_va + i + 5 + disp
            if tgt in targets:
                e9_found[tgt].append(text_va + i)
        i += 1
    lea_found = {t: [] for t in targets}
    j = 0
    while True:
        j = blob.find(b"\x48\x8d", j)
        if j < 0 or j + 7 > len(blob):
            break
        if (blob[j + 2] & 0xC7) == 0x05:
            disp = struct.unpack("<i", blob[j + 3:j + 7])[0]
            if text_va + j + 7 + disp in targets:
                lea_found[text_va + j + 7 + disp].append(text_va + j)
        j += 1
    for tgt, want in CENSUS.items():
        if e8_found[tgt] != want["e8"]:
            fail(f"census E8 for {hex(tgt)}: {e8_found[tgt]} != {want['e8']}")
        if e9_found[tgt] != want["e9"]:
            fail(f"census E9 for {hex(tgt)}: {e9_found[tgt]}")
        if lea_found[tgt] != want["lea"]:
            fail(f"census LEA for {hex(tgt)}: {lea_found[tgt]}")

    # .rela.dyn: no RELATIVE addend may equal a census target.
    out = subprocess.run(["readelf", "-r", BINARY], capture_output=True,
                         text=True, check=True).stdout
    for line in out.splitlines():
        m = re.match(r"\s*[0-9a-f]+\s+[0-9a-f]+\s+R_X86_64_RELATIVE\s+"
                     r"([0-9a-f]+)", line)
        if m and int(m.group(1), 16) in targets:
            fail(f"GOT RELATIVE addend equals census target {m.group(1)}")

    # Weight table: 200 qwords, monotone, 20 -> 2**24.
    with open(BINARY, "rb") as f:
        f.seek(TABLE_VA)
        raw = f.read(200 * 8)
    vals = struct.unpack("<200q", raw)
    if len(vals) != 200 or vals[0] != 20 or vals[199] != 1 << 24:
        fail(f"table endpoints wrong: {vals[0]} .. {vals[199]}")
    if any(vals[k] > vals[k + 1] for k in range(199)):
        fail("table not monotone nondecreasing")

    # Disjointness from prior exhibits.
    for name, start, end, _ in EXHIBITS:
        for ps, pe in PRIOR:
            if start < pe and ps < end:
                fail(f"{name} range overlaps prior {hex(ps)}..{hex(pe)}")

    # MANIFEST hashes.
    man = os.path.join(PACKET, "MANIFEST.sha256")
    with open(man, encoding="utf-8") as f:
        entries = [ln.split() for ln in f.read().splitlines() if ln.strip()]
    if len(entries) != 11:
        fail(f"MANIFEST has {len(entries)} entries, want 11")
    for digest, rel in entries:
        p = os.path.normpath(os.path.join(PACKET, rel))
        with open(p, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != digest:
                fail(f"MANIFEST mismatch for {rel}")

    print("verifier: all checks passed (3 excerpts, "
          f"{sum(s for _, _, _, s in EXHIBITS)} strict, "
          "census drain 2 / accum 1 / pred 1 E8, table 200, MANIFEST 11/11)")


if __name__ == "__main__":
    main()
