#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-workers (packet #209).

Reads binary bytes only; never executes the node. Checks:
binary size + SHA-256, excerpt regeneration (hex + objdump),
strict mnemonic counts, key-byte sites, whole-.text census
(E8/E9/LEA/GOT), prior-range disjointness, MANIFEST hashes.
Exit 0 on success, 1 on any failure. No pipes are involved.
"""

import hashlib
import os
import re
import struct
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKET_DIR = os.path.join(ROOT, "research", "work-items",
                           "RE-001-node115-lu-workers")
BIN_PATH = os.path.join(ROOT, "artifacts", "node", "115", "hl-node")
EXPECTED_SHA = ("a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301")
EXPECTED_SIZE = 105896032

EXCERPTS = [
    ("wB_head", 0x63C1930, 0x63C195F, 16),
    ("wA_gate", 0x63C19CF, 0x63C19F2, 8),
    ("wA_mode", 0x63C1A1C, 0x63C1A32, 6),
    ("wA_call", 0x63C1A6E, 0x63C1A8E, 11),
    ("callee_gate", 0x63C1030, 0x63C106C, 22),
]

# (va, expected bytes) — address-cited claims, not shipped excerpts.
KEY_BYTES = [
    (0x63B0510, "f30f1efa488b87a8250000c3"),   # field loader body
    (0x635FBAD, "488d05041f3b00"),             # mode-2 lea .bss
    (0x635FBB4, "41b902000000"),               # mode-2 mov $0x2
    (0x635FBC2, "4129d1"),                     # mode-2 sub
    (0x635FC88, "488d0d291e3b00"),             # mode-0 lea (address only)
    (0x635FC8F, "4531c9"),                     # mode-0 xor r9d
    (0x635FC97, "e929ffffff"),                 # mode-0 jmp back to call setup
    (0x635FB6D, "807c245000"),                 # stack7 test
    (0x63C1936, "4589cf"),                     # workerB mode save
    (0x63C196E, "450fb6cf"),                   # workerB mode forward
    (0x63C1989, "e8a2f6ffff"),                 # workerB callee call
    (0x63C1AE1, "e84af5ffff"),                 # workerA ==0-path callee call
    (0x63C1AE7, "31c0"),                       # workerA ==0-path return 0
    (0x63C1A58, "4183f902"),                   # workerA mode-1 cmp $0x2
    (0x63C1A5C, "75d4"),                       # workerA mode-1 jne return
    (0x63C1A5E, "84c0"),                       # workerA mode-2 al test
    (0x63C1A60, "74d0"),                       # workerA mode-2 je return
    (0x63C1090, "e8dbfa0200"),                 # callee unlock call
    (0x63C1095, "488bbd08e40000"),             # callee ref+0xe408 load
    (0x63BFD17, "bf06000000"),                 # timestamp clock id 6
    (0x635FBD8, "e8c31d0600"),                 # inner workerA call
    (0x635FC71, "e8ba1c0600"),                 # inner workerB call
    (0x63C1A54, "c3"),                         # workerA main ret
    (0x63C199C, "c3"),                         # workerB ret
    (0x63C19F2, "488d7d70"),                   # workerA sum lea +0x70
    (0x63C19FB, "488dbd28260000"),             # workerA sum lea +0x2628
    (0x63C1948, "498d7870"),                   # workerB sum lea +0x70
    (0x63C195F, "488dbb28260000"),             # workerB sum lea +0x2628
    (0x63C1AA2, "31c0"),                       # workerA <0-path return 0
    (0x63C1068, "c6427001"),                   # callee latch set
    (0x63A9780, "ff10"),                       # compute GOT predicate call
    (0x63C1A17, "e8347dfeff"),                 # workerA compute call
    (0x63C19ED, "e8fee2ffff"),                 # workerA timestamp call
]

# (call-site va, expected target) for E8 rel32 verification.
CALL_TARGETS = [
    (0x635FBD8, 0x63C19A0), (0x6360F7C, 0x63C19A0),
    (0x63611EF, 0x63C19A0), (0x63C1BFC, 0x63C19A0),
    (0x635FC71, 0x63C1930), (0x63610A4, 0x63C1930),
    (0x63C1989, 0x63C1030), (0x63C1A89, 0x63C1030),
    (0x63C1AE1, 0x63C1030), (0x63C195A, 0x63B0510),
    (0x63C1969, 0x63B0510), (0x63C19F6, 0x63B0510),
    (0x63C1A05, 0x63B0510),
]

EXPECTED_CENSUS = {
    0x63C19A0: ([0x635FBD8, 0x6360F7C, 0x63611EF, 0x63C1BFC], [], []),
    0x63C1930: ([0x635FC71, 0x63610A4], [], []),
}

# Prior packets' claimed exhibit ranges (must not overlap ours).
PRIOR_RANGES = [
    (0x635DE30, 0x635DEC6), (0x5A8E3C0, 0x5A8E493),
    (0x5A8C9F0, 0x5A8CA2C), (0x5A8C110, 0x5A8C14C),
    (0x635C6D0, 0x635C886), (0x635CDF8, 0x635CE47),
    (0x635CCE8, 0x635CD7F), (0x63EAEF0, 0x63EAF7E),
    (0x63EB9D0, 0x63EBA48), (0x63BD640, 0x63BD687),
    (0x63EC019, 0x63EC068), (0x63C0340, 0x63C03E8),
    (0x63BD687, 0x63BD6B3), (0x63612E6, 0x6361313),
    (0x6360610, 0x636063A), (0x635FB50, 0x635FB90),
    (0x635FC30, 0x635FC76), (0x635FBAD, 0x635FBE5),
    (0x636063A, 0x636066F), (0x6360680, 0x636069A),
    (0x635F4E0, 0x635F50B), (0x635F523, 0x635F53E),
    (0x635F678, 0x635F68D), (0x635F610, 0x635F637),
    (0x635FBE5, 0x635FC1E), (0x63697A0, 0x63697D2),
    (0x63A9712, 0x63A9742), (0x63BFB90, 0x63BFB98),
]

STRICT_RE = re.compile(r"^\s*[0-9a-f]+:\t[0-9a-f ]+\t\S")


def load_binary():
    with open(BIN_PATH, "rb") as f:
        return f.read()


def va_bytes(data, va, n):
    off = va - 0x1000
    return data[off:off + n]


def objdump_body(start, end):
    out = subprocess.run(
        ["objdump", "-d", "--start-address=%s" % hex(start),
         "--stop-address=%s" % hex(end), BIN_PATH],
        capture_output=True, text=True, check=True).stdout
    body = []
    started = False
    for line in out.splitlines():
        if not started and re.match(r"^\s*[0-9a-f]+:\t", line):
            started = True
        if started:
            body.append(line)
    return body


def section_headers(data):
    e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, offset, size = struct.unpack_from(
            "<IIQQQQ", data, off)
        sections.append((name, typ, addr, offset, size))
    str_off = e_shoff + e_shstrndx * e_shentsize
    _, _, _, _, shstr_off, shstr_size = struct.unpack_from(
        "<IIQQQQ", data, str_off)
    shstr = data[shstr_off:shstr_off + shstr_size]

    def name_of(idx):
        end = shstr.index(b"\x00", idx)
        return shstr[idx:end].decode()

    return {name_of(n): (typ, addr, offset, size)
            for (n, typ, addr, offset, size) in sections}


def census(data):
    secs = section_headers(data)
    _, text_addr, text_off, text_size = secs[".text"]
    e8 = {t: [] for t in EXPECTED_CENSUS}
    e9 = {t: [] for t in EXPECTED_CENSUS}
    lea = {t: [] for t in EXPECTED_CENSUS}
    blob = data[text_off:text_off + text_size]
    va = text_addr
    end = text_addr + text_size
    i = 0
    while va < end:
        op = blob[i]
        if op in (0xE8, 0xE9):
            rel = struct.unpack_from("<i", blob, i + 1)[0]
            tgt = va + 5 + rel
            if tgt in EXPECTED_CENSUS:
                (e8 if op == 0xE8 else e9)[tgt].append(va)
            va += 5
            i += 5
        elif op in (0x48, 0x4C) and blob[i + 1] == 0x8D:
            modrm = blob[i + 2]
            if (modrm & 0xC7) == 0x05:
                rel = struct.unpack_from("<i", blob, i + 3)[0]
                tgt = va + 7 + rel
                if tgt in EXPECTED_CENSUS:
                    lea[tgt].append(va)
                va += 7
                i += 7
            else:
                va += 1
                i += 1
        else:
            va += 1
            i += 1
    # .rela.dyn RELATIVE addends (type 8 on x86-64).
    _, _, rela_off, rela_size = secs[".rela.dyn"]
    got = []
    for j in range(0, rela_size, 24):
        r_offset, r_info, r_addend = struct.unpack_from(
            "<QQq", data, rela_off + j)
        if (r_info & 0xFFFFFFFF) == 8 and r_addend in EXPECTED_CENSUS:
            got.append((hex(r_offset), hex(r_addend)))
    return e8, e9, lea, got


def check_manifest():
    manifest = os.path.join(PACKET_DIR, "MANIFEST.sha256")
    with open(manifest, encoding="utf-8") as f:
        entries = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            digest, path = line.split(None, 1)
            entries.append((digest, path))
    for digest, path in entries:
        full = os.path.normpath(os.path.join(PACKET_DIR, path))
        with open(full, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        if actual != digest:
            return False, "MANIFEST mismatch: %s" % path
    return True, "%d entries" % len(entries)


def run_checks(data):
    failures = []
    if len(data) != EXPECTED_SIZE:
        failures.append("binary size %d != %d" % (len(data), EXPECTED_SIZE))
    if hashlib.sha256(data).hexdigest() != EXPECTED_SHA:
        failures.append("binary SHA mismatch")
    for name, start, end, strict in EXCERPTS:
        raw = va_bytes(data, start, end - start)
        with open(os.path.join(PACKET_DIR, name + ".hex"),
                  encoding="utf-8") as f:
            claimed = bytes.fromhex("".join(f.read().split()))
        if claimed != raw:
            failures.append("hex mismatch: %s" % name)
        body = objdump_body(start, end)
        with open(os.path.join(PACKET_DIR, name + ".objdump.txt"),
                  encoding="utf-8") as f:
            shipped = f.read().splitlines()
        if shipped != body:
            failures.append("objdump mismatch: %s" % name)
        got_strict = sum(1 for ln in body if STRICT_RE.match(ln))
        if got_strict != strict:
            failures.append("strict count %s: %d != %d"
                            % (name, got_strict, strict))
    for va, hexstr in KEY_BYTES:
        if va_bytes(data, va, len(bytes.fromhex(hexstr))).hex() != hexstr:
            failures.append("key bytes mismatch at %#x" % va)
    for va, tgt in CALL_TARGETS:
        raw = va_bytes(data, va, 5)
        if raw[0] != 0xE8:
            failures.append("not E8 at %#x" % va)
            continue
        got = va + 5 + struct.unpack("<i", raw[1:5])[0]
        if got != tgt:
            failures.append("call target %#x -> %#x != %#x" % (va, got, tgt))
    e8, e9, lea, got = census(data)
    for tgt, (exp_e8, exp_e9, exp_lea) in EXPECTED_CENSUS.items():
        if e8[tgt] != exp_e8 or e9[tgt] != exp_e9 or lea[tgt] != exp_lea:
            failures.append("census mismatch at %#x: E8 %s E9 %s LEA %s"
                            % (tgt, e8[tgt], e9[tgt], lea[tgt]))
    if got:
        failures.append("GOT hits: %s" % got)
    for name, start, end, _ in EXCERPTS:
        for ps, pe in PRIOR_RANGES:
            if start < pe and ps < end:
                failures.append("overlap %s with prior %#x..%#x"
                                % (name, ps, pe))
    ok, msg = check_manifest()
    if not ok:
        failures.append(msg)
    return failures, msg


def main():
    data = load_binary()
    failures, manifest_msg = run_checks(data)
    if failures:
        for f in failures:
            print("FAIL: %s" % f)
        return 1
    total_bytes = sum(e - s for _, s, e, _ in EXCERPTS)
    total_strict = sum(s for *_, s in EXCERPTS)
    print("verifier: all checks passed (%d excerpts, %d key-byte sites, "
          "census %d E8 sites, MANIFEST %s)"
          % (len(EXCERPTS), len(KEY_BYTES),
             sum(len(v[0]) for v in EXPECTED_CENSUS.values()), manifest_msg))
    print("verifier: exhibit totals %d bytes, %d strict mnemonics"
          % (total_bytes, total_strict))
    return 0


if __name__ == "__main__":
    sys.exit(main())
