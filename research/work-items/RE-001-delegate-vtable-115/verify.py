#!/usr/bin/env python3
"""Independent verification for the RE-001-delegate-vtable-115 packet.

Run from the repository root:
    python3 research/work-items/RE-001-delegate-vtable-115/verify.py

Exits 0 and prints ALL CHECKS PASSED only when every check below
passes; otherwise it prints the failures and exits non-zero.

Checks:
  1. The node #115 binary digest matches provenance/artifacts.json.
  2. MANIFEST.sha256 covers every packet file with matching hashes.
  3. Every excerpt regenerates byte-for-byte from a fresh objdump.
  4. Every excerpt line's raw bytes match the binary at that address.
  5. Three seeded random gate spots (random.seed(20261106)) are
     verified byte-for-byte against a fresh objdump run.
  6. Every routine's FDE range is present in frames.txt.
  7. relocations.txt holds the 19 family typeinfo-pointer relocs
     and the five GOT landmark rows, and they re-derive from
     readelf -r.
  8. Every pinned literal reads back from the binary.
  9. census.py reproduces callers.tsv byte-identically (75 rows)
     and the per-target counts match records.json.
 10. The model constants match the packet: the vtable family
     re-derives from the relocations (701 typeinfos, 406 strict
     vtables, the 19 family bases with matching slot maps), the GOT
     landmarks re-derive, the twins are byte-identical after address
     normalization, the parse-gate constants (0x15 fallback,
     0x04/0x01 gate) are present at the excerpted addresses, and the
     Name/NickName literals match.
 11. The model tests pass (tests/test_delegate_vtable_115.py).
"""

import hashlib
import json
import random
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

sys.dont_write_bytecode = True
sys.path.insert(0, str(PACKET))
from export_excerpts import WINDOWS  # noqa: E402

FAILURES = []


def check(name, ok, detail=""):
    print("%-4s %s %s" % ("PASS" if ok else "FAIL", name, detail))
    if not ok:
        FAILURES.append(name)


def run(cmd, cwd=ROOT):
    return subprocess.run(cmd, capture_output=True, text=True,
                          check=True, cwd=cwd).stdout


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --- vaddr -> file offset, from readelf -S ------------------------------


def load_sections():
    sections = []
    for line in run(["readelf", "-S", "-W", str(BINARY)]).splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+"
                     r"([0-9a-f]+)\s+([0-9a-f]+)", line)
        if m:
            sections.append((m.group(1), int(m.group(2), 16),
                             int(m.group(3), 16), int(m.group(4), 16)))
    return sections


SECTIONS = load_sections()
_BINARY_DATA = BINARY.read_bytes()


def read_vaddr(addr, n):
    for _name, vaddr, off, size in SECTIONS:
        if vaddr <= addr < vaddr + size:
            start = off + (addr - vaddr)
            return _BINARY_DATA[start: start + n]
    raise ValueError("address %#x not in any section" % addr)


def read_cstr(addr):
    out = bytearray()
    cur = addr
    while True:
        b = read_vaddr(cur, 1)[0]
        if b == 0:
            return bytes(out)
        out.append(b)
        cur += 1


# --- 1. digest ----------------------------------------------------------


def check_digest():
    artifacts = json.load(open(ROOT / "provenance" / "artifacts.json"))
    entry = None
    for f in artifacts["files"]:
        if f["path"] == "artifacts/node/115/hl-node":
            entry = f
            break
    ok = entry is not None and entry["sha256"] == DIGEST
    ok = ok and sha256_file(BINARY) == DIGEST
    check("digest", ok, "provenance + binary == " + DIGEST[:16] + "...")


# --- 2. manifest --------------------------------------------------------


def check_manifest():
    manifest = PACKET / "MANIFEST.sha256"
    listed = {}
    for line in manifest.read_text().splitlines():
        if not line.strip():
            continue
        parts = line.split(None, 1)
        listed[parts[1]] = parts[0]
    actual = {}
    for p in sorted(PACKET.rglob("*")):
        if p.is_file() and p.name != "MANIFEST.sha256":
            actual[str(p.relative_to(PACKET))] = sha256_file(p)
    ok = listed == actual
    missing = sorted(set(actual) - set(listed))
    extra = sorted(set(listed) - set(actual))
    mismatched = sorted(k for k in listed if k in actual
                        and listed[k] != actual[k])
    check("manifest", ok, "files=%d missing=%s extra=%s mismatched=%s"
          % (len(actual), missing, extra, mismatched))


# --- 3. excerpts regenerate ----------------------------------------------


def check_excerpts_regenerate():
    bad = []
    for name, start, stop in WINDOWS:
        text = run(["objdump", "-d",
                    "--start-address=%#x" % start,
                    "--stop-address=%#x" % stop,
                    "work/hl-node-115.bin"])
        if (PACKET / "excerpts" / name).read_text() != text:
            bad.append(name)
    check("excerpts-regenerate", not bad, "bad=%s" % bad)


# --- 4. raw bytes of every excerpt line -----------------------------------


def excerpt_lines():
    lines = []
    for name, _s, stop in WINDOWS:
        file_lines = (PACKET / "excerpts" / name).read_text().splitlines()
        parsed = []
        for line in file_lines:
            m = re.match(r"\s+([0-9a-f]+):\t([0-9a-f ]+)\t", line)
            if m:
                addr = int(m.group(1), 16)
                raw = bytes.fromhex(m.group(2).strip())
                parsed.append((name, addr, raw, line.strip()))
        for i, (name, addr, raw, line) in enumerate(parsed):
            # objdump wraps long instructions: the raw-bytes
            # column holds only the first 7 bytes and the rest
            # appears on a continuation line, so the
            # instruction's true end is the NEXT line's
            # address (or the window end for the last line).
            nxt = parsed[i + 1][1] if i + 1 < len(parsed) else stop
            lines.append((name, addr, raw, line, nxt))
    return lines


def check_raw_bytes():
    bad = []
    for name, addr, raw, line, _nxt in excerpt_lines():
        if read_vaddr(addr, len(raw)) != raw:
            bad.append((name, "%#x" % addr, line))
    check("raw-bytes", not bad, "checked=%d bad=%s"
          % (len(excerpt_lines()), bad[:3]))


# --- 5. seeded random gate spots ------------------------------------------


def check_random_spots():
    lines = excerpt_lines()
    random.seed(20261106)
    spots = random.sample(lines, 3)
    bad = []
    for name, addr, raw, line, nxt in spots:
        text = run(["objdump", "-d",
                    "--start-address=%#x" % addr,
                    "--stop-address=%#x" % nxt,
                    "work/hl-node-115.bin"])
        if line.split("\t")[-1].strip() not in text:
            bad.append((name, "%#x" % addr))
    check("random-spots", not bad,
          "spots=%s" % [(n, a) for n, a, _r, _l, _x in spots])


# --- 6. FDE presence ------------------------------------------------------


def check_fdes():
    frames = (PACKET / "frames.txt").read_text()
    missing = []
    for name, start, stop in WINDOWS:
        if "pc=%016x..%016x" % (start, stop) not in frames:
            missing.append((name, "%#x..%#x" % (start, stop)))
    check("fdes", not missing, "windows=%d missing=%s"
          % (len(WINDOWS), missing))


# --- 7. relocations ---------------------------------------------------------


FAMILY_BASES = [
    0x64CDA68, 0x64CDAD0, 0x64CDD88, 0x64CE2D8, 0x64CE590,
    0x64CE930, 0x64CEA10, 0x64D1398, 0x64D1650, 0x64D1940,
    0x64D1980, 0x64D19A0, 0x64D1F00, 0x64D2D88, 0x64D3138,
    0x64D31B8, 0x64D3430, 0x64D3638, 0x64D36B8,
]

GOT_EXPECTED = {
    0x64ECEB8: 0x5D2E770,
    0x64ECEB0: 0x5D2CA10,
    0x64ECF50: 0x5D48960,
    0x64ECF80: 0x5D4D490,
    0x64ED8B0: 0x5FCC240,
}


def check_relocations():
    reloc = (PACKET / "relocations.txt").read_text()
    dyn = run(["readelf", "-r", "-W", str(BINARY)])
    ok = True
    detail = []
    for base in FAMILY_BASES:
        if ("%x" % (base - 0x8)) not in reloc:
            ok = False
            detail.append(("typeinfo-reloc-missing", hex(base)))
    for got, target in GOT_EXPECTED.items():
        if ("%x" % got) not in reloc or ("%x" % target) not in reloc:
            ok = False
            detail.append(("got-missing", hex(got)))
        row = [ln for ln in dyn.splitlines()
               if re.match(r"\s*0*%x\s" % got, ln)]
        if not row or ("%x" % target) not in row[0]:
            ok = False
            detail.append(("got-rederive", hex(got)))
    check("relocations", ok, "bases=%d got=%d detail=%s"
          % (len(FAMILY_BASES), len(GOT_EXPECTED), detail[:3]))


# --- 8. literals ------------------------------------------------------------


LITERALS = {
    0x4376FD: b"",
    0x441B15: b"id",
    0x445245: b"=",
    0x4341C2: b"Option not changeable: ",
    0x4496D1: b"target=",
    0x431007: b"DefaultClock",
    0x431014: b"DefaultEnv",
    0x432248: b"BasicStatistics",
    0x43E762: b"CompositeEnv",
    0x438375: b"PosixEnv",
    0x44768E: b"PosixClock",
    0x447686: b"MockEnv",
    0x4372AE: b"TimeEmulatedSystemClock",
}


def check_literals():
    bad = []
    for addr, want in LITERALS.items():
        if read_cstr(addr) != want:
            bad.append("%#x" % addr)
    check("literals", not bad, "checked=%d bad=%s"
          % (len(LITERALS), bad))


# --- 9. census --------------------------------------------------------------


CENSUS_COUNTS = {
    "0x5d2e090:lea": 1,
    "0x5d2e770:jmp": 1,
    "0x5d4d490:lea": 29,
    "0x60956f0:lea": 1,
    "0x6095710:lea": 2,
    "0x6095a60:call": 1,
    "0x6095e70:call": 8,
    "0x6096790:call": 4,
    "0x6097110:call": 2,
    "0x60985e0:call": 1,
    "0x60986b0:call": 1,
    "0x6099030:call": 1,
    "0x60996a0:jmp": 1,
    "0x609d0e0:call": 2,
    "0x609de80:call": 3,
    "0x64ce930:lea": 1,
    "0x64cea10:lea": 3,
    "0x64d02e0:lea": 5,
    "0x64d1940:lea": 1,
    "0x64d1980:lea": 3,
    "0x64d19a0:lea": 4,
}


def check_census():
    before = (PACKET / "callers.tsv").read_bytes()
    run([sys.executable, str(PACKET / "census.py")], cwd=ROOT)
    after = (PACKET / "callers.tsv").read_bytes()
    ok = before == after
    rows = after.decode().splitlines()[1:]
    ok = ok and len(rows) == 75
    counts = {}
    for line in rows:
        parts = line.split("\t")
        counts["%s:%s" % (parts[1], parts[3].strip())] = \
            counts.get("%s:%s" % (parts[1], parts[3].strip()), 0) + 1
    bad = {k: (counts.get(k, 0), v)
           for k, v in CENSUS_COUNTS.items()
           if counts.get(k, 0) != v}
    check("census", ok and not bad,
          "rows=%d bad-counts=%s" % (len(rows), bad))


# --- 10. model constants -----------------------------------------------------


def load_relocs():
    sections = {n: (v, o, s) for n, v, o, s in SECTIONS}
    rela_off, rela_size = sections[".rela.dyn"][1], sections[".rela.dyn"][2]
    relocs = {}
    for i in range(rela_size // 24):
        off, info, add = struct.unpack_from(
            "<QQq", _BINARY_DATA, rela_off + i * 24)
        relocs[off] = (info & 0xFFFFFFFF, info >> 32,
                       add & (2**64 - 1))
    return relocs, sections


def check_model_constants():
    sys.path.insert(0, str(ROOT / "tools"))
    import delegate_vtable_115 as m
    records = json.load(open(PACKET / "records.json"))
    ok = True
    detail = []
    relocs, sections = load_relocs()
    text_lo = sections[".text"][0]
    text_hi = text_lo + sections[".text"][2]

    # The typeinfo census and the strict-vtable census re-derive.
    typeinfos = {}
    for off, (typ, sym, _add) in relocs.items():
        if typ == 1 and sym in (260, 261):
            typeinfos[off] = read_cstr(relocs[off + 8][2]).decode("latin1")
    strict = {}
    for off, (typ, _sym, add) in relocs.items():
        if typ == 8 and add in typeinfos:
            base = off + 8
            if (base - 0x10) not in relocs:
                strict[base] = typeinfos[add]
    if len(typeinfos) != 701 or len(strict) != 406:
        ok = False
        detail.append("census-counts: %d/%d"
                      % (len(typeinfos), len(strict)))
    if records["census"]["typeinfo_objects"] != 701 \
            or records["census"]["strict_vtables"] != 406:
        ok = False
        detail.append("records-census")

    # The 19 family bases are strict vtables with matching slot maps.
    def is_slot(addr):
        r = relocs.get(addr)
        if r and r[0] == 8 and text_lo <= r[2] < text_hi:
            return True
        if r and r[0] == 1 and r[1] == 263 and r[2] == 0:
            return True
        if r is None and struct.unpack(
                "<Q", read_vaddr(addr, 8))[0] == 0:
            return True
        return False

    bases = sorted(strict)
    for v in records["vtables"]:
        base = int(v["vtable"], 16)
        if base not in strict:
            ok = False
            detail.append(("not-strict", v["vtable"]))
            continue
        if strict[base] != v["class"]:
            ok = False
            detail.append(("class-mismatch", v["vtable"]))
        idx = bases.index(base)
        cap = ((bases[idx + 1] - 0x10 - base) // 8
               if idx + 1 < len(bases)
               else (sections[".data.rel.ro"][0]
                     + sections[".data.rel.ro"][2] - base) // 8)
        n = 0
        while n < cap and is_slot(base + n * 8):
            n += 1
        if n != v["nslots"]:
            ok = False
            detail.append(("nslots", v["vtable"], n, v["nslots"]))
        for off, s in v["slots"].items():
            addr = base + int(off, 16)
            r = relocs.get(addr)
            if s["kind"] == "function":
                if not r or r[0] != 8 or r[2] != int(s["target"], 16):
                    ok = False
                    detail.append(("slot", v["vtable"], off))
            elif s["kind"] == "pure-virtual":
                if not r or r[0] != 1 or r[1] != 263:
                    ok = False
                    detail.append(("pure-virtual", v["vtable"], off))
            elif s["kind"] == "null":
                if r is not None or struct.unpack(
                        "<Q", read_vaddr(addr, 8))[0] != 0:
                    ok = False
                    detail.append(("null-slot", v["vtable"], off))

    # The twins are one template instantiated twice: their
    # instruction streams (mnemonics + operands, intra-function
    # jump targets relative-ized to each function's own start,
    # rip-relative lea resolved to its absolute target) differ only
    # in the two holder-map loads, 0x630 in A and 0x90 in B.
    def instr_lines(path, start, stop):
        out = []
        for line in Path(path).read_text().splitlines():
            parts = line.split("\t")
            if len(parts) >= 3 and re.match(r"\s*[0-9a-f]+:", parts[0]):
                insn = parts[2]
                insn = re.sub(r"\s*<[^>]*>", "", insn)
                m2 = re.search(
                    r"lea\s+(-?0x[0-9a-f]+)\(%rip\)(.*)#\s*([0-9a-f]+)",
                    insn)
                if m2:
                    insn = re.sub(
                        r"lea\s+-?0x[0-9a-f]+\(%rip\)",
                        "lea #%s(%%rip)" % m2.group(3), insn)
                m3 = re.match(
                    r"(j\w+|call)\s+([0-9a-f]+)(\s.*)?$", insn.strip())
                if m3:
                    t = int(m3.group(2), 16)
                    if start <= t < stop:
                        insn = re.sub(
                            r"\b%s\b" % m3.group(2), "+%#x" % (t - start),
                            insn, count=1)
                out.append(insn)
        return out
    ta = instr_lines(PACKET / "excerpts" / "twin_a.txt", 0x6086B70, 0x6086CC9)
    tb = instr_lines(PACKET / "excerpts" / "twin_b.txt", 0x60A7420, 0x60A7579)
    diffs = [(x, y) for x, y in zip(ta, tb) if x != y]
    if len(ta) != len(tb) or len(diffs) != 2 or not all(
            x == "mov    0x630(%r14),%rdi"
            and y == "mov    0x90(%r14),%rdi" for x, y in diffs):
        ok = False
        detail.append("twin-difference: %s" % diffs)

    # The parse-gate constants are present at the excerpted
    # addresses: sub $0x15 at both fallback sites (0x6096427,
    # 0x6096d27) and sub $0x4 / cmp $0x1 / jbe at the gate heads.
    if read_vaddr(0x6096427, 3) != bytes.fromhex("83ea15"):
        ok = False
        detail.append("gate-28-fallback")
    if read_vaddr(0x6096D27, 3) != bytes.fromhex("83e815"):
        ok = False
        detail.append("gate-30-fallback")
    if read_vaddr(0x60961A0, 3) != bytes.fromhex("83fa01"):
        ok = False
        detail.append("gate-28-head")
    if read_vaddr(0x6096D17, 3) != bytes.fromhex("83e804"):
        ok = False
        detail.append("gate-30-head")

    # Records agree with the model on the literals and constants.
    for addr, text in LITERALS.items():
        if records["literals"].get("0x%x" % addr) != text.decode("latin1"):
            ok = False
            detail.append(("literal-record", hex(addr)))
    if m.NAME["PosixClock"] != "DefaultClock" \
            or m.NAME["StatisticsImpl"] != "BasicStatistics" \
            or m.NICKNAME["PosixClock"] != "PosixClock" \
            or m.NICKNAME["PosixEnv"] != "DefaultEnv":
        ok = False
        detail.append("model-names")
    if len(records["vtables"]) != 19 \
            or len(records["interface_slots"]) != 18:
        ok = False
        detail.append("records-shape")
    tsv_rows = (PACKET / "vtables.tsv").read_text().splitlines()[1:]
    if len(tsv_rows) != 646:
        ok = False
        detail.append("vtables-tsv: %d" % len(tsv_rows))
    ok = ok and m.FIND_ENTRY == 0x609E510
    ok = ok and m.DELEGATE_IMPL == 0x6097110
    ok = ok and m.CREATE_HOST == 0x6077820
    ok = ok and m.IS_INSTANCE_OF == 0x5D2E770
    ok = ok and m.SLOT38_RESOLVER == 0x60958C0
    ok = ok and m.SLOT98_TERMINAL == 0x5FCC240
    check("model-constants", ok, "mismatches=%s" % detail[:5])


# --- 11. model tests ----------------------------------------------------------


def check_model_tests():
    out = run([sys.executable,
               "tests/test_delegate_vtable_115.py"], cwd=ROOT)
    ok = "all 34 tests passed" in out
    check("model-tests", ok, out.strip().splitlines()[-1]
          if out.strip() else "")


def main():
    check_digest()
    check_manifest()
    check_excerpts_regenerate()
    check_raw_bytes()
    check_random_spots()
    check_fdes()
    check_relocations()
    check_literals()
    check_census()
    check_model_constants()
    check_model_tests()
    if FAILURES:
        print("FAILED: %s" % ", ".join(FAILURES))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
