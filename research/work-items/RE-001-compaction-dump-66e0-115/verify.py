#!/usr/bin/env python3
"""Self-check for this work item.  Usage (from the repository root):
    python3 research/work-items/RE-001-compaction-dump-66e0-115/verify.py

Checks, in order (fails fast with a named check):
  1. artifact digest: work/hl-node-115.bin matches provenance/artifacts.json
  2. manifest: every packet file's SHA-256 matches MANIFEST.sha256
  3. excerpt regeneration: fresh objdump output is byte-for-byte the
     committed excerpt (the eight re-shipped excerpts were regenerated
     with the same command and diffed byte-for-byte against the source
     packets before committing)
  4. excerpt bytes: every instruction line's bytes match the raw binary
     at the mapped file offset (program-header mapping)
  5. FDE lines: every line of frames.txt appears in a fresh readelf dump
  6. census: a fresh census run reproduces callers.tsv and relocations.txt
  7. records + spot check: the JSON parses; the digit-pair table build
     is parsed from main.txt (both builds must agree with the
     chunks/store_offsets recorded in records.json and assemble to the
     model's table); three random instruction lines (random.Random(66))
     are verified byte-for-byte against a fresh objdump; the model
     reproduces the level-0 ratio correction (computed independently
     from the recorded formula) and a blob line rendered independently
     via the C library from the recorded format string
  8. model tests: tests/test_compaction_dump_66e0_115.py exits 0
  9. literals: the pinned .rodata format/label/throw strings and the
     pinned doubles match the raw binary
 10. section order: re-derived from main.txt — the direct call targets
     and the snprintf format addresses must appear in the recorded
     section order
"""

import ctypes
import ctypes.util
import hashlib
import json
import random
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"
PACKET = HERE

sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools"))
import census as census_mod
import compaction_dump_66e0_115 as model
import export_excerpts as export_mod

FAILURES = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (" " + detail if detail else ""))
    if not ok:
        FAILURES.append(name)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_segments(data):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    loads = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type, _f, p_offset, p_vaddr, _p, p_filesz, _m, _a = \
            struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1:
            loads.append((p_offset, p_vaddr, p_filesz))
    return loads


def vaddr_to_offset(loads, vaddr, size):
    for p_offset, p_vaddr, p_filesz in loads:
        if p_vaddr <= vaddr and vaddr + size <= p_vaddr + p_filesz:
            return p_offset + (vaddr - p_vaddr)
    return None


INSTR_RE = re.compile(r"^\s+([0-9a-f]+):\t([0-9a-f ]+?)(?:\t|$)")
CALL_RE = re.compile(r"call\s+([0-9a-f]+)\b")
FMT_LEA_RE = re.compile(r"lea\s+[^,]+,%r8\s+# ([0-9a-f]+)")
LOAD_RE = re.compile(r"movdqa\s+[^,]+,%(xmm\d+)\s+# ([0-9a-f]+)")
STORE_RE = re.compile(r"mov(?:aps|ups)\s+%(xmm\d+),0x([0-9a-f]+)\(%rsp\)")

LIBC = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def c_snprintf(fmt, *args):
    buf = ctypes.create_string_buffer(4096)
    cfmt = ctypes.create_string_buffer(fmt.encode())
    cargs = [ctype(value) for ctype, value in args]
    LIBC.snprintf(buf, 4096, cfmt, *cargs)
    return buf.value.decode()


def parse_table_build(start, stop, base):
    """Parse one digit-pair-table build from main.txt.

    Each movdqa loads one chunk into an xmm register and the matching
    movaps/movups stores it at base+offset, so the table is assembled
    by store offset, not by load order."""
    pending, pairs = {}, []
    for line in (PACKET / "main.txt").read_text().splitlines():
        m = INSTR_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        if not (start <= addr < stop):
            continue
        lm = LOAD_RE.search(line)
        if lm:
            pending[lm.group(1)] = int(lm.group(2), 16)
        sm = STORE_RE.search(line)
        if sm and sm.group(1) in pending:
            pairs.append((pending.pop(sm.group(1)),
                          int(sm.group(2), 16) - base))
    return sorted(pairs, key=lambda p: p[1])


def main():
    data = BIN.read_bytes()
    loads = load_segments(data)
    records = json.loads((PACKET / "records.json").read_text())

    # 1. artifact digest.
    artifacts = json.loads(
        (ROOT / "provenance" / "artifacts.json").read_text())
    want_digest = None
    for entry in artifacts.get("files", []):
        if entry.get("path", "") == "artifacts/node/115/hl-node":
            want_digest = entry["sha256"]
    assert want_digest is not None, "node #115 entry missing from artifacts.json"
    digest_ok = hashlib.sha256(data).hexdigest() == want_digest == \
        records["artifact"]["sha256"]
    check("artifact digest", digest_ok, records["artifact"]["sha256"][:12])

    # 2. manifest.
    manifest_ok = True
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        want, name = line.split(None, 1)
        if sha256_file(PACKET / name.strip()) != want:
            manifest_ok = False
            print("  manifest mismatch: %s" % name)
    check("manifest", manifest_ok)

    # 3. excerpt regeneration.
    regen_ok = True
    for name, (start, stop) in export_mod.EXCERPTS.items():
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=%#x" % start, "--stop-address=%#x" % stop,
             "work/hl-node-115.bin"],
            cwd=str(ROOT), check=True, capture_output=True, text=True).stdout
        if out != (PACKET / name).read_text():
            regen_ok = False
            print("  regeneration mismatch: %s" % name)
    check("excerpt regeneration", regen_ok,
          "%d excerpts" % len(export_mod.EXCERPTS))

    # 4. excerpt bytes vs the raw binary.
    bytes_ok = True
    n_instr = 0
    for name in sorted(export_mod.EXCERPTS):
        for line in (PACKET / name).read_text().splitlines():
            m = INSTR_RE.match(line)
            if not m:
                continue
            n_instr += 1
            addr = int(m.group(1), 16)
            raw = bytes.fromhex(m.group(2).replace(" ", ""))
            off = vaddr_to_offset(loads, addr, len(raw))
            if off is None or data[off:off + len(raw)] != raw:
                bytes_ok = False
                print("  byte mismatch at %#x in %s" % (addr, name))
    check("excerpt bytes", bytes_ok, "%d instructions" % n_instr)

    # 5. FDE lines.
    frames = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        check=True, capture_output=True, text=True).stdout
    fde_ok = all(
        line in frames
        for line in (PACKET / "frames.txt").read_text().splitlines() if line)
    check("FDE lines", fde_ok,
          "%d lines" % len((PACKET / "frames.txt").read_text().splitlines()))

    # 6. census reproduction.
    data2, exec_segs, loads2 = census_mod.load_segments()
    calls = census_mod.scan_calls(data2, exec_segs, census_mod.fde_ranges())
    stored = census_mod.scan_stored_qwords(data2, loads2)
    rels = census_mod.scan_relative_relocations()
    tsv_lines = ["target\tkind\tsite"]
    for _name, target in census_mod.TARGETS.items():
        for kind in ("call", "jmp"):
            for site in calls[target][kind]:
                tsv_lines.append("0x%x\t%s\t0x%x" % (target, kind, site))
    rel_lines = []
    for _name, target in census_mod.TARGETS.items():
        rel_lines.append("0x%x relative_records:%s" % (
            target, (" " + " ".join("0x%x" % o for o in rels[target]))
            if rels[target] else " none"))
        rel_lines.append("0x%x stored_qwords:%s" % (
            target, (" " + " ".join(
                "0x%x%s" % (v, " (in .rela.dyn, addend field)" if r else "")
                for v, r in stored[target])) if stored[target] else " none"))
    census_ok = \
        (PACKET / "callers.tsv").read_text() == "\n".join(tsv_lines) + "\n" and \
        (PACKET / "relocations.txt").read_text() == "\n".join(rel_lines) + "\n"
    check("census reproduction", census_ok)

    # 7. records + spot check.
    table_rec = records["decimal_conversion"]["digit_pair_table"]
    want_pairs = list(zip(
        [int(c, 16) for c in table_rec["chunks"]],
        table_rec["store_offsets"]))
    build1 = parse_table_build(0x5EF6A14, 0x5EF6AEC, 0x3F0)
    build2 = parse_table_build(0x5EF6CBE, 0x5EF6D93, 0x3F0)
    pairs_ok = build1 == want_pairs and build2 == want_pairs
    buf = bytearray(200)
    for src, off in build1:
        chunk = data[vaddr_to_offset(loads, src, 16):
                     vaddr_to_offset(loads, src, 16) + 16]
        buf[off:min(off + 16, 200)] = chunk[:max(0, 200 - off)]
    table_ok = bytes(buf) == model.DIGIT_TABLE
    # Three random instruction lines, byte-for-byte vs a fresh objdump.
    all_lines = []
    for name in sorted(export_mod.EXCERPTS):
        for line in (PACKET / name).read_text().splitlines():
            m = INSTR_RE.match(line)
            if m:
                all_lines.append((name, int(m.group(1), 16), line))
    rng = random.Random(records["spot_check"]["seed"])
    picked = rng.sample(all_lines, 3)
    spot_ok = True
    for name, addr, line in picked:
        out = subprocess.run(
            ["objdump", "-d",
             "--start-address=%#x" % addr,
             "--stop-address=%#x" % (addr + 16),
             "work/hl-node-115.bin"],
            cwd=str(ROOT), check=True, capture_output=True, text=True).stdout
        if line.strip() not in out:
            spot_ok = False
            print("  spot check failed at %#x in %s" % (addr, name))
    # Level-0 ratio correction, computed independently from the
    # recorded formula: (70+30)/(400+100) = 0.2, not 0.0.
    level = bytearray(192)
    level[0x28:0x30] = struct.pack("<q", 30)
    level[0x30:0x38] = struct.pack("<q", 70)
    ratio_ok = model.ratio_for_level(bytes(level), 0, 400, 100) == 100.0 / 500.0
    # Blob line rendered independently via the C library from the
    # recorded format string.
    fmt = records["formats"]["blob"]["format"]
    want_blob = c_snprintf(fmt, (ctypes.c_size_t, 7),
                           (ctypes.c_double, 3.0),
                           (ctypes.c_double, 1.0),
                           (ctypes.c_double, 1.5))
    blob_ok = model.blob_line(7, 3 * 2 ** 30, 1 * 2 ** 30) == want_blob
    check("records + spot check",
          pairs_ok and table_ok and spot_ok and ratio_ok and blob_ok,
          "pairs=%s table=%s spot=%s ratio=%s blob=%s" % (
              pairs_ok, table_ok, spot_ok, ratio_ok, blob_ok))

    # 8. model tests.
    proc = subprocess.run(
        [sys.executable, "tests/test_compaction_dump_66e0_115.py"],
        cwd=str(ROOT), capture_output=True, text=True)
    check("model tests", proc.returncode == 0,
          proc.stdout.strip().splitlines()[-1] if proc.stdout
          else proc.stderr[-200:])

    # 9. literals.
    def read_vaddr(addr, size):
        off = vaddr_to_offset(loads, addr, size)
        assert off is not None, hex(addr)
        return data[off:off + size]

    lit_ok = True
    for addr, want_bytes in (
            (0x44D03D, b"Level\x00"),
            (0x43F948, b"Sum\x00"),
            (0x441A38, b"Int\x00"),
            (0x43E67F, b"Priority\x00"),
            (0x44FD1A, b"Bottom\x00"),
            (0x43A5D9, b"Low\x00"),
            (0x4409FD, b"High\x00"),
            (0x4487BB, b"User\x00"),
            (0x432082, b"Invalid\x00"),
            (0x44DE6C, b"Write Stall (count): \x00"),
            (0x43C575, b"interval: \x00"),
            (0x433107, b" total count\n\x00"),
            (0x957C88, b"\nBlob file count: %zu, total size: %.1f GB, "
                       b"garbage size: %.1f GB, space amp: %.1f\n\n\x00"),
            (0x9621A8, b"Uptime(secs): %.1f total, %.1f interval\n\x00"),
            (0x95A548, b"Flush(GB): cumulative %.3f, interval %.3f\n\x00"),
            (0x9661B0, b"AddFile(GB): cumulative %.3f, interval %.3f\n\x00"),
            (0x964030, b"AddFile(Total Files): cumulative %lu, "
                       b"interval %lu\n\x00"),
            (0x9590D0, b"AddFile(L0 Files): cumulative %lu, "
                      b"interval %lu\n\x00"),
            (0x95CF78, b"AddFile(Keys): cumulative %lu, "
                      b"interval %lu\n\x00"),
            (0x964AA8, b"Cumulative compaction: %.2f GB write, "
                      b"%.2f MB/s write, %.2f GB read, %.2f MB/s read, "
                      b"%.1f seconds\n\x00"),
            (0x964B10, b"Interval compaction: %.2f GB write, "
                      b"%.2f MB/s write, %.2f GB read, %.2f MB/s read, "
                      b"%.1f seconds\n\x00")):
        if read_vaddr(addr, len(want_bytes)) != want_bytes:
            lit_ok = False
            print("  literal mismatch at %#x" % addr)
    for addr, want in ((0x459C48, 2.0 ** -30), (0x459638, 2.0 ** -20),
                       (0x4599A0, 1e6), (0x459AF0, 0.001)):
        got = struct.unpack("<d", read_vaddr(addr, 8))[0]
        if got != want:
            lit_ok = False
            print("  double mismatch at %#x: %r" % (addr, got))
    check("literals", lit_ok)

    # 10. section order re-derived from main.txt.
    calls = []
    fmts = []
    for line in (PACKET / "main.txt").read_text().splitlines():
        m = INSTR_RE.match(line)
        if not m:
            continue
        cm = CALL_RE.search(line)
        if cm:
            calls.append(int(cm.group(1), 16))
        fm = FMT_LEA_RE.search(line)
        if fm:
            fmts.append(int(fm.group(1), 16))
    want_calls = [0x5EEDDA0, 0x5EF1FA0, 0x5EED6F0, 0x5EED6F0, 0x5EF1630,
                  0x5EED6F0, 0x5EEDDA0, 0x5EF1D60, 0x5EED6F0, 0x5EF6280,
                  0x5EEFDA0]

    def is_subsequence(need, have):
        it = iter(have)
        return all(any(x == n for x in it) for n in need)

    want_fmts = [0x957C88, 0x9621A8, 0x95A548, 0x9661B0, 0x964030,
                 0x9590D0, 0x95CF78, 0x964AA8, 0x964B10]
    calls_ok = is_subsequence(want_calls, calls)
    fmts_ok = fmts == want_fmts
    check("section order", calls_ok and fmts_ok,
          "calls=%s fmts=%s" % (calls_ok, fmts_ok))

    print("ALL CHECKS PASSED" if not FAILURES
          else "FAILURES: %s" % ", ".join(FAILURES))
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
