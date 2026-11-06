#!/usr/bin/env python3
"""Self-check for this work item.  Usage (from the repository root):
    python3 research/work-items/RE-001-snapshot-consumer-8360-115/verify.py

Checks, in order (fails fast with a named check):
  1. artifact digest: work/hl-node-115.bin matches provenance/artifacts.json
  2. manifest: every packet file's SHA-256 matches MANIFEST.sha256
  3. excerpt regeneration: fresh objdump output is byte-for-byte the
     committed excerpt (the re-shipped excerpts were regenerated with the
     same command and diffed byte-for-byte against the source packets)
  4. excerpt bytes: every instruction line's bytes match the raw binary
     at the mapped file offset (program-header mapping)
  5. FDE lines: every line of frames.txt appears in a fresh readelf dump
  6. census: a fresh census run reproduces callers.tsv and relocations.txt
  7. records: the JSON parses and the model spot-check render matches
  8. model tests: tests/test_snapshot_consumer_8360_115.py exits 0
"""

import hashlib
import json
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
import export_excerpts as export_mod
import snapshot_consumer_8360_115 as model

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


def main():
    data = BIN.read_bytes()
    loads = load_segments(data)

    # 1. artifact digest
    prov = json.loads((ROOT / "provenance" / "artifacts.json").read_text())
    want = next(f["sha256"] for f in prov["files"]
                if f["path"] == "artifacts/node/115/hl-node")
    check("artifact digest", sha256_file(BIN) == want, want[:12])

    # 2. manifest
    manifest = {}
    for line in (PACKET / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, name = line.split(None, 1)
        manifest[name.strip()] = digest
    bad = [n for n, d in manifest.items()
           if sha256_file(PACKET / n) != d]
    extra = sorted(p.name for p in PACKET.iterdir()
                   if p.is_file() and p.name not in manifest
                   and p.name != "MANIFEST.sha256")
    check("manifest", not bad and not extra,
          "bad=%s extra=%s" % (bad, extra))

    # 3. excerpt regeneration
    regen_bad = []
    for name, (start, stop) in export_mod.EXCERPTS.items():
        out = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            cwd=str(ROOT), check=True, capture_output=True, text=True).stdout
        if (PACKET / name).read_text() != out:
            regen_bad.append(name)
    check("excerpt regeneration", not regen_bad, str(regen_bad))

    # 4. excerpt bytes vs raw binary
    n_lines = n_bad = 0
    for path in sorted(PACKET.glob("*.txt")):
        if path.name in ("frames.txt", "callers.tsv", "relocations.txt"):
            continue
        for line in path.read_text().splitlines():
            m = INSTR_RE.match(line)
            if not m:
                continue
            addr = int(m.group(1), 16)
            raw = bytes.fromhex(m.group(2).replace(" ", ""))
            n_lines += 1
            off = vaddr_to_offset(loads, addr, len(raw))
            if off is None or data[off:off + len(raw)] != raw:
                n_bad += 1
                if n_bad <= 5:
                    print("  byte mismatch %s:%#x" % (path.name, addr))
    check("excerpt bytes vs binary", n_bad == 0,
          "%d lines, %d bad" % (n_lines, n_bad))

    # 5. FDE lines
    frames_out = subprocess.run(
        ["readelf", "--debug-dump=frames-interp", str(BIN)],
        check=True, capture_output=True, text=True).stdout
    missing = [ln for ln in (PACKET / "frames.txt").read_text().splitlines()
               if ln.strip() and ln not in frames_out]
    check("FDE lines", not missing, str(missing))

    # 6. census reproduction
    cdata, exec_segs, cloads = census_mod.load_segments()
    calls = census_mod.scan_calls(cdata, exec_segs, census_mod.fde_ranges())
    stored = census_mod.scan_stored_qwords(cdata, cloads)
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
    tsv_ok = (PACKET / "callers.tsv").read_text().splitlines() == tsv_lines
    rel_ok = (PACKET / "relocations.txt").read_text().splitlines() == rel_lines
    check("census reproduction", tsv_ok and rel_ok,
          "tsv=%s rel=%s" % (tsv_ok, rel_ok))

    # 7. records + model spot check
    records = json.loads((PACKET / "records.json").read_text())
    spot = records["model_spot_checks"]["render"]
    rendered = model.build_map(dict(spot["snapshot"]), spot["slot_now"])
    check("model spot check", rendered == spot["expected"])

    # 8. model tests
    proc = subprocess.run(
        [sys.executable, "tests/test_snapshot_consumer_8360_115.py"],
        cwd=str(ROOT), capture_output=True, text=True)
    check("model tests", proc.returncode == 0,
          proc.stdout.strip().splitlines()[-1] if proc.stdout else proc.stderr[-200:])

    print("ALL CHECKS PASSED" if not FAILURES
          else "FAILURES: %s" % ", ".join(FAILURES))
    sys.exit(1 if FAILURES else 0)


if __name__ == "__main__":
    main()
