#!/usr/bin/env python3
"""Verify the RE-001-thread-local-dtor-registration-115 packet.

Checks, all against the real node #115 binary (work/hl-node-115.bin):
  1. binary SHA-256 matches provenance/artifacts.json (artifacts/node/115/hl-node)
  2. excerpts regenerate byte-for-byte (export_excerpts.py into a temp dir)
  3. census reproduces callers.tsv exactly (census.py --full-objdump-check)
  4. records.json regenerates byte-for-byte (gen_records.py)
  5. frames.txt matches the unwind (FDE) index
  6. relocations.txt matches fresh `readelf -r` output
  7. three seeded random gate spots verify byte-for-byte against a fresh
     objdump run AND against the raw binary bytes at the mapped file offset
  8. MANIFEST.sha256 matches every packet file
  9. the model tests pass (tests/test_thread_local_dtor_registration_115.py)

Usage: python3 verify.py
"""
import hashlib
import json
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
BIN = ROOT / "work" / "hl-node-115.bin"
PROV = ROOT / "provenance" / "artifacts.json"
MODEL_TEST = ROOT / "tests" / "test_thread_local_dtor_registration_115.py"

FAILURES = []


def check(name, ok, detail=""):
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail else ""))
    if not ok:
        FAILURES.append(name)


def load_segments():
    """Return [(vaddr, offset, filesz)] for PT_LOAD segments, via readelf.
    Each LOAD entry spans two lines: the first carries offset/vaddr/paddr,
    the second carries filesz/memsz/flags."""
    out = subprocess.run(["readelf", "-l", str(BIN)], capture_output=True,
                         text=True, check=True).stdout
    lines = out.splitlines()
    segs = []
    for i, line in enumerate(lines):
        m = re.match(r"\s*LOAD\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)", line)
        if not m:
            continue
        m2 = re.match(r"\s*0x([0-9a-f]+)\s+0x([0-9a-f]+)", lines[i + 1])
        assert m2, f"no filesz line after LOAD at readelf line {i}"
        segs.append((int(m.group(2), 16), int(m.group(1), 16), int(m2.group(1), 16)))
    return segs


def vaddr_to_offset(segs, vaddr):
    for v, o, fsz in segs:
        if v <= vaddr < v + fsz:
            return o + (vaddr - v)
    return None


def main():
    data = BIN.read_bytes()
    prov = json.loads(PROV.read_text())
    entry = next(e for e in prov["files"] if e["path"] == "artifacts/node/115/hl-node")
    check("artifact digest", hashlib.sha256(data).hexdigest() == entry["sha256"],
          entry["sha256"][:16] + "...")

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        # 2. excerpts regenerate byte-for-byte
        subprocess.run([sys.executable, str(HERE / "export_excerpts.py"),
                        "--out", str(td / "excerpts")],
                       check=True, capture_output=True)
        got = sorted(p.name for p in (td / "excerpts").iterdir())
        want = sorted(p.name for p in (HERE / "excerpts").iterdir())
        same = got == want and all(
            (td / "excerpts" / n).read_bytes() == (HERE / "excerpts" / n).read_bytes()
            for n in want)
        check("excerpts regenerate byte-for-byte", same, f"{len(want)} files")

        # 3. census reproduces callers.tsv (includes the full-objdump cross-check)
        subprocess.run([sys.executable, str(HERE / "census.py"), "--full-objdump-check",
                        "--out", str(td / "callers.tsv")],
                       check=True, capture_output=True)
        check("census reproduces callers.tsv",
              (td / "callers.tsv").read_bytes() == (HERE / "callers.tsv").read_bytes())

        # 4. records.json regenerates byte-for-byte
        before = (HERE / "records.json").read_bytes()
        subprocess.run([sys.executable, str(HERE / "gen_records.py")],
                       check=True, capture_output=True)
        check("records.json regenerates byte-for-byte",
              (HERE / "records.json").read_bytes() == before)
        rec = json.loads((HERE / "records.json").read_text())
        check("records.json consistent",
              rec["census"]["sites"] == 1153
              and rec["census"]["distinct_caller_fdes"] == 604
              and len(rec["destructors"]) == 28
              and rec["artifact_sha256"] == entry["sha256"],
              "1153 sites / 604 FDEs / 28 dtors")

    # 5. frames.txt matches the FDE index (recomputed from the binary)
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(HERE))
    import census
    starts, ends = census.fde_table(data)
    import bisect
    frames_ok = True
    for line in (HERE / "frames.txt").read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        s, e, _name = line.split(None, 2)
        s, e = int(s, 16), int(e, 16)
        i = bisect.bisect_right(starts, s) - 1
        if starts[i] != s or ends[i] != e:
            frames_ok = False
    check("frames.txt matches FDE index", frames_ok)

    # 6. relocations.txt matches fresh readelf -r
    reloc = subprocess.run(["readelf", "-r", str(BIN)], capture_output=True,
                           text=True, check=True).stdout.splitlines()
    reloc_ok = True
    for line in (HERE / "relocations.txt").read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if line.strip() not in [r.rstrip() for r in reloc]:
            reloc_ok = False
    check("relocations.txt matches readelf -r", reloc_ok)

    # 7. three seeded random gate spots, byte-for-byte vs fresh objdump + raw binary
    rng = random.Random(115)
    excerpt_files = sorted((HERE / "excerpts").glob("*.txt"))
    segs = load_segments()
    ins_re = re.compile(r"^\s*([0-9a-f]+):\t((?:[0-9a-f]{2} )+)\s*\t(.*)$")
    spots = []
    for _ in range(3):
        f = rng.choice(excerpt_files)
        lines = [l for l in f.read_text().splitlines() if ins_re.match(l)]
        spots.append((f.name, rng.choice(lines)))
    spots_ok = True
    for fname, line in spots:
        m = ins_re.match(line)
        addr = int(m.group(1), 16)
        bytestr = m.group(2).strip()
        want = bytes.fromhex(bytestr.replace(" ", ""))
        off = vaddr_to_offset(segs, addr)
        raw_ok = off is not None and data[off:off + len(want)] == want
        fresh = subprocess.run(["objdump", "-d", f"--start-address=0x{addr:x}",
                                f"--stop-address=0x{addr + len(want):x}", str(BIN)],
                               capture_output=True, text=True, check=True).stdout
        fresh_line = next((l for l in fresh.splitlines() if ins_re.match(l)), "")
        obj_ok = ins_re.match(fresh_line) and ins_re.match(fresh_line).group(2).strip() == bytestr
        print(f"  spot {fname} 0x{addr:x}: raw={'ok' if raw_ok else 'MISMATCH'} "
              f"objdump={'ok' if obj_ok else 'MISMATCH'}")
        spots_ok = spots_ok and raw_ok and obj_ok
    check("3 seeded random gate spots byte-for-byte", spots_ok)

    # 8. MANIFEST.sha256
    man_ok = True
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        if not line.strip():
            continue
        digest, rel = line.split(None, 1)
        rel = rel.lstrip("*")
        p = HERE / rel
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest() != digest:
            man_ok = False
    check("MANIFEST.sha256 matches packet files", man_ok)

    # 9. model tests
    r = subprocess.run([sys.executable, str(MODEL_TEST)],
                       capture_output=True, text=True)
    check("model tests pass", r.returncode == 0,
          (r.stdout.strip().splitlines() or [""])[-1] if r.stdout.strip() else r.stderr.strip()[-200:])

    if FAILURES:
        print(f"\n{len(FAILURES)} CHECK(S) FAILED: {', '.join(FAILURES)}")
        return 1
    print("\nALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
