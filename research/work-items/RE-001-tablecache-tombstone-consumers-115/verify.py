"""Verify the RE-001-tablecache-tombstone-consumers-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-tablecache-tombstone-consumers-115/verify.py

Checks (all against the node #115 binary, never against the PR):
  1. Binary digest matches provenance/artifacts.json.
  2. MANIFEST.sha256 entries match the files on disk.
  3. Every excerpt regenerates byte-for-byte from a fresh objdump run
     (including the re-shipped max_covering_seqnum.txt from #3900).
  4. Three seeded-random gate spots verify byte-for-byte against a
     fresh objdump run AND against the raw binary bytes.
  5. Every FDE in frames.txt exists in the binary's unwind tables.
  6. The census reproduces: re-run census.py and require the caller
     counts in records.json to match the fresh callers.tsv.
  7. RELATIVE relocations: the GOT slots resolve to the recorded
     targets, the vtable typeinfo pointers resolve, and the typeinfo
     name strings read from the binary match.
  8. The model tests pass (448 checks).
"""

import hashlib
import json
import random
import re
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

ARTIFACT_SHA256 = (
    "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
)

WINDOWS = {
    "update_seqnums.txt": (0x5F3D4F0, 0x5F3D64A),
    "tablecache_get.txt": (0x5F40070, 0x5F40A8D),
    "get_cleanup.txt": (0x5F4000E, 0x5F40070),
    "null_stub.txt": (0x5EBA930, 0x5EBA937),
    "iterator_gate.txt": (0x5F0B050, 0x5F0B073),
    "get_tail_marker.txt": (0x616FB90, 0x616FBAE),
    "max_covering_seqnum.txt": (0x5F32900, 0x5F32A0A),
}

# (GOT/vtable slot address, expected RELATIVE addend)
RELATIVE_CHECKS = [
    (0x64ED6E8, 0x5EBA930),
    (0x64D5EA8, 0x5EBA930),
    (0x64D6768, 0x5EBA930),
    (0x64ECD48, 0x5D42220),
    (0x64ECD18, 0x5D3F090),
    (0x64ECE10, 0x5D420A0),
    (0x64C8DB8, 0x5D42220),
    (0x64C8EB8, 0x5D42220),
    (0x64C8DD8, 0x5D3F090),
    (0x64C8ED8, 0x5D3F090),
    (0x64C8DE0, 0x5D420A0),
    (0x64C9E40, 0x5D420A0),
    (0x64D5E88, 0x64D5E50),
    (0x64D6748, 0x64D6710),
    (0x64C8D98, 0x64C8D50),
    (0x64C8E98, 0x64C8D68),
    (0x64C9DF8, 0x64C9DA8),
]

# (typeinfo address, expected name string)
TYPEINFO_NAMES = [
    (0x64D5E50, "N7rocksdb17CuckooTableReaderE"),
    (0x64D6710, "N7rocksdb16PlainTableReaderE"),
    (0x64C8D50, "N7rocksdb12CacheWrapperE"),
    (0x64C8D68, "N7rocksdb25CacheWithSecondaryAdapterE"),
    (0x64C9DA8, "N7rocksdb12ChargedCacheE"),
]

FAILURES = []


def fail(msg):
    FAILURES.append(msg)
    print("FAIL: %s" % msg)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def objdump(start, stop, raw=False):
    cmd = ["objdump", "-d", "--start-address=%#x" % start,
           "--stop-address=%#x" % stop]
    if raw:
        cmd.append("--show-raw-insn")
    # The relative path matters: objdump prints it in the header line,
    # so regeneration must use the same relative path as
    # export_excerpts.py for byte-equality.
    cmd.append("work/hl-node-115.bin")
    return subprocess.run(cmd, capture_output=True, text=True,
                          check=True, cwd=ROOT).stdout


def section_map():
    out = subprocess.run(["readelf", "-S", str(BINARY)],
                         capture_output=True, text=True,
                         check=True).stdout
    secs = []
    for m in re.finditer(
            r"\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)",
            out):
        secs.append((m.group(1), int(m.group(2), 16),
                     int(m.group(3), 16), int(m.group(4), 16)))
    return secs


def va2off(va, secs):
    for _, addr, off, size in secs:
        if addr <= va < addr + size:
            return off + (va - addr)
    return None


def main():
    # 1. digest
    digest = sha256_file(BINARY)
    if digest != ARTIFACT_SHA256:
        fail("binary digest %s != provenance %s" % (digest, ARTIFACT_SHA256))
    else:
        print("digest OK: %s" % digest)

    # 2. manifest
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    for line in manifest:
        parts = line.split()
        if len(parts) != 2:
            fail("malformed manifest line: %r" % line)
            continue
        want, name = parts
        path = PACKET / name
        if not path.exists():
            fail("manifest file missing: %s" % name)
        elif sha256_file(path) != want:
            fail("manifest mismatch: %s" % name)
    print("manifest OK: %d entries" % len(manifest))

    # 3. excerpts regenerate byte-for-byte
    for name, (start, stop) in WINDOWS.items():
        fresh = objdump(start, stop)
        saved = (PACKET / name).read_text()
        if fresh != saved:
            fail("excerpt %s does not regenerate byte-for-byte" % name)
    print("excerpts OK: %d windows" % len(WINDOWS))

    # 4. three seeded-random gate spots, byte-for-byte vs fresh
    # objdump AND vs the raw binary bytes.
    data = BINARY.read_bytes()
    secs = section_map()
    insn_re = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.*)$")
    spots = []
    for name in sorted(WINDOWS):
        raw = objdump(*WINDOWS[name], raw=True)
        for line in raw.splitlines():
            m = insn_re.match(line)
            if m:
                addr = int(m.group(1), 16)
                bytestr = m.group(2).strip()
                if bytestr:
                    spots.append((addr, bytes.fromhex(bytestr)))
    rng = random.Random(20261107)
    chosen = rng.sample(spots, 3)
    for addr, raw_bytes in chosen:
        off = va2off(addr, secs)
        if off is None:
            fail("gate spot %#x has no file offset" % addr)
            continue
        if data[off:off + len(raw_bytes)] != raw_bytes:
            fail("gate spot %#x mismatches the raw binary" % addr)
    print("gate spots OK: %s"
          % ", ".join("%#x" % a for a, _ in chosen))

    # 5. frames
    frames_out = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    have = set()
    for m in re.finditer(r"FDE.*pc=([0-9a-f]+)\.\.([0-9a-f]+)", frames_out):
        have.add((int(m.group(1), 16), int(m.group(2), 16)))
    for line in (PACKET / "frames.txt").read_text().splitlines():
        if not line.strip():
            continue
        s, e = line.split("..")
        if (int(s, 16), int(e, 16)) not in have:
            fail("FDE %s not in unwind tables" % line)
    print("frames OK")

    # 6. census reproduction
    subprocess.run([sys.executable, str(PACKET / "census.py")],
                   capture_output=True, text=True, check=True, cwd=ROOT)
    records = json.loads((PACKET / "records.json").read_text())
    fresh_counts = {}
    with open(PACKET / "callers.tsv") as f:
        next(f)
        for line in f:
            parts = line.rstrip("\n").split("\t")
            if len(parts) == 4:
                fresh_counts.setdefault(int(parts[0], 16), []).append(parts)
    for addr_s, want in records["census"]["counts"].items():
        addr = int(addr_s, 16)
        rows = fresh_counts.get(addr, [])
        calls = sum(1 for r in rows if r[2] == "call")
        jumps = sum(1 for r in rows if r[2] == "tail_jump")
        if "calls" in want and calls != want["calls"]:
            fail("census calls for %#x: %d != %d" % (addr, calls, want["calls"]))
        if "jumps" in want and jumps != want["jumps"]:
            fail("census jumps for %#x: %d != %d" % (addr, jumps, want["jumps"]))
    print("census OK")

    # 7. relocations
    rel_out = subprocess.run(["readelf", "-r", str(BINARY)],
                             capture_output=True, text=True,
                             check=True).stdout
    relmap = {}
    for line in rel_out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == "R_X86_64_RELATIVE":
            try:
                relmap[int(parts[0], 16)] = int(parts[3], 16)
            except ValueError:
                pass
    for slot, want in RELATIVE_CHECKS:
        if relmap.get(slot) != want:
            fail("RELATIVE %#x -> %#x, want %#x"
                 % (slot, relmap.get(slot, -1), want))
    for ti, want_name in TYPEINFO_NAMES:
        name_ptr = relmap.get(ti + 0x8)
        if name_ptr is None:
            fail("no RELATIVE record for typeinfo %#x name" % ti)
            continue
        off = va2off(name_ptr, secs)
        if off is None:
            fail("typeinfo %#x name has no file offset" % ti)
            continue
        end = data.find(b"\x00", off)
        got = data[off:end].decode(errors="replace")
        if got != want_name:
            fail("typeinfo %#x name %r != %r" % (ti, got, want_name))
    print("relocations OK: %d RELATIVE checks, %d typeinfo names"
          % (len(RELATIVE_CHECKS), len(TYPEINFO_NAMES)))

    # 8. literals: the lazy-static addresses must be referenced by
    # lea in the Get excerpt (they live in .bss, so no file content).
    get_text = (PACKET / "tablecache_get.txt").read_text()
    for lit in ["# 6504690", "# 65046a0"]:
        if lit not in get_text:
            fail("literal %s not referenced in tablecache_get.txt" % lit)
    print("literals OK")

    # 9. model tests
    res = subprocess.run(
        [sys.executable, "tests/test_tablecache_tombstone_consumers_115.py"],
        capture_output=True, text=True, cwd=ROOT)
    print(res.stdout.strip().splitlines()[-1] if res.stdout else "")
    if res.returncode != 0:
        fail("model tests failed:\n%s" % res.stdout)

    if FAILURES:
        print("VERIFY FAILED: %d failure(s)" % len(FAILURES))
        return 1
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
