"""Checker for the RE-001-value-widen-57ae540-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-value-widen-57ae540-115/verify.py

Checks, in order: the work binary digest against the packet
digest; MANIFEST.sha256 against every packet file; excerpt
regeneration byte-for-byte against fresh objdump runs (main
body and jump table) and fresh readelf frame lines; every
main.txt instruction byte-for-byte against the raw binary
(objdump continuation lines are accumulated); the jump table
entries recomputed from the raw binary against records.json;
the census against a fresh census.py run (call sites, tail
jumps, stored qwords, RELATIVE addends, table entries) and
callers.tsv against that census and the frame lines; the
semantic records (including the body and jump-table SHA-256
values against the raw binary); and the model tests. Prints
ALL CHECKS PASSED on success, else raises.
"""

import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

BODY = (0x57AE540, 0x57AE642)
TABLE = (0x931ABC, 0x931B18)
TARGET = 0x57AE540

sys.path.insert(0, str(PACKET))
import census  # noqa: E402

LINE_RE = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)(?:\t(.*))?$")
FDE_RE = re.compile(r"FDE cie=[0-9a-f]+ pc=([0-9a-f]+)\.\.([0-9a-f]+)")


def fail(msg):
    raise AssertionError(msg)


def run(args):
    return subprocess.run(args, capture_output=True, text=True,
                          check=True, cwd=ROOT).stdout


def voff(data, vaddr):
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(e_phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz, _ = \
            struct.unpack_from("<IIQQQQI", data,
                               e_phoff + i * e_phentsize)
        if p_type == 1 and p_vaddr <= vaddr < p_vaddr + p_filesz:
            return vaddr - p_vaddr + p_offset
    fail("vaddr %#x not in any LOAD" % vaddr)


def check_digest(data):
    if hashlib.sha256(data).hexdigest() != DIGEST:
        fail("work binary digest mismatch")


def check_manifest():
    manifest = (PACKET / "MANIFEST.sha256").read_text().splitlines()
    listed = {}
    for line in manifest:
        if not line.strip():
            continue
        digest, name = line.split("  ", 1)
        listed[name] = digest
    actual = {p.name for p in PACKET.iterdir()
              if p.is_file() and p.name != "MANIFEST.sha256"}
    if set(listed) != actual:
        fail("MANIFEST file set mismatch: %s vs %s"
             % (sorted(listed), sorted(actual)))
    for name, digest in listed.items():
        got = hashlib.sha256((PACKET / name).read_bytes()).hexdigest()
        if got != digest:
            fail("MANIFEST hash mismatch for %s" % name)


def check_excerpts():
    text = run(["objdump", "-d",
                "--start-address=%#x" % BODY[0],
                "--stop-address=%#x" % BODY[1],
                "work/hl-node-115.bin"])
    if text != (PACKET / "main.txt").read_text():
        fail("main.txt does not match a fresh objdump run")
    text = run(["objdump", "-s",
                "--start-address=%#x" % TABLE[0],
                "--stop-address=%#x" % TABLE[1],
                "work/hl-node-115.bin"])
    if text != (PACKET / "table.txt").read_text():
        fail("table.txt does not match a fresh objdump run")


def check_frames(census_result):
    sites = [int(s, 16) for s in census_result["direct_calls"]]
    dump = run(["readelf", "--debug-dump=frames", "-W",
                "work/hl-node-115.bin"])
    kept = []
    body_seen = False
    for line in dump.splitlines():
        m = FDE_RE.search(line)
        if not m:
            continue
        lo, hi = int(m.group(1), 16), int(m.group(2), 16)
        if (lo, hi) == BODY:
            body_seen = True
            kept.append(line)
        elif any(lo <= s < hi for s in sites):
            kept.append(line)
    if not body_seen:
        fail("body FDE line not found in a fresh frame dump")
    if "\n".join(kept) + "\n" != (PACKET / "frames.txt").read_text():
        fail("frames.txt does not match a fresh frame dump")
    return kept


def check_instructions(data):
    """Every main.txt instruction's bytes against the raw binary."""
    expect = {}
    cur_addr = None
    cur_bytes = bytearray()
    for line in (PACKET / "main.txt").read_text().splitlines():
        m = LINE_RE.match(line)
        if not m:
            continue
        addr = int(m.group(1), 16)
        raw = bytes.fromhex(m.group(2).replace(" ", ""))
        rest = (m.group(3) or "").strip()
        if rest:  # a new instruction starts on this line
            if cur_addr is not None:
                expect[cur_addr] = bytes(cur_bytes)
            cur_addr, cur_bytes = addr, bytearray(raw)
        else:     # continuation of a split instruction
            cur_bytes += raw
    if cur_addr is not None:
        expect[cur_addr] = bytes(cur_bytes)
    if not expect:
        fail("no instructions parsed from main.txt")
    for addr, raw in expect.items():
        off = voff(data, addr)
        if data[off:off + len(raw)] != raw:
            fail("instruction bytes at %#x differ from the binary" % addr)
    total = sum(len(v) for v in expect.values())
    if total != BODY[1] - BODY[0]:
        fail("excerpt covers %d bytes, body is %d"
             % (total, BODY[1] - BODY[0]))


def check_records(data, census_result, frame_lines):
    records = json.loads((PACKET / "records.json").read_text())
    if records["artifact_sha256"] != DIGEST:
        fail("records artifact digest mismatch")
    body = records["bodies"]["convert"]
    off = voff(data, BODY[0])
    raw = data[off:off + (BODY[1] - BODY[0])]
    if hashlib.sha256(raw).hexdigest() != body["sha256"]:
        fail("records body sha256 mismatch")
    if body["size_bytes"] != BODY[1] - BODY[0]:
        fail("records body size mismatch")
    if body["fde"] != "%#x..%#x" % BODY:
        fail("records body FDE mismatch")
    table = records["jump_table"]
    toff = voff(data, TABLE[0])
    traw = data[toff:toff + 88]
    if hashlib.sha256(traw).hexdigest() != table["sha256"]:
        fail("records jump-table sha256 mismatch")
    entries = []
    for i in range(22):
        delta = struct.unpack_from("<i", traw, 4 * i)[0]
        entries.append("%#x" % (TABLE[0] + delta))
    if entries != table["entries"]:
        fail("records jump-table entries mismatch")
    if entries != census_result["jump_table_entries"]:
        fail("census jump-table entries mismatch")
    cases = records["cases"]
    if [c["input_tag"] for c in cases] != list(range(22)):
        fail("records cases do not cover input tags 0..21 in order")
    if [c["case"] for c in cases] != entries:
        fail("records case addresses do not match the jump table")
    crec = records["census"]
    if crec["direct_calls"] != census_result["direct_calls"]:
        fail("records census direct calls mismatch")
    if crec["tail_jumps"] != census_result["tail_jumps"]:
        fail("records census tail jumps mismatch")
    if crec["stored_qwords"] != census_result["stored_qwords"]:
        fail("records census stored qwords mismatch")
    if crec["relative_addends"] != census_result["relative_addends"]:
        fail("records census RELATIVE addends mismatch")

    # callers.tsv against the census and the frame lines.
    frame_ranges = set()
    for line in frame_lines:
        m = FDE_RE.search(line)
        frame_ranges.add((int(m.group(1), 16), int(m.group(2), 16)))
    rows = (PACKET / "callers.tsv").read_text().splitlines()
    if rows[0] != "site\ttarget\tcaller\tkind\tsetup":
        fail("callers.tsv header mismatch")
    seen = []
    tsv_ranges = set()
    for row in rows[1:]:
        site, target, caller, kind, _ = row.split("\t", 4)
        if int(target, 16) != TARGET or kind != "call":
            fail("callers.tsv row shape mismatch: %s" % row)
        lo_s, hi_s = caller.split("..")
        lo, hi = int(lo_s, 16), int(hi_s, 16)
        if (lo, hi) not in frame_ranges:
            fail("callers.tsv caller range %s not in frames.txt" % caller)
        if not (lo <= int(site, 16) < hi):
            fail("callers.tsv site %s outside its caller range" % site)
        seen.append(site)
        tsv_ranges.add("%#x..%#x" % (lo, hi))
    if seen != census_result["direct_calls"]:
        fail("callers.tsv sites do not match the census")
    if tsv_ranges != set(crec["caller_fdes"]):
        fail("records caller FDE set does not match callers.tsv")


def check_model_tests():
    out = subprocess.run(
        [sys.executable, "tests/test_value_widen_57ae540.py"],
        capture_output=True, text=True, cwd=ROOT)
    if out.returncode != 0 or "checks pass" not in out.stdout:
        fail("model tests did not pass: %s %s" % (out.stdout, out.stderr))


def main():
    data = BINARY.read_bytes()
    check_digest(data)
    check_manifest()
    check_excerpts()
    census_result = census.collect()
    frame_lines = check_frames(census_result)
    check_instructions(data)
    check_records(data, census_result, frame_lines)
    check_model_tests()
    print("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
