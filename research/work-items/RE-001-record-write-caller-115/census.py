"""Reproduce the reference census for the
RE-001-record-write-caller-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-record-write-caller-115/census.py

Method (same as the RE-001-record-write-115 packet):
  * One objdump pass over every executable LOAD segment,
    streamed line by line and keeping only direct call/jump
    lines (--no-show-raw-insn). Parsing a linear disassembly
    yields true instruction starts only, so data bytes can
    never fake a call site.
  * The same pass also keeps `lea` lines whose objdump comment
    names a pinned routine address.
  * Scan the raw binary at 8-byte strides for qwords equal to
    each routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each routine address.

Prints one line per pinned routine:
    <addr> calls=<n> <site,...> jumps=<n> <site,...> leas=<n> <site,...> qwords=<n> relative=<n>
Also writes callers.tsv (one row per direct call / tail jump /
lea reference with the smallest enclosing FDE as the caller)
and relocations.txt (the RELATIVE records installing the two
GOT canonicals read in-window by the sibling routine, plus the
produce-object vtable records, with the prose header) into
this packet directory.

Routines already mapped by earlier packets are census targets
and their excerpts are re-shipped byte-identical: the record
insert 0x5f0e890 and the varint32 encoder 0x61bd410 (#3330),
the record-write entry 0x5f0f930 (#3337) and the Status
builder 0x61cf670 (#3330). The 64-bit hash 0x61c3530, the
duplicate-detector check 0x5fbe340 with its helpers, and the
singleton 0x61be810 are census targets only: their bodies are
cited by contract, not excerpted.
"""

import bisect
import re
import struct
import subprocess
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
BINARY = ROOT / "work" / "hl-node-115.bin"

TARGETS = {
    0x5FC6070: (0x5FC6070, 0x5FC6E8B),  # record-write caller (this packet)
    0x5F0F3D0: (0x5F0F3D0, 0x5F0F8C1),  # sibling record write (this packet)
    0x5FB9A10: (0x5FB9A10, 0x5FB9BCB),  # validator (this packet)
    0x5FC5E30: (0x5FC5E30, 0x5FC5FDF),  # hashmap find-or-insert (this packet)
    0x5FC5CF0: (0x5FC5CF0, 0x5FC5E2D),  # hashmap rehash (this packet)
    0x5FB7040: (0x5FB7040, 0x5FB70D2),  # map lower_bound (this packet)
    0x5FB70E0: (0x5FB70E0, 0x5FB7131),  # hash combine (this packet)
    0x5FB71B0: (0x5FB71B0, 0x5FB7219),  # Status move-assign (this packet)
    0x60B21F0: (0x60B21F0, 0x60B2262),  # produce-request init (this packet)
    0x61CF610: (0x61CF610, 0x61CF64F),  # strdup into slot (this packet)
    0x5D54F00: (0x5D54F00, 0x5D54F05),  # no-op stub (this packet)
    0x5FBED30: (0x5FBED30, 0x5FBF077),  # closed-path delegate (this packet)
    0x5FBB000: (0x5FBB000, 0x5FBB00C),  # fallback counter getter (this packet)
    0x5FBB010: (0x5FBB010, 0x5FBB019),  # fallback counter getter alias (this packet)
    0x5FBBC30: (0x5FBBC30, 0x5FBBC3C),  # fallback counter setter (this packet)
    0x5FB7440: (0x5FB7440, 0x5FB75BB),  # fallback vector grow (this packet)
    0x5FBEBC0: (0x5FBEBC0, 0x5FBED25),  # fallback finalizer (this packet)
    0x5F0A1A0: (0x5F0A1A0, 0x5F0A1D0),  # min-register (this packet)
    0x5F0F930: (0x5F0F930, 0x5F10134),  # record-write entry (re-shipped, #3337)
    0x5F0E890: (0x5F0E890, 0x5F0F37E),  # record insert (re-shipped, #3330)
    0x61BD410: (0x61BD410, 0x61BD4E9),  # varint32 encoder (re-shipped, #3330)
    0x61CF670: (0x61CF670, 0x61CF767),  # Status builder (re-shipped, #3330)
    # Cited ground, census only (see docstring).
    0x61C3530: (0x61C3530, 0x61C389D),  # 64-bit hash (contract only)
    0x5FBE340: (0x5FBE340, 0x5FBE843),  # duplicate-detector check (contract only)
    0x5FBE180: (0x5FBE180, 0x5FBE2C6),  # check node test (contract only)
    0x5D54B10: (0x5D54B10, 0x5D54B44),  # check registry lookup (contract only)
    0x5FB9560: (0x5FB9560, 0x5FB97F9),  # check map op (contract only)
    0x5FB9CF0: (0x5FB9CF0, 0x5FB9F5D),  # check reset (contract only)
    0x61BE810: (0x61BE810, 0x61BE8C8),  # singleton (contract only)
    0x5FCF060: (0x5FCF060, 0x5FCF290),  # check throw helper (contract only)
}

# Routines installed by RELATIVE records: the two GOT
# canonicals compared in-window by the sibling routine, and
# the SnapshotImpl vtable slots of the produce object.
RELOCATED = {
    0x5D2CA80,
    0x5F04D80,
    0x5D484B0,
    0x5D484C0,
    0x5D484D0,
    0x5D54F10,
    0x5D54F30,
}


RELOCATION_RANGES = [
    (0x64ED010, 0x64ED018),  # GOT slot for the product-2 canonical 0x5d2ca80
    (0x64ED778, 0x64ED780),  # GOT slot for the product-1 canonical 0x5f04d80
    (0x64C92C8, 0x64C92F8),  # SnapshotImpl vtable: typeinfo + 5 slots
    (0x64C9158, 0x64C9168),  # SnapshotImpl typeinfo: vtable + name pointer
]


def exec_segments(data):
    """Return [(file offset, vaddr, file size)] of executable LOADs."""
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize, e_phnum = struct.unpack_from("<HH", data, 0x36)
    out = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        (p_type, p_flags, p_offset, p_vaddr, _p_paddr, p_filesz,
         _p_memsz, _p_align) = struct.unpack_from("<IIQQQQQQ", data, off)
        if p_type == 1 and p_flags & 1:
            out.append((p_offset, p_vaddr, p_filesz))
    if not out:
        raise SystemExit("no executable LOAD segment")
    return out


def disassembly_sites():
    """One objdump pass over every executable LOAD segment,
    streamed line by line, keeping direct call/jump lines and
    lea lines whose comment names a pinned routine. Returns
    {target: ([call sites], [jump sites], [lea sites])}."""
    sites = {}
    for _file_off, vaddr, filesz in exec_segments(BINARY.read_bytes()):
        proc = subprocess.Popen(
            ["objdump", "-d", "--no-show-raw-insn",
             "--start-address=%#x" % vaddr,
             "--stop-address=%#x" % (vaddr + filesz), str(BINARY)],
            stdout=subprocess.PIPE, text=True)
        for line in proc.stdout:
            if ("call" not in line and "jmp" not in line
                    and "lea" not in line):
                continue
            parts = line.split()
            if len(parts) < 3 or not parts[0].endswith(":"):
                continue
            try:
                site = int(parts[0][:-1], 16)
            except ValueError:
                continue
            mnemonic = parts[1]
            if mnemonic in ("call", "jmp"):
                target = parts[2]
                if not target or target[0] == "*":
                    continue
                try:
                    tgt = int(target, 16)
                except ValueError:
                    continue
                entry = sites.setdefault(tgt, ([], [], []))
                entry[0 if mnemonic == "call" else 1].append(site)
            elif mnemonic == "lea" and "#" in line:
                comment = line.split("#", 1)[1].strip()
                token = comment.split()[0]
                try:
                    tgt = int(token, 16)
                except ValueError:
                    continue
                entry = sites.setdefault(tgt, ([], [], []))
                entry[2].append(site)
        proc.wait()
        if proc.returncode != 0:
            raise SystemExit("objdump failed on segment %#x" % vaddr)
    for entry in sites.values():
        for lst in entry:
            lst.sort()
    return sites


def scan(sites, target):
    """(direct calls, tail jumps) for one target from a sites dict."""
    calls, jumps, _leas = sites.get(target, ([], [], []))
    return calls, jumps


def qwords(data, target):
    """File offsets holding target as an 8-byte-aligned qword."""
    needle = struct.pack("<Q", target)
    found = []
    pos = data.find(needle)
    while pos != -1:
        if pos % 8 == 0:
            found.append(pos)
        pos = data.find(needle, pos + 1)
    return found


def relative_records():
    """(offset -> addend) and raw lines for RELATIVE relocations."""
    text = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    out = {}
    lines = []
    for line in text.splitlines():
        m = re.match("[ ]*([0-9a-f]+)[ ]+([0-9a-f]+)[ ]+R_X86_64_([A-Za-z]+)"
                     "(?:[ ]+([0-9a-f]+))?", line)
        if not m:
            continue
        off = int(m.group(1), 16)
        typ = m.group(3)
        addend = m.group(4)
        if typ == "RELATIVE" and addend is not None:
            out[off] = int(addend, 16)
            lines.append(line)
    return out, lines


def frame_ranges():
    """All FDE pc ranges from a fresh frame dump."""
    text = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True).stdout
    ranges = []
    for match in re.finditer("pc=([0-9a-f]+)[.][.]([0-9a-f]+)", text):
        ranges.append((int(match.group(1), 16), int(match.group(2), 16)))
    return ranges


def enclosing_fde(ordered, starts, value):
    """Smallest enclosing FDE for an address. `ordered` is the
    sorted FDE ranges and `starts` their starts, computed once by
    the caller (sorting per row would be O(rows x ranges))."""
    idx = bisect.bisect_right(starts, value) - 1
    cands = []
    for j in range(max(0, idx - 2), min(len(ordered), idx + 3)):
        a, b = ordered[j]
        if a <= value < b:
            cands.append((a, b))
    if not cands:
        cands = [(a, b) for a, b in ordered if a <= value < b]
    if not cands:
        raise SystemExit("no enclosing FDE for %#x" % value)
    a, b = min(cands, key=lambda ab: ab[1] - ab[0])
    return "%#x..%#x" % (a, b)


def main():
    data = BINARY.read_bytes()
    sites = disassembly_sites()
    relocs, reloc_lines = relative_records()
    ranges = frame_ranges()
    rows = []
    for target in sorted(TARGETS):
        calls, jumps, leas = sites.get(target, ([], [], []))
        qw = qwords(data, target)
        rel = sorted(o for o, a in relocs.items() if a == target)
        print("%#x calls=%d %s jumps=%d %s leas=%d %s qwords=%d %s relative=%d %s" % (
            target, len(calls),
            " ".join("%#x" % c for c in calls),
            len(jumps), " ".join("%#x" % j for j in jumps),
            len(leas), " ".join("%#x" % l for l in leas),
            len(qw), " ".join("%#x" % q for q in qw),
            len(rel), " ".join("%#x" % r for r in rel)))
        for site in calls:
            rows.append((site, target, "call"))
        for site in jumps:
            rows.append((site, target, "tail jump"))
        for site in leas:
            rows.append((site, target, "lea"))
    rows.sort()
    ordered = sorted(ranges)
    starts = [a for a, _b in ordered]
    with open(PACKET / "callers.tsv", "w") as handle:
        handle.write("site\ttarget\tcaller\tkind\n")
        for site, target, kind in rows:
            handle.write("%#x\t%#x\t%s\t%s\n" % (
                site, target, enclosing_fde(ordered, starts, site), kind))
    kept = []
    for line in reloc_lines:
        parts = line.split()
        off = int(parts[0], 16)
        if any(lo <= off < hi for lo, hi in RELOCATION_RANGES):
            kept.append(line)
    with open(PACKET / "relocations.txt", "w") as handle:
        handle.write("The two GOT slots read in-window by the sibling routine hold canonical\n")
        handle.write("forwarders, installed by these RELATIVE records (readelf -r):\n")
        for line in kept:
            handle.write(line + "\n")
        handle.write("- GOT slot 0x64ed778 holds 0x5f04d80: the canonical target compared\n")
        handle.write("  against product-1 (owner+0xa50) vtable slot 0x98 at 0x5f0f44b; when\n")
        handle.write("  equal, the sibling calls slot 0x90 instead (#3286's forwarder).\n")
        handle.write("- GOT slot 0x64ed010 holds 0x5d2ca80: the canonical target compared\n")
        handle.write("  against product-2 (owner+0x10) vtable slot 0x98 at 0x5f0f52e; when\n")
        handle.write("  equal, the sibling calls slot 0x10 on the product+0x20 subobject\n")
        handle.write("  instead.\n")
        handle.write("- The produce object built on the code-1 path is a rocksdb::SnapshotImpl\n")
        handle.write("  (typeinfo name `N7rocksdb12SnapshotImplE` at 0x96ce30, via the RELATIVE\n")
        handle.write("  record at 0x64c9160); its vtable 0x64c92d0 holds, by RELATIVE records,\n")
        handle.write("  slots 0x5d484b0, 0x5d484c0, 0x5d484d0, 0x5d54f10 and 0x5d54f30, with\n")
        handle.write("  the typeinfo pointer 0x64c9158 at 0x64c92c8.\n")
    print("relocations kept: %d" % len(kept))


if __name__ == "__main__":
    main()
