"""Reproduce the reference census for the
RE-001-objectlibrary-registry-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-objectlibrary-registry-115/census.py

Method (same as the RE-001-systemclock-installers-115 packet):
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
and relocations.txt (the RELATIVE records for the
Env, CompositeEnv, CompositeEnvWrapper, Configurable,
FactoryEntry<Env> node, factory control-block and MockEnv
vtable headers and slots) into this packet directory.

The vtable-header leas name data addresses, not routines, so
they are recorded in records.json from the targeted search and
checked by verify.py against the vtable excerpts instead.

The shared_ptr release helpers 0x5d35070/0x5d350c0 are shared
libstdc++ machinery with many callers binary-wide; the packet
pins their call sites from the registry routines, and the census
lists every site for the pinned routines only.
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
    0x61F8B60: (0x61F8B60, 0x61F8D12),  # ObjectLibrary::Default getter
    0x61F8700: (0x61F8700, 0x61F8760),  # registry count (lock, *out, sum)
    0x5FD1DA0: (0x5FD1DA0, 0x5FD1FFA),  # map find-or-insert
    0x5FD1C60: (0x5FD1C60, 0x5FD1D9D),  # _Hashtable rehash (M_rehash)
    0x5FD17C0: (0x5FD17C0, 0x5FD1962),  # vector<FactoryEntry*> insert
    0x5FD24C0: (0x5FD24C0, 0x5FD2748),  # insert (node+entry build, lock, append)
    0x5FD20D0: (0x5FD20D0, 0x5FD241D),  # default-init (SystemClock registration)
    0x5FD27C0: (0x5FD27C0, 0x5FD297F),  # register (MockEnv + CompositeEnv, count)
    0x5FEFC70: (0x5FEFC70, 0x5FEFC75),  # control-block D1 (ret)
    0x5FEFD00: (0x5FEFD00, 0x5FEFD0E),  # control-block D0 (delete 0x90)
    0x5FF7900: (0x5FF7900, 0x5FF7952),  # control-block _M_dispose (~ObjectLibrary)
    0x5FEFD50: (0x5FEFD50, 0x5FEFD5E),  # control-block _M_destroy (delete 0x90)
    0x5FEFF70: (0x5FEFF70, 0x5FEFFB7),  # control-block _M_get_deleter
    0x5FF7820: (0x5FF7820, 0x5FF78FF),  # map node-chain destroy
    0x5FF2030: (0x5FF2030, 0x5FF2145),  # PatternEntry D2 (slot 0)
    0x5FF2150: (0x5FF2150, 0x5FF225F),  # PatternEntry D0 (slot 1)
    0x61F8670: (0x61F8670, 0x61F86F2),  # PatternEntry Matches (slot 2)
    0x61F8430: (0x61F8430, 0x61F8670),  # pattern string matcher
    0x61F8280: (0x61F8280, 0x61F842B),  # per-element sub-pattern matcher
    0x61F8120: (0x61F8120, 0x61F8129),  # PatternEntry pattern accessor (slot 3)
    0x5FCC700: (0x5FCC700, 0x5FCC742),  # FactoryEntry<Env> node D2
    0x5FCD840: (0x5FCD840, 0x5FCD88A),  # FactoryEntry<Env> node D0
    0x5FCC7E0: (0x5FCC7E0, 0x5FCC7EE),  # FactoryEntry<Env> node slot 2 forwarder
    0x5FCC7F0: (0x5FCC7F0, 0x5FCC7FE),  # FactoryEntry<Env> node slot 3 forwarder
    0x5FCC6B0: (0x5FCC6B0, 0x5FCC6F2),  # FactoryEntry<SystemClock> node D2
    0x5FCD7F0: (0x5FCD7F0, 0x5FCD83A),  # FactoryEntry<SystemClock> node D0
    0x5FCC7C0: (0x5FCC7C0, 0x5FCC7CE),  # FactoryEntry<SystemClock> node slot 2 fwd
    0x5FCC7D0: (0x5FCC7D0, 0x5FCC7DE),  # FactoryEntry<SystemClock> node slot 3 fwd
    0x5FCC6A0: (0x5FCC6A0, 0x5FCC6A5),  # _Sp_counted_ptr<Env*> D1 (ret)
    0x5FCC830: (0x5FCC830, 0x5FCC83E),  # _Sp_counted_ptr<Env*> D0 (delete 0x18)
}

RELOCATION_RANGES = [
    (0x64CDE58, 0x64CDED8),  # FactoryEntry<Env> + FactoryEntry<SystemClock> + _Sp_counted_ptr<Env*> vtables
    (0x64D00E0, 0x64D0118),  # _Sp_counted_ptr_inplace<ObjectLibrary> control-block vtable
    (0x64D8EC0, 0x64D8F28),  # PatternEntry vtable + _Sp_counted_ptr_inplace<ObjectRegistry> control-block vtable
    (0x64ECDC8, 0x64ECDD0),  # _Sp_make_shared_tag typeinfo GOT slot (cb-getdeleter / matcher)
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
        for line in kept:
            handle.write(line + "\n")
    print("relocations kept: %d" % len(kept))


if __name__ == "__main__":
    main()
