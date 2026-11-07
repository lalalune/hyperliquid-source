"""Reproduce the reference census for the
RE-001-composite-env-wrapper-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-composite-env-wrapper-115/census.py

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

The append helper 0x6099ce0 and the last-use helper 0x5d35070
are shared libstdc++/Configurable machinery with many callers
binary-wide; the packet pins their behaviour plus the wrapper
call sites, and the census lists every site.
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
    0x5FD7360: (0x5FD7360, 0x5FD7466),  # CompositeEnvWrapper builder (ctor)
    0x5FCEB20: (0x5FCEB20, 0x5FCEBB7),  # Env-vtable install + shared_ptr copy
    0x5FD5CC0: (0x5FD5CC0, 0x5FD5CD4),  # empty std::string init
    0x5FD72D0: (0x5FD72D0, 0x5FD730B),  # wrapper D2 (slot 0)
    0x5FD7510: (0x5FD7510, 0x5FD7558),  # wrapper D0 (slot 1)
    0x5FCF4D0: (0x5FCF4D0, 0x5FCF585),  # CompositeEnv D2 (base)
    0x5FD7560: (0x5FD7560, 0x5FD76B1),  # wrapper slot 5 (PrepareOptions)
    0x5FD5E00: (0x5FD5E00, 0x5FD5F07),  # wrapper slot 12 (SerializeOptions)
    0x5FD4E60: (0x5FD4E60, 0x5FD4E6C),  # wrapper slot 14 (Name)
    0x5FD6240: (0x5FD6240, 0x5FD6271),  # wrapper slot 16 (IsInstanceOf)
    0x5FD4E70: (0x5FD4E70, 0x5FD4E79),  # wrapper slot 17 (wrapped env)
    0x5FE2860: (0x5FE2860, 0x5FE2C2F),  # holder initializer
    0x5FCC7E0: (0x5FCC7E0, 0x5FCC7EE),  # FactoryEntry node slot 2 forwarder
    0x6025950: (0x6025950, 0x6025964),  # factory control-block dispose
    0x6025B90: (0x6025B90, 0x6025B9E),  # factory control-block destroy
    0x5FCF390: (0x5FCF390, 0x5FCF399),  # &this+0x28 helper
    0x5FD4E80: (0x5FD4E80, 0x5FD4EC7),  # wrapper slot 45 forwarder
    0x5FD4ED0: (0x5FD4ED0, 0x5FD4EE1),  # wrapper slot 46 forwarder
    0x5FD4EF0: (0x5FD4EF0, 0x5FD4F01),  # wrapper slot 47 forwarder
    0x5FD4F10: (0x5FD4F10, 0x5FD4F21),  # wrapper slot 48 forwarder
    0x5FD4F30: (0x5FD4F30, 0x5FD4F41),  # wrapper slot 49 forwarder
    0x5FD4F70: (0x5FD4F70, 0x5FD4F81),  # wrapper slot 50 forwarder
    0x5FD4F90: (0x5FD4F90, 0x5FD4FA1),  # wrapper slot 51 forwarder
    0x5FD4F50: (0x5FD4F50, 0x5FD4F61),  # wrapper slot 52 forwarder
    0x5FD4FB0: (0x5FD4FB0, 0x5FD4FF7),  # wrapper slot 59 forwarder
    0x5FD5000: (0x5FD5000, 0x5FD5011),  # wrapper slot 63 forwarder
    0x5FD5020: (0x5FD5020, 0x5FD5031),  # wrapper slot 64 forwarder
    0x5FD5040: (0x5FD5040, 0x5FD508A),  # wrapper slot 65 forwarder
    0x5FD5090: (0x5FD5090, 0x5FD50A1),  # wrapper slot 66 forwarder
    0x5FD50B0: (0x5FD50B0, 0x5FD50C1),  # wrapper slot 67 forwarder
    0x5FD50F0: (0x5FD50F0, 0x5FD5137),  # wrapper slot 68 forwarder
    0x5FD50D0: (0x5FD50D0, 0x5FD50E1),  # wrapper slot 69 forwarder
    0x5FD51D0: (0x5FD51D0, 0x5FD5217),  # wrapper slot 71 forwarder
    0x5FD5140: (0x5FD5140, 0x5FD5187),  # wrapper slot 79 forwarder
    0x5FD5190: (0x5FD5190, 0x5FD51A1),  # wrapper slot 80 forwarder
    0x5FD51B0: (0x5FD51B0, 0x5FD51C1),  # wrapper slot 81 forwarder
    0x5FCF430: (0x5FCF430, 0x5FCF439),  # holder+0x38 accessor (re-shipped)
    0x5FCF450: (0x5FCF450, 0x5FCF4CB),  # CompositeEnv invoker (re-shipped)
    0x6099CE0: (0x6099CE0, 0x6099E34),  # options-vector record append
    0x6099790: (0x6099790, 0x6099CAD),  # options-vector grow/realloc
    0x5D35070: (0x5D35070, 0x5D350BC),  # shared_ptr last-use helper
    0x5D350C0: (0x5D350C0, 0x5D35145),  # shared_ptr _M_release
    0x60289F0: (0x60289F0, 0x6028A0D),  # MockEnv ctor (calls the builder)
    0x60029F0: (0x60029F0, 0x6002B02),  # PosixFileSystem holder accessor
    0x61D2CA0: (0x61D2CA0, 0x61D2CA9),  # holder-init callee 1 (by contract)
    0x61C21B0: (0x61C21B0, 0x61C21B9),  # holder-init callee 2 (by contract)
    0x5FE2680: (0x5FE2680, 0x5FE2756),  # PosixClock holder accessor
    0x60971C0: (0x60971C0, 0x609755B),  # slot-12 wrapped-serialize helper
}

RELOCATION_RANGES = [
    (0x64CDAC0, 0x64CDAD8),  # Env vtable header
    (0x64CE2C8, 0x64CE580),  # CompositeEnv vtable header + slots 0..84
    (0x64CE580, 0x64CE840),  # CompositeEnvWrapper vtable header + slots 0..84
    (0x64D3420, 0x64D3470),  # Configurable vtable header + slots 0..7
    (0x64CDE58, 0x64CDE80),  # FactoryEntry<Env> node vtable header + slots
    (0x64D1C28, 0x64D1C60),  # factory control-block vtable
    (0x64D1388, 0x64D13A0),  # MockEnv vtable header + slot 0
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
