"""Reproduce the reference census for the
RE-001-tablecache-tombstone-consumers-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-tablecache-tombstone-consumers-115/census.py

Method (same as the RE-001-stats-write-side-115 packet):
  * One objdump pass over the single executable LOAD segment
    (0x1419300..0x63f1ba0), streamed line by line and keeping
    only direct call/jump lines (--no-show-raw-insn). Parsing a
    linear disassembly yields true instruction starts only, so
    data bytes can never fake a call site.
  * The same pass also keeps `lea` lines whose objdump comment
    names a pinned routine address, and indirect virtual-dispatch
    lines `call *0x18(%r..)` / `call *0x8(%r..)` / `call *0x58(%r..)`
    / `call *0x38(%r..)` / `call *0x40(%r..)` (the slot-0x18
    iterator build, the slot-0x8 iterator release, the slot-0x58
    table Get, and the slot-0x38/0x40 chain-walk dispatches).
  * Scan the raw binary at 8-byte strides for qwords equal to
    each routine address.
  * Parse `readelf -r` output for RELATIVE records mentioning
    each routine address (the GOT slot 0x64ed6e8 resolves to the
    null-returning canonical 0x5eba930; 0x64ecd48/0x64ecd18/
    0x64ece10 resolve to the chain-walk canonicals).

Prints one line per pinned routine:
    <addr> calls=<n> <site,...> jumps=<n> <site,...> leas=<n> <site,...> qwords=<n> relative=<n>
Also writes callers.tsv (one row per direct call / tail jump /
lea reference with the smallest enclosing FDE as the caller)
and dispatch.tsv (one row per indirect call through vtable
slots 0x18/0x8/0x58/0x38/0x40 with the smallest enclosing FDE).

Routines mapped by earlier packets are census targets and
their bodies are cited by contract, not excerpted: the
FragmentedRangeTombstoneIterator method family and
MaxCoveringTombstoneSeqnum 0x5f32900 (RE-001-fragmented-
tombstone-iterator-115 #3900), the MemTable range-tombstone
cache builder 0x5f0a3d0 and the per-CPU slot claim 0x5f0a9c0
(RE-001-fragmented-range-tombstones-115 #3803 /
RE-001-range-tombstone-cache-115 #3674), the iterator gate
0x5f0b050 (cited in #3900's callers.tsv). The callee excerpt
max_covering_seqnum.txt is re-shipped byte-identical from
#3900 with credit, because the packet's model calls it.
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
    0x5F3D4F0: (0x5F3D4F0, 0x5F3D64A),  # TableCache::UpdateRangeTombstoneSeqnums
    0x5F40070: (0x5F40070, 0x5F40A8D),  # TableCache::Get
    0x5F4000E: (0x5F4000E, 0x5F40070),  # Get exception-cleanup fragment FDE
    0x5F32900: (0x5F32900, 0x5F32A0A),  # MaxCoveringTombstoneSeqnum (re-shipped from #3900)
    0x5EBA930: (0x5EBA930, 0x5EBA937),  # null-returning slot-0x18 canonical stub
    0x5F0B050: (0x5F0B050, 0x5F0B073),  # MemTable iterator gate (cited; #3674/#3900 ground)
    0x5F0A9C0: (0x5F0A9C0, 0x5F0B04C),  # NewRangeTombstoneIteratorInternal (cited; #3674)
    # Cited ground, census only (see docstring).
    0x5F3F6C0: (0x5F3F6C0, 0x5F4000D),  # Get fallback when the reader is null
    0x5F3CD50: (0x5F3CD50, 0x5F3D0AA),  # not-ready path helper 1
    0x5F3D0D0: (0x5F3D0D0, 0x5F3D4DE),  # not-ready path helper 2
    0x616FB90: (0x616FB90, 0x616FBAE),  # Get tail marker (+0x108 = 1)
    0x5F3CB30: (0x5F3CB30, 0x5F3CB69),  # lazy-static 0x20-byte deleter
    0x5D42220: (0x5D42220, 0x5D42220),  # chain canonical behind GOT 0x64ecd48 (range unknown; census only)
    0x5D3F090: (0x5D3F090, 0x5D3F090),  # chain canonical behind GOT 0x64ecd18 (census only)
    0x5D420A0: (0x5D420A0, 0x5D420A0),  # chain canonical behind GOT 0x64ece10 (census only)
}

GOT_SLOTS = {
    0x64ED6E8: 0x5EBA930,  # slot-0x18 canonical (null stub)
    0x64ECD48: 0x5D42220,  # slot-0x18 chain canonical in Get cleanup region
    0x64ECD18: 0x5D3F090,  # slot-0x38 chain canonical
    0x64ECE10: 0x5D420A0,  # slot-0x40 chain canonical
}

CALL_RE = re.compile(r"^\s*([0-9a-f]+):\s+(call|jmp)\s+([0-9a-f]+)\s")
LEA_RE = re.compile(r"^\s*([0-9a-f]+):\s+lea\s+.*#\s*([0-9a-f]+)\s")
INDIRECT_RE = re.compile(
    r"^\s*([0-9a-f]+):\s+call\s+\*(0x18|0x8|0x58|0x38|0x40)\(%r[a-z0-9]+\)"
)
FDE_RE = re.compile(r"FDE.*pc=([0-9a-f]+)\.\.([0-9a-f]+)")


def load_fdes():
    out = subprocess.run(
        ["readelf", "--debug-dump=frames", str(BINARY)],
        capture_output=True, text=True, check=True,
    ).stdout
    fdes = []
    for line in out.splitlines():
        m = FDE_RE.search(line)
        if m:
            fdes.append((int(m.group(1), 16), int(m.group(2), 16)))
    fdes.sort()
    return fdes


def main():
    fdes = load_fdes()
    starts = [f[0] for f in fdes]

    def enclosing(addr):
        i = bisect.bisect_right(starts, addr) - 1
        if i >= 0 and fdes[i][0] <= addr < fdes[i][1]:
            return fdes[i]
        return None

    calls = {a: [] for a in TARGETS}
    jumps = {a: [] for a in TARGETS}
    leas = {a: [] for a in TARGETS}
    dispatch = []  # (site, slot, fde)

    proc = subprocess.Popen(
        ["objdump", "-d", "--no-show-raw-insn",
         "--start-address=0x1419300", "--stop-address=0x63f1ba0",
         str(BINARY)],
        stdout=subprocess.PIPE, text=True,
    )
    for line in proc.stdout:
        m = CALL_RE.match(line)
        if m:
            site = int(m.group(1), 16)
            tgt = int(m.group(3), 16)
            if tgt in TARGETS:
                (calls if m.group(2) == "call" else jumps)[tgt].append(site)
            continue
        m = LEA_RE.match(line)
        if m:
            site = int(m.group(1), 16)
            tgt = int(m.group(2), 16)
            if tgt in TARGETS:
                leas[tgt].append(site)
            continue
        m = INDIRECT_RE.match(line)
        if m:
            site = int(m.group(1), 16)
            fde = enclosing(site)
            dispatch.append((site, m.group(2),
                             "%#x..%#x" % fde if fde else "none"))
    proc.wait()

    data = BINARY.read_bytes()
    qwords = {a: 0 for a in TARGETS}
    for off in range(0, len(data) - 7, 8):
        val = struct.unpack_from("<Q", data, off)[0]
        if val in qwords:
            qwords[val] += 1

    rel = subprocess.run(
        ["readelf", "-r", str(BINARY)],
        capture_output=True, text=True, check=True,
    ).stdout
    relative = {a: 0 for a in TARGETS}
    for line in rel.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == "R_X86_64_RELATIVE":
            try:
                tgt = int(parts[-1], 16)
            except ValueError:
                continue
            if tgt in relative:
                relative[tgt] += 1

    rows = []
    for addr in sorted(TARGETS):
        print("%#x calls=%d %s jumps=%d %s leas=%d %s qwords=%d relative=%d" % (
            addr,
            len(calls[addr]),
            ",".join("%#x" % s for s in sorted(calls[addr])),
            len(jumps[addr]),
            ",".join("%#x" % s for s in sorted(jumps[addr])),
            len(leas[addr]),
            ",".join("%#x" % s for s in sorted(leas[addr])),
            qwords[addr], relative[addr]))
        for site in sorted(calls[addr]):
            fde = enclosing(site)
            rows.append((addr, site, "call",
                         "%#x..%#x" % fde if fde else "none"))
        for site in sorted(jumps[addr]):
            fde = enclosing(site)
            rows.append((addr, site, "tail_jump",
                         "%#x..%#x" % fde if fde else "none"))
        for site in sorted(leas[addr]):
            fde = enclosing(site)
            rows.append((addr, site, "lea",
                         "%#x..%#x" % fde if fde else "none"))

    with open(PACKET / "callers.tsv", "w") as f:
        f.write("target\tsite\tkind\tcontaining_fde\n")
        for addr, site, kind, fde in sorted(rows, key=lambda r: (r[0], r[1])):
            f.write("%#x\t%#x\t%s\t%s\n" % (addr, site, kind, fde))
    with open(PACKET / "dispatch.tsv", "w") as f:
        f.write("site\tslot\tcontaining_fde\n")
        for site, slot, fde in sorted(dispatch):
            f.write("%#x\t%s\t%s\n" % (site, slot, fde))
    print("wrote callers.tsv (%d rows) dispatch.tsv (%d rows)"
          % (len(rows), len(dispatch)))
    for slot_addr, tgt in sorted(GOT_SLOTS.items()):
        print("GOT %#x -> %#x (RELATIVE records for target: %d)"
              % (slot_addr, tgt, relative.get(tgt, 0)))


if __name__ == "__main__":
    main()
