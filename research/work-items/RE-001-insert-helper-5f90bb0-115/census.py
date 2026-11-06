"""Census for node #115's insert helper 0x5f90bb0, its twin window
0x5da0640 and its rehash callee 0x5da04d0.

Scans the whole .text section (file range 0x1418300+0x4fd7700, vaddr
base 0x1419300) for direct e8 calls and e9 tail jumps to each window,
for 8-byte little-endian occurrences of each window start in .text,
and scans .rela.dyn/.rela.plt for RELATIVE addends equal to each
window start. Also scans the whole file for 8-byte little-endian
occurrences of each window start (vtable/data references) and
compares the two insert-helper windows byte by byte. Uses bytes.find
(C speed) rather than a per-byte Python loop. Prints a JSON summary
to stdout.

Result: the insert helper at 0x5f90bb0 has exactly 2 direct calls
(0x5f90f9c inside the distinct-key-sum walk 0x5f90da0 and 0x5f91217
inside the distinct-sum getter at 0x5f91010), 0 tail jumps, 0 qword
hits and 0 RELATIVE addends. The twin at 0x5da0640 has exactly 2
direct calls (0x5da0e6e, 0x5da17cb). The rehash body at 0x5da04d0 is
shared: exactly 7 direct calls across the build cluster, one of
which is 0x5f90d16 inside the insert helper. The two insert-helper
windows differ at 13 byte offsets, all inside relative-call/jump
displacement fields (the operator new, _M_need_rehash, rehash and
__stack_chk_fail calls and the landing pad's jump to its cleanup
block). See records.json.
"""

import hashlib
import json
import struct
from pathlib import Path

PACKET_DIR = Path(__file__).resolve().parent
REPO_ROOT = PACKET_DIR.parents[2]
BINARY = REPO_ROOT / "work" / "hl-node-115.bin"
TEXT_VMA = 0x1419300
TEXT_OFF = 0x1418300
TEXT_SIZE = 0x4FD7700
TARGETS = (0x5F90BB0, 0x5DA0640, 0x5DA04D0)
WINDOW = 0x1C2  # 450 bytes, FDE 0x5f90bb0..0x5f90d72 (twin: same size)


def scan_branch(text, opcode, target):
    hits = []
    start = 0
    while True:
        j = text.find(bytes([opcode]), start)
        if j < 0 or j + 5 > len(text):
            break
        rel = struct.unpack_from("<i", text, j + 1)[0]
        if TEXT_VMA + j + 5 + rel == target:
            hits.append(hex(TEXT_VMA + j))
        start = j + 1
    return hits


def find_all(blob, needle, base):
    hits = []
    start = 0
    while True:
        j = blob.find(needle, start)
        if j < 0:
            break
        hits.append(hex(base + j))
        start = j + 1
    return hits


def main():
    data = BINARY.read_bytes()
    text = data[TEXT_OFF:TEXT_OFF + TEXT_SIZE]
    result = {}
    for target in TARGETS:
        rela_hits = []
        for off, size in [(0x6BE8, 0x163CC8), (0x16A8B0, 0x1A10)]:
            for i in range(off, off + size, 24):
                _, _, addend = struct.unpack_from("<QQq", data, i)
                if addend == target:
                    rela_hits.append(hex(i))
        result[hex(target)] = {
            "direct_calls": scan_branch(text, 0xE8, target),
            "tail_jumps": scan_branch(text, 0xE9, target),
            "qword_hits": find_all(text, struct.pack("<Q", target), TEXT_VMA),
            "qword_hits_whole_file": find_all(data, struct.pack("<Q", target), 0),
            "relative_addend_hits": rela_hits,
        }
    a = data[0x5F90BB0 - 0x1000:0x5F90BB0 - 0x1000 + WINDOW]
    b = data[0x5DA0640 - 0x1000:0x5DA0640 - 0x1000 + WINDOW]
    diff = [i for i in range(WINDOW) if a[i] != b[i]]
    result["twin_comparison"] = {
        "window_bytes": WINDOW,
        "sha256_0x5f90bb0": hashlib.sha256(a).hexdigest(),
        "sha256_0x5da0640": hashlib.sha256(b).hexdigest(),
        "differing_offsets": [hex(i) for i in diff],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
