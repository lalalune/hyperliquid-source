"""Census for RE-014-probe-gated-lookup-115: direct calls, tail jumps,
whole-file qword references and RELATIVE relocations for the pinned
node #115 addresses. Run from the repository root.

Method: one pass over the executable LOAD segment for 0xe8/0xe9
rel32 targets; a whole-file search for the little-endian qword of
each target; .rela.dyn parsed from `readelf -rW` output for
R_X86_64_RELATIVE entries whose addend equals a target.
"""
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
BIN = ROOT / "work" / "hl-node-115.bin"
TEXT_OFF, TEXT_VA = 0x1418300, 0x1419300
TEXT_END = TEXT_OFF + 0x4FD7700

TARGETS = {
    "window": 0x5F0D050,
    "hash": 0x61C34A0,
    "thunk": 0x5F0B050,
    "driver": 0x5F0CE10,
    "transform": 0x5F32900,
    "move": 0x5F05310,
    "timer": 0x5F05950,
}


def main():
    data = BIN.read_bytes()
    calls = {k: [] for k in TARGETS}
    jumps = {k: [] for k in TARGETS}
    by_va = {v: k for k, v in TARGETS.items()}
    for i in range(TEXT_OFF, TEXT_END - 5):
        op = data[i]
        if op not in (0xE8, 0xE9):
            continue
        rel = struct.unpack_from("<i", data, i + 1)[0]
        dest = (i + 0x1000) + 5 + rel
        name = by_va.get(dest)
        if name:
            (calls if op == 0xE8 else jumps)[name].append(hex(i + 0x1000))
    for name, va in TARGETS.items():
        qword = data.find(struct.pack("<Q", va))
        hits = []
        while qword != -1:
            hits.append(hex(qword))
            qword = data.find(struct.pack("<Q", va), qword + 1)
        rela = subprocess.run(["readelf", "-rW", str(BIN)],
                              capture_output=True, text=True,
                              check=True).stdout
        relative = [ln for ln in rela.splitlines()
                    if "R_X86_64_RELATIVE" in ln
                    and ln.strip().endswith("%x" % va)]
        print("%s %#x: calls=%d %s jumps=%d %s qwords=%s relative=%d"
              % (name, va, len(calls[name]), calls[name][:12],
                 len(jumps[name]), jumps[name][:12], hits[:5],
                 len(relative)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
