"""Regenerate the verbatim objdump excerpts and frames in this packet.

Run from the repository root:
    python3 research/work-items/RE-001-plain-table-index-115/export_excerpts.py

Uses the relative binary path, as the README records; objdump
addresses are the window virtual addresses used throughout.

Re-shipped excerpts are regenerated here from the same binary and
ranges pinned in their source packets and must come out
byte-identical to the copies committed here:
- record.txt, record_thunk.txt, bucket_index.txt, percentile.txt,
  median.txt, average.txt, stddev.txt, renderer.txt,
  tostring_entry.txt and boundaries.tsv come from open PR #3371
  (RE-001-histogram-stats-family-115), which pins the whole
  HistogramImpl statistics family;
- hex-encode-61c7e30.objdump.txt comes from open PR #3585
  (RE-001-hashlinklist-insert-115), originally pinned in open PR
  #3561 (RE-001-serializer-115).
The record host, the dump host and the index machinery around
them (subrec append, chunk-ptrs push-back, bucket-count computer,
gather, serializer, varint encoder, log dispatcher) are pinned
fresh here; the rocksdb::Hash entry 0x61c34a0 is NOT re-pinned
here — it is the centerpiece of dd12m54's open PR #3525 and is
used here only as a referenced callee (see README).
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))

# Fresh windows pinned by this packet: (file, start, stop).
EXCERPTS = [
    ("host-6198900.objdump.txt", "0x6198900", "0x6198ce2"),
    ("host-cleanup-6198ce2.objdump.txt", "0x6198ce2", "0x6198d34"),
    ("host-6198d40.objdump.txt", "0x6198d40", "0x6198f4d"),
    ("subrec-6198790.objdump.txt", "0x6198790", "0x6198853"),
    ("pushback-61985f0.objdump.txt", "0x61985f0", "0x6198775"),
    ("throwstub-6198776.objdump.txt", "0x6198776", "0x6198790"),
    ("bucket-count-6198230.objdump.txt", "0x6198230", "0x6198283"),
    ("gather-6198290.objdump.txt", "0x6198290", "0x6198364"),
    ("serializer-6198370.objdump.txt", "0x6198370", "0x61985e2"),
    ("varint-enc-61bd410.objdump.txt", "0x61bd410", "0x61bd4e9"),
    ("log-5fceda0.objdump.txt", "0x5fceda0", "0x5fcee93"),
]

# Re-shipped windows: regenerated from the same binary and ranges
# as their source packets; verify.py requires byte-equality with
# the committed copies.
RESHIPPED = [
    ("record.txt", "0x606b130", "0x606b1b3"),
    ("record_thunk.txt", "0x606b1c0", "0x606b1cd"),
    ("bucket_index.txt", "0x606afa0", "0x606b013"),
    ("percentile.txt", "0x606b260", "0x606b4fe"),
    ("median.txt", "0x606b500", "0x606b511"),
    ("average.txt", "0x606b540", "0x606b5b9"),
    ("stddev.txt", "0x606b5d0", "0x606b6ae"),
    ("renderer.txt", "0x606b6f0", "0x606bc8d"),
    ("tostring_entry.txt", "0x606bc90", "0x606bcd3"),
    ("hex-encode-61c7e30.objdump.txt", "0x61c7e30", "0x61c7fb6"),
]

# .eh_frame section-relative offset of each window FDE, as printed
# by objdump --dwarf=frames (first column, zero-padded to 8 digits).
FRAME_PREFIXES = [
    "00374d28 ",  # record host 0x6198900..0x6198ce2
    "00769888 ",  # record-host landing-pad cleanup 0x6198ce2..0x6198d34
    "0076983c ",  # dump host 0x6198d40..0x6198f4d
    "00374cac ",  # subrec append 0x6198790..0x6198853
    "00374c60 ",  # chunk-ptrs push-back 0x61985f0..0x6198775
    "00374ce8 ",  # length-error throw stub 0x6198776..0x6198790
    "00374bd4 ",  # bucket-count computer 0x6198230..0x6198283
    "00374be8 ",  # gather 0x6198290..0x6198364
    "00374c14 ",  # serializer 0x6198370..0x61985e2
    "00376518 ",  # varint encoder 0x61bd410..0x61bd4e9
    "003622e4 ",  # log dispatcher 0x5fceda0..0x5fcee93
    "00368f08 ",  # record impl 0x606b130..0x606b1b3 (re-shipped #3371)
    "00368f34 ",  # record thunk 0x606b1c0..0x606b1cd (re-shipped #3371)
    "00368ea4 ",  # bucket index 0x606afa0..0x606b013 (re-shipped #3371)
    "00368f5c ",  # percentile core 0x606b260..0x606b4fe (re-shipped #3371)
    "00368f70 ",  # P50 0x606b500..0x606b511 (re-shipped #3371)
    "00368fac ",  # average 0x606b540..0x606b5b9 (re-shipped #3371)
    "00368fd4 ",  # stddev 0x606b5d0..0x606b6ae (re-shipped #3371)
    "0075b2d0 ",  # text renderer 0x606b6f0..0x606bc8d (re-shipped #3371)
    "00368ffc ",  # ToString entry 0x606bc90..0x606bcd3 (re-shipped #3371)
    "0076c584 ",  # hex encode 0x61c7e30..0x61c7fb6 (re-shipped #3585/#3561)
]


def dump_one(name, start, stop):
    out = subprocess.run(
        ["objdump", "-d",
         "--start-address=" + start, "--stop-address=" + stop,
         "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    with open(os.path.join(HERE, name), "w") as fh:
        fh.write(out)
    print("wrote", name, len(out.splitlines()), "lines")


def main():
    for name, start, stop in EXCERPTS + RESHIPPED:
        dump_one(name, start, stop)
    frames = subprocess.run(
        ["objdump", "--dwarf=frames", "work/hl-node-115.bin"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    blocks = []
    for prefix in FRAME_PREFIXES:
        block = []
        in_block = False
        for line in frames.splitlines():
            if line.startswith(prefix):
                in_block = True
            elif in_block and line == "":
                break
            if in_block:
                block.append(line)
        if not block:
            print("MISSING frame for prefix", prefix, file=sys.stderr)
            return 1
        blocks.append("\n".join(block))
    with open(os.path.join(HERE, "frames.txt"), "w") as fh:
        fh.write("\n\n".join(blocks) + "\n")
    print("wrote frames.txt", len(blocks), "FDEs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
