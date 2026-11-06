"""Export the verbatim objdump excerpts for the
RE-001-stats-produce-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-produce-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

The stats_copy_site.txt window is the single exception: it is the
statistics shared_ptr copy site inside the 0xf73-byte struct-copy
routine 0x5d57770 (0x5d58249..0x5d5828c), pinned as a site because
only that site is claimed; the rest of the copy routine is not
modelled. The log dispatch excerpt is regenerated here (it is
byte-identical to #3037's log_dispatch.txt). Re-shipped excerpts
(stats_emit.txt, mutex_lock.txt, mutex_unlock.txt, acquire.txt)
are copied byte-identical from their source packets by hand, not
regenerated here; verify.py diffs them against the sources.

Instruction-level detail lives only in these excerpt text files,
not in records.json. The mnemonics in the excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    ("main.txt", 0x6070810, 0x6070AB5),            # StatisticsImpl::ToString
    ("ticker_getter.txt", 0x6070430, 0x607047D),   # sharded ticker sum
    ("histogram_builder.txt", 0x6070500, 0x60705D8),  # HistogramData build
    ("histogram_init_a.txt", 0x606B080, 0x606B0A2),  # bucket-count init
    ("histogram_init_b.txt", 0x606B0C0, 0x606B10A),  # locked shared init
    ("histogram_merge.txt", 0x606BDF0, 0x606BE3D),  # shard merge
    ("histogram_percentiles.txt", 0x606BCE0, 0x606BDCD),  # percentile struct
    ("histogram_thunk.txt", 0x606BDD0, 0x606BDDD),  # slot-0x78 thunk
    ("histogram_delete.txt", 0x5D8B3B0, 0x5D8B3BE),  # sized delete 0x3c8
    ("shared_ptr_copy.txt", 0x5D35C00, 0x5D35C26),  # control copy + bump
    ("rebuild_caller.txt", 0x5D58720, 0x5D58809),  # mutex-guarded rebuild
    ("stats_copy_site.txt", 0x5D58249, 0x5D5828C),  # site in 0x5d57770
    ("log_dispatch.txt", 0x5FCF060, 0x5FCF153),    # log dispatch
]


def main():
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / name).write_text(text)
        print("wrote %s (%d bytes)" % (name, len(text)))


if __name__ == "__main__":
    sys.exit(main())
