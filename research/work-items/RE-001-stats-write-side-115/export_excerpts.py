"""Export the verbatim objdump excerpts for the
RE-001-stats-write-side-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-stats-write-side-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Re-shipped excerpts (mutex_lock.txt, mutex_unlock.txt from
RE-001-locked-ticker-read-115 #3392, themselves from
RE-001-stats-produce-115 #3362) are copied byte-identical, not
regenerated here; verify.py regenerates every excerpt fresh from
the binary and requires byte-equality, which subsumes the
re-ship check.

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
    ("record_tick.txt", 0x606FBA0, 0x606FC59),           # slot 0xb0 record tick
    ("cpu_shard_pick.txt", 0x60D5CD0, 0x60D5CF0),       # CPUID APIC-id picker
    ("lcg_seed.txt", 0x61C4080, 0x61C4117),             # thread-local LCG seed
    ("set_ticker.txt", 0x6070DC0, 0x6070E9A),           # slot 0xb8 locked set
    ("set_cleanup.txt", 0x6070D92, 0x6070DB2),           # 0xb8 unlock + resume
    ("set_core.txt", 0x6070AC0, 0x6070B1B),             # unlocked set core
    ("get_reset_ticker.txt", 0x6070C50, 0x6070D92),     # slot 0xc0 get-and-reset
    ("record_hist.txt", 0x606FEF0, 0x606FFCE),          # slot 0xd8 record hist
    ("record_hist_devirt.txt", 0x606FFD0, 0x60700C4),   # slot 0xd0 devirt twin
    ("reset_stats.txt", 0x6070B30, 0x6070C2A),          # slot 0xe0 reset
    ("reset_cleanup.txt", 0x6070B1C, 0x6070B2E),         # reset unlock + resume
    ("reset_cleanup2.txt", 0x6070C2A, 0x6070C4A),        # reset unlock + resume 2
    ("stats_name.txt", 0x606FA20, 0x606FA2C),           # slot 0x70 name
    ("delegate_getter.txt", 0x606FA30, 0x606FA39),      # slot 0x88 delegate
    ("hist_id_check.txt", 0x606FA40, 0x606FA4B),        # slot 0xf8 hist-id check
    ("stats_ctor.txt", 0x6071A00, 0x6071B60),           # StatisticsImpl ctor
    ("stats_dtor.txt", 0x6070EA0, 0x607103C),           # slot 0x0 dtor
    ("hist_record.txt", 0x606B130, 0x606B1B3),          # HistogramImpl slot 0x20
    ("hist_bucket_index.txt", 0x606AFA0, 0x606B013),    # bucket lower_bound
    ("hist_locked_init.txt", 0x606B0C0, 0x606B10A),     # HistogramImpl slot 0x10
    ("hist_shared_init.txt", 0x606B020, 0x606B07C),     # shared record init
    ("boundary_gen.txt", 0x606BF10, 0x606C134),         # boundary generator
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
