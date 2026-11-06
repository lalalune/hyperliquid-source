"""Regenerate the verbatim disassembly excerpts for the
RE-001-refresh-callee-8a0-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-refresh-callee-8a0-115/export_excerpts.py

Writes the whole-function excerpts for the refresh routine
0x5eef8a0, its cleanup fragment, the snapshot filler, the
string-move helper, the produce identity, the +0x70/+0x78 chain
identities, the +0x80/+0x88 constant identities, the pid wrapper,
the range functions, the record helpers, the handler walker, the
two new caller functions, and the three call-site windows. The
excerpts are stored verbatim; verify.py checks that a fresh run
reproduces them byte-for-byte. Instruction-level detail lives
only in these excerpt texts, not in records.json.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [('main.txt', 99547296, 99548489), ('cleanup.txt', 99547220, 99547293), ('filler.txt', 99545984, 99547219), ('string_move.txt', 99531552, 99531768), ('produce_identity.txt', 97789920, 97790114), ('walker70.txt', 97710016, 97710186), ('walker78.txt', 97709840, 97710010), ('const_minus1.txt', 97775472, 97775484), ('const_zero.txt', 97775488, 97775495), ('pid_wrapper.txt', 101539456, 101539476), ('range_begin.txt', 99529360, 99529404), ('range_end.txt', 99530576, 99530629), ('init_record.txt', 99542304, 99542354), ('store_value.txt', 99542368, 99542380), ('bump_counter.txt', 99542384, 99542396), ('walker.txt', 97834128, 97834322), ('caller_5ef0390.txt', 99550096, 99550728), ('caller_5ef9520.txt', 99587360, 99587936), ('site-5d7e0d7.txt', 98033840, 98033906), ('site-5ef03d5.txt', 99550134, 99550170), ('site-5ef9565.txt', 99587398, 99587434)]


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
