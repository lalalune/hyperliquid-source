"""Export the verbatim objdump excerpts for the
RE-001-registry-create-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-registry-create-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Instruction-level detail lives only in these excerpt text files,
not in records.json. The mnemonics in the excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.

Excerpts marked "re-shipped" were already exported byte-identical
by the RE-001-basic-stats-factory-115 packet (#3386); this script
regenerates them from the same binary so the packet stays
self-contained, and verify.py checks them byte-for-byte against a
fresh objdump run like every other excerpt.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    # Core behaviour: create a Statistics object from a registered
    # factory by name (the host's second step for a non-default
    # name, after the Find pair 0x609e510/0x609a410).
    ("translator.txt", 0x6076B20, 0x6077712),      # create-by-name translator
    ("find_wrapper.txt", 0x6076620, 0x6076B15),    # mutex-guarded registry find
    ("status_builder.txt", 0x61CF670, 0x61CF767),  # Status(code, subcode, msg1, msg2)
    # Caller context (re-shipped from #3386).
    ("host.txt", 0x6077820, 0x60780A0),            # create-by-name entry
    # Factory create callback + object lifecycle (re-shipped #3386).
    ("creator.txt", 0x6071BA0, 0x6071CCB),         # factory create callback
    ("stats_ctor.txt", 0x6071A00, 0x6071B60),      # StatisticsImpl ctor
    ("stats_dtor.txt", 0x6070EA0, 0x607103C),      # StatisticsImpl destructor
    ("stats_dtor_delete.txt", 0x6071040, 0x607105B),  # deleting destructor
    # std::function manager for the creator lambda (re-shipped #3386).
    ("manager.txt", 0x606FA50, 0x606FA7D),
    # FactoryEntry<Statistics> vtable slots (re-shipped #3386).
    ("factory_matches.txt", 0x606FB40, 0x606FB4E),
    ("factory_name.txt", 0x606FB50, 0x606FB5E),
    # PatternEntry vtable slots + matcher helper (re-shipped #3386).
    ("pattern_matches.txt", 0x61F8670, 0x61F86F2),
    ("pattern_name.txt", 0x61F8120, 0x61F8129),
    ("match_helper.txt", 0x61F8430, 0x61F8670),
    ("submatch.txt", 0x61F8280, 0x61F842B),
]


def main():
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / "excerpts" / name).write_text(text)
        print("wrote excerpts/%s (%d bytes)" % (name, len(text)))


if __name__ == "__main__":
    sys.exit(main())
