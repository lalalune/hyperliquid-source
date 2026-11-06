#!/usr/bin/env python3
"""Export the verbatim objdump excerpts for the RE-001-default-name-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-default-name-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Instruction-level detail lives only in these excerpt text files,
not in records.json. The mnemonics in the excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.

The find_entry, find_norm and matcher excerpts were already
exported byte-identical by the RE-001-registry-find-115 (#3485)
packet; this script regenerates them from the same binary so the
packet stays self-contained, and verify.py checks them byte-for-byte
against a fresh objdump run like every other excerpt. The
status_builder excerpt is likewise regenerated from the
RE-001-registry-create-115 (#3440) packet.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    # The centerpiece: the static initializer for the global name.
    ("initializer.txt", 0x61D2970, 0x61D29AF),          # "nullptr" ctor + atexit
    # Consumers that decide on the name.
    ("create_host.txt", 0x6077820, 0x60780A0),          # create-by-name host
    ("resolver_host.txt", 0x607E710, 0x607EA0A),         # resolver host
    ("twin_a.txt", 0x6086B70, 0x6086CC9),                # twin consumer A
    ("twin_b.txt", 0x60A7420, 0x60A7579),                # twin consumer B
    ("matcher_wrapper.txt", 0x60BF5F0, 0x60BF78D),       # matcher wrapper
    ("release_host.txt", 0x6137290, 0x6137688),          # release-by-name host
    # Shared helpers the consumers call.
    ("string_equal.txt", 0x5E4BCF0, 0x5E4BD2B),          # string equality
    ("map_find_name.txt", 0x5D66E30, 0x5D66F67),         # unordered_map find
    ("kind_validator.txt", 0x60BF980, 0x60BFCA2),        # kind validator
    ("once_init_create.txt", 0x6075BC0, 0x6075FF5),      # pthread_once init
    ("once_init_release.txt", 0x6138A10, 0x6138A8B),     # pthread_once init
    ("canonical_name.txt", 0x6130140, 0x613014C),        # canonical-name getter
    # Re-shipped byte-identical from #3485 (consumers themselves).
    ("find_entry.txt", 0x609E510, 0x609F073),            # registry Find entry
    ("find_norm.txt", 0x609A410, 0x609A67C),             # normalized Find
    ("matcher.txt", 0x60BB9A0, 0x60BBDEB),               # kind matcher
    # Re-shipped byte-identical from #3440.
    ("status_builder.txt", 0x61CF670, 0x61CF767),        # Status builder
]


def main():
    (PACKET / "excerpts").mkdir(exist_ok=True)
    for name, start, stop in WINDOWS:
        text = subprocess.run(
            ["objdump", "-d", "--start-address=%#x" % start,
             "--stop-address=%#x" % stop, "work/hl-node-115.bin"],
            capture_output=True, text=True, check=True, cwd=ROOT).stdout
        (PACKET / "excerpts" / name).write_text(text)
        print("wrote excerpts/%s (%d bytes)" % (name, len(text)))


if __name__ == "__main__":
    sys.exit(main())
