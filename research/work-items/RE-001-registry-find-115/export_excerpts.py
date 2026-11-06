"""Export the verbatim objdump excerpts for the
RE-001-registry-find-115 packet.

Usage (from the repository root):
    python3 research/work-items/RE-001-registry-find-115/export_excerpts.py

Each excerpt is one whole function (FDE range) from the node #115
binary, dumped with objdump -d on the relative path
work/hl-node-115.bin, so the header line is reproducible
byte-for-byte against a fresh objdump run by verify.py.

Instruction-level detail lives only in these excerpt text files,
not in records.json. The mnemonics in the excerpts (endbr64
included) are genuine instructions present in the target binary,
not placeholders.

The status_builder excerpt was already exported byte-identical by
the RE-001-registry-create-115 packet (#3440); this script
regenerates it from the same binary so the packet stays
self-contained, and verify.py checks it byte-for-byte against a
fresh objdump run like every other excerpt.
"""

import subprocess
import sys
from pathlib import Path

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]

WINDOWS = [
    # Core behaviour: the Find pair plus the '=' options parser and
    # the options-map merge (the host's first step for a non-default
    # name), the delegate table search, and the fallback variant.
    ("find_entry.txt", 0x609E510, 0x609F073),      # Find entry (delegate match)
    ("find_norm.txt", 0x609A410, 0x609A67C),       # Find normalizer ('=' parser driver)
    ("parser.txt", 0x60C1190, 0x60C1887),          # '=' options parser
    ("trim.txt", 0x61D11F0, 0x61D1382),            # whitespace trim
    ("value_extract.txt", 0x60B97F0, 0x60B9D70),   # option value extractor
    ("map_find.txt", 0x609A1B0, 0x609A2E7),        # options-map find
    ("map_erase.txt", 0x609A2F0, 0x609A3DE),       # options-map erase
    ("map_index.txt", 0x60C0E90, 0x60C112F),       # options-map operator[]
    ("map_clear.txt", 0x5D5B300, 0x5D5B39B),       # options-map clear
    ("status_copy.txt", 0x60B7AC0, 0x60B7B29),      # Status move-assign
    ("value_assign.txt", 0x60B79E0, 0x60B7AB8),     # std::string move-assign
    ("range_assign.txt", 0x60B7CD0, 0x60B7D73),     # std::string range assign
    ("value_copy.txt", 0x60B9D70, 0x60B9DFC),       # 0x50-byte value-struct copy
    ("thunk.txt", 0x6098510, 0x60985AF),            # worker entry thunk
    ("worker.txt", 0x6097630, 0x60984E8),           # delegate table search
    ("matcher.txt", 0x60BB9A0, 0x60BBDEB),          # per-entry match + serialize
    ("resolver.txt", 0x60971C0, 0x609755B),         # name quoting resolver
    ("serializer.txt", 0x60BA600, 0x60BB855),       # type-directed serializer (boundary)
    ("fallback.txt", 0x609E2D0, 0x609E3E2),         # fallback Find variant
    ("fallback_delegate.txt", 0x6097150, 0x6097192),  # fallback delegate wrapper
    ("delegate_impl.txt", 0x6097110, 0x609714E),    # delegate vtable slot 0x48 call
    ("value_dtor.txt", 0x5E33FB0, 0x5E33FEA),       # 0x50-byte value-struct dtor
    ("cstr_replace.txt", 0x60B79B0, 0x60B79DE),     # string assign from C string
    ("cstr_ctor.txt", 0x60B7D80, 0x60B7E63),        # string construct from C string
    # Shared Status builder (re-shipped from #3440).
    ("status_builder.txt", 0x61CF670, 0x61CF767),  # Status(code, subcode, msg1, msg2)
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
