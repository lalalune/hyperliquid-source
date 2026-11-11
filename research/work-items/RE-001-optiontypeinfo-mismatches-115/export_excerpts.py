"""Export verbatim objdump excerpts for RE-001-optiontypeinfo-mismatches-115.

Run from the repository root:
    python3 research/work-items/RE-001-optiontypeinfo-mismatches-115/export_excerpts.py

Writes one file per window next to this script, using the relative binary
path work/hl-node-115.bin so the objdump header line matches verify.py.
All windows are whole functions (FDE ranges verified with readelf).
"""

import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
BIN = "work/hl-node-115.bin"

# (filename, start, stop). Four windows are re-shipped byte-identical
# from #4146 (same FDE ranges, same objdump version); the other three are
# new in this work item.
WINDOWS = [
    # The name -> offset map builder (the static initializer).
    ("static-initializer-60aa2b0.objdump.txt", "0x60aa2b0", "0x60b1d78"),
    # The ImmutableDBOptions ctor pack (+0x158..0x15c, +0x190..0x19a).
    ("immutabledboptions-ctor-60a3b60.objdump.txt", "0x60a3b60",
     "0x60a4363"),
    # The DBOptions default ctor tail (+0x210..0x220 stores).
    ("dboptions-ctor-60b2db0.objdump.txt", "0x60b2db0", "0x60b3154"),
    # BuildDBOptions: max_open_files from MutableDBOptions+0x40.
    ("builddboptions-60c2e20.objdump.txt", "0x60c2e20", "0x60c3477"),
    # The (key, OptionTypeInfo) pair constructor used by every entry.
    ("pair-ctor-5d400f0.objdump.txt", "0x5d400f0", "0x5d40477"),
    # The OptionTypeInfo record destructor (five std::function members).
    ("record-dtor-5d3f950.objdump.txt", "0x5d3f950", "0x5d3f9d3"),
    # The std::string(const char*) ctor used for every key string.
    ("string-ctor-609fb90.objdump.txt", "0x609fb90", "0x609fc73"),
    # The one function that accesses a +0x21b struct field (five sites,
    # %rbx) -- evidence that the field belongs to a different struct,
    # not DBOptions (strings at +0x18/+0x28/+0x38/+0x40, a 'D' tag byte
    # at +0x110, +0x220 written as a single byte = 2).
    ("field-21b-owner-5a897e0.objdump.txt", "0x5a897e0", "0x5a8a1cc"),
]


def main():
    for name, start, stop in WINDOWS:
        out = subprocess.run(
            ["objdump", "-d", "--start-address=" + start,
             "--stop-address=" + stop, BIN],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
        with open(os.path.join(HERE, name), "w") as fh:
            fh.write(out)
        print("wrote", name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
