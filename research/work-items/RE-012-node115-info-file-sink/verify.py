#!/usr/bin/env python3
"""Verify the static info-to-file-sink exhibits against node #115."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET = ROOT / "artifacts/node/115/hl-node"
EXPECTED_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
EXPECTED_SIZE = 105_896_032


def require(ok, message):
    if not ok:
        raise ValueError(message)


def section_map(blob):
    shoff = struct.unpack_from("<Q", blob, 40)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", blob, 58)

    def header(index):
        return struct.unpack_from("<IIQQQQIIQQ", blob, shoff + index * shentsize)

    name_header = header(shstrndx)
    names = blob[name_header[4]:name_header[4] + name_header[5]]
    result = {}
    for index in range(shnum):
        item = header(index)
        end = names.index(b"\0", item[0])
        name = names[item[0]:end].decode("ascii")
        result[name] = {"address": item[3], "offset": item[4], "size": item[5]}
    return result


def main():
    data = TARGET.read_bytes()
    require(len(data) == EXPECTED_SIZE, "target size changed")
    require(hashlib.sha256(data).hexdigest() == EXPECTED_SHA256, "target digest changed")
    sections = section_map(data)
    text = sections[".text"]
    windows = {
        "owner-writer-setup.bin": (0x63D4C44, 0x63D4CD0),
        "owner-final-flush-close.bin": (0x63D5333, 0x63D53E0),
        "buffer-context-init.bin": (0x636C4A0, 0x636C52C),
        "outer-buffer-sink.bin": (0x636C530, 0x636C612),
        "final-buffer-flush.bin": (0x636C620, 0x636C672),
        "fd-writer.bin": (0x63D3B90, 0x63D3BD3),
    }
    for name, (start, end) in windows.items():
        offset = text["offset"] + start - text["address"]
        expected = data[offset:offset + end - start]
        require(len(expected) == end - start, f"truncated target window: {name}")
        require((PACKET / name).read_bytes() == expected, f"raw code exhibit differs: {name}")

    fde_dir = ROOT / "work/info-file-sink-verification"
    subprocess.run([
        sys.executable, str(ROOT / "tools/fde_extents.py"), "--release", "115",
        "--output-dir", str(fde_dir),
    ], check=True, stdout=subprocess.DEVNULL)
    fdes = {}
    for row in (fde_dir / "node-115-fde.tsv").read_text().splitlines()[1:]:
        fields = row.split("\t")
        fdes[int(fields[0], 16)] = (int(fields[1], 16), int(fields[4], 16))
    expected_fdes = {
        0x63D4BBE: (0x63D5428, 0x103A7CC),
        0x636C4A0: (0x636C52C, 0x102F04C),
        0x636C530: (0x636C612, 0x102F078),
        0x636C620: (0x636C672, 0x102F0C4),
        0x63D3B90: (0x63D3BD3, 0x103A3FC),
    }
    for start, expected in expected_fdes.items():
        require(fdes.get(start) == expected, f"FDE record differs at {start:#x}")

    print(json.dumps({
        "target_sha256": EXPECTED_SHA256,
        "target_size_bytes": EXPECTED_SIZE,
        "raw_code_windows_checked": len(windows),
        "fde_extents_checked": len(expected_fdes),
        "syscall_number": 1,
        "captured_code_executed": False,
    }, indent=2))


if __name__ == "__main__":
    main()
