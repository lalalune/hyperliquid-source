#!/usr/bin/env python3
"""Check static RE-012 info-format exhibits against node #115."""
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


def sections(blob):
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
    sec = sections(data)

    code = {
        "caller-context.bin": (0x63D4CC0, 0x63D4D38),
        "format-key-helper.bin": (0x63D3D27, 0x63D3D66),
        "varargs-bridge.bin": (0x63D3BD3, 0x63D3C92),
        "callback-dispatch.bin": (0x63BF52C, 0x63BF5B6),
        "formatter.bin": (0x63BE94E, 0x63BF47C),
        "output-buffer-sink.bin": (0x636C530, 0x636C612),
    }
    for name, (start, end) in code.items():
        text = sec[".text"]
        offset = text["offset"] + start - text["address"]
        expected = data[offset:offset + end - start]
        require(len(expected) == end - start, f"truncated target range: {name}")
        require((PACKET / name).read_bytes() == expected, f"raw code exhibit differs: {name}")

    rodata = sec[".rodata"]

    def read_rodata(address, size):
        offset = rodata["offset"] + address - rodata["address"]
        return data[offset:offset + size]

    require(read_rodata(0x4312F2, 5) == b"info\0", "info literal differs")
    require(read_rodata(0x449912, 8) == b'"%s":%s\0', "format literal differs")
    require((PACKET / "info-literal.bin").read_bytes() == b"info\0", "literal exhibit differs")
    require((PACKET / "format-string.bin").read_bytes() == b'"%s":%s\0', "format exhibit differs")

    table = 0xB9E790
    entry = read_rodata(table + 16 * 4, 4)
    require((PACKET / "s-dispatch-entry.bin").read_bytes() == entry, "dispatch exhibit differs")
    displacement = struct.unpack("<i", entry)[0]
    require(table + displacement == 0x63BF226, "s dispatch target differs")
    require(0x73 - 0x63 == 16, "s dispatch index differs")
    corrupted = bytearray(entry)
    corrupted[0] ^= 1
    corrupted_displacement = struct.unpack("<i", corrupted)[0]
    require(table + corrupted_displacement != 0x63BF226,
            "corrupted dispatch control was not detected")

    fde_dir = ROOT / "work/info-format-verification"
    subprocess.run([
        sys.executable, str(ROOT / "tools/fde_extents.py"), "--release", "115",
        "--output-dir", str(fde_dir),
    ], check=True, stdout=subprocess.DEVNULL)
    fde_rows = {}
    for row in (fde_dir / "node-115-fde.tsv").read_text().splitlines()[1:]:
        fields = row.split("\t")
        fde_rows[int(fields[0], 16)] = (int(fields[1], 16), int(fields[4], 16))
    expected_fdes = {
        0x63D4BBE: (0x63D5428, 0x103A7CC),
        0x63D3D27: (0x63D3D66, 0x103A49C),
        0x63D3BD3: (0x63D3C92, 0x103A424),
        0x63BF52C: (0x63BF5B6, 0x1037B10),
        0x63BE94E: (0x63BF47C, 0x1037AA8),
        0x636C530: (0x636C612, 0x102F078),
    }
    for start, expected in expected_fdes.items():
        require(fde_rows.get(start) == expected, f"FDE record differs at {start:#x}")

    print(json.dumps({
        "target_sha256": EXPECTED_SHA256,
        "target_size_bytes": EXPECTED_SIZE,
        "code_exhibits_checked": len(code),
        "string_literals_checked": 2,
        "s_dispatch_entry": entry.hex(),
        "s_dispatch_target": hex(table + displacement),
        "corrupted_dispatch_control_detected": True,
        "fde_extents_checked": len(expected_fdes),
        "captured_code_executed": False,
    }, indent=2))


if __name__ == "__main__":
    main()
