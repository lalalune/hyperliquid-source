"""Recheck the two native serializer spans and compare synthetic byte receipts."""

import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory

from compare import CHUNK, compare

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET = Path(__file__).resolve().parent


def verify_binary():
    data = Path("artifacts/node/115/hl-node").read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    ranges = {(row["start"], row["end"]) for row in fdes if (row["start"], row["fde"]) in indexed}
    wanted = {(0x4E4AF80, 0x4E4B3EE), (0x4E4B3F0, 0x4E4B85E),
              (0x5485A60, 0x5485F7F), (0x5485F80, 0x548649F),
              (0x5A07EC0, 0x5A0871C), (0x5A08720, 0x5A08F7C),
              (0x15024A0, 0x15026D1), (0x5CA5110, 0x5CA53A1)}
    assert wanted <= ranges
    compact = {
        0x4E4AFF1: "c744241800040001", 0x4E4B02B: "4939c4",
        0x4E4B03E: "488bbc2480000000", 0x4E4B046: "4c8ba42488000000",
        0x4E4B055: "48897c2420", 0x4E4B05A: "4c89e6",
        0x4E4B069: "4885c0", 0x4E4B26F: "488b442420",
        0x4E4B274: "48894108", 0x4E4B278: "4c896110",
    }
    captures = {
        0x4E35F5F: "488d7c2450", 0x4E35F84: "0f10442450", 0x4E35F89: "0f1103",
        0x4E35F8C: "488b442460", 0x4E35F91: "48894310",
    }
    wrappers = {
        0x5485B39: "488b442458", 0x5485B3E: "4889442448",
        0x5485B4D: "0f10442460", 0x5485B52: "0f29842470010000",
        0x5485D82: "488b442448", 0x5485D87: "49894708", 0x5485D93: "410f114710",
    }
    hash_inputs = {
        0x5A0802C: "488b442408", 0x5A08031: "488b542410", 0x5A08081: "48890424",
        0x5A0808D: "4889542408", 0x5A080B1: "4889e6",
    }
    file_writer = {
        0x15024B7: "4989f5", 0x15024BA: "4889fd",
        0x1502557: "4889ea", 0x150255A: "4c89e9",
        0x5CA5124: "4889cb", 0x5CA5127: "4989d6",
        0x5CA52E0: "4901c6", 0x5CA52EE: "4c89f6", 0x5CA52F1: "4889da",
        0x5CA52F4: "41ffd4", 0x5CA5305: "4829c1",
    }
    for group, delta in ((compact, 0x470), (captures, 0x530), (wrappers, 0x520), (hash_inputs, 0x860), (file_writer, 0)):
        for address, encoding in group.items():
            raw = bytes.fromhex(encoding)
            assert read_va(data, address, len(raw)) == raw
            assert read_va(data, address + delta, len(raw)) == raw
    for address, target in (
        (0x4E4B010, 0x5480950), (0x4E4B480, 0x5481900),
        (0x4E35F6D, 0x4E4AF80), (0x4E3649D, 0x4E4B3F0),
        (0x4E499F9, 0x4E35E90), (0x4E45AC9, 0x4E363C0),
        (0x5485B2B, 0x4E49960), (0x548604B, 0x4E45A30),
        (0x5A0801E, 0x5485A60), (0x5A0887E, 0x5485F80),
        (0x5A080B9, 0x452AAB0), (0x5A08919, 0x452AAB0),
    ):
        assert rip_target(data, address, b"\xe8", 5) == target
    relocs = relative_relocations(data)
    for address, slot, target in (
        (0x4E4B063, 0x64E09E8, 0x15024A0), (0x4E4B4D3, 0x64E09E8, 0x15024A0),
        (0x150255D, 0x64E09F8, 0x5CA5110), (0x150264B, 0x64E0A00, 0x1502DA0),
    ):
        assert rip_target(data, address, b"\xff\x15", 6) == slot
        assert relocs[slot] == target
    slot = rip_target(data, 0x5CA52CF, b"\x4c\x8b\x25", 7)
    assert slot == 0x64DFFC0
    section = {row["name"]: row for row in sections}
    dyn = section[".dynsym"]["offset"]
    strings = section[".dynstr"]["offset"]
    rel = section[".rela.dyn"]
    offset = rel["offset"]
    matching = [(symbol, addend) for target, symbol, addend in
                struct.iter_unpack("<QQq", data[offset:offset + rel["size"]]) if target == slot]
    assert len(matching) == 1
    symbol, _ = matching[0]
    assert symbol & 0xffffffff == 6  # R_X86_64_GLOB_DAT
    name = struct.unpack_from("<I", data, dyn + 24 * (symbol >> 32))[0]
    assert data[strings + name:strings + name + 6] == b"write\0"
    print(f"PASS: node #115 SHA-256 {TARGET}")
    print("PASS: both native layouts pass and return identical pointer/length words")
    print("PASS: atomic writer forwards the exact span to the dynamic write loop")


def compare_controls():
    data = bytes.fromhex("81a66865696768742a") + bytes(index % 251 for index in range(CHUNK + 32))
    with TemporaryDirectory() as temp:
        root = Path(temp)
        left, right = root / "periodic.rmp", root / "span.bin"

        def save(path, value):
            path.write_bytes(value)
            return path, hashlib.sha256(value).hexdigest()

        first = save(left, data)
        second = save(right, data)
        assert compare(*first, *second)["identical"]
        for value, offset in (
            (data[:-1], len(data) - 1),
            (data + b"\x00", len(data)),
            (data[:CHUNK] + bytes([data[CHUNK] ^ 1]) + data[CHUNK + 1:], CHUNK),
        ):
            changed = save(right, value)
            result = compare(*first, *changed)
            assert not result["identical"] and result["first_difference_offset"] == offset
        try:
            compare(*first, right, "0" * 64)
        except ValueError as error:
            assert "serializer slice SHA-256 mismatch" in str(error)
        else:
            raise AssertionError("accepted wrong SHA-256")
        status = subprocess.run([sys.executable, "-B", PACKET / "compare.py", *first, *changed],
                                capture_output=True, text=True)
        assert status.returncode == 1
        assert json.loads(status.stdout)["first_difference_offset"] == CHUNK
    print("PASS: synthetic exact match, extension/truncation, cross-chunk difference and SHA/CLI controls")


if __name__ == "__main__":
    verify_binary()
    compare_controls()
