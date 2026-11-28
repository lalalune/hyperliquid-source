"""Authenticate the whole-Locus child worker and exercise its offline schedule."""

from pathlib import Path
import hashlib
import re
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET = Path("artifacts/node/115/hl-node")
FUNCTIONS = {
    (0x3D2A000, 0x3D2A522), (0x3DDBDA0, 0x3DDBE37), (0x3EBE3F0, 0x3EBE62F),
    (0x457CCB0, 0x457CE66), (0x3B91FE0, 0x3B92084),
}


def verify_binary():
    data = TARGET.read_bytes()
    assert hashlib.sha256(data).hexdigest() == SHA
    sections, head = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in head}
    bounds = {(row["start"], row["end"]) for row in fdes if (row["start"], row["fde"]) in indexed}
    assert FUNCTIONS <= bounds

    spans = {}
    for text in Path(__file__).with_name("windows.txt").read_text().splitlines():
        if match := re.match(r"\s+([0-9a-f]+):\s*((?:[0-9a-f]{2} )+)", text):
            address, code = int(match[1], 16), bytes.fromhex(match[2])
            assert address not in spans and read_va(data, address, len(code)) == code
            assert any(start <= address < address + len(code) <= end for start, end in FUNCTIONS)
            spans[address] = code

    def jump(address, opcode, target):
        code = spans[address]
        assert code.startswith(opcode)
        assert address + len(code) + int.from_bytes(code[len(opcode):], "little", signed=True) == target

    for address, opcode, target in (
        (0x3D2A515, b"\xe8", 0x3DDBDA0),
        (0x3DDBE23, b"\xe8", 0x3EBE3F0),
        (0x3EBE415, b"\x0f\x85", 0x3EBE5EE),
        (0x3EBE421, b"\x73", 0x3EBE49D),
        (0x3EBE48B, b"\xe8", 0x457CCB0),
        (0x3EBE4C8, b"\x0f\x84", 0x3EBE423),
        (0x3EBE5DE, b"\xe8", 0x3B91FE0),
        (0x457CD05, b"\x0f\x84", 0x457CE20),
        (0x457CD10, b"\x0f\x84", 0x457CE20),
        (0x457CD68, b"\x75", 0x457CDA2),
        (0x457CD7A, b"\x75", 0x457CD54),
        (0x457CE09, b"\x75", 0x457CE20),
        (0x457CE1A, b"\x0f\x84", 0x457CD00),
    ):
        jump(address, opcode, target)
    for site, code in {
        0x3D2A499: "48c784241801000010000000", 0x3D2A4BA: "488d44240e",
        0x3D2A4BF: "4889842430010000", 0x3D2A4E3: "c644240e00",
        0x3D2A4F4: "48c784244001000010000000", 0x3D2A510: "ba10000000", 0x3DDBDB7: "4c8b7730", 0x3DDBDF9: "480f47d0",
        0x3EBE410: "b004", 0x3EBE41B: "48d1ef", 0x3EBE4CE: "48d1ea",
        0x3EBE507: "4829f8", 0x3EBE514: "4829f9",
        0x3EBE524: "4c8d047f", 0x3EBE528: "4e8d04c2", 0x3EBE52F: "49c1e204", 0x3EBE533: "4901f2",
        0x3EBE597: "4c89442450", 0x3EBE59C: "4889442458", 0x3EBE5A1: "4c89542460",
        0x3EBE5A6: "48894c2468", 0x457CD16: "498d4c2418", 0x457CD20: "488d4810",
        0x457CD5E: "41ff5618", 0x457CD84: "41ff5620", 0x457CDD7: "c60101",
        0x457CDF3: "44884610", 0x457CE0B: "0fb609",
    }.items():
        assert spans[site] == bytes.fromhex(code)
    print(f"PASS: node #115 SHA-256 {SHA}")
    print(f"PASS: {len(spans)} instruction spans, five indexed FDEs, launcher and worker joins")
    print("PASS: paired split and serial strides, lazy constructor, shared stop byte, and status return")


def clip(left_base, right_base, count):
    midpoint = count // 2
    return (left_base, right_base, midpoint), (
        left_base + 24 * midpoint, right_base + 16 * midpoint, count - midpoint,
    )


def serial(destination, descriptor, constructors_needed, visits, stopped=False):
    if stopped:
        return [], [], True, 4
    created, called = [], []
    for index, (empty, status) in enumerate(zip(constructors_needed, visits)):
        pair = (destination + 24 * index, descriptor + 16 * index)
        if empty:
            created.append(pair)
        called.append(pair)
        if status != 4:
            return created, called, True, status
    return created, called, False, 4


def controls():
    d, s = 0x1000, 0x2000
    prefix, suffix = clip(d, s, 16)
    assert prefix == (d, s, 8) and suffix == (d + 0xC0, s + 0x80, 8)
    for n in (2, 3, 15, 16, 17, 59):
        prefix, suffix = clip(d, s, n)
        full = serial(d, s, [True] * n, [4] * n)[1]
        split_visits = []
        for d0, s0, size in (prefix, suffix):
            split_visits.extend(serial(d0, s0, [True] * size, [4] * size)[1])
        assert full == split_visits
    created, called, stopped, status = serial(d, s, [True, False, True, True], [4, 4, 3, 4])
    assert called == [(d, s), (d + 24, s + 16), (d + 48, s + 32)]
    assert created == [called[0], called[2]]
    assert stopped and status == 3
    assert serial(d + 72, s + 48, [True], [4], stopped=stopped) == ([], [], True, 4)
    print("PASS: synthetic full 16-slot split, odd bounds, reuse, non-4 abort and already-stopped cases")


if __name__ == "__main__":
    verify_binary()
    controls()
