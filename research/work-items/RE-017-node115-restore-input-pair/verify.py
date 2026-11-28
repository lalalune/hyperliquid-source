"""Verify the rolling snapshot and materializer-row joins for node #115."""

import csv
import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

PACKET = Path(__file__).parent
MISSING_ROW = 1 << 63


def first_height_row(rows, height):
    return next((row for row in rows if row[3] == height and row[0] != MISSING_ROW), None)


def select_inputs(root, requested_height, decoded_height, rows):
    """Model ordinary loader coordinates with an already decoded state."""
    row = first_height_row(rows, requested_height)
    if row is None:
        return "missing-materializer-row", None
    rolling_path = root + b"/hyperliquid_data/abci_state.rmp"
    if decoded_height != requested_height:
        return "decoded-height-mismatch", rolling_path
    return rolling_path, row


def verify_anchors():
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def read(name, address, size):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + size <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + size]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", frame["va"], frame["size"]), frame["va"])
    bounds = {fde["entry"]: fde["end"] for fde in fdes}
    windows = {}
    starts = set()
    with (PACKET / "instructions.tsv").open() as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            start, address = (int(row[field], 16) for field in ("fde", "va"))
            raw = bytes.fromhex(row["bytes"])
            assert start <= address < address + len(raw) <= bounds[start]
            assert address not in windows and raw == read(".text", address, len(raw))
            windows[address] = raw
            starts.add(start)

    def edge(site, opcode):
        raw = windows[site]
        assert raw.startswith(bytes.fromhex(opcode))
        return site + len(raw) + int.from_bytes(raw[len(opcode) // 2:], "little", signed=True)

    rela = sections[".rela.dyn"]
    relative = {address: addend for address, info, addend in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"]),
    ) if info == 8}
    assert [
        edge(0x3C12847, "e8"), edge(0x3C12877, "e8"), edge(0x4468C51, "e8"),
        relative[edge(0x3C128A2, "ff15")], edge(0x3C13536, "e8"),
        relative[edge(0x3C135C2, "ff15")], relative[edge(0x3C13665, "ff15")],
    ] == [0x4468C20, 0x38DBD80, 0x4468E30, 0x3C13520, 0x422E410, 0x3C13610, 0x3C2E860]
    assert edge(0x3C128D7, "0f85") == 0x3C12A16
    assert edge(0x5485AE0, "e8") == 0x5942870

    for name_site, writer_or_reader in ((0x3C1286B, "reader"), (0x5485ACE, "writer")):
        name_record = edge(name_site, "488d35")
        assert read(".rodata", relative[name_record], 10) == b"abci_state", writer_or_reader
        assert read(".data.rel.ro", name_record + 8, 8) == struct.pack("<Q", 10)

    root_slot = edge(0x38DBD8E, "4c8b3d")
    assert root_slot == edge(0x594287E, "4c8b3d") == 0x64E0918
    assert relative[root_slot] == 0x64F06C0
    for reader, writer, opcode, literal in (
        (0x38DBDC4, 0x59428B4, "488d15", b"rmp"),
        (0x38DBDCB, 0x59428BB, "488d0d", b"json"),
        (0x38DBE4F, 0x594293F, "488d35", b"\xc0\x01.\xc0\x00"),
        (0x38DBE89, 0x5942979, "488d35", b"\xc0\x12/hyperliquid_data/\xc0\x00"),
    ):
        assert all(read(".rodata", edge(site, opcode), len(literal)) == literal
                   for site in (reader, writer))
    assert edge(0x38DBE56, "4c8b25") == edge(0x5942946, "4c8b25") == 0x64DF6E8
    for left_ref, right_ref, left_jump, right_jump in (
        (0x38DBE34, 0x5942924, 0x46DD7FD, 0x561632D),
        (0x38DBE73, 0x5942963, 0x37BE6FE, 0x58621BE),
    ):
        left = edge(left_ref, "488d05")
        right = edge(right_ref, "488d05")
        assert (left_jump - left) == (right_jump - right)
        size = left_jump - left + 2
        assert read(".text", left, size) == read(".text", right, size)
        assert edge(left_jump, "ff25") == edge(right_jump, "ff25") == 0x64DF720

    print(f"PASS: {len(windows)} spans, {len(starts)} FDEs, SHA-256 {TARGET_SHA256}")
    print("PASS: reader/writer same rooted filename, two matching callback bodies with rel32-only masks")
    print("PASS: height-row selector and separate path enter the same loader/materializer chain")


def controls():
    root = b"/offline-node"
    rolling = b"/offline-node/hyperliquid_data/abci_state.rmp"
    row = (4, b"path-a", 6, 10000)
    rows = [(1, b"wrong", 5, 10001), (MISSING_ROW, None, 0, 10000),
            row, (5, b"path-b", 6, 10000)]
    assert select_inputs(root, 10000, 10000, rows) == (rolling, row)
    assert select_inputs(root, 10000, 10001, rows) == ("decoded-height-mismatch", rolling)
    assert select_inputs(root, 10001, 10000, rows) == ("decoded-height-mismatch", rolling)
    assert select_inputs(root, 10002, 10002, rows) == ("missing-materializer-row", None)
    assert select_inputs(root, 10000, 10000, rows[:2]) == ("missing-materializer-row", None)
    empty_owner = (0, b"", 0, 10000)
    assert select_inputs(root, 10000, 10000, [empty_owner, row]) == (rolling, empty_owner)
    assert select_inputs(root + b"/", 10000, 10000, rows)[0] == rolling.replace(
        b"/hyperliquid_data", b"//hyperliquid_data")
    print("PASS: seven synthetic input-pair controls")


if __name__ == "__main__":
    assert __debug__, "run without -O"
    verify_anchors()
    controls()
