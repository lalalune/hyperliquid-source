"""Verify selected post-restore c_staking preparation in the #115 ELF."""

import csv
import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

PACKET = Path(__file__).parent


def first_collection(primary_tag, fallback_count):
    """Classify the first descriptor at the round-aware helper entry."""
    if primary_tag != 1 << 63:
        return "ordinary", 0x457F2F0
    if fallback_count != 0:
        return "fallback", 0x3920A30
    return "empty", None


def history_spans(capacity, cursor, length):
    """Return the two row ranges for an ordinary, valid in-memory ring."""
    if capacity == 0:
        if cursor or length:
            raise ValueError("nonempty ring requires capacity")
        return (0, 0), (0, 0)
    if not 0 <= cursor < 2 * capacity or not 0 <= length <= capacity:
        raise ValueError("input outside the selected ordinary ring")
    if length == 0:
        return (0, 0), (0, 0)
    head = cursor - capacity if cursor >= capacity else cursor
    tail_length = min(length, capacity - head)
    return (head * 0x70, (head + tail_length) * 0x70), (0, (length - tail_length) * 0x70)


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
    with (PACKET / "instructions.tsv").open() as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            start, address = (int(row[field], 16) for field in ("fde", "va"))
            raw = bytes.fromhex(row["bytes"])
            assert start <= address < address + len(raw) <= bounds[start]
            assert address not in windows and raw == read(".text", address, len(raw))
            windows[address] = raw

    def edge(site, opcode):
        raw = windows[site]
        assert raw.startswith(bytes.fromhex(opcode))
        return site + len(raw) + int.from_bytes(raw[len(opcode) // 2:], "little", signed=True)

    assert edge(0x3C12923, "e8") == 0x420B9C0
    slot = edge(0x3C1292B, "ff15")
    rela = sections[".rela.dyn"]
    assert [(info, target) for addr, info, target in struct.iter_unpack(
        "<QQq", read(".rela.dyn", rela["va"], rela["size"]),
    ) if addr == slot] == [(8, 0x3C374E0)]
    for site, opcode, target in (
        (0x420B9E5, "71", 0x420BA13), (0x420B9F6, "74", 0x420BA3B),
        (0x420BA0C, "e8", 0x3920A30), (0x420BA1C, "e8", 0x457F2F0),
        (0x420BA92, "e8", 0x391C6A0), (0x420BAFF, "e8", 0x3CDBA10),
        (0x420BB40, "e8", 0x3CEB5A0), (0x3C37501, "71", 0x3C37530),
        (0x3C3755B, "77", 0x3C3756D), (0x3C375D0, "e8", 0x451D9A0),
        (0x3C3765F, "e8", 0x3D6EEE0), (0x3C376B8, "e8", 0x39038F0),
        (0x3C376E6, "e8", 0x392EA10),
    ):
        assert edge(site, opcode) == target
    assert bytes(windows[site][-1] for site in (0x3C37574, 0x3C3757B, 0x3C37582)) == b"ppp"
    assert windows[0x3C376BD][-1] == 0x14
    print(f"PASS: #115 {TARGET_SHA256}, {len(windows)} spans in verified FDEs")
    print(f"PASS: first helper direct edge, second helper R_X86_64_RELATIVE slot {slot:#x}")


def controls():
    sentinel = 1 << 63
    descriptors = (
        (0, 0, ("ordinary", 0x457F2F0)),
        (sentinel - 1, 0, ("ordinary", 0x457F2F0)),
        (sentinel, 4, ("fallback", 0x3920A30)),
        (sentinel, 0, ("empty", None)),
        (sentinel + 1, 4, ("ordinary", 0x457F2F0)),
    )
    for tag, fallback_count, expected in descriptors:
        assert first_collection(tag, fallback_count) == expected
    print(f"PASS: {len(descriptors)} primary descriptor route controls")
    for capacity in range(1, 13):
        for cursor in range(capacity * 2):
            for length in range(capacity + 1):
                actual = [row for first, end in history_spans(capacity, cursor, length)
                          for row in range(first // 0x70, end // 0x70)]
                expected = [(cursor + index) % capacity for index in range(length)]
                assert actual == expected, (capacity, cursor, length)
    count = sum((capacity * 2) * (capacity + 1) for capacity in range(1, 13))
    print(f"PASS: {count} finite valid-ring cases against independent row-by-row iteration")
    assert history_spans(0, 0, 0) == ((0, 0), (0, 0))
    for capacity, cursor, length in ((0, 0, 1), (3, 0, 4), (3, 6, 0)):
        try:
            history_spans(capacity, cursor, length)
        except ValueError:
            pass
        else:
            raise AssertionError((capacity, cursor, length))
    print("PASS: empty ring and three out-of-contract controls")


if __name__ == "__main__":
    assert __debug__, "run without -O"
    verify_anchors()
    controls()
