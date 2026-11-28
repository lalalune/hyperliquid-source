"""Check the selected positional checkpoint-root cadence path without executing the ELF."""

import hashlib
from pathlib import Path
import sys

PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(Path.cwd() / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def main():
    assert __debug__, "run without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def at(name, address, length):
        section = sections[name]
        delta = address - section["va"]
        assert 0 <= delta <= delta + length <= section["size"]
        offset = section["offset"] + delta
        return data[offset:offset + length]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(at(".eh_frame", frame["va"], frame["size"]), frame["va"])
    indexed = {row["entry"]: row["end"] for row in fdes}
    entries = (0x33B2A30, 0x303C300, 0x3C2E860, 0x54897E0, 0x5AFA030, 0x5AFA3B0)
    bounds = [(entry, indexed[entry]) for entry in entries]
    def matches_window(address, raw):
        return (any(start <= address < address + len(raw) <= end for start, end in bounds)
                and at(".text", address, len(raw)) == raw)

    windows = {}
    for line in (PACKET / "windows.txt").read_text().splitlines():
        address, encoding, _ = line.split("\t", maxsplit=2)
        address = int(address, 16)
        raw = bytes.fromhex(encoding)
        assert address not in windows
        assert matches_window(address, raw)
        windows[address] = raw

    def operand(address, opcode):
        prefix = bytes.fromhex(opcode)
        raw = windows[address]
        assert raw.startswith(prefix) and len(raw) > len(prefix)
        return int.from_bytes(raw[len(prefix):], "little")

    def edge(address, opcode):
        prefix = bytes.fromhex(opcode)
        raw = windows[address]
        assert raw.startswith(prefix) and len(raw) > len(prefix)
        return address + len(raw) + int.from_bytes(raw[len(prefix):], "little", signed=True)

    table = edge(0x33B2C3A, "4c8d2d")
    assert table == 0x765648
    assert edge(0x33B2C47, "e8") == 0x303C300
    assert operand(0x303C30A, "8b46") == 8
    assert windows[0x303C30D] == bytes.fromhex("85c0")
    assert edge(0x303C30F, "74") == 0x303C353
    result = operand(0x303C353, "66c707")
    assert result & 0xFF == operand(0x33B2C54, "4080fd") == 9
    assert windows[0x33B2C66] == bytes.fromhex("4963448500")
    assert windows[0x33B2C6B] == bytes.fromhex("4c01e8")
    assert windows[0x33B2C6E] == bytes.fromhex("ffe0")

    def entry(index):
        return table + int.from_bytes(at(".rodata", table + 4 * index, 4), "little", signed=True)

    assert [entry(i) for i in (1, 2, 3, result >> 8)] == [
        0x33B2F9D, 0x33B2DC1, 0x33B2C70, 0x33B35E0,
    ]
    for key, branch, address in [
        (b"qrs", 0x33B2FAF, 0x33B4B24),
        (b"highest_quorum_height", 0x33B2DCA, 0x33B49F5),
        (b"htm", 0x33B2C7D, 0x33B43A4),
    ]:
        assert 0 < address - edge(branch, "0f85") < 0x40
        assert at(".rodata", edge(address, "488d05"), len(key)) == key

    assert edge(0x33B2FC2, "e8") == 0x3259070
    assert operand(0x33B2FCF, "4080fd") == 9
    assert operand(0x33B2FD9, "488b8424") == 0x180
    assert operand(0x33B2FE1, "48894424") == operand(0x33B35E0, "488b5424") == 0x10
    assert operand(0x33B2FE6, "488d8424") == 0x17B
    assert 0x17B + operand(0x33B2FEE, "0f1040") == 0x188
    assert operand(0x33B2FFA, "488d8424") == 0x158
    assert windows[0x33B3002] == bytes.fromhex("0f1100")
    qrs_staging = operand(0x33B35E5, "48899424")
    assert qrs_staging == 0x150
    assert edge(0x33B3951, "0f85") == 0x33B3AFA
    assert at(".rodata", edge(0x33B3957, "488d05"), 3) == b"qrs"
    assert edge(0x33B39B1, "e8") == 0x3046740
    assert operand(0x33B3AFA, "488b8424") == qrs_staging + 0x10
    assert operand(0x33B3B0A, "0f108424") == qrs_staging
    qrs_words = operand(0x33B3B12, "0f298424")
    assert operand(0x33B3E0C, "0f288424") == qrs_words
    assert operand(0x33B3B02, "48898424") == operand(0x33B3E1C, "488b8424") == qrs_words + 0x10
    assert operand(0x33B3E14, "0f298424") == operand(0x33B3EA4, "0f289424")
    assert operand(0x33B3E24, "48898424") == operand(0x33B3EAC, "488b8424")
    qrs_out = operand(0x33B3ECC, "0f119424")
    assert operand(0x33B3EB4, "48898424") == qrs_out + 0x10

    assert edge(0x33B2E4A, "ff15") == 0x64E2580
    assert operand(0x33B2E58, "4080fd") == 9
    assert operand(0x33B2E62, "488b8424") == 0x180
    assert operand(0x33B2E6A, "48898424") == operand(0x33B3F8B, "488b8424") == 0x3B8
    assert operand(0x33B2E77, "48898424") == 0x3A8
    assert windows[0x33B3B1D] == bytes.fromhex("f68424a803000001")
    assert edge(0x33B3B25, "0f85") == 0x33B3BCC
    assert at(".rodata", edge(0x33B3B2B, "488d05"), 21) == b"highest_quorum_height"
    assert edge(0x33B3B82, "e8") == 0x3046740
    height_out = operand(0x33B3F93, "48898424")

    assert edge(0x33B2C92, "e8") == 0x3223900
    assert windows[0x33B2CDB] == bytes.fromhex("83f801")
    assert edge(0x33B2CDE, "0f84") == 0x33B36CB
    assert operand(0x33B3BD1, "48398424") == operand(0x33B3C92, "0f108424") == 0x280
    assert operand(0x33B3C9A, "0f108c24") == 0x290
    assert edge(0x33B3BD9, "0f85") == 0x33B3C92
    assert windows[0x33B3BF7] == bytes.fromhex("0f57c0")
    lower = operand(0x33B3CAA, "0f298424")
    higher = operand(0x33B3CA2, "0f298c24")
    assert higher == lower + 0x10
    assert operand(0x33B3BDF, "48c78424") == lower
    assert operand(0x33B3BEB, "48c78424") == (8 << 32) | (lower + 8)
    assert operand(0x33B3BFA, "0f298424") == higher
    assert edge(0x33B3C05, "e9") == 0x33B3CB5
    assert operand(0x33B3E2C, "0f288424") == lower
    assert operand(0x33B3E34, "0f288c24") == higher
    assert operand(0x33B3E3C, "0f118424") == 0x4A8
    assert operand(0x33B3E44, "0f118c24") == 0x4B8
    assert operand(0x33B3EBC, "488b8424") == 0x4A8
    assert operand(0x33B3E84, "0f288424") == 0x4B0
    assert operand(0x33B3E74, "488b8424") == 0x4C0
    timer_out = operand(0x33B3EC4, "48898424")
    assert operand(0x33B3E8C, "0f118424") == timer_out + 8
    assert operand(0x33B3E7C, "48898424") == timer_out + 24

    output = operand(0x33B4088, "488db424")
    assert (qrs_out - output, timer_out - output, height_out - output) == (0x48, 0x60, 0x80)
    assert operand(0x33B4080, "488dbc24") == operand(0x33B40B1, "488db424")
    size = operand(0x33B4090, "ba")
    assert size == operand(0x33B40B9, "ba") == operand(0x3C2EFDA, "ba") == 0xB8
    assert edge(0x33B4095, "ff15") == edge(0x33B40C1, "ff15") == edge(0x3C2EC6A, "4c8b2d") == 0x64DF508
    assert windows[0x3C2EFE6] == bytes.fromhex("41ffd5")
    assert operand(0x3C2EFDF, "498db6") == 0x2330
    live = operand(0x3C2EFD3, "488dbb")
    assert live == operand(0x548BF2D, "498db424") == 0x3E50
    assert edge(0x548BF4B, "e8") == 0x5AFA030
    assert operand(0x5AFA044, "488d7e") == timer_out - output
    assert edge(0x5AFA0A0, "e8") == 0x4DE0540
    assert operand(0x5AFA0AE, "410f1046") == qrs_out - output
    assert operand(0x5AFA0A5, "498b46") == qrs_out - output + 0x10
    assert operand(0x5AFA048, "488b46") == 0x78
    assert operand(0x5AFA48E, "498b87") == operand(0x5AFA4A0, "498987") == height_out - output
    assert windows[0x5AFA495] == bytes.fromhex("4939c5")
    assert windows[0x5AFA498] == bytes.fromhex("490f47c5")

    assert not matches_window(0x303C353, bytes.fromhex("66c7070906"))  # dispatch to unknown-field route
    assert not matches_window(0x5AFA48E, bytes.fromhex("498b8778000000"))  # use pending cutoff word
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} instruction windows")
    print("FDEs: " + ", ".join(f"{start:#x}..{end:#x}" for start, end in bounds))
    print("PASS: keyed qrs, htm and highest_quorum_height slots +0x48, +0x60 and +0x80")
    print("PASS: omitted htm initializes {0, 8, 0, 0}; qrs and height use named missing-field routes")
    print("PASS: materialized slots +0x3e98, +0x3eb0, +0x3ed0; drain offsets +0x48/+0x60 and separate +0x80 watermark")
    print("PASS: wrong end-of-map index and wrong watermark offset controls are rejected")


if __name__ == "__main__":
    main()
