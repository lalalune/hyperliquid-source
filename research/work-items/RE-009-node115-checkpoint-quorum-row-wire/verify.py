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
    entries = (0x33B2A30, 0x3259070, 0x38A99C0, 0x31EAED0, 0x314D020)
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

    assert edge(0x33B2FC2, "e8") == 0x3259070
    assert operand(0x32590D6, "24") == 15
    assert windows[0x32590D8] == bytes.fromhex("4189c0")
    assert edge(0x32590DB, "e9") == 0x32591E7
    assert windows[0x32591E7] == bytes.fromhex("410fb6d8")
    assert operand(0x3259213, "899c24") == 0x88
    assert edge(0x3259227, "e8") == 0x38A99C0
    assert operand(0x38A99DB, "8b6e") == 8
    assert operand(0x38A99DE, "81fd") == operand(0x38A99E4, "bb") == 0x2762
    assert windows[0x38A99E9] == bytes.fromhex("0f42dd")
    row_size = operand(0x38A99F4, "4c6bfb")
    assert row_size == operand(0x38A9A45, "496bce") == 0x68
    assert windows[0x38A9A3A] == bytes.fromhex("ffcd")
    assert operand(0x38A9AB9, "8968") == 8
    assert edge(0x38A9AC9, "e8") == 0x31EAED0
    assert windows[0x38A9AA3] == bytes.fromhex("49ffc6")
    assert operand(0x38A9AA6, "4c897424") == 0x18
    assert windows[0x38A9AAB] == bytes.fromhex("83c5ff")
    assert edge(0x38A9BA4, "0f85") == 0x38A9A40
    assert edge(0x38A9BAF, "ff15") == 0x64E5110

    assert operand(0x31EAF3A, "24") == 15
    assert edge(0x31EAF3F, "e9") == 0x31EB04D
    assert edge(0x31EB63C, "ff15") == 0x64E2580
    assert operand(0x31EB64A, "4c8ba424") == 0x198
    assert operand(0x31EB652, "3c") == 9
    assert edge(0x31EB66C, "e8") == 0x314D020
    assert operand(0x31EB7F7, "4c896424") == operand(0x31EB839, "488b4424") == 0x78
    assert operand(0x31EB804, "83fd") == 2
    assert edge(0x31EB807, "75") == 0x31EB888
    assert operand(0x31EB876, "48898424") == operand(0x31EB9E5, "0f288424") == 0xE0
    assert windows[0x31EBA11] == bytes.fromhex("0f1107")

    name = edge(0x314D4B6, "488d15")
    assert at(".rodata", name, operand(0x314D4C2, "b9")) == b"AbciDigest"
    assert operand(0x314D4BD, "488d7c24") == 0x18
    assert edge(0x314D4CA, "e8") == 0x2F52FA0
    assert edge(0x314D4D4, "0f84") == 0x314D74B
    low = operand(0x314D74B, "0f104424")
    high = operand(0x314D750, "0f104c24")
    assert (low, high) == (0x19, 0x29)
    stage = operand(0x314D755, "0f298424")
    assert operand(0x314D75D, "0f298c24") == stage + 16
    assert edge(0x314D77B, "e8") == 0x333B880
    assert operand(0x314DA36, "83fd") == 2
    assert edge(0x314DA39, "0f85") == 0x314DC9F
    assert edge(0x314DCAC, "e8") == 0x3324390
    assert operand(0x314DEE8, "0f288424") == stage
    assert operand(0x314DEF0, "0f288c24") == stage + 16
    low = operand(0x314DEF8, "0f298424")
    high = operand(0x314DF00, "0f298c24")
    assert high == low + 16
    payload_source = operand(0x314DF3B, "488d8c24")
    payload_target = operand(0x314DF70, "0f119424")
    assert windows[0x314DF65] == bytes.fromhex("0f1011")
    assert operand(0x314DF68, "0f1059") == 0x10
    assert operand(0x314DF6C, "0f1061") == 0x20
    assert operand(0x314DF78, "0f119c24") == payload_target + 16
    assert operand(0x314DF80, "0f11a424") == payload_target + 32
    assert operand(0x314DF88, "488b49") == 0x30
    assert operand(0x314DF8C, "48898c24") == payload_target + 48
    assert payload_source <= low and high + 16 <= payload_source + 56
    low += payload_target - payload_source
    high += payload_target - payload_source
    assert operand(0x314DFAD, "83fd") == 3
    assert operand(0x314DFD6, "0f108424") == low
    assert operand(0x314DFB6, "488b8424") == high
    assert operand(0x314DFC6, "488b8424") == high + 8
    assert operand(0x314DFDE, "0f298424") == operand(0x314E2EE, "0f288424") == 0xB0
    assert operand(0x314DFBE, "48898424") == operand(0x314E2E2, "0f288424") == 0xC0
    assert operand(0x314DFCE, "48898424") == 0xC8
    assert edge(0x314E032, "e9") == 0x314E2CC
    body_digest = operand(0x314E2F6, "0f1143")
    assert operand(0x314E2EA, "0f1143") == body_digest + 16
    assert body_digest == 0x40

    # Track the full 40-byte band containing the two digest lanes through the row.
    parsed_body = operand(0x31EB65F, "488dbc24")
    body_band = parsed_body + body_digest - 8
    assert operand(0x31EB743, "0f108c24") == body_band
    assert operand(0x31EB74B, "0f109424") == body_band + 16
    assert operand(0x31EB72B, "488b8c24") == body_band + 32
    band = operand(0x31EB77A, "0f114c24")
    assert operand(0x31EB77F, "0f115424") == band + 16
    assert operand(0x31EB784, "48894c24") == band + 32
    assert operand(0x31EB7B5, "0f104c24") == band
    assert operand(0x31EB7BA, "0f105424") == band + 16
    assert operand(0x31EB7A3, "488b4c24") == band + 32
    band = operand(0x31EB7C7, "0f118c24")
    assert operand(0x31EB7BF, "0f119424") == band + 16
    assert operand(0x31EB7A8, "48898c24") == band + 32
    assert operand(0x31EB829, "0f108424") == band
    assert operand(0x31EB819, "0f108424") == band + 16
    assert operand(0x31EB809, "488b8424") == band + 32
    band = operand(0x31EB831, "0f298424")
    assert operand(0x31EB821, "0f298424") == band + 16
    assert operand(0x31EB811, "48898424") == band + 32
    assert operand(0x31EB9D9, "0f288424") == band
    assert operand(0x31EB9CD, "0f288424") == band + 16
    assert operand(0x31EB9C1, "488b8424") == band + 32
    row_band = operand(0x31EB9E1, "0f1147")
    assert operand(0x31EB9D5, "0f1147") == row_band + 16
    assert operand(0x31EB9C9, "488947") == row_band + 32
    assert row_band + 8 == 0x48 and row_band + 40 == row_size
    assert operand(0x38A9ABC, "488dbc24") == 0x120
    assert operand(0x38A9B47, "48898c24") == 0xB8
    assert operand(0x38A9A6B, "0f114408") == row_band
    assert operand(0x38A9A51, "48895408") == row_band + 32

    assert not matches_window(0x38A9A45, bytes.fromhex("496bce60"))
    assert not matches_window(0x314E2F6, bytes.fromhex("0f114348"))
    print(f"PASS: #115 SHA-256 {TARGET_SHA256}; {len(windows)} instruction windows")
    print("FDEs: " + ", ".join(f"{start:#x}..{end:#x}" for start, end in bounds))
    print("PASS: qrs array reservation is separate from item count and 104-byte publication")
    print("PASS: selected row reads [height, payload]; payload's first field is a 32-byte AbciDigest")
    print("PASS: digest lanes reach row +0x48..+0x67; bad stride and lane-offset controls differ")


if __name__ == "__main__":
    main()
