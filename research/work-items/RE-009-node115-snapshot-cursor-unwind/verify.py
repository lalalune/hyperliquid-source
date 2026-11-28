import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, decode_lsda, parse_sections, walk_eh_frame

VALUE_SITES = [(0xB, 5, 0x3B, 0), (0x10, 0x4A, 0, 0), (0x5A, 8, 0x6A, 1), (0x62, 0xE, 0, 0)]
OUTER_SITES = [(0, 0x3E, 0, 0), (0x3E, 5, 0x5F, 0), (0x43, 0x1F, 0, 0),
               (0x62, 8, 0x72, 1), (0x6A, 0xE, 0, 0)]
TARGETS = {
    0x2481C40: (120, 0x21E1E8, OUTER_SITES),
    0x2433C50: (95, None, None),
    0x2433CB0: (95, None, None),
    0x243A250: (112, 0x21B270, VALUE_SITES),
    0x243A2C0: (112, 0x21B28C, VALUE_SITES),
}
CALLS = {
    0x2481C7E: 0x243A250,
    0x2481CA5: 0x2433C50,
    0x2481CAD: 0x63F0A50,
}
ANCHORS = {0x2481C9F: "4989c64889df", 0x2481CAA: "4c89f7"}
for helper, value, field in [(0x2433C50, 0x243A250, 0x242DFC0), (0x2433CB0, 0x243A2C0, 0x242E150)]:
    CALLS.update({
        helper + 0x10: 0x2442420, helper + 0x3E: value, helper + 0x49: 0x2442420,
        value + 0xB: 0x24722C0, value + 0x5D: field, value + 0x65: 0x63F0A50,
    })
    ANCHORS.update({
        helper + 0x30: "486b4c241058488d3c084883c708",
        helper + 0x43: "4c89f74889de", helper + 0x4E: "488b04244885c075d9",
        value + 0x3B: "4989c6488b334885f67410488b7b0848c1e60331d2",
        value + 0x56: "4883c3204889df", value + 0x62: "4c89f7",
    })


def static_control_flow(text, text_va):
    for address, target in CALLS.items():
        offset = address - text_va
        assert text[offset] == 0xE8
        assert address + 5 + struct.unpack_from("<i", text, offset + 1)[0] == target
    for address, expected in ANCHORS.items():
        offset = address - text_va
        encoded = bytes.fromhex(expected)
        assert text[offset:offset + len(encoded)] == encoded
    for address in (0x243A2A0, 0x243A310):
        offset = address - text_va
        assert text[offset:offset + 2] == b"\xff\x15"
        assert address + 6 + struct.unpack_from("<i", text, offset + 2)[0] == 0x64DF4A0


def main():
    assert __debug__, "run Python without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def section(name):
        record = sections[name]
        offset = record["offset"]
        return data[offset:offset + record["size"]], record["va"]

    eh, eh_va = section(".eh_frame")
    gcc, gcc_va = section(".gcc_except_table")
    text, text_va = section(".text")
    _, entries = walk_eh_frame(eh, eh_va)
    fdes = {fde["entry"]: fde for fde in entries if fde["entry"] in TARGETS}
    assert set(fdes) == set(TARGETS)
    controls = 0
    for address, (size, lsda, expected) in TARGETS.items():
        fde = fdes[address]
        assert fde["range"] == size
        print(f"FDE {address:#x}..{fde['end']:#x} raw={fde['record_bytes_hex']}")
        if lsda is None:
            assert fde["lsda"] is None
            print("  No LSDA pointer")
            continue
        assert fde["lsda"] == {"encoding": 0x1B, "value": lsda, "indirect": False}
        table = decode_lsda(gcc, lsda, gcc_va)
        header = table["header"]
        assert header["lpstart_encoding"] == 0xFF and header["call_site_encoding"] == 1
        sites = [(s["start_offset"], s["byte_length"], int(s["landing_pad"], 16), s["action"])
                 for s in table["call_sites"]]
        assert sites == expected
        print(f"  LSDA {lsda:#x}, raw={header['header_bytes_hex']}{table['call_site_table_bytes_hex']}")
        for offset, length, pad, action in sites:
            print(f"  site {address + offset:#x}+{length:#x}, pad {address + pad if pad else 0:#x}, action {action}")
        end = lsda - gcc_va + header["call_site_table_offset"] + header["call_site_table_length"]
        try:
            decode_lsda(gcc[:end - 1], lsda, gcc_va)
        except ValueError:
            controls += 1
        else:
            raise AssertionError(f"accepted a truncated LSDA at {lsda:#x}")
    static_control_flow(text, text_va)
    mutated = bytearray(text)
    for address in [*CALLS, *ANCHORS, 0x243A2A0, 0x243A310]:
        offset = address - text_va
        mutated[offset] ^= 1
        try:
            static_control_flow(mutated, text_va)
        except AssertionError:
            controls += 1
        else:
            raise AssertionError(f"accepted altered instructions at {address:#x}")
        mutated[offset] ^= 1
    print(f"PASS: 5 FDEs, 3 LSDA tables, {len(CALLS)} direct calls, 2 RIP release calls, {controls} rejected mutations")


if __name__ == "__main__":
    main()
