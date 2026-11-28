"""Recover ordered Locus and Context root child descriptors from pinned #115."""

import csv
import hashlib
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path.cwd() / "tools"))
from abci_hash_slots_115 import bind, builder_pointers
from elf_index import unwind_index
from fde_extents import eh_frame_records
from freeze_snapshot_115 import read_va, relative_relocations, rip_target

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET = Path("artifacts/node/115/hl-node")
TABLE = Path(__file__).with_name("captures.tsv")
NAMES = {
    "locus": ("ctx", "cls", "scl", "ftr", "ust", "chn", "pdl", "uaR",
              "blp", "qus", "ctr", "uac", "vlt", "hcm", "pmu", "msc"),
    "context": ("hardfork_height", "hardfork", "height", "tx_index", "round",
                "time", "prev_time", "next_oid", "next_lid", "next_twap_id",
                "system_nonce", "use_system_nonce", "mac"),
}
LOCUS_KEYS = (
    (0x5480aa0, 0x5480ac1, "4c89fe"),
    (0x5480ae0, 0x5480afe, "4d8d87c0070000"),
    (0x5480b30, 0x5480b4e, "498db780000000"),
    (0x56795f6, 0x5480b6d, "498d97d8070000"),
    (0x5480b93, 0x5480bb1, "498d9768090000"),
    (0x567640f, 0x5480bd0, "410fb6979a0b0000"),
    (0x5480bf8, 0x5480bf0, "450fb687980b0000"),
    (0x5678afe, 0x5480c1c, "498d97f8090000"),
    (0x56747ad, 0x5480c3b, "498d9770060000"),
    (0x5480c61, 0x5480c5a, "4d8d87780b0000"),
    (0x5679147, 0x5480c85, "498d97780a0000"),
    (0x5678c7f, 0x5480ca4, "498d97b0090000"),
    (0x5673e1e, 0x5480cc3, "498d97180a0000"),
    (0x56764c5, 0x5480ce2, "410fb697990b0000"),
    (0x5480d09, 0x5480d02, "4d8b87900b0000"),
    (0x5677a6d, 0x5480d2d, "498d97380a0000"),
)
CONTEXT_KEYS = {
    0x4D930B4: b"hardfork_height", 0x4E0BDD9: b"hardfork", 0x4D9311C: b"height",
    0x4D93160: b"tx_index", 0x4D931FA: b"round", 0x4D9323C: b"time",
    0x4D93264: b"prev_time", 0x4D9328C: b"next_oid", 0x4D932B4: b"next_lid",
    0x4D932DC: b"next_twap_id", 0x4E0CACE: b"system_nonce",
    0x4D93318: b"use_system_nonce", 0x4D9333C: b"mac",
}


def setup_pairs(data, start, end, stack_base, count):
    """Recognize only contiguous, straight-line source/descriptor setup."""
    code = read_va(data, start, end - start)
    index = 0
    regs = {7: ("state", 0)}
    stack = {}
    while index < len(code):
        op, operand = code[index + 1:index + 3]
        mode, reg, rm = operand >> 6, (operand >> 3) & 7, operand & 7
        assert code[index] == 0x48
        if op == 0x8D and mode == 0 and rm == 5:
            delta = struct.unpack_from("<i", code, index + 3)[0]
            regs[reg] = ("descriptor", start + index + 7 + delta)
            index += 7
        elif op in (0x8B, 0x8D) and rm == 7 and mode in (0, 1):
            displacement = code[index + 3] if mode else 0
            regs[reg] = ("group_pointer" if op == 0x8B else "state", displacement)
            index += 3 + mode
        elif op == 0x89 and rm == 4 and mode in (1, 2):
            assert code[index + 3] == 0x24
            displacement = code[index + 4] if mode == 1 else struct.unpack_from("<I", code, index + 4)[0]
            assert displacement not in stack
            stack[displacement] = regs[reg]
            index += 5 if mode == 1 else 8
        elif code[index:index + 3] == b"\x48\x83\xc7":
            regs[7] = ("state", code[index + 3])
            index += 4
        else:
            raise ValueError(f"unexpected setup at {start + index:#x}")
    assert sorted(stack) == list(range(stack_base, stack_base + 16 * count, 8))
    return [(stack[p], stack[p + 8]) for p in range(stack_base, stack_base + 16 * count, 16)]


def first_fields(data):
    sections, header = unwind_index(data)
    _, fdes = eh_frame_records(data, sections)
    indexed = {(row["start"], row["fde"]) for row in header}
    bounds = {(row["start"], row["end"]) for row in fdes if (row["start"], row["fde"]) in indexed}
    assert {(0x3D29F50, 0x3D29FF3), (0x3D2A000, 0x3D2A522),
            (0x4303730, 0x43037BE), (0x43037C0, 0x4303B6B)} <= bounds
    rels = relative_relocations(data)
    group = bind(data)["slots"][0]
    assert (group["vtable"], group["type_size"], group["method_0"], group["method_1"]) == (
        "0x64a8160", 128, "0x3d2a000", "0x3d29f50",
    )
    pointers = builder_pointers(data)
    group_pairs = setup_pairs(data, 0x3D2A007, 0x3D2A18C, 0x10, 16)
    context_pairs = setup_pairs(data, 0x43037D1, 0x43038EE, 0x38, 13)
    assert group_pairs[0][1] == ("descriptor", 0x6479380)
    assert rels[0x6479398] == 0x43037C0 and rels[0x64793A0] == 0x4303730

    rows = []
    for kind, pairs, prefix in (("locus", group_pairs, "0"), ("context", context_pairs, "0.0")):
        for i, ((source_kind, source), (descriptor_kind, descriptor)) in enumerate(pairs):
            assert descriptor_kind == "descriptor"
            if kind == "locus":
                assert source_kind == "group_pointer" and source == 8 * i
                source = pointers[i]
            else:
                assert source_kind == "state"
            rows.append((f"{prefix}.{i}", NAMES[kind][i], hex(source), hex(descriptor),
                         hex(rels[descriptor + 24]), hex(rels[descriptor + 32])))

    # Constructor width/count, visitor count, and successful child placement.
    for address, encoding in {
        0x3D29F54: "bf80010000", 0x3D29FCB: "48c70310000000",
        0x3D29FD6: "48c7431010000000", 0x3D2A19B: "48837e1010",
        0x3D2A510: "ba10000000", 0x4303734: "bf38010000",
        0x4303796: "48c7030d000000", 0x43037A1: "48c743100d000000",
        0x43038FD: "48837e100d", 0x4303AB0: "4883c510", 0x4303ABA: "ff5318",
        0x4303AC1: "3c04", 0x4303ADF: "ff5320", 0x4303B17: "4883c118",
        0x14199B5: "488b0f", 0x14199DC: "48890c02", 0x14199E0: "4883c008",
    }.items():
        expected = bytes.fromhex(encoding)
        assert read_va(data, address, len(expected)) == expected
    assert rip_target(data, 0x3D2A515, b"\xe8", 5) == 0x3DDBDA0
    for thunk in (0x457D610, 0x4303720):
        assert rip_target(data, thunk, b"\xff\x25", 6) == 0x64DF530
    assert rels[0x64DF530] == 0x14199B0
    for i, (site, source_site, encoding) in enumerate(LOCUS_KEYS):
        name = NAMES["locus"][i].encode()
        prefix = read_va(data, site, 3)
        assert prefix[:2] == b"\x48\x8d" and prefix[2] & 0xC7 == 5
        assert read_va(data, rip_target(data, site, prefix, 7), len(name)) == name
        insn = bytes.fromhex(encoding)
        assert read_va(data, source_site, len(insn)) == insn
        assert pointers[i] == (int.from_bytes(insn[-4:], "little") if len(insn) >= 7 else 0)
    for address, name in CONTEXT_KEYS.items():
        prefix = read_va(data, address, 3)
        assert prefix in (b"\x48\x8d\x35", b"\x48\x8d\x15", b"\x48\x8d\x05")
        assert read_va(data, rip_target(data, address, prefix, 7), len(name)) == name
    return rows


def main():
    data = TARGET.read_bytes()
    assert hashlib.sha256(data).hexdigest() == SHA
    rows = first_fields(data)
    with TABLE.open(newline="") as file:
        reader = csv.reader(file, delimiter="\t")
        assert next(reader) == ["path", "key", "compact_offset", "descriptor", "visit", "create"]
        assert list(reader) == [list(row) for row in rows]
    print(f"PASS: authenticated node #115 {SHA}")
    print("PASS: 16 ordered Locus capture pairs, 13 ordered Context children and both constructors")
    print("PASS: checkpoint keys; Context height, hardfork height and round use distinct paths")
    print("PASS: native qword leaf width, scalar thunk bindings and normal child-loop guard")


if __name__ == "__main__":
    main()
