#!/usr/bin/env python3
"""Record the node115 tag-4/tag-5 bridge caller source spans; never execute the target."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_MEM, __version__ as CAPSTONE_VERSION
from capstone.x86_const import X86_REG_RSP

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105_896_032
FUNCTIONS = (0x44D69F0, 0x44D7210)
OUTER_HELPER = 0x4526E40
OUTER_SLOT = 0x64EAAE8
CONSTRUCTOR = 0x4526230
CONSTRUCTOR_SLOT = 0x64EAB68

# Observed source-to-stack copies in the tag-5 constructor record. The first
# two columns are input and record offsets; the third is the byte count.
TAG5_SPANS = (
    (0x58, 0x01, 16, 0x44D72B5, 0x44D72BA),
    (0x68, 0x11, 4, 0x44D72AD, 0x44D72B1),
    (0x6C, 0x15, 16, 0x44D72BF, 0x44D72C4),
    (0x7C, 0x25, 4, 0x44D72CA, 0x44D72CD),
    (0x00, 0x30, 8, 0x44D7227, 0x44D72D1),
    (0x08, 0x38, 8, 0x44D722A, 0x44D72D6),
)
TAG4_SPANS = (
    # Destination offsets are relative to the post-prologue RSP. The stores
    # are not a contiguous copy into the buffer passed at RSP+0x1d0.
    (0x00, 0x1D0, 16, 0x44D6A71, 0x44D6A7B),
    (0x10, 0x1E0, 16, 0x44D6A76, 0x44D6A83),
    (0x20, 0x230, 16, 0x44D6A8B, 0x44D6AB4),
    (0x30, 0x240, 16, 0x44D6A91, 0x44D6ABD),
    (0x40, 0x210, 16, 0x44D6A97, 0x44D6AA2),
    (0x50, 0x220, 16, 0x44D6A9D, 0x44D6AAB),
    (0x60, 0x250, 8, 0x44D6AC5, 0x44D6AC9),
)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def section_by_name(rows: list[dict], name: str) -> dict:
    found = [row for row in rows if row["name"] == name]
    require(len(found) == 1, f"expected one {name} section")
    return found[0]


def relative_relocations(data: bytes, rows: list[dict]) -> dict[int, tuple[int, int, int]]:
    rela = section_by_name(rows, ".rela.dyn")
    require(rela["size"] % 24 == 0, "malformed .rela.dyn size")
    result = {}
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        slot, info, addend = struct.unpack_from("<QQq", data, off)
        result[slot] = (info >> 32, info & 0xFFFFFFFF, addend)
    return result


def collect(binary: Path) -> dict:
    data = binary.read_bytes()
    require(len(data) == TARGET_SIZE, "unexpected target size")
    digest = hashlib.sha256(data).hexdigest()
    require(digest == TARGET_SHA256, "node115 artifact digest mismatch")
    require(CAPSTONE_VERSION == "5.0.7", f"expected Capstone 5.0.7, got {CAPSTONE_VERSION}")
    rows = sections(data)
    text = section_by_name(rows, ".text")
    _, fdes = eh_frame_records(data, rows)
    by_start = {row["start"]: row for row in fdes}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    functions, instructions = [], []
    decoded_by_va = {}
    for start in FUNCTIONS:
        require(start in by_start, f"missing FDE at {start:#x}")
        fde = by_start[start]
        end = fde["end"]
        offset = text["offset"] + start - text["address"]
        body = data[offset:offset + end - start]
        insns = list(md.disasm(body, start))
        require(insns and insns[0].address == start, f"no decode at {start:#x}")
        require(insns[-1].address + insns[-1].size == end, f"decode does not reach FDE end {end:#x}")
        cursor = start
        for insn in insns:
            require(insn.address == cursor, f"decode gap at {cursor:#x}")
            cursor += insn.size
            decoded_by_va[insn.address] = insn
            instructions.append((insn.address, start, insn.size, insn.bytes.hex(), insn.mnemonic, insn.op_str))
        functions.append((start, end, len(body), len(insns), offset,
                          hashlib.sha256(body).hexdigest()))

    # Both tagged callers place their distinct tag byte and call the same
    # relocated outer bridge helper with a local record.
    expected_anchors = {
        0x44D6AD6: ("lea", "rsi, [rsp + 0x1d0]"),
        0x44D6ADE: ("call", "qword ptr [rip + 0x20121d4]"),
        0x44D6D2E: ("call", "0x46e1cb0"),
        0x44D6CC2: ("mov", "byte ptr [rsp + 0x10], 4"),
        0x44D6CD8: ("call", "qword ptr [rip + 0x2013e0a]"),
        0x44D72DB: ("mov", "byte ptr [rsp], 5"),
        0x44D72ED: ("call", "qword ptr [rip + 0x20137f5]"),
    }
    for va, expected in expected_anchors.items():
        insn = decoded_by_va.get(va)
        require(insn is not None and (insn.mnemonic, insn.op_str) == expected,
                f"changed caller anchor at {va:#x}")
    relocs = relative_relocations(data, rows)
    require(relocs.get(0x64E8CB8) == (0, 8, 0x364CC80),
            "tag-4 preparatory helper relocation changed")
    require(relocs.get(OUTER_SLOT) == (0, 8, OUTER_HELPER), "outer helper relocation changed")
    require(relocs.get(CONSTRUCTOR_SLOT) == (0, 8, CONSTRUCTOR), "tagged constructor relocation changed")

    span_facts = []
    for variant, spans in (("tag4", TAG4_SPANS), ("tag5", TAG5_SPANS)):
        for src, dst, size, load_va, store_va in spans:
            require(load_va in decoded_by_va, f"missing {variant} source instruction {load_va:#x}")
            require(store_va in decoded_by_va, f"missing {variant} destination instruction {store_va:#x}")
            store = decoded_by_va[store_va]
            require(store.operands and store.operands[0].type == CS_OP_MEM and
                    store.operands[0].mem.base == X86_REG_RSP and store.operands[0].mem.disp == dst,
                    f"changed {variant} stack destination at {store_va:#x}")
            span_facts.append((variant, f"r8+{src:#x}",
                               f"{'rsp' if variant == 'tag4' else 'tag5_record'}+{dst:#x}",
                               size, load_va, decoded_by_va[load_va].bytes.hex(),
                               store_va, decoded_by_va[store_va].bytes.hex()))
    return {
        "target": {"path": str(binary.relative_to(ROOT)) if binary.is_relative_to(ROOT) else binary.name,
                   "size": len(data), "sha256": digest},
        "analysis": {"decoder": "Capstone", "version": CAPSTONE_VERSION,
                     "coordinates": "ELF virtual address and file offset",
                     "execution": "static decode only; captured executable was not run"},
        "outer_helper": {"slot": hex(OUTER_SLOT), "relocation_type": 8,
                         "symbol_index": 0, "target": hex(OUTER_HELPER)},
        "tag4_preparer": {"slot": hex(0x64E8CB8), "relocation_type": 8,
                           "symbol_index": 0, "target": hex(0x364CC80),
                           "call_site": hex(0x44D6ADE)},
        "tag4_followup_helper": {"target": hex(0x46E1CB0),
                                 "call_site": hex(0x44D6D2E),
                                 "arguments": ["rsp+0x10", "rsp+0x170"]},
        "tagged_constructor": {"slot": hex(CONSTRUCTOR_SLOT), "relocation_type": 8,
                               "symbol_index": 0, "target": hex(CONSTRUCTOR)},
        "functions": functions,
        "instructions": instructions,
        "source_spans": span_facts,
    }


def write_packet(result: dict, out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "tag5-spans.tsv").unlink(missing_ok=True)
    evidence = {key: value for key, value in result.items() if key != "instructions"}
    (out / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    with (out / "functions.tsv").open("w", encoding="utf-8", newline="") as f:
        f.write("start_va\tend_va\tbytes\tinstructions\tfile_offset\tsha256\n")
        for start, end, size, count, offset, digest in result["functions"]:
            f.write(f"{start:#x}\t{end:#x}\t{size}\t{count}\t{offset:#x}\t{digest}\n")
    with (out / "instructions.tsv").open("w", encoding="utf-8", newline="") as f:
        f.write("va\tfunction_start\tsize\tbytes\tmnemonic\toperands\n")
        for va, owner, size, raw, mnemonic, op_str in result["instructions"]:
            f.write(f"{va:#x}\t{owner:#x}\t{size}\t{raw}\t{mnemonic}\t{op_str or '-'}\n")
    with (out / "source-spans.tsv").open("w", encoding="utf-8", newline="") as f:
        f.write("variant\tsource\tdestination\tbytes\tload_va\tload_bytes\tstore_va\tstore_bytes\n")
        for variant, src, dst, size, load_va, load_bytes, store_va, store_bytes in result["source_spans"]:
            f.write(f"{variant}\t{src}\t{dst}\t{size}\t{load_va:#x}\t{load_bytes}\t{store_va:#x}\t{store_bytes}\n")
    files = ["evidence.json", "functions.tsv", "instructions.tsv", "source-spans.tsv"]
    lines = [f"{hashlib.sha256((out / name).read_bytes()).hexdigest()}  {name}" for name in files]
    (out / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    parser.add_argument("--out", type=Path, default=ROOT / "research/work-items/RE-005-node115-bridge-caller-source-fields")
    args = parser.parse_args()
    result = collect(args.binary)
    write_packet(result, args.out)
    print(json.dumps({"functions": len(result["functions"]),
                      "instructions": len(result["instructions"]),
                      "source_spans": len(result["source_spans"]),
                      "out": str(args.out)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
