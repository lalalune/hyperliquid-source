#!/usr/bin/env python3
"""Authenticate and recheck one node94 key-search contract without execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections, unwind_index  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

HERE = Path(__file__).resolve().parent
NODE = ROOT / "artifacts/node/94/hl-node"
SHA256 = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
SIZE = 91774280
START, END = 0x28546C0, 0x2854930
BODY_SHA256 = "f10dde406ec27ba21c2dd1180560e96403e9c8d182130587376ce96424444ec0"


def span(data, secs, address, size):
    if type(address) is not int or type(size) is not int or address < 0 or size <= 0:
        raise ValueError("invalid virtual range")
    matches = [s for s in secs if s["type"] != 8 and
               s["address"] <= address and address + size <= s["address"] + s["size"]]
    if len(matches) != 1:
        raise ValueError("range is not uniquely file backed")
    offset = matches[0]["offset"] + address - matches[0]["address"]
    if offset < 0 or offset + size > len(data):
        raise ValueError("range exceeds input")
    return data[offset:offset + size]


def shape(data, secs, address, encoded, fields=()):
    """Recognize one fixed instruction form; expose only specified field bytes."""
    expected = bytes.fromhex(encoded)
    actual = span(data, secs, address, len(expected))
    if any(a != b for i, (a, b) in enumerate(zip(actual, expected)) if i not in fields):
        raise ValueError(f"instruction form changed at {address:#x}")
    return actual


def transfer(data, secs, address):
    raw = span(data, secs, address, 2)
    if raw[0] in (0xE8, 0xE9):
        size, disp, kind = 5, 1, "call" if raw[0] == 0xE8 else "jump"
    elif raw[0] == 0xEB or 0x70 <= raw[0] <= 0x7F:
        return {"site": hex(address), "opcode": raw[:1].hex(),
                "target": hex(address + 2 + int.from_bytes(raw[1:], "little", signed=True))}
    elif raw[0] == 0x0F and 0x80 <= raw[1] <= 0x8F:
        size, disp, kind = 6, 2, "conditional"
    elif raw == b"\xff\x15":
        size, disp, kind = 6, 2, "indirect-call-slot"
    else:
        raise ValueError(f"unexpected transfer at {address:#x}")
    code = span(data, secs, address, size)
    return {"site": hex(address), "opcode": code[:disp].hex(), "kind": kind,
            "target": hex(address + size + struct.unpack_from("<i", code, disp)[0])}


def decode_contract(data, secs=None):
    """Decode fields of the inspected local contract below the identity boundary.

    This describes a mathematical comparison and fixed memory transfers; it
    neither executes instructions nor models a tree or the captured program.
    """
    secs = sections(data) if secs is None else secs
    loads = shape(data, secs, 0x28546E4, "488b7a184c8b42104c8b0a4c8b5208", (3, 7, 14))
    candidate_offsets = [loads[3], loads[7], loads[14], 0]
    node_offsets = [
        shape(data, secs, 0x2854730, "4e8b6c28184889fd4c39ef75d3", (4, 12))[4],
        shape(data, secs, 0x285473D, "4e8b6c30104c89c54d39e875c6", (4, 12))[4],
        shape(data, secs, 0x285474A, "4e8b6c30084c89d54d39ea75b9", (4, 12))[4],
        0,
    ]
    shape(data, secs, 0x2854757, "4e8b2c304c89cd4d39e975adeb31", (11, 13))
    relation = shape(data, secs, 0x2854710, "4c39ed400f97c54080dd00", (5,))[5]
    if relation not in (0x97, 0x9F):
        raise ValueError("unrecognized comparison relation")
    shape(data, secs, 0x285471B, "4d8d6e2048ffc24080fd017548", (12,))
    shape(data, secs, 0x2854770, "400fb6ed85ed741eeb09", (7, 9))
    shape(data, secs, 0x2854783, "4983eb017258488b84d0d0020000e95dffffff", (5,))
    equal = shape(data, secs, 0x2854796,
                  "420f10843060010000420f108c30700100000f114b110f114301"
                  "0f10010f104910420f11843060010000420f118c3070010000b001e920010000",
                  (*range(5, 9), *range(14, 18), 21, 25,
                   *range(38, 42), *range(47, 51), 52))
    shape(data, secs, 0x28548F0, "88034889d84881c4980000005b415c415d415e415f5dc3")
    mismatch_sites = (0x285473B, 0x2854748, 0x2854755, 0x2854761)
    return {
        "word_bits": 64, "memory_byte_order": "little",
        "candidate_offsets": candidate_offsets, "stored_key_offsets": node_offsets,
        "relation": "unsigned" if relation == 0x97 else "signed-greater/unsigned-borrow",
        "mismatch_targets": [transfer(data, secs, a)["target"] for a in mismatch_sites],
        "greater_scan": {"step_bytes": 32, "required_relation": 1,
                         "other_relation_target": transfer(data, secs, 0x2854726)["target"]},
        "less_descent": {"edge_array_offset": 0x2D0,
                         "leaf_target": transfer(data, secs, 0x2854787)["target"]},
        "equal_target": transfer(data, secs, 0x2854763)["target"],
        "equal_old_value_offsets": [int.from_bytes(equal[5:9], "little"),
                                    int.from_bytes(equal[14:18], "little")],
        "equal_result_offsets": [equal[25], equal[21]],
        "equal_new_value_input_offsets": [0, 16],
        "equal_new_value_offsets": [int.from_bytes(equal[38:42], "little"),
                                    int.from_bytes(equal[47:51], "little")],
        "equal_result_tag": equal[52],
        "equal_return_join": transfer(data, secs, 0x28547CB)["target"],
    }


EXPECTED = {
    "word_bits": 64, "memory_byte_order": "little",
    "candidate_offsets": [24, 16, 8, 0], "stored_key_offsets": [24, 16, 8, 0],
    "relation": "unsigned", "mismatch_targets": ["0x2854710"] * 4,
    "greater_scan": {"step_bytes": 32, "required_relation": 1,
                     "other_relation_target": "0x2854770"},
    "less_descent": {"edge_array_offset": 0x2D0, "leaf_target": "0x28547e1"},
    "equal_target": "0x2854796", "equal_old_value_offsets": [0x160, 0x170],
    "equal_result_offsets": [1, 17], "equal_new_value_input_offsets": [0, 16],
    "equal_new_value_offsets": [0x160, 0x170], "equal_result_tag": 1,
    "equal_return_join": "0x28548f0",
}


def validate_contract(data, secs=None):
    decoded = decode_contract(data, secs)
    if decoded != EXPECTED:
        raise ValueError("local search/replacement contract changed")
    return decoded


def compare_words(contract, candidate, stored):
    """Mathematical relation described by the decoded fields, not a node codec."""
    if len(candidate) != 32 or len(stored) != 32:
        raise ValueError("comparison needs two 32-byte keys")
    for left_at, right_at in zip(contract["candidate_offsets"], contract["stored_key_offsets"]):
        left = int.from_bytes(candidate[left_at:left_at + 8], "little")
        right = int.from_bytes(stored[right_at:right_at + 8], "little")
        if left != right:
            greater = left > right
            if contract["relation"] == "signed-greater/unsigned-borrow":
                signed_left = left - (2**64 if left >= 2**63 else 0)
                signed_right = right - (2**64 if right >= 2**63 else 0)
                greater = signed_left > signed_right
            # SETA preserves CF; SBB subtracts the unsigned CMP borrow.
            return int(greater) - int(left < right)
    return 0


TRANSFERS = (0x28546DA, 0x285470C, 0x2854726, 0x285472B, 0x285473B,
             0x2854748, 0x2854755, 0x2854761, 0x2854763, 0x2854776,
             0x2854778, 0x2854787, 0x2854791, 0x28547CB, 0x2854814,
             0x2854859, 0x2854862, 0x2854872, 0x285487B, 0x28548AD,
             0x2854911, 0x285492A)


def analyze(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError("node94 size/SHA-256 mismatch")
    secs, index = unwind_index(data)
    cies, fdes = eh_frame_records(data, secs)
    matches = [f for f in fdes if f["start"] == START and f["end"] == END]
    if len(matches) != 1:
        raise ValueError("primary FDE extent changed")
    fde = matches[0]
    if fde["cie"] not in cies or sum(r["start"] == START and r["fde"] == fde["fde"] for r in index) != 1:
        raise ValueError("primary CIE/index membership changed")
    body = span(data, secs, START, END - START)
    if hashlib.sha256(body).hexdigest() != BODY_SHA256:
        raise ValueError("primary complete body changed")
    sec = next(s for s in secs if s["type"] != 8 and s["address"] <= START < s["address"] + s["size"])
    primary = {k: hex(fde[k]) for k in ("start", "end", "fde", "cie")}
    primary.update({"body_sha256": BODY_SHA256, "body_hex": body.hex(),
                    "file_offset": hex(sec["offset"] + START - sec["address"])})
    for kind in ("fde", "cie"):
        address = fde[kind]
        length = int.from_bytes(span(data, secs, address, 4), "little") + 4
        primary[kind + "_hex"] = span(data, secs, address, length).hex()
    context = span(data, secs, 0x269FD9C, 0x269FDC6 - 0x269FD9C)
    if context.hex() != "4c89e7488d742408488d9424b0000000488d8c2490000000e807491b00ffcd807c2448010f853affffff":
        raise ValueError("credited row-reader call context changed")
    return {"schema": "re009-evm-hash-key-order/1", "source_commit":
            "56c0ec672bd8fdcfaa80f2db700a61e6240b3663",
            "target": {"path": "artifacts/node/94/hl-node", "release": 94,
                       "size": SIZE, "sha256": SHA256},
            "primary": primary, "contract": validate_contract(data, secs),
            "transfers": [transfer(data, secs, a) for a in TRANSFERS],
            "credited_context": {"start": "0x269fd9c", "end": "0x269fdc6",
                "bytes": context.hex(), "prior_work": "PR #1379 collection-reader context",
                "call": transfer(data, secs, 0x269FDB4),
                "argument_setup": {"rdi": "r12", "rsi": "rsp+0x8",
                                   "rdx": "rsp+0xb0", "rcx": "rsp+0x90"},
                "scope": "Credited context only; excluded from primary evidence counts."},
            "counts": {"primary_FDE_extents": 1, "primary_bytes": END - START,
                       "selected_transfers": len(TRANSFERS), "compared_key_words": 4},
            "limitations": ["One local search/replacement path, not global iteration order.",
                "FDEs describe unwind ranges, not complete source functions.",
                "Insertion helper 0x1ab3d20 and three indirect callees remain unresolved.",
                "Valid memory, ABI and aliasing conditions are premises; no runtime execution.",
                "No reconstructed Rust, equivalent build or component gate."]}


def check_disassembly(text, data, secs):
    """Rebind every exported raw byte, including GNU continuation lines."""
    cursor = START
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) < 2 or not fields[0].strip().endswith(":"):
            continue
        address = int(fields[0].strip()[:-1], 16)
        raw = bytes.fromhex(fields[1])
        if address != cursor or not raw or span(data, secs, cursor, len(raw)) != raw:
            raise ValueError("raw disassembly export differs from target")
        cursor += len(raw)
    if cursor != END:
        raise ValueError("raw disassembly export is incomplete")


def check_manifest(directory):
    expected = {p.name for p in directory.iterdir() if p.is_file() and p.name != "MANIFEST.sha256"}
    seen = set()
    for line in (directory / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ")
        if name in seen or name not in expected or "/" in name or "\\" in name:
            raise ValueError("duplicate or invalid manifest entry")
        path = directory / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("manifest digest mismatch")
        seen.add(name)
    if seen != expected:
        raise ValueError("manifest is incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="write deterministic evidence.json to this directory")
    args = parser.parse_args()
    data = NODE.read_bytes()
    evidence = analyze(data)
    encoded = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "evidence.json").write_text(encoded, encoding="utf-8")
    elif (HERE / "evidence.json").read_text(encoding="utf-8") != encoded:
        raise ValueError("committed evidence differs from authenticated extraction")
    else:
        check_manifest(HERE)
        check_disassembly((HERE / "native.asm").read_text(encoding="utf-8"), data, sections(data))
    print("node94 local key order: one 624-byte FDE, unsigned words 24/16/8/0, equal replacement tag 1")


if __name__ == "__main__":
    main()
