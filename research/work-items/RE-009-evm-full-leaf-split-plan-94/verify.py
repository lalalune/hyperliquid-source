#!/usr/bin/env python3
"""Recover one leaf split planning decision from authenticated node94 bytes."""
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
DIGEST = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
SIZE = 91774280
START, END = 0x1AB3D20, 0x1AB4A43
BODY_DIGEST = "93d07eae728e5ddaadc820741e5508fffe77bf2a74f50ec73d3bd448b3124d15"
RANGES = ((0x1AB3D31, 0x1AB3D45), (0x1AB3D72, 0x1AB3DA9),
          (0x1AB3E5F, 0x1AB3FD8), (0x28547E1, 0x2854867))


def read_va(data, secs, address, size):
    if type(address) is not int or type(size) is not int or address < 0 or size <= 0:
        raise ValueError("invalid virtual range")
    matches = [s for s in secs if s["type"] != 8 and s["address"] <= address
               and address + size <= s["address"] + s["size"]]
    if len(matches) != 1:
        raise ValueError("virtual range is not uniquely file backed")
    offset = matches[0]["offset"] + address - matches[0]["address"]
    if offset < 0 or offset + size > len(data):
        raise ValueError("virtual range exceeds input")
    return data[offset:offset + size]


def form(data, secs, address, encoded, fields=()):
    expected = bytes.fromhex(encoded)
    actual = read_va(data, secs, address, len(expected))
    if any(a != e for i, (a, e) in enumerate(zip(actual, expected)) if i not in fields):
        raise ValueError(f"native instruction form changed at {address:#x}")
    return actual


def control(data, secs, address):
    head = read_va(data, secs, address, 2)
    if head[0] in (0xE8, 0xE9):
        length, at, kind = 5, 1, "call" if head[0] == 0xE8 else "jump"
    elif head[0] == 0xEB or 0x70 <= head[0] <= 0x7F:
        return {"site": hex(address), "opcode": head[:1].hex(),
                "target": hex(address + 2 + int.from_bytes(head[1:], "little", signed=True))}
    elif head[0] == 0x0F and 0x80 <= head[1] <= 0x8F:
        length, at, kind = 6, 2, "conditional"
    elif head == b"\xff\x15":
        length, at, kind = 6, 2, "indirect-slot"
    else:
        raise ValueError("unexpected native control transfer")
    raw = read_va(data, secs, address, length)
    return {"site": hex(address), "opcode": raw[:at].hex(), "kind": kind,
            "target": hex(address + length + struct.unpack_from("<i", raw, at)[0])}


def decode_fields(data, secs=None):
    """Decode a fixed family of operand fields, without executing instructions."""
    secs = sections(data) if secs is None else secs
    form(data, secs, 0x1AB3D31, "4989cd4c8b3e410fb79fca020000")
    capacity = form(data, secs, 0x1AB3D3F, "4883fb0b", (3,))[3]
    form(data, secs, 0x1AB3D43, "732d", (1,))
    form(data, secs, 0x1AB3D72, "4c897c24084c8b7e10")
    first_cut = form(data, secs, 0x1AB3D7B, "4983ff05", (3,))[3]
    # These MOVs preserve the preceding CMP flags through the distant JAE.
    form(data, secs, 0x1AB3D7F, "48897c24284c898424c00000004889542418")
    form(data, secs, 0x1AB3D91, "0f83c8000000", range(2, 6))
    form(data, secs, 0x1AB3D97, "4c897c2410")
    left_pivot = int.from_bytes(form(data, secs, 0x1AB3D9C, "41bc04000000", range(2, 6))[2:], "little")
    form(data, secs, 0x1AB3DA2, "31dbe9ee000000")
    form(data, secs, 0x1AB3E5F, "7419", (1,))
    second_cut = form(data, secs, 0x1AB3E61, "4983ff06", (3,))[3]
    form(data, secs, 0x1AB3E65, "751f", (1,))
    center_pivot = int.from_bytes(form(data, secs, 0x1AB3E67, "41bc05000000", range(2, 6))[2:], "little")
    center_side = form(data, secs, 0x1AB3E6D, "b301", (1,))[1]
    form(data, secs, 0x1AB3E6F, "48c744241000000000eb1d")
    form(data, secs, 0x1AB3E7A, "31db4c897c24104d89fceb11")
    delta = int.from_bytes(form(data, secs, 0x1AB3E86, "4983c7f9", (3,))[3:], "little", signed=True)
    form(data, secs, 0x1AB3E8A, "4c897c2410")
    right_pivot = int.from_bytes(form(data, secs, 0x1AB3E8F, "41bc06000000", range(2, 6))[2:], "little")
    right_side = form(data, secs, 0x1AB3E95, "b301", (1,))[1]
    form(data, secs, 0x1AB3E97, "488b46084889442420bfd0020000")
    form(data, secs, 0x1AB3EA5, "ff152da1cb03")
    form(data, secs, 0x1AB3EAB, "4885c00f84e40a00004989c6")
    form(data, secs, 0x1AB3EB7, "48c780c00200000000000066c780ca0200000000")
    # right_count = old_count + ~pivot; the old node later receives pivot.
    form(data, secs, 0x1AB3ED0, "410fb787ca0200004c89e548f7d54801c5664189aeca0200004c89e049c1e405")
    # Four 16-byte loads gather the selected old key/value, before transfers.
    form(data, secs, 0x1AB3EF0, "430f100427430f104c27100f298c24b00000000f298424a0000000")
    form(data, secs, 0x1AB3F0B, "430f10842760010000430f108c27700100000f298c24200100000f29842410010000")
    form(data, secs, 0x1AB3F2D, "4883fd0c0f83480a0000")
    form(data, secs, 0x1AB3F37, "4c892c24895c2438498d9f600100004b8d34274883c62048c1e5054c89f74889ea4989c5")
    form(data, secs, 0x1AB3F5B, "ff157fa0cb034a8d34234883c620498dbe600100004889eaff1567a0cb03")
    form(data, secs, 0x1AB3F79, "664589afca020000")
    form(data, secs, 0x1AB3FB9, "31c9807c2438004c89f2")
    select = form(data, secs, 0x1AB3FC3, "490f44d7", (2,))[2]
    if select not in (0x44, 0x45):
        raise ValueError("unrecognized side selection")
    form(data, secs, 0x1AB3FC7, "0f298424f00000004c8b6c2420490f44cd")
    # Contextual caller constructs the zero-height handle and passes its copy.
    form(data, secs, 0x28547FE, "488944242848c7442430000000004889542438")
    form(data, secs, 0x2854816, "488d442428488b501048895424500f10000f29442440")
    form(data, secs, 0x285484C, "488d742440488d5424604989e0")
    targets = {hex(a): control(data, secs, a)["target"] for a in
               (0x1AB3D43, 0x1AB3D91, 0x1AB3E5F, 0x1AB3E65, 0x2854859)}
    return {"capacity": capacity, "first_cut": first_cut, "second_cut": second_cut,
            "left_outer_pivot": left_pivot, "right_center_pivot": center_pivot,
            "right_outer_pivot": right_pivot, "right_center_side": center_side,
            "right_outer_side": right_side, "right_outer_delta": delta,
            "zero_selects_old_node": select == 0x44, "targets": targets}


EXPECTED = {"capacity": 11, "first_cut": 5, "second_cut": 6,
    "left_outer_pivot": 4, "right_center_pivot": 5, "right_outer_pivot": 6,
    "right_center_side": 1, "right_outer_side": 1, "right_outer_delta": -7,
    "zero_selects_old_node": True, "targets": {"0x1ab3d43": "0x1ab3d72",
    "0x1ab3d91": "0x1ab3e5f", "0x1ab3e5f": "0x1ab3e7a",
    "0x1ab3e65": "0x1ab3e86", "0x2854859": "0x1ab3d20"}}


def validate_fields(data, secs=None):
    fields = decode_fields(data, secs)
    if fields != EXPECTED:
        raise ValueError("native split planning fields changed")
    return fields


def split_plan(index, fields):
    """A mathematical plan for exactly eleven old entries; no memory mutation."""
    if type(index) is not int or not 0 <= index <= 11:
        raise ValueError("model domain is insertion index 0..11 for eleven old entries")
    if index < fields["first_cut"]:
        pivot, flag, local = fields["left_outer_pivot"], 0, index
    elif index == fields["first_cut"]:
        pivot, flag, local = index, 0, index
    elif index == fields["second_cut"]:
        pivot, flag, local = fields["right_center_pivot"], fields["right_center_side"], 0
    else:
        pivot, flag, local = fields["right_outer_pivot"], fields["right_outer_side"], (index + fields["right_outer_delta"]) % (1 << 64)
    left = (flag == 0) == fields["zero_selects_old_node"]
    return [index, pivot, "left" if left else "right", local,
            pivot + int(left), 10 - pivot + int(not left)]


TRANSFERS = (0x1AB3D43, 0x1AB3D91, 0x1AB3DA4, 0x1AB3E5F,
    0x1AB3E65, 0x1AB3E78, 0x1AB3E84, 0x1AB3EA5, 0x1AB3EAE,
    0x1AB3F31, 0x1AB3F5B, 0x1AB3F73)


def analyze(data):
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != DIGEST:
        raise ValueError("node94 identity mismatch")
    secs, index = unwind_index(data)
    cies, fdes = eh_frame_records(data, secs)
    fs = [f for f in fdes if f["start"] == START and f["end"] == END]
    if len(fs) != 1:
        raise ValueError("primary FDE range changed")
    f = fs[0]
    if f["cie"] not in cies or sum(e["start"] == START and e["fde"] == f["fde"] for e in index) != 1:
        raise ValueError("primary FDE index/CIE changed")
    body = read_va(data, secs, START, END - START)
    if hashlib.sha256(body).hexdigest() != BODY_DIGEST:
        raise ValueError("primary body changed")
    sec = next(s for s in secs if s["address"] <= START < s["address"] + s["size"])
    primary = {k: hex(f[k]) if f[k] is not None else None for k in ("start", "end", "fde", "cie", "lsda")}
    primary.update({"body_hex": body.hex(), "body_sha256": BODY_DIGEST,
                    "file_offset": hex(sec["offset"] + START - sec["address"])})
    for kind in ("fde", "cie"):
        length = int.from_bytes(read_va(data, secs, f[kind], 4), "little") + 4
        primary[kind + "_hex"] = read_va(data, secs, f[kind], length).hex()
    fields = validate_fields(data, secs)
    windows = [{"start": hex(a), "end": hex(b), "bytes": read_va(data, secs, a, b-a).hex(),
                "scope": "primary" if a < END else "credited caller context"} for a,b in RANGES]
    return {"schema": "re009-evm-full-leaf-split-plan/1", "base":
        "56c0ec672bd8fdcfaa80f2db700a61e6240b3663", "target_sha256": DIGEST,
        "primary": primary, "windows": windows, "fields": fields,
        "cases": [split_plan(i, fields) for i in range(12)],
        "selected_transfers": [control(data, secs, a) for a in TRANSFERS],
        "caller_edge": control(data, secs, 0x2854859),
        "counts": {"primary_FDEs": 1, "retained_primary_bytes": END-START,
            "selected_primary_windows": 3, "selected_primary_bytes": sum(b-a for a,b in RANGES[:3]),
            "credited_context_bytes": RANGES[3][1]-RANGES[3][0], "valid_model_positions": 12},
        "unknowns": ["The model assumes a valid eleven-entry leaf and insertion index 0..11.",
            "Allocation, byte-moving callees, split propagation and exception paths are not closed.",
            "Post-insertion counts are mathematical predictions, not captured target output.",
            "No full insertion, global order, runtime behavior or acceptance gate."]}


def check_listing(text, data, secs):
    expected = {a+i: value for a,b in RANGES for i,value in enumerate(read_va(data,secs,a,b-a))}
    actual = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) < 2 or not parts[0].strip().endswith(":"):
            continue
        address = int(parts[0].strip()[:-1], 16)
        for i, byte in enumerate(bytes.fromhex(parts[1])):
            if address+i in actual:
                raise ValueError("duplicate disassembly byte")
            actual[address+i] = byte
    if actual != expected:
        raise ValueError("selected disassembly bytes differ or are incomplete")


def check_bundle():
    files = {p.name for p in HERE.iterdir() if p.is_file() and p.name != "MANIFEST.sha256"}
    seen = set()
    for line in (HERE / "MANIFEST.sha256").read_text().splitlines():
        digest, name = line.split("  ")
        if name in seen or name not in files or (HERE/name).is_symlink():
            raise ValueError("invalid manifest membership")
        if hashlib.sha256((HERE/name).read_bytes()).hexdigest() != digest:
            raise ValueError("manifest digest differs")
        seen.add(name)
    if seen != files:
        raise ValueError("manifest is incomplete")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    data = NODE.read_bytes()
    record = analyze(data)
    encoded = json.dumps(record, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "evidence.json").write_text(encoded)
    else:
        check_bundle()
        check_listing((HERE / "selected.asm").read_text(), data, sections(data))
        if (HERE / "evidence.json").read_text() != encoded:
            raise ValueError("committed evidence differs")
    print("node94 full-leaf split plan: 12 valid positions; pivots 4/5/6; local selection only")


if __name__ == "__main__":
    main()
