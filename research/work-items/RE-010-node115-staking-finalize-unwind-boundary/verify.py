#!/usr/bin/env python3
"""Verify the pinned #115 link-staking finalize unwind evidence; static reads only."""
import argparse
import copy
import hashlib
import importlib.util
import json
import platform
import sys
from pathlib import Path

import capstone
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
PIN = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def uleb(raw, cursor):
    value = shift = 0
    for _ in range(10):
        require(cursor < len(raw), "truncated LSDA ULEB128")
        byte = raw[cursor]
        cursor += 1
        value |= (byte & 0x7f) << shift
        if byte < 0x80:
            return value, cursor
        shift += 7
    raise ValueError("overlong LSDA ULEB128")


def decode_lsda(raw, base, end):
    require(len(raw) >= 5, "short LSDA")
    cursor = 0
    lpstart_encoding = raw[cursor]
    cursor += 1
    require(lpstart_encoding == 0xff, "unsupported LPStart encoding")
    type_encoding = raw[cursor]
    cursor += 1
    type_table_base_offset = None
    if type_encoding != 0xff:
        require(type_encoding == 0x9b, "unsupported type-table encoding")
        type_offset, cursor = uleb(raw, cursor)
        type_table_base_offset = cursor - 1 + type_offset
    callsite_encoding = raw[cursor]
    cursor += 1
    require(callsite_encoding == 0x01, "unsupported call-site encoding")
    table_length, cursor = uleb(raw, cursor)
    table_end = cursor + table_length
    require(table_end <= len(raw), "call-site table outside retained LSDA bytes")
    entries = []
    while cursor < table_end:
        start, cursor = uleb(raw, cursor)
        length, cursor = uleb(raw, cursor)
        landing, cursor = uleb(raw, cursor)
        action, cursor = uleb(raw, cursor)
        lo, hi = base + start, base + start + length
        require(base <= lo <= hi <= end, "call-site range outside FDE")
        require(landing == 0 or base <= base + landing < end, "landing pad outside FDE")
        entries.append([hex(lo), hex(hi), hex(base + landing) if landing else None, action])
    require(cursor == table_end, "call-site table length mismatch")
    if type_table_base_offset is None:
        require(table_end == len(raw), "unexpected bytes after table without type table")
    else:
        require(table_end <= type_table_base_offset <= len(raw), "type table base outside retained LSDA")
    return {
        "lpstart_encoding": lpstart_encoding,
        "type_encoding": type_encoding,
        "type_table_base_offset": type_table_base_offset,
        "callsite_encoding": callsite_encoding,
        "callsite_table_end_offset": table_end,
        "entries": entries,
    }


def load_image(data):
    helper_path = ROOT / "research/work-items/RE-001-node115-registry-row-labels/verify.py"
    spec = importlib.util.spec_from_file_location("node115_static_elf_helper", helper_path)
    require(spec is not None and spec.loader is not None, "missing pinned ELF helper")
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper.Image(data), helper


def decode_window(image, decoder, window):
    start, end = int(window["start"], 16), int(window["end"], 16)
    raw = image.get(start, end - start)
    require(hashlib.sha256(raw).hexdigest() == window["sha256"], "window digest: " + window["name"])
    decoded = list(decoder.disasm(raw, start))
    rows = [[hex(row.address), row.bytes.hex(), row.mnemonic + " " + row.op_str] for row in decoded]
    require(rows and rows[0][0] == hex(start), "window start boundary: " + window["name"])
    require(int(rows[-1][0], 16) + len(bytes.fromhex(rows[-1][1])) == end,
            "window end boundary: " + window["name"])
    require(rows == window["rows"], "decoded rows: " + window["name"])
    return decoded


def verify_packet(data, packet):
    require(capstone.__version__ == "5.0.7", "use recorded Capstone 5.0.7")
    require(len(data) == packet["target_size"], "target size")
    require(hashlib.sha256(data).hexdigest() == PIN == packet["target_sha256"], "target SHA-256")
    image, helper = load_image(data)
    _, fdes = helper.eh_frame_records(data, image.sections)
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True

    actual_fdes = {}
    for expected in packet["fdes"]:
        start = int(expected["start"], 16)
        matches = [f for f in fdes if f["start"] == start]
        require(len(matches) == 1, "unique FDE start: " + expected["role"])
        fde = matches[0]
        observed = {
            "role": expected["role"],
            "start": hex(fde["start"]),
            "end": hex(fde["end"]),
            "lsda": hex(fde["lsda"]) if fde["lsda"] is not None else None,
        }
        require(observed == expected, "FDE identity/LSDA: " + expected["role"])
        actual_fdes[expected["role"]] = fde

    windows = {window["name"]: decode_window(image, decoder, window)
               for window in packet["windows"]}
    require(len(windows) == len(packet["windows"]), "duplicate instruction window")

    parsed_lsdas = {}
    for expected in packet["lsdas"]:
        raw = image.get(int(expected["address"], 16), expected["length"])
        require(raw.hex() == expected["raw_hex"], "LSDA bytes: " + expected["role"])
        require(hashlib.sha256(raw).hexdigest() == expected["sha256"],
                "LSDA digest: " + expected["role"])
        fde = actual_fdes[expected["role"]]
        observed = decode_lsda(raw, fde["start"], fde["end"])
        for key in ("lpstart_encoding", "type_encoding", "type_table_base_offset",
                    "callsite_encoding", "callsite_table_end_offset", "entries"):
            require(observed[key] == expected[key], "LSDA " + key + ": " + expected["role"])
        parsed_lsdas[expected["role"]] = observed["entries"]

    # Direct call edges must resolve to the independently retained target VA.
    for call in packet["direct_calls"]:
        insns = [row for rows in windows.values() for row in rows
                 if row.address == int(call["site"], 16)]
        require(len(insns) == 1, "unique direct call instruction: " + call["role"])
        row = insns[0]
        require(row.mnemonic == "call" and len(row.operands) == 1
                and row.operands[0].type == X86_OP_IMM
                and row.operands[0].imm == int(call["target"], 16),
                "direct call target: " + call["role"])

    # The wrapper's indirect call resolves through a pinned R_X86_64_RELATIVE slot.
    indirect = packet["indirect_call"]
    rows = [row for values in windows.values() for row in values
            if row.address == int(indirect["site"], 16)]
    require(len(rows) == 1 and rows[0].mnemonic == "call", "wrapper indirect call")
    rip_mem = [op for op in rows[0].operands if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP]
    require(len(rip_mem) == 1, "wrapper RIP-relative call slot")
    slot = rows[0].address + rows[0].size + rip_mem[0].mem.disp
    require(slot == int(indirect["slot"], 16), "wrapper call slot address")
    relocation = image.relocs().get(slot)
    require(relocation is not None and relocation[0] & 0xffffffff == indirect["type"]
            and relocation[1] == int(indirect["target"], 16), "wrapper call relocation target")

    # The first and second upserts use the same descriptor and are adjacent
    # normal-path calls. No conditional edge in this retained interval rolls back write one.
    finalize_rows = windows["finalize_two_writes"]
    at = {row.address: row for row in finalize_rows}
    first, second = int("0x46a0288", 16), int("0x46a02b6", 16)
    require(at[first - 3].mnemonic == "mov" and at[first - 3].op_str == "rsi, r13",
            "first upsert descriptor argument")
    require(at[second - 3].mnemonic == "mov" and at[second - 3].op_str == "rsi, r13",
            "second upsert descriptor argument")
    between = [row for row in finalize_rows if first < row.address < second]
    require(not any(row.mnemonic.startswith("j") or row.mnemonic.startswith("ret") for row in between),
            "unexpected branch/return between normal upserts")

    # These exact call sites have no local LSDA landing pad/action. The writer's
    # conversion calls do have cleanup pads, verified in the linked packet.
    for site in packet["unwind_sites"]:
        require(actual_fdes[site["owner"]]["lsda"] is not None, "missing expected caller LSDA")
        rows = parsed_lsdas[site["owner"]]
        matches = [entry for entry in rows if int(entry[0], 16) <= int(site["site"], 16) < int(entry[1], 16)]
        require(len(matches) == 1, "unique call-site LSDA row: " + site["role"])
        _, _, landing, action = matches[0]
        require(landing == site["landing_pad"] and action == site["action"],
                "call-site cleanup/action: " + site["role"])

    return {
        "target_sha256": PIN,
        "target_size": len(data),
        "fdes_checked": len(packet["fdes"]),
        "instruction_windows": len(packet["windows"]),
        "lsda_tables": len(packet["lsdas"]),
        "direct_calls_checked": len(packet["direct_calls"]),
        "indirect_calls_checked": 1,
        "exception_sites_checked": len(packet["unwind_sites"]),
        "scope": "selected static call and unwind metadata only; no runtime or outer-transaction claim",
    }


def self_test(data, packet):
    controls = [
        ("changed second writer target", lambda p: p["direct_calls"][1].update(target="0x3ce1081")),
        ("false finalizer LSDA", lambda p: p["fdes"][0].update(lsda="0x3001e8")),
        ("false parent landing pad", lambda p: p["lsdas"][2]["entries"][2].__setitem__(2, "0x553703b")),
        ("changed wrapper relocation", lambda p: p["indirect_call"].update(target="0x469fe91")),
    ]
    rejected = []
    for label, mutate in controls:
        altered = copy.deepcopy(packet)
        mutate(altered)
        try:
            verify_packet(data, altered)
        except (ValueError, KeyError, IndexError):
            rejected.append(label)
        else:
            raise ValueError("self-test accepted " + label)
    return rejected


def write_manifest(packet=HERE):
    names = sorted(p.name for p in packet.iterdir() if p.is_file() and p.name != "MANIFEST.sha256")
    lines = [f"{hashlib.sha256((packet / name).read_bytes()).hexdigest()}  {name}" for name in names]
    (packet / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")


def verify_manifest():
    path = HERE / "MANIFEST.sha256"
    require(path.is_file(), "missing MANIFEST.sha256")
    entries = {}
    for line in path.read_text().splitlines():
        digest, name = line.split("  ", 1)
        require(name not in entries, "duplicate manifest name")
        entries[name] = digest
    names = sorted(p.name for p in HERE.iterdir() if p.is_file() and p.name != "MANIFEST.sha256")
    require(sorted(entries) == names, "manifest file set")
    for name in names:
        require(hashlib.sha256((HERE / name).read_bytes()).hexdigest() == entries[name],
                "manifest digest: " + name)


def compare_retained(summary, retained):
    """Python's patch version is historical provenance, not a byte result."""
    def stable(row):
        return {key: value for key, value in row.items() if key != "python"}
    require(stable(summary) == stable(retained), "retained verification differs")
    return ({"retained_python": retained["python"], "current_python": summary["python"]}
            if summary["python"] != retained["python"] else {})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    parser.add_argument("--write", action="store_true", help="write verification.json and MANIFEST.sha256")
    parser.add_argument("--out", type=Path, default=HERE,
                        help="separate directory for current-host verification output")
    args = parser.parse_args()
    packet = json.loads((HERE / "records.json").read_text())
    data = args.target.read_bytes()
    summary = verify_packet(data, packet)
    summary["corruptions_rejected"] = self_test(data, packet)
    summary["python"] = platform.python_version()
    summary["capstone"] = capstone.__version__
    retained = json.loads((HERE / "verification.json").read_text())
    if args.write:
        require(args.out.resolve() != HERE.resolve() or summary == retained,
                "preserve historical verification provenance; use --write --out with a separate directory")
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "verification.json").write_text(json.dumps(summary, indent=2) + "\n")
        write_manifest(args.out)
    else:
        verify_manifest()
        summary.update(compare_retained(summary, retained))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, IndexError) as error:
        print(f"staking-finalize-unwind: {error}", file=sys.stderr)
        raise SystemExit(1)
