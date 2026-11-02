#!/usr/bin/env python3
"""Collect bounded native evidence. Never execute or interpret captured instructions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
BODIES = {
    "timeout-verifier": (0x454AA10, 0x454AD45),
    "timeout-signing-caller": (0x454B170, 0x454B2FE),
    "digest-context": (0x454C050, 0x454C2AC),
    "timed-context": (0x4B747D0, 0x4B7496A),
    "mode-context": (0x471CE30, 0x471D083),
    "variant-dispatch": (0x45873D0, 0x45878C2),
    "timeout-write": (0x4778820, 0x4778A62),
    "timeout-size": (0x4778A70, 0x4778BE2),
    "votes-size": (0x485B780, 0x485B818),
    "vote-size": (0x4C7E7A0, 0x4C7E830),
    "signature-write": (0x4DF20D0, 0x4DF2242),
    "signature-size": (0x4DF2250, 0x4DF2392),
    "tag-write-dependency": (0x4AA9AE0, 0x4AA9C86),
    "bytes32-size-dependency": (0x4AA9E20, 0x4AA9E4B),
    "bytes20-write-dependency": (0x4AA9E50, 0x4AA9EC6),
    "bytes32-write-dependency": (0x4AA9ED0, 0x4AA9F48),
    "u64-write-dependency": (0x4AA9F80, 0x4AAA228),
    "u64-size-dependency": (0x4AAA230, 0x4AAA2CB),
}
# These callers/root are included only for their argument handoff. Keep their
# full FDE and body identity, but export only the corridors used in the proof.
CONTEXT = {
    "timeout-verifier-entry": ("timeout-verifier", 0x454AA10, 0x454AA30),
    "timeout-verifier-pair": ("timeout-verifier", 0x454AAE5, 0x454AB53),
    "timeout-signing-pair": ("timeout-signing-caller", 0x454B170, 0x454B1A5),
    "digest-route": ("digest-context", 0x454C050, 0x454C0B0),
}
CONTEXT_OWNERS = {owner for owner, _, _ in CONTEXT.values()}
TABLES = {0x6F5E18: [0x458740E, 0x45874F1, 0x458749B, 0x45874C6, 0x458743D],
          0x6F5E2C: [0x4587643, 0x45877C1, 0x4587753, 0x458778C, 0x45876CB]}
DISPATCH = {0x458740C: 0x6F5E18, 0x458760D: 0x6F5E2C, 0x4587641: 0x6F5E2C}
SUCCESS_GATES = {
    "timeout-write": (0x47789C7, [0x4778846, 0x477886E, 0x477888F, 0x47788B1, 0x47788D6, 0x47788F9, 0x477891E]),
    "timeout-size": (0x4778B58, [0x4778AAF, 0x4778ACD, 0x4778AEF, 0x4778B11, 0x4778B2D, 0x4778B48]),
    "signature-write": (0x4DF21F8, [0x4DF20F4, 0x4DF2114, 0x4DF2134, 0x4DF2154, 0x4DF2174, 0x4DF2190, 0x4DF21AC, 0x4DF21C8, 0x4DF21ED]),
    "signature-size": (0x4DF235C, [0x4DF2271, 0x4DF2290, 0x4DF22AF, 0x4DF22CE, 0x4DF22ED, 0x4DF2308, 0x4DF2323, 0x4DF233E, 0x4DF2356]),
}
ROW = re.compile(r"^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}[ \t]+)+)(\S.*)$")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def dump(value):
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def record_text(value, level=0, key=None):
    """One reviewable row per transfer; preserve all record values and bytes."""
    if key in ("fde", "cie"):
        return json.dumps(value, sort_keys=True)
    if key in ("transfers", "relocations", "tables"):
        if not value:
            return "[]"
        return "[\n" + ",\n".join(" " * (level + 2) + json.dumps(row, sort_keys=True)
                                 for row in value) + "\n" + " " * level + "]"
    if isinstance(value, dict):
        return "{\n" + ",\n".join(" " * (level + 2) + json.dumps(k) + ": " + record_text(v, level + 2, k)
                                 for k, v in sorted(value.items())) + "\n" + " " * level + "}"
    if isinstance(value, list):
        if not value:
            return "[]"
        if all(not isinstance(v, (dict, list)) for v in value):
            return json.dumps(value)
        return "[\n" + ",\n".join(" " * (level + 2) + record_text(v, level + 2)
                                 for v in value) + "\n" + " " * level + "]"
    return json.dumps(value)


class Image:
    def __init__(self, data, identity=True):
        self.data = data
        if identity:
            require(digest(data) == SHA, "target SHA-256 mismatch")
        require(data[:6] == b"\x7fELF\x02\x01", "not ELF64 little endian")
        off = struct.unpack_from("<Q", data, 32)[0]
        size, count = struct.unpack_from("<HH", data, 54)
        require(size == 56 and off + count * size <= len(data), "program table")
        self.loads = []
        for i in range(count):
            typ, flags, pos, va, _, filesz, memsz, align = struct.unpack_from("<IIQQQQQQ", data, off + i * size)
            if typ == 1:
                require(pos + filesz <= len(data), "PT_LOAD outside file")
                self.loads.append((va, va + filesz, pos, flags))
        require(bool(self.loads), "no PT_LOAD")

    def offset(self, va, size=1):
        hits = [pos + va - start for start, end, pos, _ in self.loads if start <= va and va + size <= end]
        require(len(hits) == 1 and size >= 0, f"ambiguous/non-file-backed VA {va:#x}+{size}")
        return hits[0]

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def record(self, va):
        size = struct.unpack("<I", self.read(va, 4))[0] + 4
        return {"va": hex(va), "size": size, "hex": self.read(va, size).hex()}


def rows(text):
    found = []
    for line in text.splitlines():
        match = ROW.match(line)
        if match:
            found.append((int(match[1], 16), bytes.fromhex(match[2]), match[3]))
    # LLVM emits LOCK as its own row; GNU combines it with the instruction.
    joined = []
    for va, raw, asm in found:
        if joined and joined[-1][1] == b"\xf0" and joined[-1][2].strip() == "lock":
            prior, byte, _ = joined.pop()
            require(prior + 1 == va, "nonadjacent LOCK")
            joined.append((prior, byte + raw, "lock " + asm))
        else:
            joined.append((va, raw, asm))
    return joined


def flow(va, raw, asm):
    """Decode transfer operands only; no instruction state/value evaluation."""
    end = va + len(raw)
    if raw[0] == 0xE8 and len(raw) == 5:
        return {"kind": "call", "target": hex(end + struct.unpack("<i", raw[1:])[0])}
    if raw[0] in (0xE9, 0xEB):
        width = 4 if raw[0] == 0xE9 else 1
        require(len(raw) == width + 1, f"jump encoding {va:#x}")
        return {"kind": "jump", "target": hex(end + int.from_bytes(raw[1:], "little", signed=True))}
    if 0x70 <= raw[0] <= 0x7F:
        require(len(raw) == 2, f"short Jcc encoding {va:#x}")
        return {"kind": "conditional", "condition": raw[0] & 15,
                "target": hex(end + int.from_bytes(raw[1:], "little", signed=True))}
    if len(raw) == 6 and raw[0] == 0x0F and 0x80 <= raw[1] <= 0x8F:
        return {"kind": "conditional", "condition": raw[1] & 15,
                "target": hex(end + int.from_bytes(raw[2:], "little", signed=True))}
    if raw[0] == 0xC3:
        return {"kind": "return"}
    if raw in (b"\x0f\x0b", b"\xcc"):
        return {"kind": "trap"}
    if raw[:2] in (b"\xff\x15", b"\xff\x25") and len(raw) == 6:
        return {"kind": "slot-call" if raw[1] == 0x15 else "slot-jump",
                "slot": hex(end + struct.unpack("<i", raw[2:])[0])}
    op = asm.split()[0].lower()
    if op in ("call", "jmp"):
        if va in DISPATCH:
            return {"kind": "table-jump", "table": hex(DISPATCH[va]),
                    "targets": [hex(t) for t in TABLES[DISPATCH[va]]]}
        return {"kind": "indirect-call" if op == "call" else "indirect-jump", "operand": asm}
    require(not op.startswith("j") and not op.startswith("loop") and op not in ("ret", "retq", "lret"),
            f"unhandled transfer {va:#x}: {asm}")
    return None


def native(binary, start, end, llvm):
    commands = [
        ["objdump", "-d", "-M", "intel", "--insn-width=16", f"--start-address={start}", f"--stop-address={end}", str(binary)],
        [llvm, "-d", "--x86-asm-syntax=intel", f"--start-address={start}", f"--stop-address={end}", str(binary)],
    ]
    outputs = [subprocess.check_output(cmd, text=True).replace(str(binary), "artifacts/node/94/hl-node") for cmd in commands]
    decoded = [rows(t) for t in outputs]
    require([(a, b) for a, b, _ in decoded[0]] == [(a, b) for a, b, _ in decoded[1]], f"native partition disagreement {start:#x}")
    return outputs, decoded[0]


def check_witnesses(image, pins):
    for pin in pins["witnesses"]:
        va, raw = int(pin["va"], 16), bytes.fromhex(pin["hex"])
        require(image.read(va, len(raw)) == raw, f"witness {pin['name']} at {va:#x}")
    for va, targets in TABLES.items():
        actual = [va + struct.unpack("<i", image.read(va + i * 4, 4))[0] for i in range(5)]
        require(actual == targets, f"dispatch table {va:#x}")
    require(image.read(0x209EDC, 4) == b"\x02\0\0\0", "tag2 literal")


def reachable(graph, entry, banned=None):
    seen, todo = set(), [entry]
    while todo:
        va = todo.pop()
        if va != banned and va not in seen:
            seen.add(va)
            todo.extend(graph[va])
    return seen


def gate_contract(name, graph, entry):
    if name not in SUCCESS_GATES:
        return None
    success, mandatory = SUCCESS_GATES[name]
    require(success in reachable(graph, entry), f"vacuous success {name}")
    require(all(success not in reachable(graph, entry, site) for site in mandatory), f"success bypass {name}")
    # Each listed operation must occur before the next: removing it prevents
    # reaching that later operation. This concerns local CFG paths, not callee effects.
    require(all(later not in reachable(graph, entry, earlier) for earlier, later in zip(mandatory, mandatory[1:])), f"operation order {name}")
    return {"success_node": hex(success), "ordered_dominating_nodes": [hex(s) for s in mandatory],
            "nonvacuous": True, "scope": "local direct/table CFG; normal-return calls; no exception edges"}


def projection(image):
    def load(va, prefix):
        require(image.read(va, len(prefix)) == prefix, f"load family {va:#x}")
        return image.read(va + len(prefix), 1)[0]
    timeout = [load(va, b"\x49\x8b\x4f") for va in (0x477885D, 0x4778881, 0x47788A3, 0x47788C5)]
    signature = [0] + [load(va, b"\x49\x8b\x4c\x24") for va in (0x4DF2107, 0x4DF2127, 0x4DF2147, 0x4DF2167, 0x4DF2183, 0x4DF219F, 0x4DF21BB)]
    return {"timeout_u64_offsets_in_order": [hex(o) for o in timeout],
            "timeout_signer_offset": hex(load(0x477883A, b"\x48\x83\xc6")),
            "qc_hash_offset": hex(load(0x47788ED, b"\x49\x8d\x77")),
            "qc_vote_count_offset": hex(load(0x477890D, b"\x49\x8b\x6f")),
            "nested_signature_limb_offsets_in_order": [hex(o) for o in signature],
            "nested_signature_byte_pointer_offset": hex(load(0x4DF21D7, b"\x49\x8b\x44\x24")),
            "value_projection": "20 raw bytes, four V(u64), 32 raw bytes, V(vote_count), then each 20 raw bytes + eight V(u64) + one raw byte"}


def collect(binary, llvm, pins, output, *, identity=True, witnesses=True):
    # Internal controls can remove byte-equality guards so CFG rejection is
    # tested independently. The public CLI always enables both guards.
    image = Image(binary.read_bytes(), identity=identity)
    if witnesses:
        check_witnesses(image, pins)
    cies, fdes = eh_frame_records(image.data)
    _, index = unwind_index(image.data)
    by_start = {}
    for fde in fdes:
        by_start.setdefault(fde["start"], []).append(fde)
    sec = sections(image.data)
    rela = next(s for s in sec if s["name"] == ".rela.dyn")
    relocations = {}
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        slot, info, addend = struct.unpack_from("<QQq", image.data, off)
        relocations.setdefault(slot, []).append({"slot": hex(slot), "type": info & 0xFFFFFFFF,
                                                "symbol_index": info >> 32, "addend": hex(addend),
                                                "record_file_offset": hex(off), "record_hex": image.data[off:off+24].hex()})
    records = {"target_sha256": SHA, "source_commit": "56c0ec672bd8fdcfaa80f2db700a61e6240b3663",
               "coordinate_system": "linked ELF virtual addresses; half-open intervals",
               "captured_execution": False, "instruction_evaluation": False,
               "normalization": "Only input-path header substitution and standalone LOCK row joining; no bytes masked.",
               "functions": [], "tables": [], "tag_literal": {"va": "0x209edc", "hex": image.read(0x209EDC, 4).hex()}}
    output.mkdir(parents=True, exist_ok=True)
    slots = set()
    total_rows = 0
    ranges = [(name, name, start, end, "complete-FDE") for name, (start, end) in BODIES.items() if name not in CONTEXT_OWNERS]
    ranges += [(name, owner, start, end, "bounded-caller-corridor") for name, (owner, start, end) in CONTEXT.items()]
    for name, owner, start, end, scope in ranges:
        owner_start, owner_end = BODIES[owner]
        matches = by_start.get(owner_start, [])
        require(len(matches) == 1 and matches[0]["end"] == owner_end, f"FDE extent {owner}")
        fde = matches[0]
        require(sum(row["start"] == owner_start and row["fde"] == fde["fde"] for row in index) == 1, f"FDE index {name}")
        exports, instructions = native(binary, start, end, llvm)
        cursor = start
        for va, raw, _ in instructions:
            require(va == cursor and image.read(va, len(raw)) == raw, f"complete raw partition {name} {va:#x}")
            cursor += len(raw)
        require(cursor == end, f"incomplete export {name}")
        total_rows += len(instructions)
        transfers = []
        starts = {va for va, _, _ in instructions}
        graph = {}
        for va, raw, asm in instructions:
            item = flow(va, raw, asm)
            successors = []
            if item:
                transfers.append(dict(va=hex(va), raw=raw.hex(), **item))
                if "slot" in item:
                    slots.add(int(item["slot"], 16))
            if scope == "bounded-caller-corridor":
                continue
            kind = item["kind"] if item else "ordinary"
            if kind in ("jump", "conditional"):
                target = int(item["target"], 16)
                require(target in starts, f"branch outside/local-middle {name} {va:#x}")
                successors.append(target)
            if kind == "table-jump":
                targets = [int(t, 16) for t in item["targets"]]
                require(all(t in starts for t in targets), "table outside instruction starts")
                successors.extend(targets)
            if kind in ("ordinary", "call", "slot-call", "indirect-call", "conditional"):
                following = va + len(raw)
                if following < end:
                    require(following in starts, "fallthrough middle")
                    successors.append(following)
            graph[va] = successors
        seen = reachable(graph, start) if graph else None
        contract = gate_contract(name, graph, start) if graph else None
        for tool, text in zip(("gnu", "llvm"), exports):
            (output / f"{name}.{tool}.txt").write_text(text)
        records["functions"].append({"name": name, "scope": scope, "start": hex(start), "end": hex(end),
            "owner_name": owner, "owner_start": hex(owner_start), "owner_end": hex(owner_end),
            "file_offset": hex(image.offset(start, end-start)), "bytes": end-start,
            "body_sha256": digest(image.read(owner_start, owner_end-owner_start)),
            "selected_sha256": digest(image.read(start, end-start)), "fde": image.record(fde["fde"]),
            "cie": image.record(fde["cie"]), "lsda": None if fde["lsda"] is None else hex(fde["lsda"]),
            "instructions": len(instructions), "normal_graph_reachable_rows": len(seen) if seen is not None else None,
            "success_gates": contract,
            "transfers": transfers, "native_exports": {tool: digest(text.encode()) for tool, text in zip(("gnu", "llvm"), exports)}})
    records["relocations"] = [r for slot in sorted(slots) for r in relocations.get(slot, [])]
    records["unrelocated_slots"] = [hex(s) for s in sorted(slots) if s not in relocations]
    records["projection"] = projection(image)
    records["tables"] = [{"va": hex(va), "hex": image.read(va, 20).hex(), "targets": [hex(t) for t in ts]} for va, ts in TABLES.items()]
    records["summary"] = {"full_fdes": len(BODIES) - len(CONTEXT_OWNERS), "bounded_caller_corridors": len(CONTEXT),
                           "bytes": sum(end-start for _,_,start,end,_ in ranges),
                           "instructions": total_rows, "native_partitions_agree": True,
                           "new_semantics": ["variant2 field order", "QC vote count/stride", "nested signature integer projection"],
                           "compiled_matches": "not measured", "progress_gates_changed": 0}
    (output / "records.json").write_text(record_text(records) + "\n")
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "artifacts/node/94/hl-node")
    parser.add_argument("--llvm", default=os.environ.get("LLVM_OBJDUMP") or shutil.which("llvm-objdump"))
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    if not args.llvm:
        parser.error("LLVM objdump is required; pass --llvm, set LLVM_OBJDUMP, or add llvm-objdump to PATH")
    pins = json.loads((HERE / "pins.json").read_text())
    result = collect(args.binary, args.llvm, pins, args.out)
    print(dump(result["summary"]), end="")


if __name__ == "__main__":
    main()
