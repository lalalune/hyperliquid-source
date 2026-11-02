#!/usr/bin/env python3
"""Static node94 TC abort/reduction binding. Never executes captured code."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

PACKET = Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

TARGET = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
CORES = {
    0x4768F80: (0x47694D3, "5f650382bd5bfd15d6ff2bfaad4d89e7ae8cf4e644c52f6f3033e4689da1bd78"),
    0x476F3E0: (0x476F6ED, "c2b2a4a1a877d410474c5380f460207625bed9779cc33b53c1d292c012daf619"),
}
# Complete supporting bodies are binding context, not newly implemented functions.
CONTEXT = {
    0x47594F0: 0x4759963, 0x454AA10: 0x454AD45,
    0x47328A0: 0x473291B, 0x467A960: 0x467B0A8,
    0x46AA2B0: 0x46AA4CA, 0x46AFFD0: 0x46B01B3,
    0x4E17630: 0x4E17641, 0x4E16030: 0x4E16122,
    0x4780ED0: 0x47811BD,
}
ANCHORS = {
    0x4759772: "c6042400",       # caller initializes the shared byte
    0x4759813: "41b801000000",   # minimum chunk length = 1
    0x475982B: "e850f70000",     # actual caller -> bridge
    0x475983E: "4839442428",     # caller observes result tag
    0x4759843: "7573",           # error bypasses voter collection/quorum
    0x4768FB0: "0fb638",         # byte-width entry cancellation read
    0x4768FB6: "741f",           # zero continues, nonzero returns identity
    0x4768FDF: "48d1ee",         # midpoint = length / 2
    0x4768FE5: "0f8301010000",   # minimum split boundary
    0x4769058: "e883630000",     # bridge -> sequential fold
    0x4769151: "4929f6",         # remaining producer length
    0x4769154: "0f822e030000",   # underflow panic path
    0x4769248: "e81317f1ff",     # worker-context join boundary
    0x4769432: "0f848afbffff",   # both identity -> only tag store
    0x4769449: "480f44c7",       # choose right iff left is identity
    0x4769478: "0f8547fbffff",   # drop right only for two errors
    0x476947E: "e81d94fcff",     # error drop delegation
    0x476F405: "4939c7",         # empty producer span
    0x476F446: "31c9",           # do not verify the nested QC again
    0x476F448: "e8c3b5ddff",     # signed-timeout verifier boundary
    0x476F45A: "0f8428020000",   # extra niche marker leaves folder unchanged
    0x476F592: "e80933fcff",     # discard incoming error if folder already failed
    0x476F5DD: "41c60601",       # shared byte store on local error
    0x476F66C: "751a",           # local error stops without a byte read
    0x476F66E: "410fb606",       # cancellation read after successful consume
    0x476F674: "7512",           # nonzero observed cancellation stops
    0x476F676: "4981c7b8000000", # 184-byte timeout row stride
    0x476F682: "0f85a8fdffff",   # continue only before producer end
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        if len({s["name"] for s in self.sections}) != len(self.sections):
            raise ValueError("duplicate section name")
        self.cies, self.fdes = eh_frame_records(data, self.sections)
        self.relocations = {}
        for section in self.sections:
            if section["type"] != 4:
                continue
            if section["size"] % 24:
                raise ValueError("partial RELA")
            for off in range(section["offset"], section["offset"] + section["size"], 24):
                slot, info, addend = struct.unpack_from("<QQq", data, off)
                if slot in self.relocations:
                    raise ValueError("duplicate relocation slot")
                self.relocations[slot] = {
                    "slot": hex(slot), "type": info & 0xFFFFFFFF,
                    "symbol_index": info >> 32, "addend": hex(addend),
                    "file_offset": hex(off), "raw_hex": data[off:off + 24].hex(),
                }
        self.decoder = Cs(CS_ARCH_X86, CS_MODE_64)
        self.decoder.detail = True

    def offset(self, address, size):
        found = [s for s in self.sections if s["type"] != 8
                 and s["address"] <= address
                 and address + size <= s["address"] + s["size"]]
        if size < 0 or len(found) != 1:
            raise ValueError("ambiguous or unmapped file-backed range")
        section = found[0]
        return section["offset"] + address - section["address"]

    def raw(self, address, size):
        off = self.offset(address, size)
        return self.data[off:off + size]

    def record(self, address):
        length = struct.unpack("<I", self.raw(address, 4))[0] + 4
        data = self.raw(address, length)
        return {"va": hex(address), "bytes": length,
                "raw_hex": data.hex(), "sha256": digest(data)}

    def owner(self, address):
        found = [f for f in self.fdes if f["start"] <= address < f["end"]]
        if len(found) != 1:
            raise ValueError("missing or overlapping FDE owner")
        return found[0]

    def body(self, start, end):
        fde = self.owner(start)
        if fde["start"] != start or fde["end"] != end:
            raise ValueError("FDE extent mismatch")
        raw = self.raw(start, end - start)
        instructions = list(self.decoder.disasm(raw, start))
        if sum(i.size for i in instructions) != len(raw):
            raise ValueError("incomplete instruction decode")
        boundaries = {i.address for i in instructions}
        edges = []
        data_edges = []
        rows = []
        for ins in instructions:
            rows.append({"va": hex(ins.address), "hex": ins.bytes.hex(),
                         "mnemonic": ins.mnemonic, "operands": ins.op_str})
            for operand in ins.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    target = ins.address + ins.size + operand.mem.disp
                    data_edges.append({"site": hex(ins.address), "address": hex(target),
                                       "operand_width": operand.size,
                                       "relocation": self.relocations.get(target)})
            if ins.mnemonic == "call" or ins.mnemonic.startswith("j"):
                operand = ins.operands[0]
                edge = {"site": hex(ins.address), "kind": ins.mnemonic,
                        "operand": ins.op_str, "direct": operand.type == X86_OP_IMM}
                if operand.type == X86_OP_IMM:
                    target = operand.imm
                    edge["target"] = hex(target)
                    edge["inside_owner"] = start <= target < end
                    if edge["inside_owner"] and target not in boundaries:
                        raise ValueError("branch/call enters middle of instruction")
                elif operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    slot = ins.address + ins.size + operand.mem.disp
                    edge["slot"] = hex(slot)
                    edge["relocation"] = self.relocations.get(slot)
                edges.append(edge)
        return {"start": hex(start), "end": hex(end), "bytes": len(raw),
                "file_offset": hex(self.offset(start, len(raw))), "sha256": digest(raw),
                "raw_hex": raw.hex(), "fde": self.record(fde["fde"]),
                "cie": self.record(fde["cie"]),
                "lsda": hex(fde["lsda"]) if fde["lsda"] is not None else None,
                "instructions": rows, "control_edges": edges, "rip_edges": data_edges}


def collect(data, *, admitted_digest=TARGET, check_core_hashes=True):
    if digest(data) != admitted_digest:
        raise ValueError("target digest mismatch")
    image = Image(data)
    if len(image.fdes) != 121299 or len(image.cies) != 3:
        raise ValueError("FDE/CIE inventory mismatch")
    for address, expected in ANCHORS.items():
        if image.raw(address, len(bytes.fromhex(expected))).hex() != expected:
            raise ValueError(f"critical instruction changed at {address:#x}")
    for slot, target in [(0x5773298, 0x4E16030), (0x576E010, 0x54C8CB0),
                         (0x5776AE8, 0x4AD90D0)]:
        r = image.relocations.get(slot)
        if not r or r["type"] != 8 or r["symbol_index"] != 0 or int(r["addend"], 16) != target:
            raise ValueError(f"selected relocation mismatch at {slot:#x}")
    bodies = []
    for start, (end, expected) in CORES.items():
        body = image.body(start, end)
        if check_core_hashes and body["sha256"] != expected:
            raise ValueError("complete core body hash mismatch")
        body["role"] = "subject"
        bodies.append(body)
    for start, end in CONTEXT.items():
        body = image.body(start, end)
        body["role"] = "credited context / external boundary"
        bodies.append(body)
    # Drop helper has a 39-entry relative jump table. Binding it does not
    # assume ownership validity or run its allocator calls.
    table = image.raw(0x6F9758, 39 * 4)
    targets = [0x6F9758 + x[0] for x in struct.iter_unpack("<i", table)]
    if set(targets) != {0x47328D6, 0x47328DA, 0x47328EF, 0x4732919}:
        raise ValueError("drop table target mismatch")
    # Validate direct CALL encodings whose destinations equal a subject start.
    # Every hit is checked against an actual containing FDE instruction start.
    text = next(s for s in image.sections if s["name"] == ".text")
    code = data[text["offset"]:text["offset"] + text["size"]]
    incoming = []
    scan = 0
    cache = {}
    while True:
        scan = code.find(b"\xe8", scan)
        if scan < 0:
            break
        if scan + 5 <= len(code):
            site = text["address"] + scan
            target = site + 5 + struct.unpack_from("<i", code, scan + 1)[0]
            if target in CORES:
                owner = image.owner(site)
                key = (owner["start"], owner["end"])
                if key not in cache:
                    cache[key] = image.body(*key)
                rows = cache[key]["instructions"]
                hits = [r for r in rows if int(r["va"], 16) == site
                        and r["mnemonic"] == "call" and r["hex"] == code[scan:scan + 5].hex()]
                incoming.append({"site": hex(site), "target": hex(target),
                                 "instruction_confirmed": bool(hits),
                                 "owner": [hex(key[0]), hex(key[1])]})
        scan += 1
    address_relocations = [r for r in image.relocations.values()
                           if int(r["addend"], 16) in CORES and r["type"] == 8]
    return {"schema": 1, "target_sha256": digest(data), "target_bytes": len(data),
            "coordinate_system": "linked ELF VAs; ends exclusive",
            "fde_count": len(image.fdes), "cie_count": len(image.cies),
            "bodies": bodies, "direct_incoming_candidates": incoming,
            "incoming_owner_bodies": list(cache.values()),
            "subject_relative_relocations": address_relocations,
            "drop_table": {"va": "0x6f9758", "raw_hex": table.hex(),
                           "sha256": digest(table), "targets": list(map(hex, targets))},
            "limits": ["No captured execution or instruction evaluation.",
                       "FDE extents are exact unwind records, not a whole-program function census.",
                       "Complete selected instruction and direct edge census; register-indirect and scheduler effects remain explicit boundaries.",
                       "Incoming scan checks E8 direct calls only; no complete indirect reachability claim."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--target", type=Path, default=ROOT / "artifacts/node/94/hl-node")
    args = parser.parse_args()
    result = collect(args.target.read_bytes())
    encoded = (json.dumps(result, indent=2, sort_keys=True) + "\n").encode()
    if args.out:
        args.out.mkdir(parents=True, exist_ok=False)
        (args.out / "records.json").write_bytes(encoded)
    else:
        if (PACKET / "static/records.json").read_bytes() != encoded:
            raise ValueError("retained static records differ")
    print(json.dumps({"subject_bodies": len(CORES), "subject_bytes": 2144,
                      "context_bodies": len(CONTEXT), "records_sha256": digest(encoded)}))


if __name__ == "__main__":
    main()
