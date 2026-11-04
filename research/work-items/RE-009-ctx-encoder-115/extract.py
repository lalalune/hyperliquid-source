"""Digest-bound static Ctx contexts. Never executes or emulates captured code."""
from pathlib import Path
import argparse
import hashlib
import json
import mmap
import struct
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records
import capstone
from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
STARTS = [0x1628bc0, 0x162a760, 0x1680500, 0x1688a20, 0x1688c00,
          0x4d93030, 0x4e0b920, 0x4e0bdb0, 0x4e0cab0, 0x4e0da40,
          0x4e0dd00, 0x4e0f0d0, 0x526e1a0, 0x526e2b0, 0x52f0080,
          0x5307510, 0x531cfa0, 0x57ce100, 0x57ceba0, 0x57cf860,
          0x57d00b0, 0x57d0250, 0x57d0510, 0x57d0750, 0x57d08e0,
          0x57d0b20, 0x5963650, 0x5963a10, 0x635de30]


def analyze(target):
    with Path(target).open("rb") as handle:
        if hashlib.file_digest(handle, "sha256").hexdigest() != SHA:
            raise ValueError("wrong Node115 digest")
    with Path(target).open("rb") as handle, mmap.mmap(
            handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
        secs = sections(data)
        _, fdes = eh_frame_records(data)

        def offset(va, size):
            found = [s["offset"] + va - s["address"] for s in secs
                     if s["type"] != 8 and s["address"] <= va
                     and va + size <= s["address"] + s["size"]]
            if len(found) != 1:
                raise ValueError(("unbacked/ambiguous VA", hex(va), size))
            return found[0]

        engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        engine.detail = True
        records = []
        slots = {0x6405468: ["date-bounds Location.file"]}
        for add in (0, 8, 16, 24, 32):
            slots[0x64a46e0 + add] = ["String-vtable+" + hex(add)]
        for start in STARTS:
            matches = [r for r in fdes if r["start"] == start]
            if len(matches) != 1:
                raise ValueError(("FDE count", hex(start)))
            fde = matches[0]
            length = fde["end"] - start
            if not 0 < length <= 32768:
                raise ValueError("context budget")
            off = offset(start, length)
            body = data[off:off + length]
            decoded = list(engine.disasm(body, start))
            if sum(r.size for r in decoded) != length:
                raise ValueError("undecoded context bytes")
            rows = []
            for ins in decoded:
                row = {"va": hex(ins.address), "bytes": ins.bytes.hex(),
                       "mnemonic": ins.mnemonic, "operands": ins.op_str}
                refs = []
                for op in ins.operands:
                    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                        va = ins.address + ins.size + op.mem.disp
                        ref = {"va": hex(va)}
                        try:
                            pos = offset(va, 32)
                            ref["raw32"] = data[pos:pos + 32].hex()
                        except ValueError:
                            ref["unbacked32"] = True
                        refs.append(ref)
                        if ins.mnemonic in ("call", "mov"):
                            slots.setdefault(va, []).append(hex(ins.address))
                if refs:
                    row["ripReferences"] = refs
                if ins.mnemonic == "call" and ins.operands[0].type == X86_OP_IMM:
                    row["directCall"] = hex(ins.operands[0].imm)
                rows.append(row)
            records.append({"start": hex(start), "end": hex(fde["end"]),
                            "fde": hex(fde["fde"]), "fileOffset": hex(off),
                            "size": length, "sha256": hashlib.sha256(body).hexdigest(),
                            "instructionCount": len(rows), "instructions": rows})
        rela = next(s for s in secs if s["name"] == ".rela.dyn")
        dynsym = next(s for s in secs if s["name"] == ".dynsym")
        dynstr = next(s for s in secs if s["name"] == ".dynstr")
        rels = {}
        for pos in range(rela["offset"], rela["offset"] + rela["size"], 24):
            dest, info, addend = struct.unpack_from("<QQq", data, pos)
            if dest in slots:
                if dest in rels:
                    raise ValueError("duplicate relocation")
                rels[dest] = (pos, info, addend)
        bindings = []
        for va, sites in sorted(slots.items()):
            off = offset(va, 8)
            row = {"slot": hex(va), "fileOffset": hex(off),
                   "raw": data[off:off + 8].hex(), "sites": sites}
            if va in rels:
                pos, info, addend = rels[va]
                row.update(relocationFileOffset=hex(pos), relocationType=info & 0xffffffff,
                           symbolIndex=info >> 32, addend=hex(addend),
                           relocationRaw=data[pos:pos + 24].hex())
                if info >> 32:
                    sym = info >> 32
                    name = struct.unpack_from("<I", data, dynsym["offset"] + sym * 24)[0]
                    a = dynstr["offset"] + name
                    b = data.find(b"\0", a, dynstr["offset"] + dynstr["size"])
                    if b < a:
                        raise ValueError("dynamic symbol string")
                    row["symbol"] = data[a:b].decode("ascii")
                if info & 0xffffffff == 8:
                    row["targetFdes"] = [
                        {"start": hex(f["start"]), "end": hex(f["end"])}
                        for f in fdes if f["start"] == addend]
                    if va == 0x6405468:
                        size = struct.unpack_from("<Q", data, offset(va + 8, 8))[0]
                        if size > 512:
                            raise ValueError("source path budget")
                        pos = offset(addend, size)
                        row["sourceFilename"] = data[pos:pos + size].decode("utf-8")
            bindings.append(row)
        saved_data = []
        for va, size, label in [(0x46bfcb, 733, "ordinal-month-delta"),
                                (0x46ea12, 200, "decimal-digit-pairs"),
                                (0x459860, 8, "signed-year-format"),
                                (0x46c7a4, 10, "fraction3-format"),
                                (0x46c7ae, 10, "fraction6-format"),
                                (0x46c7b8, 10, "fraction9-format")]:
            off = offset(va, size)
            raw = data[off:off + size]
            saved_data.append({"va": hex(va), "fileOffset": hex(off), "label": label,
                               "size": size, "sha256": hashlib.sha256(raw).hexdigest(),
                               "rawHex": raw.hex()})
        return {"targetSha256": SHA, "capstone": capstone.__version__,
                "coordinateSystem": "original ELF virtual addresses; file offsets recorded",
                "rangeInterpretation": "actual unwind FDE contexts, not asserted Rust source boundaries",
                "records": records, "bindings": bindings, "data": saved_data,
                "capturedCodeExecuted": False, "capturedCodeEmulated": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.target)
    args.out.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"contexts": len(result["records"]),
                      "bytes": sum(x["size"] for x in result["records"]),
                      "instructions": sum(x["instructionCount"] for x in result["records"])}))
