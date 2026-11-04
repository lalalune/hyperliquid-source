#!/usr/bin/env python3
"""Reproduce this packet's Node115 static bindings; never execute the ELF."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tools"))
from elf_index import sections
from fde_extents import eh_frame_records

def require(condition, message):
    if not condition:
        raise ValueError(message)

def offset(secs, va, size=1):
    matches = [s["offset"] + va - s["address"] for s in secs
               if s["type"] != 8 and s["address"] <= va
               and va + size <= s["address"] + s["size"]]
    require(len(matches) == 1, "ambiguous/unmapped VA " + hex(va))
    return matches[0]

def pin_checks(data, secs, pins):
    for p in pins:
        want = bytes.fromhex(p["bytes"])
        off = offset(secs, int(p["address"], 16), len(want))
        require(data[off:off + len(want)] == want, "instruction pin: " + p["label"])

def bindings(data, spec):
    require(hashlib.sha256(data).hexdigest() == spec["targetSha256"], "target digest")
    secs = sections(data)
    _, fdes = eh_frame_records(data, secs)
    for row in spec["ranges"]:
        start, end = int(row["start"], 16), int(row["end"], 16)
        found = [f for f in fdes if f["start"] == start and f["end"] == end]
        require(len(found) == 1, "FDE extent " + row["start"])
        off = offset(secs, start, end - start)
        require(hashlib.sha256(data[off:off + end - start]).hexdigest() == row["sha256"],
                "body digest " + row["start"])
    pin_checks(data, secs, spec["pins"])
    rela = next(s for s in secs if s["name"] == ".rela.dyn")
    relocs = {}
    for off in range(rela["offset"], rela["offset"] + rela["size"], 24):
        slot, info, addend = struct.unpack_from("<QQq", data, off)
        relocs[slot] = (info & 0xffffffff, info >> 32, addend)
    require(relocs[0x64e6a98] == (8, 0, 0x4d3e1a0), "stake predicate relocation")
    require(relocs[0x64e4df8] == (8, 0, 0x4f3cef0), "long sort relocation")
    require(relocs[0x64dfb50][:2] == (6, 12), "memcmp relocation")
    dynsym = next(s for s in secs if s["name"] == ".dynsym")
    dynstr = next(s for s in secs if s["name"] == ".dynstr")
    nameoff = struct.unpack_from("<I", data, dynsym["offset"] + 12 * 24)[0]
    pos = dynstr["offset"] + nameoff
    require(data[pos:data.index(b"\0", pos)] == b"memcmp", "memcmp symbol")
    constants = [(0x451210, "0000304300003045"),
                 (0x450170, "00000000000030430000000000003045")]
    for va, hexbytes in constants:
        want = bytes.fromhex(hexbytes)
        off = offset(secs, va, len(want))
        require(data[off:off + len(want)] == want, "unsigned conversion constants")
    return secs, fdes, constants

def controls(data, secs, spec):
    # Bypass whole-file/body digest checks deliberately: these challenge actual
    # semantic instruction pins, rather than merely rediscovering a hash mismatch.
    labels = ["second-field", "first-failure-branch", "count-call",
              "ordered-zero-branch", "strict-greater"]
    results = []
    for label in labels:
        p = next(p for p in spec["pins"] if p["label"] == label)
        off = offset(secs, int(p["address"], 16), len(bytes.fromhex(p["bytes"])))
        changed = bytearray(data)
        changed[off + len(bytes.fromhex(p["bytes"])) - 1] ^= 1
        try:
            pin_checks(changed, secs, spec["pins"])
        except ValueError as exc:
            require(str(exc) == "instruction pin: " + label, "wrong rejection reason")
            results.append({"changed": label, "rejectedBy": str(exc),
                            "digestChecksBypassed": True})
        else:
            raise ValueError("accepted corrupt control " + label)
    return results

def export(data, secs, fdes, spec, target_arg, out, objdump):
    import capstone
    out.mkdir(parents=True, exist_ok=True)
    report = []
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    decoder.detail = True
    for row in spec["ranges"]:
        start, end = int(row["start"], 16), int(row["end"], 16)
        off = offset(secs, start, end-start)
        blob = data[off:off+end-start]
        decoded = list(decoder.disasm(blob, start))
        cursor = start
        for ins in decoded:
            require(ins.address == cursor, "Capstone gap")
            cursor += ins.size
        require(cursor == end and len(decoded) == row["instructionCount"],
                "Capstone denominator")
        command = [objdump, "-d", "-Mintel", "--insn-width=16",
                   "--start-address=" + hex(start), "--stop-address=" + hex(end),
                   target_arg]
        result = subprocess.run(command, cwd=ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=90)
        stem = hex(start)[2:]
        (out / (stem + ".objdump")).write_bytes(result.stdout)
        (out / (stem + ".stderr")).write_bytes(result.stderr)
        require(result.returncode == 0, "GNU objdump failure")
        gnu = []
        for line in result.stdout.decode("utf-8").splitlines():
            m = re.match(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)", line)
            if m:
                gnu.append((int(m.group(1), 16), bytes.fromhex(m.group(2))))
        require(gnu == [(i.address, bytes(i.bytes)) for i in decoded],
                "GNU/Capstone byte partition")
        insns = [{"address":hex(i.address), "bytes":i.bytes.hex(),
                  "mnemonic":i.mnemonic, "operands":i.op_str} for i in decoded]
        fde = next(f for f in fdes if f["start"] == start and f["end"] == end)
        body = dict(row, fileOffset=hex(off), fde=fde, instructions=insns)
        (out / (stem + ".json")).write_text(json.dumps(body, indent=2)+"\n")
        report.append(dict(row, gnuCapstonePartitionsEqual=True))
    return report

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="artifacts/node/115/hl-node")
    parser.add_argument("--export", type=Path)
    parser.add_argument("--objdump", default="objdump")
    args = parser.parse_args()
    spec = json.loads((PACKET / "bindings.json").read_text())
    target = Path(args.target)
    if not target.is_absolute():
        target = ROOT / target
    data = target.read_bytes()
    secs, fdes, constants = bindings(data, spec)
    negatives = controls(data, secs, spec)
    report = {"targetSha256":spec["targetSha256"], "targetExecuted":False,
              "fdeRanges":len(spec["ranges"]),
              "bytes":sum(r["size"] for r in spec["ranges"]),
              "instructionPins":len(spec["pins"]), "controls":negatives,
              "constants":[{"va":hex(va),"bytes":b} for va,b in constants],
              "limits":"Static evidence bindings, not native/Rust machine-code comparison. "
                       "Shared owners are not new coverage; helper/ABI/runtime gaps remain."}
    if args.export:
        report["ranges"] = export(data, secs, fdes, spec, args.target,
                                  args.export, args.objdump)
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
