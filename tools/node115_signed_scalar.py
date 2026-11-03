"""Bind one Node115 signed-scalar family to native bytes; never execute the capture."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
PACKET = ROOT / "research/work-items/RE-005-node115-signed-scalar"
FUNCTIONS = (
    (0x2935ae0, 357, "a0df652992ddf903932f898c228eb1bd57544e15e8d1a12af1d009f1c0f3a0bf"),
    (0x5659e00, 357, "3aaddb4b9d8b89247ea59d361217a9694f9690919d3274dc3e435a38b11c8bca"),
    (0x58225c0, 316, "f539a558803ddc4d700e9ca5a560a716d2906d2e530bcdf536c1fe6619e45721"),
    (0x5822700, 14, "e9c285d5d073c7afed38f1407c356d1bbd68f7d91948f2527ca58b5c55e64841"),
)
SLOTS = {0x64e6c38: 0x58225c0, 0x64e6c40: 0x5822700, 0x64e7f78: 0x5822700}
TABLES = {
    0x5fdc8c: "a07e3302d57e3302be7e3302247f3302",
    0x928918: "3415d3046915d3045215d304b815d304",
    0x935c24: "03caee041dcaee0410caee04a8caee04",
}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def image(blob):
    need(hashlib.sha256(blob).hexdigest() == SHA, "Node115 identity mismatch")
    secs = sections(blob)
    need(len({s["name"] for s in secs}) == len(secs), "duplicate section")
    def read(va, size):
        matches = [s for s in secs if s["type"] != 8 and s["flags"] & 2
                   and s["address"] <= va and va + size <= s["address"] + s["size"]]
        need(len(matches) == 1, "ambiguous/outside VA range")
        off = matches[0]["offset"] + va - matches[0]["address"]
        return blob[off:off + size]
    return secs, read


def analyze(blob):
    secs, read = image(blob)
    _, fdes = eh_frame_records(blob, secs)
    records = []
    for start, size, digest in FUNCTIONS:
        need(sum(f["start"] == start and f["end"] == start + size for f in fdes) == 1,
             "FDE extent mismatch")
        need(hashlib.sha256(read(start, size)).hexdigest() == digest, "body mismatch")
        records.append({"start": hex(start), "end": hex(start + size),
                        "size": size, "sha256": digest})
    rel = next(s for s in secs if s["name"] == ".rela.dyn")
    found = {}
    for off in range(rel["offset"], rel["offset"] + rel["size"], 24):
        slot, info, addend = struct.unpack_from("<QQq", blob, off)
        if slot in SLOTS:
            need(info & 0xffffffff == 8 and slot not in found, "relative slot ambiguity")
            found[slot] = addend
    need(found == SLOTS, "helper relocation mismatch")
    tables = []
    for base, expected in TABLES.items():
        raw = read(base, 16)
        need(raw.hex() == expected, "jump table mismatch")
        tables.append({"base": hex(base), "raw": raw.hex(),
                       "destinations": [hex(base + x) for x in struct.unpack("<iiii", raw)]})
    return {"targetSha256": SHA, "coordinate": "linked ELF VA before load bias",
            "functions": records, "relativeSlots": {hex(k): hex(v) for k, v in SLOTS.items()},
            "jumpTables": tables, "targetExecuted": False}


def verify_rows(raw, start, rows):
    cursor = 0
    for address, code in rows:
        need(code and len(code) <= 15 and address == start + cursor, "row gap/overlap")
        need(raw[cursor:cursor + len(code)] == code, "row bytes differ from target")
        cursor += len(code)
    need(cursor == len(raw), "incomplete rows")


def capstone_rows(text):
    rows = []
    for line in text.splitlines():
        fields = line.split("\t")
        need(len(fields) == 4, "Capstone row fields")
        rows.append((int(fields[0], 16), bytes.fromhex(fields[1])))
    return rows


def gnu_rows(text):
    rows = []
    for line in text.splitlines():
        match = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(\S.*)?$", line)
        if match:
            rows.append((int(match[1], 16), bytes.fromhex(match[2])))
    return rows


def verify(binary, packet=PACKET):
    blob = Path(binary).read_bytes()
    records = analyze(blob)
    need(json.loads((packet / "records.json").read_text()) == records, "records differ")
    _, read = image(blob)
    counts = []
    for start, size, _ in FUNCTIONS:
        cap = capstone_rows((packet / f"{start:x}.capstone.tsv").read_text())
        gnu = gnu_rows((packet / f"{start:x}.gnu.txt").read_text())
        verify_rows(read(start, size), start, cap)
        verify_rows(read(start, size), start, gnu)
        need(cap == gnu, "independent decoder rows differ")
        counts.append(len(cap))
    need(counts == [99, 99, 95, 5], "instruction denominator differs")
    return {"functions": 4, "bytes": 1044, "rows": sum(counts), "rawEqualRows": True,
            "targetExecuted": False}


def collect(binary, packet, objdump):
    import capstone
    blob = Path(binary).read_bytes()
    records = analyze(blob)
    _, read = image(blob)
    packet.mkdir(parents=True, exist_ok=False)
    cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    for start, size, _ in FUNCTIONS:
        instructions = list(cs.disasm(read(start, size), start))
        text = "\n".join(f"{x.address:x}\t{x.bytes.hex()}\t{x.mnemonic}\t{x.op_str}"
                         for x in instructions) + "\n"
        result = subprocess.run([str(objdump), "-d", "-w", "--insn-width=16",
                                 f"--start-address={start}", f"--stop-address={start+size}",
                                 str(binary)], capture_output=True, timeout=40)
        need(result.returncode == 0, "GNU disassembler failed")
        (packet / f"{start:x}.gnu.txt").write_bytes(result.stdout)
        (packet / f"{start:x}.capstone.tsv").write_text(text, encoding="utf-8")
    (packet / "records.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    return verify(binary, packet)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "artifacts/node/115/hl-node")
    parser.add_argument("--packet", type=Path, default=PACKET)
    parser.add_argument("--collect", action="store_true")
    parser.add_argument("--objdump", type=Path)
    args = parser.parse_args()
    if args.collect:
        need(args.objdump is not None, "--collect requires explicit --objdump")
        result = collect(args.binary, args.packet, args.objdump)
    else:
        result = verify(args.binary, args.packet)
    print(json.dumps(result, sort_keys=True))
