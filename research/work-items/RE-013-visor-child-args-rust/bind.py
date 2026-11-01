#!/usr/bin/env python3
"""Read-only static admission; no captured execution or instruction evaluator.

New MIT code. Prior proofs/exports are referenced by hashes, not copied.
The native providers decode bytes; this script checks identity and coordinates.
"""

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_json(path):
    return json.loads(path.read_text())


def write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


class Image:
    def __init__(self, data):
        self.data = data
        require(data[:6] == b"\x7fELF\x02\x01", "expected ELF64 little endian")
        require(struct.unpack_from("<H", data, 18)[0] == 62, "expected x86-64")
        phoff, shoff = struct.unpack_from("<QQ", data, 32)
        phsize, phcount, shsize, shcount, names = struct.unpack_from("<HHHHH", data, 54)
        require(phsize == 56 and shsize == 64, "unexpected header stride")
        require(phoff + phsize * phcount <= len(data), "truncated program headers")
        require(shoff + shsize * shcount <= len(data), "truncated section headers")
        self.loads = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * phsize)
                      for i in range(phcount)]
        headers = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shsize)
                   for i in range(shcount)]
        require(names < shcount, "bad section name index")
        name_header = headers[names]
        table = self.file(name_header[4], name_header[5])
        self.sections = {}
        for h in headers:
            require(h[0] < len(table), "bad section name")
            end = table.find(b"\0", h[0])
            require(end >= 0, "unterminated section name")
            name = table[h[0]:end].decode("ascii")
            require(name not in self.sections, "duplicate section name")
            self.sections[name] = h

    def file(self, offset, length):
        require(0 <= offset <= offset + length <= len(self.data), "file bounds")
        return self.data[offset:offset + length]

    def offset(self, address, length):
        hits = [h for h in self.loads if h[0] == 1 and
                h[3] <= address <= address + length <= h[3] + h[5]]
        require(len(hits) == 1, "ambiguous/unbacked VA range")
        return hits[0][2] + address - hits[0][3]

    def at(self, address, length):
        return self.file(self.offset(address, length), length)

    def record(self, address):
        length = struct.unpack("<I", self.at(address, 4))[0]
        require(0 < length < 0xffffffff, "unsupported DWARF record")
        return self.at(address, 4 + length)


def admit_image(data, target):
    require(len(data) == target["bytes"] and sha(data) == target["sha256"],
            "target identity differs")
    return Image(data)


def authenticate(repo, pins):
    path = repo / pins["target"]["path"]
    image = admit_image(path.read_bytes(), pins["target"])
    for entry in pins["prior_files"]:
        raw = (repo / entry["path"]).read_bytes()
        require(len(raw) == entry["bytes"] and sha(raw) == entry["sha256"],
                "credited input differs: " + entry["path"])
    return image


def native(command, cwd):
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=True)
    require(not result.stderr, "unexpected native stderr")
    return result.stdout


def rows(text, image, start, end):
    found = []
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}[ \t]+)+)(\S.*)$", line)
        if m:
            found.append((int(m[1], 16), bytes.fromhex(m[2])))
    cursor = start
    for address, raw in found:
        require(address == cursor, f"native rows do not tile: expected{cursor:#x}, observed{address:#x}")
        require(raw == image.at(address, len(raw)), "native row differs from capture")
        cursor += len(raw)
    require(cursor == end, "incomplete native body")
    return [(a, b.hex()) for a, b in found]


def derive(image, pins, frames):
    eh = image.sections[".eh_frame"]
    ranges = []
    for p in pins["ranges"]:
        start, end = int(p["va"], 16), int(p["end"], 16)
        raw = image.at(start, end - start)
        require(len(raw) == p["bytes"] and sha(raw) == p["sha256"], "body identity differs")
        pattern = (r"^([0-9a-f]+)\s+[0-9a-f]+\s+[0-9a-f]+ FDE cie=([0-9a-f]+) "
                   r"pc=" + f"{start:016x}" + r"\.\." + f"{end:016x}" + r"$")
        matches = list(re.finditer(pattern, frames, re.MULTILINE))
        require(len(matches) == 1, "FDE range absent/duplicated")
        m = matches[0]
        fde = eh[3] + int(m[1], 16)
        cie = eh[3] + int(m[2], 16)
        require(fde == int(p["fde_va"], 16), "FDE coordinate differs")
        if "cie_va" in p:
            require(cie == int(p["cie_va"], 16), "CIE coordinate differs")
        fraw, craw = image.record(fde), image.record(cie)
        require(fde + 4 - struct.unpack_from("<I", fraw, 4)[0] == cie, "CIE reference differs")
        # This capture's admitted CIEs use signed32 PC-relative FDE locations.
        require(fde + 8 + struct.unpack_from("<i", fraw, 8)[0] == start, "FDE start differs")
        require(struct.unpack_from("<I", fraw, 12)[0] == end - start, "FDE size differs")
        ranges.append(dict(p, file_offset=hex(image.offset(start, end - start)),
                           fde_raw=fraw.hex(), cie_va=hex(cie), cie_raw=craw.hex(),
                           readelf_line=m[0]))
    relas = []
    for slot_text, expected in pins["used_slots"].items():
        slot, hits = int(slot_text, 16), []
        for h in image.sections.values():
            if h[1] != 4:
                continue
            require(h[9] == 24 and h[5] % 24 == 0, "invalid RELA stride")
            for off in range(h[4], h[4] + h[5], 24):
                raw = image.file(off, 24)
                where, info, addend = struct.unpack("<QQq", raw)
                if where == slot:
                    hits.append((off, info & 0xffffffff, info >> 32, addend, raw))
        require(len(hits) == 1, "selected RELA absent/duplicated")
        off, kind, symbol, addend, raw = hits[0]
        require([kind, symbol, hex(addend)] == expected, "selected binding differs")
        relas.append(dict(slot=slot_text, file_offset=off, type=kind, symbol=symbol,
                          addend=hex(addend), raw=raw.hex()))
    symtab, strings = image.sections[".dynsym"], image.sections[".dynstr"]
    require(symtab[9] == 24, "invalid dynamic symbol stride")
    sym = image.file(symtab[4] + 6 * 24, 24)
    name_offset, info, other, section, value, size = struct.unpack("<IBBHQQ", sym)
    table = image.file(strings[4], strings[5])
    end = table.find(b"\0", name_offset)
    require(end >= name_offset and table[name_offset:end] == b"memcpy" and section == 0,
            "copy symbol differs")
    lead = image.at(int(pins["lead_table"]["va"], 16), 256)
    require(sha(lead) == pins["lead_table"]["sha256"], "lead table differs")
    return dict(target=pins["target"], ranges=ranges, relas=relas,
                copy_symbol=dict(index=6, name="memcpy", raw=sym.hex(), undefined=True),
                lead_table=dict(pins["lead_table"], hex=lead.hex()),
                caller_corridor=dict(start="0x5b920a", end="0x5b925a",
                                     raw=image.at(0x5b920a, 0x50).hex()),
                child_name=dict(va="0xb72d3", hex=image.at(0xb72d3, 10).hex()),
                scope="Integrity/coordinate binding only; conditional semantics credited to prior full proofs. No target execution.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--gnu", default="/opt/homebrew/opt/binutils/bin/objdump")
    parser.add_argument("--readelf", default="/opt/homebrew/opt/binutils/bin/readelf")
    parser.add_argument("--llvm", default="/usr/bin/objdump")
    args = parser.parse_args()
    pins = read_json(HERE / "BASIS-PINS.json")
    image = authenticate(args.repo, pins)
    frames = native([args.readelf, "--debug-dump=frames", pins["target"]["path"]], args.repo)
    observed = derive(image, pins, frames)
    args.out.mkdir(parents=True, exist_ok=False)
    providers = {}
    for name, binary in [("gnu", args.gnu), ("llvm", args.llvm), ("readelf", args.readelf)]:
        resolved = Path(binary).resolve()
        providers[name] = dict(command=binary, sha256=sha(resolved.read_bytes()),
                               version=native([binary, "--version"], args.repo).strip())
    for body in observed["ranges"]:
        a, z = int(body["va"], 16), int(body["end"], 16)
        gcmd = [args.gnu, "-d", "-Mintel", "--insn-width=16", f"--start-address={hex(a)}",
                f"--stop-address={hex(z)}", pins["target"]["path"]]
        lcmd = [args.llvm, "--disassemble", "--x86-asm-syntax=intel", f"--start-address={hex(a)}",
                f"--stop-address={hex(z)}", pins["target"]["path"]]
        gtxt, ltxt = native(gcmd, args.repo), native(lcmd, args.repo)
        grows, lrows = rows(gtxt, image, a, z), rows(ltxt, image, a, z)
        require(grows == lrows, "independent native partitions differ")
        if "rows" in body:
            require(len(grows) == body["rows"], "row count differs")
        body["rows"] = len(grows)
        body["gnu"] = dict(command=gcmd, stdout_sha256=sha(gtxt.encode()))
        body["llvm"] = dict(command=lcmd, stdout_sha256=sha(ltxt.encode()))
        # Complete GNU exports already exist among pinned credited files.
        # Retain one fresh complete independent LLVM export, not duplicate dumps.
        (args.out / (body["name"] + ".llvm.txt.gz")).write_bytes(gzip.compress(ltxt.encode(), mtime=0))
    observed["providers"] = providers
    observed["credited_files"] = pins["prior_files"]
    write_json(args.out / "basis.json", observed)
    print(json.dumps(dict(bodies=len(observed["ranges"]),
                          rows=sum(x["rows"] for x in observed["ranges"]),
                          bytes=sum(x["bytes"] for x in observed["ranges"]),
                          status="PASS: static identity and partitions only")))


if __name__ == "__main__":
    main()
