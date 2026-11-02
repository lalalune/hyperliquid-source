#!/usr/bin/env python3
"""Authenticate and statically export the complete two no-call native leaves."""

import argparse
import collections
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import sys

PACKET = pathlib.Path(__file__).resolve().parent
ROOT = PACKET.parents[2]
TARGET_SHA = "3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f"
NATIVE_SHA = "5f69eea007a2a9ba6b313b4040865dccba6480c004f9b730489d65b55b85972a"


class EvidenceError(ValueError):
    pass


def require(value, message):
    if not value:
        raise EvidenceError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def receipt():
    raw = (PACKET / "NATIVE-INTAKE.json").read_bytes()
    require(sha(raw) == NATIVE_SHA, "independent native receipt changed")
    return json.loads(raw)


def view_for(data):
    require(data[:6] == b"\x7fELF\x02\x01", "expected little-endian ELF64")
    require(struct.unpack_from("<H", data, 18)[0] == 62, "expected x86-64")
    offset = struct.unpack_from("<Q", data, 32)[0]
    size, count = struct.unpack_from("<HH", data, 54)
    require(size == 56 and offset + size * count <= len(data), "invalid program-header bounds")
    loads = [struct.unpack_from("<IIQQQQQQ", data, offset + size * index) for index in range(count)]
    loads = [entry for entry in loads if entry[0] == 1]

    def view(va, length, *, executable=False):
        matches = [entry for entry in loads if entry[3] <= va and va + length <= entry[3] + entry[5]]
        require(len(matches) == 1, "native range lacks unique file-backed PT_LOAD")
        require(not executable or matches[0][1] & 1, "native code mapping is not executable")
        file_offset = matches[0][2] + va - matches[0][3]
        require(file_offset + length <= len(data), "native range exceeds input")
        return data[file_offset:file_offset + length], file_offset

    return view


def rows(text):
    result = []
    for line in text.splitlines():
        match = re.fullmatch(r"\s*([0-9a-f]+):\t([0-9a-f ]+)\t(.+)", line)
        if match:
            result.append((int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()))
    return result


def validate_rows(instructions, record, code):
    position = int(record["start"], 16)
    starts = {row[0] for row in instructions}
    returns = []
    for address, raw, assembly in instructions:
        require(address == position and 1 <= len(raw) <= 15, "incomplete native instruction partition")
        offset = address - int(record["start"], 16)
        require(code[offset:offset + len(raw)] == raw, "native instruction bytes changed")
        position += len(raw)
        mnemonic = assembly.split()[0]
        require(not mnemonic.startswith("call") and "rip" not in assembly, "unexpected callee or RIP-relative data")
        if mnemonic.startswith("j"):
            require(mnemonic in {"je", "jne", "jae"}, "unexpected native branch shape")
            require(int(assembly.split()[-1], 16) in starts, "branch escapes complete instruction starts")
        if mnemonic == "ret":
            returns.append(hex(address))
    require(position == int(record["end"], 16) and len(instructions) == record["rows"], "native extent/row count changed")
    require(returns == record["returns"], "native return set changed")


def validate(data, *, require_identity=True, closure=None):
    # Only copied-real-target structural tests bypass the outer identity gate.
    # The public collector always requires the whole captured identity.
    if require_identity:
        require(len(data) == 91774280 and sha(data) == TARGET_SHA, "target identity mismatch")
    native = receipt()
    view = view_for(data)
    records = []
    for record in native["functions"]:
        start, end = int(record["start"], 16), int(record["end"], 16)
        code, file_offset = view(start, end - start, executable=True)
        require(file_offset == int(record["file_offset"], 16), "native file coordinate changed")
        require(sha(code) == record["body_sha256"], "complete native body changed: " + record["name"])
        require(code == (PACKET / "native" / (record["name"] + ".raw")).read_bytes(), "prior raw export changed")
        fde_va = int(record["fde_va"], 16)
        fde = bytes.fromhex(record["fde_raw"])
        require(view(fde_va, len(fde))[0] == fde, "FDE bytes changed")
        require(fde_va + 8 + struct.unpack_from("<i", fde, 8)[0] == start, "FDE start changed")
        require(struct.unpack_from("<I", fde, 12)[0] == len(code), "FDE range changed")
        cie_va = int(record["cie_va"], 16)
        require(fde_va + 4 - struct.unpack_from("<I", fde, 4)[0] == cie_va, "FDE/CIE link changed")
        cie = bytes.fromhex(record["cie_raw"])
        require(view(cie_va, len(cie))[0] == cie, "CIE bytes changed")
        listing = (PACKET / "native" / (record["name"] + ".objdump.txt")).read_bytes()
        require(sha(listing) == record["listing_sha256"], "independent native listing changed")
        validate_rows(rows(listing.decode()), record, code)
        records.append((record, bytes(code)))
    require(sum(len(code) for _, code in records) == 197, "complete native byte denominator changed")
    require(sum(record["rows"] for record, _ in records) == 64, "complete native row denominator changed")
    section_offset = struct.unpack_from("<Q", data, 40)[0]
    section_size, section_count = struct.unpack_from("<HH", data, 58)
    require(section_size == 64 and section_count > 0 and section_offset + section_size * section_count <= len(data), "invalid section-header bounds")
    intervals = [(int(record["start"], 16), int(record["end"], 16)) for record, _ in records]
    rela_count = 0
    rela_types = collections.Counter()
    for index in range(section_count):
        section = struct.unpack_from("<IIQQQQIIQQ", data, section_offset + index * section_size)
        require(section[1] != 9, "unsupported REL relocation section")
        if section[1] != 4:
            continue
        require(section[9] == 24 and section[5] % 24 == 0 and section[4] + section[5] <= len(data), "invalid RELA section bounds")
        for offset in range(section[4], section[4] + section[5], 24):
            relocation_offset, info = struct.unpack_from("<QQ", data, offset)
            kind = info & 0xFFFF_FFFF
            require(kind in {1, 6, 7, 8, 18}, "unsupported actual RELA type")
            require(relocation_offset <= (1 << 64) - 8, "RELA write wraps its address domain")
            require(not any(relocation_offset < end and relocation_offset + 8 > start for start, end in intervals), "relocation targets selected code")
            rela_count += 1
            rela_types[kind] += 1
    require(rela_count == 80300, "actual RELA record denominator changed")
    if closure is not None:
        closure.update({"RELA_records": rela_count, "RELA_types": dict(rela_types), "write_width": 8,
                        "REL_sections": 0, "relocation_writes_overlapping_selected_code": []})
    return records


def collect(target, output, objdump=pathlib.Path("/usr/bin/objdump")):
    require(not output.exists(), "output directory must be new")
    data = target.read_bytes()
    closure = {}
    records = validate(data, closure=closure)
    output.mkdir(parents=True)
    commands, exports = [], []
    version = subprocess.run([str(objdump), "--version"], capture_output=True, check=False)
    (output / "objdump-version.stdout").write_bytes(version.stdout)
    (output / "objdump-version.stderr").write_bytes(version.stderr)
    commands.append({"argv": [str(objdump), "--version"], "exit_code": version.returncode, "stdout_sha256": sha(version.stdout), "stderr_sha256": sha(version.stderr)})
    (output / "COMMANDS.json").write_text(json.dumps(commands, indent=2) + "\n")
    require(version.returncode == 0 and not version.stderr and version.stdout.startswith(b"GNU objdump"), "GNU objdump version failed")
    for record, code in records:
        name = record["name"]
        raw_path = output / (name + ".raw")
        raw_path.write_bytes(code)
        raw_path.chmod(0o400)
        argv = [str(objdump), "-D", "-b", "binary", "-m", "i386:x86-64", "-M", "intel", "--insn-width=16", "--adjust-vma=" + record["start"], str(raw_path)]
        result = subprocess.run(argv, capture_output=True, check=False)
        (output / (name + ".objdump.txt")).write_bytes(result.stdout)
        (output / (name + ".objdump.stderr")).write_bytes(result.stderr)
        commands.append({"argv": argv, "exit_code": result.returncode, "stdout_sha256": sha(result.stdout), "stderr_sha256": sha(result.stderr)})
        (output / "COMMANDS.json").write_text(json.dumps(commands, indent=2) + "\n")
        require(result.returncode == 0 and not result.stderr, "bounded GNU disassembly failed")
        actual_rows = rows(result.stdout.decode())
        validate_rows(actual_rows, record, code)
        prior = rows((PACKET / "native" / (name + ".objdump.txt")).read_text())
        require(actual_rows == prior, "fresh GNU instruction records differ")
        require(raw_path.read_bytes() == code, "owned native snapshot changed")
        exports.append({"name": name, "bytes": len(code), "rows": len(actual_rows), "body_sha256": sha(code), "prior_instruction_records_equal": True})
    report = {"schema": 1, "target_sha256": sha(data), "target_bytes": len(data), "native_receipt_sha256": NATIVE_SHA,
              "bytes": 197, "rows": 64, "functions": exports, "commands": commands,
              "objdump_version": version.stdout.decode().splitlines()[0], "objdump_sha256": sha(objdump.resolve().read_bytes()),
              "normalization": "none in instruction bytes/addresses/operands; only header pathname is outside the instruction-record comparison",
              "captured_execution_or_instruction_evaluator": False, "callees_or_RIP_data": [],
              "executable_PT_LOAD": True, "native_image_closure": closure}
    (output / "REPORT.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=pathlib.Path, default=ROOT / "artifacts/node/94/hl-node")
    parser.add_argument("--out", type=pathlib.Path, required=True)
    parser.add_argument("--objdump", type=pathlib.Path, default=pathlib.Path("/usr/bin/objdump"))
    args = parser.parse_args()
    try:
        result = collect(args.target, args.out.resolve(), args.objdump)
        print("PASS: 197 native bytes / 64 complete GNU rows; exact FDE/CIE; no callee or RIP-data gap")
    except (OSError, EvidenceError, struct.error, subprocess.SubprocessError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
