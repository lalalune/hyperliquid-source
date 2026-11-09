#!/usr/bin/env python3
"""Re-derive one node #115 direct-call neighborhood from the pinned ELF."""
import hashlib
import json
import mmap
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
TARGET = ROOT / "artifacts/node/115/hl-node"
TARGET_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
TARGET_SIZE = 105_896_032
TEXT_VA = 0x1419300
TEXT_OFFSET = 0x1418300
TEXT_SIZE = 0x4FD7700
FUNCTION = 0x3A7D0D0
LEGACY_PREFIXES = {0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65, 0x66, 0x67}


def run(args, cwd=None):
    result = subprocess.run(args, check=False, text=True, capture_output=True, cwd=cwd)
    if result.returncode:
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(args)}\n{result.stderr}")
    return result.stdout


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def body_bytes(start, end):
    with TARGET.open("rb") as source:
        source.seek(TEXT_OFFSET + start - TEXT_VA)
        body = source.read(end - start)
    if len(body) != end - start:
        raise AssertionError(f"short target read for {start:x}..{end:x}")
    return body


def fde_rows():
    rows = []
    for line in run(["readelf", "--wide", "--debug-dump=frames", str(TARGET)]).splitlines():
        if "FDE cie=" not in line:
            continue
        match = re.search(r"pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)", line)
        if not match:
            raise AssertionError(f"FDE without a parseable PC range: {line}")
        rows.append((int(match[1], 16), int(match[2], 16), line.rstrip()))
    rows.sort()
    starts = [row[0] for row in rows]
    if len(starts) != len(set(starts)):
        raise AssertionError("duplicate FDE starts make ownership ambiguous")
    for previous, current in zip(rows, rows[1:]):
        if current[0] < previous[1]:
            raise AssertionError(f"overlapping FDEs make ownership ambiguous: {previous}, {current}")
    return rows


def section_coordinates(name):
    for line in run(["readelf", "--wide", "--section-headers", str(TARGET)]).splitlines():
        fields = line.split()
        if name in fields:
            index = fields.index(name)
            return tuple(int(fields[index + offset], 16) for offset in (2, 3, 4))
    raise AssertionError(f"{name} section is missing")


def text_section():
    result = section_coordinates(".text")
    if result != (TEXT_VA, TEXT_OFFSET, TEXT_SIZE):
        raise AssertionError(f"unexpected .text coordinates: {result}")
    return result


def find_fde(rows, starts, address):
    low, high = 0, len(starts)
    while low < high:
        middle = (low + high) // 2
        if starts[middle] <= address:
            low = middle + 1
        else:
            high = middle
    index = low - 1
    if index >= 0 and address < rows[index][1]:
        return rows[index]
    return None


def disassembly(start, end):
    return run([
        "objdump", "-d", f"--start-address=0x{start:x}",
        f"--stop-address=0x{end:x}", str(TARGET.relative_to(ROOT)),
    ], cwd=ROOT)


def instruction_rows(text):
    result = []
    for line in text.splitlines():
        address_text, separator, rest = line.strip().partition(":")
        if not separator or not address_text or any(char not in "0123456789abcdefABCDEF" for char in address_text):
            continue
        columns = rest.split("\t")
        if len(columns) < 3:
            continue
        try:
            encoded = bytes(int(token, 16) for token in columns[1].split())
        except ValueError:
            continue
        assembly = columns[2].strip()
        if assembly:
            result.append((int(address_text, 16), encoded, assembly))
    return result


def relocation_rows():
    output = run(["readelf", "--wide", "--relocs", str(TARGET)])
    rows = {}
    for line in output.splitlines():
        match = re.match(r"\s*([0-9a-fA-F]+)\s+\S+\s+(R_X86_64_RELATIVE)\s+([0-9a-fA-F]+)", line)
        if match:
            rows[int(match[1], 16)] = (match[2], int(match[3], 16), line.rstrip())
    return rows


def jump_slot_rows():
    output = run(["readelf", "--wide", "--relocs", str(TARGET)])
    rows = {}
    for line in output.splitlines():
        match = re.match(
            r"\s*([0-9a-fA-F]+)\s+\S+\s+(R_X86_64_JUMP_SLOT)\s+\S+\s+(\S+)",
            line,
        )
        if match:
            rows[int(match[1], 16)] = (match[2], match[3], line.rstrip())
    return rows


def ranges_and_hashes(rows, starts, addresses):
    mapped = {}
    for address in sorted(set(addresses)):
        row = find_fde(rows, starts, address)
        if row is None:
            mapped[hex(address)] = None
            continue
        start, end, _ = row
        body = body_bytes(start, end)
        mapped[hex(address)] = {
            "range": [hex(start), hex(end)],
            "sha256": sha256_bytes(body),
        }
    return mapped


def derive():
    if TARGET.stat().st_size != TARGET_SIZE or sha256_file(TARGET) != TARGET_SHA256:
        raise AssertionError("target identity mismatch")
    text_section()
    rows = fde_rows()
    starts = [row[0] for row in rows]
    root = find_fde(rows, starts, FUNCTION)
    if root is None or root[0] != FUNCTION:
        raise AssertionError("selected FDE is missing or does not start at the requested address")
    text_range = (TEXT_VA, TEXT_VA + TEXT_SIZE)
    if not text_range[0] <= root[0] < root[1] <= text_range[1]:
        raise AssertionError("selected FDE escapes the authenticated .text section")

    fdes_needed = {root[0]: root}
    direct_outgoing = []
    indirect_outgoing = []
    unresolved_indirect = []
    relocations = relocation_rows()
    root_disasm = disassembly(root[0], root[1])
    for address, encoded, assembly in instruction_rows(root_disasm):
        fields = assembly.split(None, 1)
        if not fields or not fields[0].startswith("call") or len(fields) != 2:
            continue
        operand = fields[1].strip()
        if not operand.startswith("*"):
            target_text = operand.split()[0]
            try:
                target = int(target_text, 16)
            except ValueError as error:
                raise AssertionError(f"cannot parse direct-call target at {address:x}: {assembly}") from error
            owner = find_fde(rows, starts, target)
            if owner is not None:
                fdes_needed[owner[0]] = owner
            direct_outgoing.append({
                "site": hex(address),
                "bytes": encoded.hex(),
                "target": hex(target),
                "target_label": re.search(r"<([^>]+)>", operand).group(1)
                    if re.search(r"<([^>]+)>", operand) else None,
                "target_fde": [hex(owner[0]), hex(owner[1])] if owner else None,
                "target_sha256": sha256_bytes(body_bytes(owner[0], owner[1])) if owner else None,
            })
            continue

        if len(encoded) == 6 and encoded[:2] == b"\xff\x15":
            displacement = int.from_bytes(encoded[2:6], "little", signed=True)
            slot = address + len(encoded) + displacement
            relocation = relocations.get(slot)
            addend = relocation[1] if relocation else None
            owner = find_fde(rows, starts, addend) if addend is not None else None
            if owner is not None:
                fdes_needed[owner[0]] = owner
            indirect_outgoing.append({
                "site": hex(address),
                "bytes": encoded.hex(),
                "slot": hex(slot),
                "relocation_type": relocation[0] if relocation else None,
                "addend": hex(addend) if addend is not None else None,
                "target_fde": [hex(owner[0]), hex(owner[1])] if owner else None,
                "target_sha256": sha256_bytes(body_bytes(owner[0], owner[1])) if owner else None,
            })
        else:
            unresolved_indirect.append({"site": hex(address), "bytes": encoded.hex(), "assembly": assembly})

    raw_candidates = []
    raw_near_miss = []
    incoming = []
    unowned = []
    not_call_boundaries = []
    with TARGET.open("rb") as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        cursor = TEXT_OFFSET
        text_end_offset = TEXT_OFFSET + TEXT_SIZE
        while True:
            position = data.find(b"\xe8", cursor, text_end_offset - 4)
            if position < 0:
                break
            displacement = int.from_bytes(data[position + 1 : position + 5], "little", signed=True)
            max_prefixes = min(10, position - TEXT_OFFSET)
            for prefix_length in range(max_prefixes + 1):
                instruction_offset = position - prefix_length
                prefix = data[instruction_offset:position]
                if any(byte not in LEGACY_PREFIXES and not 0x40 <= byte <= 0x4F for byte in prefix):
                    break
                site = TEXT_VA + instruction_offset - TEXT_OFFSET
                destination = site + prefix_length + 5 + displacement
                if destination != FUNCTION and destination != FUNCTION + 1:
                    continue
                encoded = data[instruction_offset : position + 5]
                if destination == FUNCTION + 1:
                    raw_near_miss.append(hex(site))
                    continue
                raw_candidates.append(site)
                owner = find_fde(rows, starts, site)
                if owner is None:
                    unowned.append(hex(site))
                    continue
                owner_start, owner_end, _ = owner
                caller_disasm = disassembly(owner_start, owner_end)
                matched = [
                    (addr, opbytes, asm)
                    for addr, opbytes, asm in instruction_rows(caller_disasm)
                    if addr == site and asm.startswith("call ")
                ]
                decoded_target = None
                if len(matched) == 1:
                    operand = matched[0][2].split(None, 1)[1].split()[0]
                    try:
                        decoded_target = int(operand, 16)
                    except ValueError:
                        pass
                if decoded_target == FUNCTION and len(matched[0][1]) == len(encoded) and matched[0][1] == encoded:
                    body = body_bytes(owner_start, owner_end)
                    incoming.append({
                        "site": hex(site),
                        "bytes": encoded.hex(),
                        "caller_fde": [hex(owner_start), hex(owner_end)],
                        "caller_sha256": sha256_bytes(body),
                    })
                    fdes_needed[owner_start] = owner
                else:
                    not_call_boundaries.append(hex(site))
            cursor = position + 1

    incoming.sort(key=lambda item: int(item["site"], 16))
    direct_outgoing.sort(key=lambda item: int(item["site"], 16))
    indirect_outgoing.sort(key=lambda item: int(item["site"], 16))
    slots = sorted({int(item["slot"], 16) for item in indirect_outgoing})
    missing_relocations = [hex(slot) for slot in slots if slot not in relocations]
    if missing_relocations:
        raise AssertionError(f"RIP-relative call slots lack authenticated relative relocations: {missing_relocations}")

    targets = [int(item["target"], 16) for item in direct_outgoing]
    targets.extend(int(item["addend"], 16) for item in indirect_outgoing)
    mapped_targets = ranges_and_hashes(rows, starts, targets)
    for address in targets:
        owner = find_fde(rows, starts, address)
        if owner is not None:
            fdes_needed[owner[0]] = owner

    direct_targets = {item["target"] for item in direct_outgoing}
    direct_targets_with_fdes = {item["target"] for item in direct_outgoing if item["target_fde"] is not None}
    direct_targets_without_fdes = [item for item in direct_outgoing if item["target_fde"] is None]
    indirect_slots = {item["slot"] for item in indirect_outgoing}
    indirect_addends = {item["addend"] for item in indirect_outgoing}
    plt_va, plt_offset, plt_size = section_coordinates(".plt")
    if len(direct_targets_without_fdes) != 1:
        raise AssertionError("expected one direct destination without an FDE")
    plt_target = int(direct_targets_without_fdes[0]["target"], 16)
    plt_label = direct_targets_without_fdes[0]["target_label"]
    if (
        plt_label != "_Unwind_Resume@plt"
        or not plt_va <= plt_target < plt_target + 16 <= plt_va + plt_size
    ):
        raise AssertionError(f"unmapped direct target is not the recorded .plt stub: {direct_targets_without_fdes[0]}")
    plt_disassembly = disassembly(plt_target, plt_target + 16)
    plt_instructions = instruction_rows(plt_disassembly)
    if len(plt_instructions) != 3 or plt_instructions[0][0] != plt_target:
        raise AssertionError("_Unwind_Resume@plt stub does not decode as three instructions")
    if len(plt_instructions[0][1]) != 6 or plt_instructions[0][1][:2] != b"\xff\x25":
        raise AssertionError("_Unwind_Resume@plt does not start with an indirect RIP-relative jump")
    got_slot = plt_target + 6 + int.from_bytes(plt_instructions[0][1][2:6], "little", signed=True)
    jump_slot = jump_slot_rows().get(got_slot)
    if jump_slot is None or jump_slot[:2] != ("R_X86_64_JUMP_SLOT", "_Unwind_Resume@GCC_3.0"):
        raise AssertionError(f"_Unwind_Resume@plt GOT slot lacks its pinned dynamic relocation: {got_slot:x} {jump_slot}")
    with TARGET.open("rb") as source:
        source.seek(plt_offset + plt_target - plt_va)
        plt_bytes = source.read(16)
    if len(plt_bytes) != 16:
        raise AssertionError("_Unwind_Resume@plt entry is not a complete RIP-relative PLT stub")
    root_instruction_count = sum(1 for _ in instruction_rows(root_disasm))
    if (
        root_instruction_count != 412
        or len(incoming) != 2
        or len(raw_candidates) != 2
        or unowned
        or not_call_boundaries
        or raw_near_miss
        or len(direct_outgoing) != 28
        or len(direct_targets) != 14
        or len(direct_targets_with_fdes) != 13
        or len(indirect_outgoing) != 12
        or len(indirect_slots) != 4
        or len(indirect_addends) != 4
        or unresolved_indirect
        or any(item["relocation_type"] != "R_X86_64_RELATIVE" or item["target_fde"] is None for item in indirect_outgoing)
    ):
        raise AssertionError(
            "selected FDE call graph differs from the recorded 2/28/12 bounded result: "
            f"instructions={root_instruction_count} incoming={len(incoming)} raw={len(raw_candidates)} "
            f"unowned={unowned} bad={not_call_boundaries} near={raw_near_miss} "
            f"direct={len(direct_outgoing)} targets={len(direct_targets)} mapped={len(direct_targets_with_fdes)} "
            f"indirect={len(indirect_outgoing)} slots={len(indirect_slots)} addends={len(indirect_addends)} "
            f"unresolved={len(unresolved_indirect)}"
        )

    evidence = {
        "target_sha256": TARGET_SHA256,
        "function": {
            "range": [hex(root[0]), hex(root[1])],
            "sha256": sha256_bytes(body_bytes(root[0], root[1])),
            "instruction_count": root_instruction_count,
            "fde_line": root[2],
        },
        "direct_incoming": {
            "scan": "every E8 rel32 byte pattern in .text; candidates validated as call instructions inside their owning FDE",
            "raw_candidates": [hex(site) for site in raw_candidates],
            "validated": incoming,
            "without_fde": unowned,
            "not_call_boundaries": not_call_boundaries,
            "target_plus_one_candidates": raw_near_miss,
        },
        "direct_outgoing": direct_outgoing,
        "external_plt_target": {
            "section": ".plt",
            "range": [hex(plt_target), hex(plt_target + 16)],
            "label": plt_label,
            "got_slot": hex(got_slot),
            "relocation_type": jump_slot[0],
            "dynamic_symbol": jump_slot[1],
            "sha256": sha256_bytes(plt_bytes),
        },
        "rip_relative_indirect_outgoing": indirect_outgoing,
        "other_indirect_outgoing": unresolved_indirect,
        "target_fdes": mapped_targets,
    }

    selected_lines = [fdes_needed[key][2] for key in sorted(fdes_needed)]
    relocation_lines = []
    for slot in slots:
        relocation = relocations[slot]
        relocation_lines.append(relocation[2])
    disassembly_text = ""
    for label, row in [("selected", root)] + [
        ("caller-" + incoming[index]["site"], fdes_needed[int(incoming[index]["caller_fde"][0], 16)])
        for index in range(len(incoming))
    ]:
        disassembly_text += f"## {label} {row[0]:#x}..{row[1]:#x}\n"
        disassembly_text += disassembly(row[0], row[1])
    files = {
        "calls.json": json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        "fdes.readelf.txt": "\n".join(selected_lines) + "\n",
        "relocations.readelf.txt": "\n".join(relocation_lines) + "\n",
        "call-sites.objdump.txt": disassembly_text,
        "unwind-resume-plt.objdump.txt": plt_disassembly,
        "unwind-resume-jump-slot.readelf.txt": jump_slot[2] + "\n",
    }
    return evidence, files


def verify_manifest():
    manifest = (PACKET / "MANIFEST.sha256").read_text(encoding="utf-8")
    listed = {}
    for line in manifest.splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or len(digest) != 64 or name in listed:
            raise AssertionError(f"malformed or duplicate manifest entry: {line!r}")
        listed[name] = digest
    present = sorted(path.name for path in PACKET.iterdir() if path.is_file() and path.name != "MANIFEST.sha256")
    if sorted(listed) != present:
        raise AssertionError(f"manifest file set differs: {sorted(listed)} != {present}")
    for name, digest in listed.items():
        if sha256_file(PACKET / name) != digest:
            raise AssertionError(f"manifest digest mismatch: {name}")


def write_packet(files):
    for name, content in files.items():
        (PACKET / name).write_text(content, encoding="utf-8")
    names = sorted(path.name for path in PACKET.iterdir() if path.is_file() and path.name != "MANIFEST.sha256")
    manifest = "".join(f"{sha256_file(PACKET / name)}  {name}\n" for name in names)
    (PACKET / "MANIFEST.sha256").write_text(manifest, encoding="utf-8")


def main():
    evidence, files = derive()
    if len(sys.argv) == 2 and sys.argv[1] == "--write":
        write_packet(files)
    elif len(sys.argv) != 1:
        raise SystemExit("usage: python3 -B verify.py [--write]")
    else:
        for name, content in files.items():
            if (PACKET / name).read_text(encoding="utf-8") != content:
                raise AssertionError(f"saved target-derived file differs: {name}")
        saved = json.loads((PACKET / "calls.json").read_text(encoding="utf-8"))
        if saved != evidence:
            raise AssertionError("saved call graph differs from target-derived evidence")
        verify_manifest()
        print(
            "verified incoming=%d direct=%d rip-relative=%d other-indirect=%d external-plt=1"
            % (
                len(evidence["direct_incoming"]["validated"]),
                len(evidence["direct_outgoing"]),
                len(evidence["rip_relative_indirect_outgoing"]),
                len(evidence["other_indirect_outgoing"]),
            )
        )


if __name__ == "__main__":
    main()
