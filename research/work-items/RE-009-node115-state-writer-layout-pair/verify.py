#!/usr/bin/env python3
"""Compare the two native node #115 MessagePack state-writer FDEs offline."""
from argparse import ArgumentParser
from collections import Counter
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
import re
from subprocess import check_output
import sys

PACKET = Path(__file__).resolve().parent
TARGET = "artifacts/node/115/hl-node"
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
FRAMES = ((0x5480950, 0x548168C), (0x5481900, 0x548263C))
INSERT = 0xB70
ROW = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*([a-z][a-z0-9]*)\s*(.*)$")
RIP = re.compile(r"\[rip [+-] 0x[0-9a-f]+\]\s+# (0x[0-9a-f]+)$")
STATE = re.compile(r"\[r15 \+ (0x[0-9a-f]+)\]|^r15, (0x[0-9a-f]+)$")
DIRECT = re.compile(r"^(0x[0-9a-f]+)(?:\s+<.*>)?$")


def require(condition, message):
    if not condition:
        raise ValueError(message)


@dataclass(frozen=True)
class Instruction:
    address: int
    raw: bytes
    mnemonic: str
    operands: str

    def pc_target(self, width):
        rel = int.from_bytes(self.raw[-width:], "little", signed=True)
        return self.address + len(self.raw) + rel


def decode(tool, elf, frame, at):
    start, end = frame
    listing = check_output(
        [tool, "-d", "--x86-asm-syntax=intel", f"--start-address={start:#x}",
         f"--stop-address={end:#x}", str(elf)], text=True)
    rows = []
    address = start
    for line in listing.splitlines():
        match = ROW.fullmatch(line)
        if match is None:
            continue
        addr, raw, mnemonic, operands = match.groups()
        addr = int(addr, 16)
        raw = bytes.fromhex(raw)
        require(addr == address and raw == at(".text", addr, len(raw)),
                f"Disassembly partition or ELF byte mismatch at {addr:#x}")
        rows.append(Instruction(addr, raw, mnemonic, operands))
        address += len(raw)
    require(address == end, f"Disassembly does not cover FDE {start:#x}..{end:#x}")
    return rows


def state_offset(op):
    match = STATE.search(op)
    if match is None:
        return None
    return int(match[1] or match[2], 16)


def pair_category(left, right, starts, ends):
    label = f"{left.address:#x} / {right.address:#x}"
    require(left.address - starts[0] == right.address - starts[1] and
            len(left.raw) == len(right.raw) and left.mnemonic == right.mnemonic,
            f"Instruction alignment or mnemonic changed at {label}")
    if left.mnemonic == "call" or left.mnemonic.startswith("j"):
        encoded = [DIRECT.fullmatch(ins.operands) for ins in (left, right)]
        require(all(encoded), f"Non-direct branch or call at {label}")
        width = 1 if len(left.raw) == 2 else 4
        require(left.raw[:-width] == right.raw[:-width], f"Opcode changed at {label}")
        targets = tuple(ins.pc_target(width) for ins in (left, right))
        require(targets == tuple(int(m[1], 16) for m in encoded),
                f"Branch displacement disagreement at {label}")
        if left.mnemonic != "call":
            a, b = targets
            require(starts[0] <= a < ends[0] and starts[1] <= b < ends[1] and
                    a - starts[0] == b - starts[1], f"Internal edge changed at {label}")
            return "internal-edge", a, b
        require(targets[0] == targets[1] and
                all(not start <= targets[0] < end for start, end in zip(starts, ends)),
                f"External call target changed at {label}")
        return "shared-call", *targets
    rip = [RIP.search(ins.operands) for ins in (left, right)]
    if any(rip):
        require(all(rip) and left.raw[:-4] == right.raw[:-4],
                f"RIP operand or opcode changed at {label}")
        targets = tuple(ins.pc_target(4) for ins in (left, right))
        require(targets[0] == targets[1] and targets == tuple(int(m[1], 16) for m in rip),
                f"RIP target changed at {label}")
        return "shared-literal", *targets
    offsets = tuple(state_offset(ins.operands) for ins in (left, right))
    if any(offset is not None for offset in offsets):
        a, b = offsets
        require(a is not None and b is not None and
                left.raw[:-4] == right.raw[:-4] and
                offsets == tuple(int.from_bytes(ins.raw[-4:], "little") for ins in (left, right)),
                f"State operand encoding changed at {label}")
        if a < 0x7C0:
            require(a == b, f"State operand before the insertion changed at {label}")
            return "preserved-state", a, b
        require(b - a == INSERT, f"State operand changed outside the insertion rule at {label}")
        return "shifted-state", a, b
    require(left.raw == right.raw and left.operands == right.operands,
            f"Unexplained byte/operand difference at {label}")
    return "unchanged", None, None


def assemble_report(left, right, at):
    starts, ends = zip(*FRAMES)
    require(len(left) == len(right) == 756, "Unexpected instruction counts")
    valid_starts = [{ins.address for ins in items} for items in (left, right)]
    counters = Counter()
    rows = ["offset\tclass\tcanonical_A\tcanonical_B\tA_bytes\tB_bytes\tmnemonic"]
    for a, b in zip(left, right):
        category, x, y = pair_category(a, b, starts, ends)
        counters[category] += 1
        if category == "internal-edge":
            require(x in valid_starts[0] and y in valid_starts[1],
                    f"Edge from {a.address:#x} does not reach an instruction boundary")
        elif category == "shared-literal":
            at(".rodata", x, 1)
        elif category == "shared-call":
            at(".text", x, 1)
        rows.append("\t".join((f"{a.address - starts[0]:#x}", category,
                              "" if x is None else f"{x:#x}",
                              "" if y is None else f"{y:#x}",
                              a.raw.hex(), b.raw.hex(), a.mnemonic)))
    return "\n".join(rows) + "\n", counters


def reject_controls(left, right):
    starts, ends = zip(*FRAMES)
    for category, description in (
        ("internal-edge", "change an internal result branch"),
        ("shared-call", "change an emitted child's dispatch target"),
        ("shared-literal", "change a shared field-literal target"),
        ("shifted-state", "change a shifted layout-B member operand"),
        ("unchanged", "alter one opcode outside recognized operand fields"),
    ):
        a, b = next((a, b) for a, b in zip(left, right)
                    if pair_category(a, b, starts, ends)[0] == category)
        bad = replace(b, raw=b.raw[:-1] + bytes((b.raw[-1] ^ 1,)))
        try:
            pair_category(a, bad, starts, ends)
        except ValueError:
            print(f"PASS control: {description} rejected")
        else:
            raise ValueError(f"Control escaped: {description}")


def main():
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--objdump", default="llvm-objdump")
    parser.add_argument("--write", action="store_true", help="regenerate the inventory TSV")
    args = parser.parse_args()
    sys.path.insert(0, str(args.repo.resolve() / "tools"))
    from foundation_lsda_call_site import parse_sections, walk_eh_frame

    binary = args.repo.resolve() / TARGET
    image = binary.read_bytes()
    require(sha256(image).hexdigest() == DIGEST, "Wrong #115 artifact")
    sections = {row["name"]: row for row in parse_sections(image)}

    def at(name, address, length):
        section = sections[name]
        delta = address - section["va"]
        require(0 <= delta <= delta + length <= section["size"],
                f"{address:#x} outside {name}")
        offset = section["offset"] + delta
        return image[offset:offset + length]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(at(".eh_frame", frame["va"], frame["size"]), frame["va"])
    for start, end in FRAMES:
        require([entry["end"] for entry in fdes if entry["entry"] == start] == [end],
                f"Wrong or ambiguous FDE end for {start:#x}")
        print(f"FDE {start:#x}..{end:#x} ({end - start} bytes)")
    print(f"target={TARGET} sha256={DIGEST} bytes={len(image)}")
    for site, word, arg, edge, target in (
        (0x4E4B8C1, "c744240800040001", "4889e2", 0x4E4B8DE, FRAMES[0][0]),
        (0x4E4B461, "c744241800040001", "488d542410", 0x4E4B480, FRAMES[1][0]),
    ):
        register_setup = bytes.fromhex(arg)
        require(at(".text", site, 8).hex() == word and
                at(".text", edge - len(register_setup), len(register_setup)) == register_setup,
                "State writer mode setting or argument setup changed")
        call = at(".text", edge, 5)
        require(call[0] == 0xE8 and edge + 5 + int.from_bytes(call[1:], "little", signed=True) == target,
                "Caller no longer dispatches to expected writer")
        print(f"named configuration {site:#x}; call {edge:#x} -> {target:#x}")

    left, right = (decode(args.objdump, binary, bounds, at) for bounds in FRAMES)
    result, counts = assemble_report(left, right, at)
    require(counts == {
        "internal-edge": 109, "preserved-state": 2, "shared-call": 91,
        "shared-literal": 41, "shifted-state": 74, "unchanged": 439,
    }, "Instruction classification census changed")
    for start, _ in FRAMES:
        require(at(".text", start + 0x1E, 4).hex() == "807a0b00" and
                at(".text", start + 0x149, 5).hex() == "41807e0b01",
                "Nonzero mode or exact map-key mode comparison changed")
    for category, count in sorted(counts.items()):
        print(f"{category}: {count} instruction pairs")
    inventory = PACKET / "operands.tsv"
    if args.write:
        inventory.write_text(result)
    else:
        require(inventory.read_text() == result, "Versioned operand inventory differs from fresh extraction")
    reject_controls(left, right)
    print("PASS: every in-FDE instruction aligned; zero unexplained bytes")


if __name__ == "__main__":
    main()
