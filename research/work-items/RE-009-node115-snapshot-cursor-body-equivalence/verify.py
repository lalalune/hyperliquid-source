import hashlib
import re
import struct
import subprocess
from collections import Counter
from pathlib import Path

BINARY = Path("artifacts/node/115/hl-node")
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
LEFT = 0x2442070
RIGHT = 0x244B6E0
SIZE = 938
TEXT_DELTA = 0x1000
EXPECTED_GEOMETRY = {
    (0x428, 0x9A8): 1,
    (0x42A, 0x9AA): 3,
    (0x430, 0x9B0): 31,
    (0x438, 0x9B8): 1,
    (0x490, 0xA10): 4,
}
EXPECTED_TARGETS = {
    0x2442155: 0x64DF4A0,
    0x244219A: 0x64DF4A0,
    0x2442263: 0x64DF4A0,
    0x24423F8: 0x64DF4A0,
    0x24423FF: 0x642FBA8,
    0x2442405: 0x64DF830,
    0x244240E: 0x642FC20,
    0x2442414: 0x64DF830,
}
INSTRUCTION = re.compile(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2} )+)[ \t]*(.+)$")


def decode(start, data):
    output = subprocess.check_output(
        ["llvm-objdump", "-d", f"--start-address={start}", f"--stop-address={start + SIZE}", BINARY],
        text=True,
    )
    records = []
    offset = 0
    for line in output.splitlines():
        match = INSTRUCTION.match(line)
        if match is None:
            continue
        address, encoded, assembly = match.groups()
        raw = bytes.fromhex(encoded)
        assert int(address, 16) == start + offset
        assert raw == data[offset:offset + len(raw)]
        assert "<unknown>" not in assembly
        records.append((offset, len(raw), assembly))
        offset += len(raw)
    assert offset == SIZE
    addresses = {start + record[0] for record in records}
    branches = 0
    for _, _, assembly in records:
        mnemonic, *args = assembly.split()
        if not mnemonic.startswith(("j", "call", "loop")) or args[0].startswith("*"):
            continue
        assert int(args[0], 16) in addresses
        branches += 1
    assert branches == 36
    return records


def compare(left, right, left_records, right_records):
    geometry = Counter()
    targets = {}
    operands = []
    unchanged = SIZE
    for (offset, size, left_asm), (right_offset, right_size, right_asm) in zip(
        left_records, right_records, strict=True
    ):
        assert (offset, size) == (right_offset, right_size)
        left_instruction = left[offset:offset + size]
        right_instruction = right[offset:offset + size]
        if left_instruction == right_instruction:
            assert "%rip" not in left_asm and "%rip" not in right_asm
            continue
        assert size > 4 and left_instruction[:-4] == right_instruction[:-4]
        operand_offset = offset + size - 4
        address = LEFT + operand_offset
        left_value, = struct.unpack("<i", left_instruction[-4:])
        right_value, = struct.unpack("<i", right_instruction[-4:])
        if "%rip" in left_asm or "%rip" in right_asm:
            assert "%rip" in left_asm and "%rip" in right_asm
            target = LEFT + offset + size + left_value
            assert target == RIGHT + offset + size + right_value
            targets[address] = target
        else:
            assert f"$0x{left_value:x}" in left_asm or f"0x{left_value:x}(" in left_asm
            assert f"$0x{right_value:x}" in right_asm or f"0x{right_value:x}(" in right_asm
            geometry[(left_value, right_value)] += 1
        operands.append(operand_offset)
        unchanged -= 4
    assert geometry == EXPECTED_GEOMETRY
    assert targets == EXPECTED_TARGETS
    assert unchanged == 746
    return operands


def main():
    assert __debug__, "run Python without -O"
    data = BINARY.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DIGEST
    bodies = [data[start - TEXT_DELTA:start - TEXT_DELTA + SIZE] for start in (LEFT, RIGHT)]
    records = [decode(start, body) for start, body in zip((LEFT, RIGHT), bodies, strict=True)]
    frames = subprocess.check_output(["llvm-dwarfdump", "--eh-frame", BINARY], text=True)
    for start in (LEFT, RIGHT):
        assert f"pc={start:08x}...{start + SIZE:08x}" in frames
    operands = compare(*bodies, *records)
    checks = 0
    for side in range(2):
        for offset in [0, *operands]:
            poisoned = bytearray(bodies[side])
            poisoned[offset] ^= 0x80
            altered = bodies.copy()
            altered[side] = poisoned
            try:
                compare(*altered, *records)
            except AssertionError:
                checks += 1
            else:
                raise AssertionError(f"mutation survived at side {side}, offset {offset:#x}")
    print(f"PASS: two FDE spans of {SIZE} bytes, {len(records[0])} instructions and 36 direct internal branches each")
    for (left, right), count in EXPECTED_GEOMETRY.items():
        print(f"geometry {left:#x} -> {right:#x}: {count}")
    for address, target in EXPECTED_TARGETS.items():
        print(f"RIP operand {address:#x}: common target {target:#x}")
    print(f"PASS: 746 unchanged bytes per body, 40 geometry operands, 8 RIP relocations; {checks} rejected mutations")


if __name__ == "__main__":
    main()
