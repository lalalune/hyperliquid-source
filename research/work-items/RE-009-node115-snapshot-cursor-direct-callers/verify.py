"""Enumerate FDE-owned direct transfers to two pinned cursor bodies."""

from bisect import bisect_right
from collections import defaultdict
import hashlib
from pathlib import Path
import re
import struct
import subprocess

TARGET = Path("artifacts/node/115/hl-node")
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
CURSORS = {0x2442070, 0x2442420}
TEXT_START, TEXT_OFFSET, TEXT_SIZE = 0x1419300, 0x1418300, 0x4FD7700
FDE_PATTERN = r"pc=([0-9a-f]+)\.\.\.([0-9a-f]+)"
INSTRUCTION_PATTERN = re.compile(
    r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+){5})(callq?|jmpq?)\s+0x([0-9a-f]+)\b",
    re.MULTILINE,
)

def transfer(address, encoded):
    if len(encoded) != 5 or encoded[0] not in (0xE8, 0xE9):
        return None
    return address + 5 + struct.unpack_from("<i", encoded, 1)[0]

def command(*args):
    return subprocess.check_output(args, text=True)

def main():
    image = TARGET.read_bytes()
    assert hashlib.sha256(image).hexdigest() == SHA256
    text = image[TEXT_OFFSET:TEXT_OFFSET + TEXT_SIZE]
    assert len(text) == TEXT_SIZE
    frames = sorted({(int(a, 16), int(b, 16)) for a, b in re.findall(
        FDE_PATTERN, command("llvm-dwarfdump", "--eh-frame", str(TARGET))
    ) if TEXT_START <= int(a, 16) < int(b, 16) <= TEXT_START + TEXT_SIZE})
    assert all(left[1] <= right[0] for left, right in zip(frames, frames[1:]))
    starts = [start for start, _ in frames]
    candidates = defaultdict(dict)
    for match in re.finditer(b"[\xe8\xe9]", text):
        offset = match.start()
        address = TEXT_START + offset
        target = transfer(address, text[offset:offset + 5])
        if target not in CURSORS:
            continue
        owner = bisect_right(starts, address) - 1
        assert owner >= 0 and address + 5 <= frames[owner][1], hex(address)
        candidates[frames[owner]][address] = target

    print("owner_start\towner_end\tinstruction\toperation\ttarget")
    for (start, end), sites in sorted(candidates.items()):
        disassembly = command(
            "llvm-objdump", "-d", f"--start-address={start:#x}",
            f"--stop-address={end:#x}", str(TARGET),
        )
        observed = {}
        for match in INSTRUCTION_PATTERN.finditer(disassembly):
            address = int(match[1], 16)
            target = int(match[4], 16)
            if target not in CURSORS:
                continue
            encoded = bytes.fromhex(match[2])
            assert transfer(address, encoded) == target
            assert transfer(address, b"\x90" + encoded[1:]) is None
            corrupted = encoded[:1] + bytes([encoded[1] ^ 1]) + encoded[2:]
            assert transfer(address, corrupted) != target
            observed[address] = target
            print(f"{start:#x}\t{end:#x}\t{address:#x}\t{match[3]}\t{target:#x}")
        assert observed == sites, (hex(start), set(sites) ^ set(observed))

if __name__ == "__main__":
    main()
