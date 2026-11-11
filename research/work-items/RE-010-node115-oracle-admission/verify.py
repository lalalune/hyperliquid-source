"""Verify selected validator reference-oracle admission in the pinned ELF."""
from hashlib import sha256
from pathlib import Path
from struct import unpack
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from tools.re010_action_type_matcher_115 import BINARY, Image

DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def verify(image):
    def expect(actual, expected, location):
        if actual != expected:
            raise ValueError(f"{location:#x}: expected {expected!r}, got {actual!r}")

    def check(address, code):
        code = bytes.fromhex(code)
        expect(image.read(address, len(code)), code, address)

    def relative(address, base, target):
        displacement, = unpack("<i", image.read(address, 4))
        expect(base + displacement, target, address)

    def edge(address, opcode, target):
        check(address, opcode)
        operand = address + len(bytes.fromhex(opcode))
        relative(operand, operand + 4, target)

    relative(0x9136B8 + 24 * 4, 0x9136B8, 0x4D40AFE)
    edge(0x4D40B05, "4c8d05", 0x64A7ED8)
    for index, field in enumerate([b"oraclePxs", b"externalPerpPxs", b"scalarUpdates"]):
        slot = 0x64A7ED8 + 16 * index
        size, = unpack("<Q", image.read(slot + 8, 8))
        expect(image.read(image.relative[slot], size), field, slot)
    edge(0x4D40B22, "e8", 0x56B4A70)
    check(0x4D40B91, "41bc9e000000")
    relative(0x92671C + 24 * 4, 0x92671C, 0x54A3439)
    check(0x54A3439, "4983c7084889e74c89ee4c89e24c89f9")
    edge(0x54A3449, "e8", 0x552F980)
    edge(0x552FEE1, "e8", 0x5551140)
    edge(0x552FF1D, "e8", 0x5551920)
    check(0x552FF22, "66817c2470a201")
    edge(0x552FF29, "0f85", 0x5530085)
    edge(0x552FF61, "e8", 0x54CD990)

    check(0x54CD9A1, "48898c2408010000")
    check(0x54CD9D6, "488b8e281900004885c9")
    edge(0x54CD9E0, "0f84", 0x54CDBE6)
    edge(0x54CDA94, "0f82", 0x54CDBE6)
    check(0x54CDBEE, "66c7032c00")
    edge(0x54CDB0F, "ff15", 0x64E79B0)
    check(0x54CDB15, "66817c2410a201")
    edge(0x54CDB24, "0f85", 0x54CDBF8)

    check(0x54CDB2A, "49bc0000000000000080")
    check(0x54CDB5C, "31c0488b8c2408010000483b4140")
    edge(0x54CDB6A, "0f81", 0x54CDC3B)
    check(0x54CDB70, "4c396158")
    edge(0x54CDB74, "0f85", 0x54CDD22)
    check(0x54CDD18, "4c396158")
    edge(0x54CDD1C, "0f84", 0x54CDB7A)
    check(0x54CDDF9, "488b4118483d10270000")
    edge(0x54CDE03, "0f86", 0x54CDB8A)
    check(0x54CDB7A, "488b4118483d10270000")
    edge(0x54CDB84, "0f87", 0x54CDE0F)
    check(0x54CDBB3, "488b41384889842418010000483d11270000")
    edge(0x54CDBC5, "0f82", 0x54CDF3B)
    check(0x54CDBCB, "66c7035801")

    for start, compare, branch, call in [
        (0x54CDC3B, "488b51504883fa65", "0f83", 0x54CDC52),
        (0x54CDD22, "488b51684883fa64", "0f87", 0x54CDD3C),
    ]:
        check(start, compare)
        edge(start + 8, branch, 0x54CDE0B)
        edge(call, "ff15", 0x64E4E60)
        check(call + 6, "0fb74424103da2010000")
        edge(call + 16, "0f85", 0x54CDE2E)
    expect(image.relative[0x64E4E60], 0x43099F0, 0x64E4E60)
    check(0x54CDE0F, "66c7035801")


def main():
    data = BINARY.read_bytes()
    if sha256(data).hexdigest() != DIGEST:
        raise ValueError("unexpected node #115 digest")
    verify(Image(data))
    changed = bytearray(data)
    mutant = Image(changed)
    for address in (0x54CDB6B, 0x54CDD29):
        offset = mutant.off(address)
        changed[offset] ^= 1
        try:
            verify(mutant)
        except ValueError:
            changed[offset] ^= 1
        else:
            raise ValueError(f"mutant accepted at {address:#x}")
    print("reference oracle: four bounded count lanes, linked collection callee, two rejected mutations")


if __name__ == "__main__":
    main()
