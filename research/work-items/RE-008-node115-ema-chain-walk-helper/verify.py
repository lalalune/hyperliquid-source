"""Verify selected node #115 EMA chain-walk-helper witnesses."""
from hashlib import sha256
from pathlib import Path
import struct, sys
sys.path.insert(0, str(Path("tools").resolve()))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BODY = "36153780be9820c9990cfe77d27277f3ad90e14ccdf7f5c87bcba1a291c7a26e"
data = Path("artifacts/node/115/hl-node").read_bytes()
if sha256(data).hexdigest() != TARGET:
    raise ValueError("wrong node artifact")
secs = sections(data)
_, frames = eh_frame_records(data, secs)
if [(f["start"], f["end"]) for f in frames if f["start"] == 0x4D2F8C0] != [(0x4D2F8C0, 0x4D2FB8D)]:
    raise ValueError("unexpected FDE")

def read(address, size):
    hits = [s for s in secs if s["type"] != 8 and s["address"] <= address and address + size <= s["address"] + s["size"]]
    if len(hits) != 1:
        raise ValueError(f"unmapped {address:#x}")
    section = hits[0]
    offset = section["offset"] + address - section["address"]
    return data[offset:offset + size]

if sha256(read(0x4D2F8C0, 717)).hexdigest() != BODY:
    raise ValueError("body changed")
witnesses = {
    0x4D2F8CB: "488b06", 0x4D2F8CE: "488b7e08", 0x4D2F8D2: "488b4e10",
    0x4D2F8D6: "4885ff", 0x4D2F8DF: "488b8cc870010000", 0x4D2F8E7: "4889f8",
    0x4D2F8EA: "48ffc8", 0x4D2F8F3: "4883c7fe", 0x4D2F910: "440fb7896a010000",
    0x4D2F918: "4a8b8cc970010000", 0x4D2F940: "0fb7b16a010000",
    0x4D2F947: "488b8cf170010000", 0x4D2F9BE: "0fb7816a010000",
    0x4D2F9C5: "48ffc8", 0x4D2F9E9: "e842c6feff", 0x4D2FA10: "0fb7b06a010000",
    0x4D2FA17: "4839f2", 0x4D2FA36: "488d3492", 0x4D2FA43: "4489442410",
    0x4D2FA51: "0f28442440", 0x4D2FA56: "0f1144b008", 0x4D2FA95: "4885c9",
    0x4D2FAE2: "4889442460", 0x4D2FAFA: "4889df", 0x4D2FB61: "0f280424",
    0x4D2FB6A: "0f114b10", 0x4D2FB71: "48894320", 0x4D2FB75: "48c7432800000000",
    0x4D2FB7D: "48895330",
}
for address, expected in witnesses.items():
    raw = bytes.fromhex(expected)
    if read(address, len(raw)) != raw:
        raise ValueError(f"witness mismatch {address:#x}")
raw = read(0x4D2F8D9, 6)
if raw[:2] != bytes.fromhex("0f84") or 0x4D2F8D9 + 6 + struct.unpack("<i", raw[2:])[0] != 0x4D2FAE2:
    raise ValueError("wrong empty-root edge")
for address, expected in witnesses.items():
    altered = bytearray(bytes.fromhex(expected)); altered[0] ^= 1
    if altered == read(address, len(altered)):
        raise RuntimeError(f"mutation accepted {address:#x}")
print(f"Verified node #115, 717-byte FDE body, {len(witnesses)} instruction witnesses, 1 edge and {len(witnesses)} mutation controls.")
