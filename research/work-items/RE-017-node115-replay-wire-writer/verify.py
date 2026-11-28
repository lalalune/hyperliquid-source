"""Check the native replay outer write choices used by the Rust adapter."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame


def test_call(address, raw, target):
    return len(raw) == 5 and raw[0] == 0xe8 and (
        address + len(raw) + struct.unpack("<i", raw[1:])[0] == target
    )


def main():
    assert __debug__, "run Python without -O"
    data = (ROOT / TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    print(f"Target SHA-256: {TARGET_SHA256}", flush=True)
    sections = {row["name"]: row for row in parse_sections(data)}

    def read(name, address, size):
        section = sections[name]
        displacement = address - section["va"]
        assert 0 <= displacement <= displacement + size <= section["size"]
        offset = section["offset"] + displacement
        return data[offset:offset + size]

    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    assert any(fde["entry"] == 0x4fb5ce0 and fde["end"] == 0x4fb5fa2 for fde in fdes)
    for address, child in (
        (0x4fb5d15, 0x5821f30),
        (0x4fb5d72, 0x59681d0),
        (0x4fb5d92, 0x5967060),
        (0x4fb5db4, 0x4e055d0),
        (0x4fb5dfb, 0x5b56e10),
    ):
        raw = read(".text", address, 5)
        assert test_call(address, raw, child)
        assert not test_call(address, raw[:-1] + bytes([raw[-1] ^ 1]), child)
    assert read(".text", 0x4fb5de4, 4) == bytes.fromhex("c6040101")
    assert read(".text", 0x4fb5f1a, 4) == bytes.fromhex("c6043000")
    for address, literal in ((0x459e6c, 0), (0x45a05c, 1)):
        assert read(".rodata", address, 4) == struct.pack("<I", literal)
    print("PASS: Block writer child calls, raw attachment 0/1, Block/Tx enum tags and call mutations")
    codec = ROOT / "research/work-items/RE-017-node115-replay-wire-payload-codec/verify.py"
    subprocess.run([sys.executable, "-B", str(codec)], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
