"""Verify the two latest-checkpoint consumers use the canonical path producer."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "tools"))
from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

LOADERS = (
    (0x4468E30, 0x44699C0, 0x4468FF1, 0x446917E, 0x4469190, 0x4469195, 0x4469284),
    (0x59FFA30, 0x5A007BB, 0x59FFC1D, 0x59FFDA4, 0x59FFDC0, 0x59FFDC5, 0x59FFEB4),
)


def read_at(data, section, address, size):
    displacement = address - section["va"]
    assert 0 <= displacement <= displacement + size <= section["size"]
    offset = section["offset"] + displacement
    return data[offset:offset + size]


def short_branch(address, raw):
    assert raw[0] == 0x75
    return address + len(raw) + struct.unpack("<b", raw[1:])[0]


def main():
    assert __debug__, "run Python without -O"
    data = (ROOT / TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    print(f"Target SHA-256: {TARGET_SHA256}", flush=True)
    sections = {section["name"]: section for section in parse_sections(data)}
    text = sections[".text"]
    rela = sections[".rela.dyn"]
    relative = {slot: target for slot, info, target in struct.iter_unpack(
        "<QQq", read_at(data, rela, rela["va"], rela["size"])
    ) if info == 8}
    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read_at(data, eh, eh["va"], eh["size"]), eh["va"])
    bounds = {(row["entry"], row["end"]) for row in fdes}
    for start, end, provider, branch, multibyte, plus, marker in LOADERS:
        assert (start, end) in bounds
        assert start < provider < branch < plus < marker < end
        raw = read_at(data, text, provider - 3, 9)
        assert raw[:5] == bytes.fromhex("4531c0ff15")
        slot = provider + 6 + struct.unpack("<i", raw[5:])[0]
        assert (slot, relative[slot]) == (0x64E1208, 0x15623E0)
        assert read_at(data, text, branch - 4, 4) == bytes.fromhex("4883fa01")
        edge = read_at(data, text, branch, 2)
        assert short_branch(branch, edge) == multibyte
        assert short_branch(branch, bytes((edge[0], edge[1] ^ 1))) != multibyte
        assert read_at(data, text, branch + 5, 4) == bytes.fromhex("83fe2b74")
        assert read_at(data, text, branch + 10, 3) == bytes.fromhex("83fe2d")
        assert read_at(data, text, plus, 22) == bytes.fromhex(
            "4080fe2b0f94c14889ce48f7de4889d74829cf4801c1"
        )
        raw = read_at(data, text, marker, 7)
        assert raw[:3] == bytes.fromhex("488d35")
        assert marker + 7 + struct.unpack("<i", raw[3:])[0] == 0x44BB44
        print(f"{start:#x}: zero suffix, canonical provider {relative[slot]:#x}; "
              f"one-byte sign guard skipped for longer names; marker format {marker:#x}")
    source = ROOT / "research/work-items/RE-009-node115-latest-checkpoint-markers/verify.py"
    subprocess.run([sys.executable, "-B", str(source)], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
