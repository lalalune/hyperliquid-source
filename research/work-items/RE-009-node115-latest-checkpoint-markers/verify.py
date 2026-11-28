import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

# FDE, literal load, primary call, fallback body, selector load, alternate call,
# accepted continuation, and rejected continuation for each observed loader.
LOADERS = [
    (0x4468E30, 0x44699C0, 0x4469284, 0x44692A6, 0x44692C7, 0x44692F1,
     0x4469308, 0x446932B, 0x4469394),
    (0x59FFA30, 0x5A007BB, 0x59FFEB4, 0x59FFED6, 0x59FFEF7, 0x59FFF21,
     0x59FFF38, 0x59FFF65, 0x59FFFCE),
]


def main():
    assert __debug__, "run Python without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def read(name, address, size):
        section = sections[name]
        displacement = address - section["va"]
        assert 0 <= displacement <= displacement + size <= section["size"]
        offset = section["offset"] + displacement
        return data[offset:offset + size]

    def rip(address, opcode):
        length = len(opcode) + 4
        raw = read(".text", address, length)
        assert raw.startswith(opcode)
        return address + length + struct.unpack("<i", raw[-4:])[0]

    def branch(address, opcode):
        raw = read(".text", address, 2)
        assert raw[0] == opcode
        return address + 2 + struct.unpack("<b", raw[1:])[0]

    reloc = sections[".rela.dyn"]
    raw_reloc = read(".rela.dyn", reloc["va"], reloc["size"])
    relative = {slot: target for slot, info, target in struct.iter_unpack("<QQq", raw_reloc)
                if info == 8}
    eh = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", eh["va"], eh["size"]), eh["va"])
    bounds = {(row["entry"], row["end"]) for row in fdes}
    assert (0x1500D20, 0x1500E43) in bounds
    assert read(".text", 0x1500DDA, 17) == bytes.fromhex(
        "b800f00000234424483d008000000f94c0"
    )
    assert read(".rodata", 0x44BB44, 23) == b"\xc0\x14/CHECKPOINT_COMPLETE\x00"
    assert relative[0x64E0950] == 0x1500D20
    for start, end, format_load, primary, fallback, selector, alternate, accept, reject in LOADERS:
        assert (start, end) in bounds and start < format_load < reject < end
        assert rip(format_load, b"\x48\x8d\x35") == 0x44BB44
        for address in (primary, alternate):
            assert rip(address, b"\xff\x15") == 0x64E0950
        assert read(".text", primary + 6, 2) == b"\x84\xc0"
        assert branch(primary + 8, 0x74) == fallback
        assert branch(fallback - 2, 0xEB) == accept
        assert read(".text", selector, 5) == b"\xbe\x02\x00\x00\x00"
        assert rip(selector + 5, b"\xe8") == 0x1696B90
        assert read(".text", alternate + 0x1E, 3) == b"\x45\x84\xe4"
        assert branch(accept - 2, 0x74) == reject
        print(f"FDE {start:#x}..{end:#x}: primary {primary:#x}, alternate {alternate:#x}, "
              f"accept {accept:#x}, reject {reject:#x}")
    print("PASS: both loader branches use one regular-file predicate and selector 2 fallback")


if __name__ == "__main__":
    main()
