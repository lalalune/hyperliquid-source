import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))

from foundation_lsda_call_site import TARGET, TARGET_SHA256, parse_sections, walk_eh_frame

BOUNDS = {
    (0x3C13960, 0x3C154C1), (0x3C2F460, 0x3C2FEBD),
    (0x3D376B0, 0x3D3770C), (0x3D2D870, 0x3D2D939),
    (0x4214250, 0x4214475), (0x42146B0, 0x42148A7),
    (0x4307FA0, 0x4307FD7), (0x4643ED0, 0x4644056),
}


def main():
    assert __debug__, "run Python without -O"
    data = Path(TARGET).read_bytes()
    assert hashlib.sha256(data).hexdigest() == TARGET_SHA256
    sections = {section["name"]: section for section in parse_sections(data)}

    def read(name, address, width):
        section = sections[name]
        displacement = address - section["va"]
        assert 0 <= displacement <= displacement + width <= section["size"]
        offset = section["offset"] + displacement
        return data[offset:offset + width]

    def anchor(address, encoded):
        raw = bytes.fromhex(encoded)
        assert read(".text", address, len(raw)) == raw

    def rip(address, encoded):
        prefix = bytes.fromhex(encoded)
        length = len(prefix) + 4
        raw = read(".text", address, length)
        assert raw.startswith(prefix)
        return address + length + struct.unpack("<i", raw[-4:])[0]

    frame = sections[".eh_frame"]
    _, fdes = walk_eh_frame(read(".eh_frame", frame["va"], frame["size"]), frame["va"])
    assert BOUNDS <= {(row["entry"], row["end"]) for row in fdes}
    anchor(0x3C15429, "498d9730230000")
    anchor(0x3C2FD6B, "488db330230000")
    assert rip(0x3C15438, "e8") == 0x3D376B0
    assert rip(0x3C2FD75, "e8") == 0x3D2D870
    anchor(0x3D376B5, "4989d64889f3")
    anchor(0x3D376E1, "4c89f64889da")
    assert rip(0x3D376EC, "e9") == 0x4214250
    anchor(0x3D2D87E, "4889f34989fe")
    anchor(0x3D2D8C4, "4889df4c89f6")
    assert rip(0x3D2D8CA, "e8") == 0x42146B0
    for address in (0x3D376C1, 0x3D2D884):
        key = rip(address, "488d35")
        anchor(address + 7, "ba04000000")
        assert read(".rodata", key, 4) == b"advt"
    for address in (0x42143C4, 0x4307FA8):
        key = rip(address, "488d35")
        anchor(address + 7, "ba03000000")
        assert read(".rodata", key, 3) == b"adu"
    anchor(0x42143BD, "41807f0b01751a")
    anchor(0x42143DE, "f2410f108688000000")
    assert rip(0x42143ED, "e8") == 0x4199450
    anchor(0x42147D2, "488db388000000")
    assert rip(0x42147DC, "e8") == 0x4307FA0
    anchor(0x4307FA5, "4889f1")
    assert rip(0x4307FB4, "e9") == 0x4643ED0
    anchor(0x4643EDD, "4889cb")
    anchor(0x4643EF6, "f30f7e03")
    anchor(0x4643F2D, "48b9")
    anchor(0x4643F37, "4821c148b8")
    mask, = struct.unpack("<Q", read(".text", 0x4643F2F, 8))
    threshold, = struct.unpack("<Q", read(".text", 0x4643F3C, 8))
    assert (mask, threshold) == (0x7FFFFFFFFFFFFFFF, 0x7FF0000000000000)
    anchor(0x4643F44, "4839c17c29")
    assert rip(0x4643F7A, "ff15") == 0x64E13D0
    anchor(0x4643F61, "c704306e756c6c4883c604")

    vectors = {
        0: True,
        0x8000000000000000: True,
        0x7FEFFFFFFFFFFFFF: True,
        0xFFEFFFFFFFFFFFFF: True,
        0x7FF0000000000000: False,
        0xFFF0000000000000: False,
        0x7FF0000000000001: False,
        0xFFF8000000000000: False,
    }
    for bits, finite in vectors.items():
        assert ((bits & mask) < threshold) == finite
        print(f"{bits:016x}: {'formatter' if finite else 'null'}")
    print(f"PASS: {len(BOUNDS)} FDEs; historical +0x23b8 maps to advt.adu in both named exporters")


if __name__ == "__main__":
    main()
