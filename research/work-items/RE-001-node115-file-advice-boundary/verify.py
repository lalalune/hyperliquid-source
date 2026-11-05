"""Static node115 file-advice boundary proof; never executes the captured target."""
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

TARGET = Path("artifacts/node/115/hl-node")
SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
START, END = 0x60214f0, 0x60215bc
BODY_SHA256 = "a569fba870c7340f340fa5da011a7ad5eaf13e1f1daaceb8ddcde875b0761352"
TABLE = 0x974298
DESTINATIONS = [0x6021578, 0x6021590, 0x60215a8, 0x6021548, 0x6021560]
BRANCHES = [0x6021584, 0x602159f, 0x60215b7, 0x6021557, 0x602156f]


def require(condition, message):
    if not condition:
        raise ValueError(message)


class Image:
    def __init__(self, data):
        self.data = data
        require(data[:6] == b"\x7fELF\x02\x01", "ELF64 little endian required")
        require(struct.unpack_from("<H", data, 18)[0] == 62, "x86-64 required")
        off = struct.unpack_from("<Q", data, 40)[0]
        size, count, names = struct.unpack_from("<HHH", data, 58)
        require(size == 64 and off + size * count <= len(data), "section table bounds")
        self.sections = [struct.unpack_from("<IIQQQQIIQQ", data, off + i * size) for i in range(count)]
        strings = self.raw(self.sections[names])
        self.named = {strings[s[0]:].split(b"\0", 1)[0].decode(): s for s in self.sections}

    def raw(self, section):
        off, size = section[4:6]
        require(off + size <= len(self.data), "section file bounds")
        return self.data[off:off + size]

    def offset(self, address, size):
        matches = [s for s in self.sections if s[1] != 8 and s[3] <= address and address + size <= s[3] + s[5]]
        require(len(matches) == 1, "unique file-backed VA mapping")
        s = matches[0]
        return s[4] + address - s[3]

    def at(self, address, size):
        off = self.offset(address, size)
        return self.data[off:off + size]


def structure(data):
    """Separate from authentication so corruption controls reach semantic checks."""
    image = Image(data)
    body = image.at(START, END - START)
    require(hashlib.sha256(body).hexdigest() == BODY_SHA256, "selected body changed")
    table = [TABLE + struct.unpack("<i", image.at(TABLE + i * 4, 4))[0] for i in range(5)]
    require(table == DESTINATIONS, "jump table destinations changed")
    for branch in BRANCHES:
        instruction = image.at(branch, 5)
        require(instruction[0] == 0xe9 and branch + 5 + struct.unpack_from("<i", instruction, 1)[0] == 0x601ed40, "advice tail edge changed")
    thunk = image.at(0x601ed40, 9)
    require(thunk[:5] == bytes.fromhex("f30f1efae9"), "thunk instruction changed")
    require(0x601ed49 + struct.unpack_from("<i", thunk, 5)[0] == 0x63f1680, "thunk destination changed")
    plt = image.at(0x63f1680, 6)
    require(plt[:2] == b"\xff\x25" and 0x63f1686 + struct.unpack_from("<i", plt, 2)[0] == 0x64ee790, "PLT slot changed")
    rela = image.named[".rela.plt"]
    symbols = image.sections[rela[6]]
    strings = image.raw(image.sections[symbols[6]])
    require(rela[9] == 24 and symbols[9] == 24, "ELF entry sizes")
    matches = []
    for off in range(0, rela[5], 24):
        slot, info, addend = struct.unpack_from("<QQq", data, rela[4] + off)
        if slot == 0x64ee790:
            sym = symbols[4] + (info >> 32) * 24
            name = struct.unpack_from("<I", data, sym)[0]
            matches.append((strings[name:].split(b"\0", 1)[0], info & 0xffffffff, addend))
    require(matches == [(b"posix_fadvise", 7, 0)], "unique posix_fadvise JUMP_SLOT")
    return {"function_va": [hex(START), hex(END)], "function_file_offsets": [image.offset(START, END - START), image.offset(START, END - START) + END - START], "function_bytes": END - START, "function_sha256": BODY_SHA256, "selector_to_advice": [{"selector": i, "advice": i, "destination": hex(DESTINATIONS[i]), "tail_jump": hex(BRANCHES[i]), "offset": 0, "length": 0} for i in range(5)], "thunk_va": "0x601ed40", "plt_va": "0x63f1680", "relocation_slot_va": "0x64ee790"}


def verify(target=TARGET):
    data = target.read_bytes()
    require(hashlib.sha256(data).hexdigest() == SHA256, "target digest mismatch")
    result = structure(data)
    command = ["objdump", "-d", "-M", "intel", "--insn-width=16", f"--start-address={START}", f"--stop-address={END}", str(target)]
    decoded = subprocess.check_output(command, text=True, timeout=15)
    image = Image(data)
    cursor = START
    instructions = 0
    for line in decoded.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)", line)
        if m:
            require(int(m[1], 16) == cursor, "noncontiguous instruction decoding")
            raw = bytes.fromhex(m[2]); require(raw == image.at(cursor, len(raw)), "decoder bytes mismatch")
            cursor += len(raw); instructions += 1
    require(cursor == END and instructions > 0, "incomplete selected decoding")
    process = subprocess.Popen(["readelf", "--debug-dump=frames", "--wide", str(target)], stdout=subprocess.PIPE, text=True)
    found = []
    for line in process.stdout:
        m = re.search(r"FDE.*?pc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)", line)
        if m and int(m[1], 16) <= START < int(m[2], 16):
            found.append(tuple(int(v, 16) for v in m.groups()))
    process.stdout.close()
    require(process.wait(timeout=15) == 0 and found == [(START, END)], "unique exact unwind FDE")
    result.update(target_sha256=SHA256, fde_matches=len(found), decoded_instructions=instructions, command=command)
    return result, decoded


if __name__ == "__main__":
    result, decoded = verify()
    out = Path(__file__).resolve().parent
    (out / "verified.json").write_text(json.dumps(result, indent=2) + "\n")
    (out / "verified-disassembly.txt").write_text(decoded)
    print(json.dumps(result, indent=2))
