#!/usr/bin/env python3
"""Digest-first static replay of one node115 caller edge; never executes target."""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

PACKET = Path(__file__).resolve().parent
DIGEST = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def facts(window, base, literal):
    """Decode only the listed instructions, not a general x86 decoder or emulator."""
    def at(va, n):
        i = va - base
        require(0 <= i and i + n <= len(window), "instruction outside excerpt")
        return window[i:i+n]
    require(at(0x3c4429e, 6) == bytes.fromhex("4989d74989f6"), "incoming register saves")
    require(at(0x3c443ed, 10) == bytes.fromhex("498d76304889e74c89fa"), "input offset or argument registers")
    call = at(0x3c443f7, 5)
    require(call[0] == 0xe8, "direct call opcode")
    destination = 0x3c443fc + struct.unpack_from("<i", call, 1)[0]
    require(destination == 0x3c453f0, "writer destination")
    require(at(0x3c443fc, 6) == bytes.fromhex("4c3924240f85"), "result head comparison/branch")
    branch = 0x3c44406 + struct.unpack("<i", at(0x3c44402, 4))[0]
    require(branch == 0x3c445f4, "result branch destination")
    lea = at(0x3c443cf, 7)
    require(lea[:3] == bytes.fromhex("488d35"), "field name LEA")
    field = 0x3c443d6 + struct.unpack_from("<i", lea, 3)[0]
    require(field == 0x45a1e4 and literal == b"spec", "field name data")
    require(at(0x3c443d6, 5) == bytes.fromhex("ba04000000"), "field name length")
    require(at(0x3c443c8, 7) == bytes.fromhex("41807f0b01751e"), "name-mode comparison/branch")
    return {"caller": "0x3c44290", "writer_call": "0x3c443f7", "writer": hex(destination),
            "input": "incoming RSI + 0x30 via R14", "writer_output": "current RSP",
            "writer_serializer": "incoming RDX via R15", "field_literal": "spec",
            "result_nonmatch_branch": hex(branch)}


def verify(data, pins, with_objdump=False, elf=None):
    require(hashlib.sha256(data).hexdigest() == DIGEST, "target digest")
    require(len(data) == 105896032 and data[:6] == b"\x7fELF\x02\x01", "target ELF identity")
    shoff = struct.unpack_from("<Q", data, 40)[0]
    ents, count, names = struct.unpack_from("<HHH", data, 58)
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff+i*ents) for i in range(count)]
    namesec = sections[names]
    strings = data[namesec[4]:namesec[4]+namesec[5]]
    byname = {strings[s[0]:].split(b"\0", 1)[0].decode(): s for s in sections}
    def off(va):
        for s in sections:
            if s[1] != 8 and s[3] <= va < s[3]+s[5]:
                return s[4]+va-s[3]
        raise ValueError("unmapped ELF VA")
    h = byname[".eh_frame_hdr"]
    require(data[h[4]:h[4]+4] == bytes([1, 0x1b, 3, 0x3b]), "unwind index encoding")
    n = struct.unpack_from("<I", data, h[4]+8)[0]
    entries = [(h[3]+a, h[3]+b) for a, b in struct.iter_unpack("<ii", data[h[4]+12:h[4]+12+8*n])]
    starts = [a for a, b in entries]
    require(starts == sorted(starts), "unsorted unwind index")
    start, fde = entries[bisect.bisect_right(starts, 0x3c44290)-1]
    require(start == 0x3c44290 and fde == int(pins["caller_fde"]["fde_va"], 16), "unwind index entry")
    fo = off(fde)
    length, cie_delta = struct.unpack_from("<II", data, fo)
    co = fo+4-cie_delta
    clen = struct.unpack_from("<I", data, co)[0]
    require(data[fo:fo+4+length].hex() == pins["caller_fde"]["fde_record_hex"], "FDE record")
    require(data[co:co+4+clen].hex() == pins["caller_fde"]["cie_record_hex"], "CIE record")
    # Pinned CIE is version1/zR, code_align1, data_align-8, return_reg16, pcrel sdata4.
    require(data[co+8:co+17] == bytes.fromhex("017a5200017810011b"), "CIE encoding fields")
    initial = fde+8+struct.unpack_from("<i", data, fo+8)[0]
    extent = struct.unpack_from("<i", data, fo+12)[0]
    require(initial == start and start+extent == 0x3c446c4, "decoded FDE extent")
    body = data[off(start):off(start)+extent]
    require(hashlib.sha256(body).hexdigest() == pins["caller_fde"]["body_sha256"], "caller body hash")
    w = pins["excerpt"]
    a, z = int(w["start"], 16), int(w["end"], 16)
    window = data[off(a):off(z)]
    require(z-a <= 512 and window.hex() == w["raw_hex"], "retained excerpt")
    observed = facts(window, a, data[off(0x45a1e4):off(0x45a1e4)+4])
    if with_objdump:
        require(elf is not None, "objdump needs target path")
        command = ["objdump", "-d", "-M", "intel", "--insn-width=16", f"--start-address={a}", f"--stop-address={z}", str(elf)]
        result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=20)
        decoded = []
        for line in result.stdout.splitlines():
            m = re.match(r"^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)\s*(.*)$", line)
            if m:
                va, raw = int(m[1], 16), bytes.fromhex(m[2])
                require(va == a+sum(len(x[1]) for x in decoded), "instruction continuity")
                require(raw == window[va-a:va-a+len(raw)], "decoded instruction bytes")
                decoded.append((va, raw, m[3]))
        require(sum(len(x[1]) for x in decoded) == len(window), "decoded excerpt extent")
        require(any(va == 0x3c443f7 and text.startswith("call") and "3c453f0" in text for va, raw, text in decoded), "aligned writer call")
        observed["decoded_instructions"] = len(decoded)
    return observed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--elf", type=Path, default=Path("artifacts/node/115/hl-node"))
    parser.add_argument("--with-objdump", action="store_true")
    args = parser.parse_args()
    pins = json.loads((PACKET/"discovery.json").read_text())
    print(json.dumps(verify(args.elf.read_bytes(), pins, args.with_objdump, args.elf), sort_keys=True, indent=2))

if __name__ == "__main__":
    main()
