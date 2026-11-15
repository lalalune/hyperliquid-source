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


def facts(window, base):
    """Decode only the listed instructions, not a general x86 decoder or emulator."""
    def at(va, n):
        i = va - base
        require(0 <= i and i + n <= len(window), "instruction outside excerpt")
        return window[i:i+n]

    def rel8(va, n):
        return va + n + struct.unpack("<b", at(va, n)[n - 1:n])[0]

    def rel32_call(va):
        call = at(va, 5)
        require(call[0] == 0xe8, "direct call opcode")
        return va + 5 + struct.unpack_from("<i", call, 1)[0]

    require(at(0x41b3000, 9) == bytes.fromhex("415741564155415453"), "entry register saves")
    require(at(0x41b3009, 4) == bytes.fromhex("4883ec20"), "entry stack frame")
    require(at(0x41b300d, 3) == bytes.fromhex("4d89c7"), "incoming r8 save")
    require(at(0x41b3010, 3) == bytes.fromhex("4989f6"), "incoming rsi save")
    require(at(0x41b3013, 3) == bytes.fromhex("4889fb"), "incoming rdi save")
    require(at(0x41b3016, 10) == bytes.fromhex("49bc0000000000000080"), "result head constant")
    require(at(0x41b3020, 2) == bytes.fromhex("31c0"), "guard zero")
    require(at(0x41b3022, 3) == bytes.fromhex("483b06"), "guard compare")
    require(at(0x41b3025, 2) == bytes.fromhex("711e"), "guard branch opcode")
    require(rel8(0x41b3025, 2) == 0x41b3045, "guard branch destination")
    require(at(0x41b3027, 4) == bytes.fromhex("498b7e28"), "first string input")
    require(at(0x41b302b, 3) == bytes.fromhex("4889d6"), "first string arg registers")
    require(at(0x41b302e, 3) == bytes.fromhex("4889ca"), "first string arg registers")
    require(rel32_call(0x41b3031) == 0x41c6110, "first string writer destination")
    require(at(0x41b3036, 4) == bytes.fromhex("4883f802"), "first string result compare")
    require(at(0x41b303a, 2) == bytes.fromhex("754e"), "first string error branch opcode")
    require(rel8(0x41b303a, 2) == 0x41b308a, "first string error branch destination")
    require(at(0x41b303c, 4) == bytes.fromhex("4983c404"), "head increment")
    require(at(0x41b3040, 3) == bytes.fromhex("4c8923"), "head store")
    require(at(0x41b3043, 2) == bytes.fromhex("eb34"), "writer path jump opcode")
    require(rel8(0x41b3043, 2) == 0x41b3079, "writer path jump destination")
    require(at(0x41b3045, 3) == bytes.fromhex("4c89f7"), "second string input")
    require(at(0x41b3048, 3) == bytes.fromhex("4889d6"), "second string arg registers")
    require(at(0x41b304b, 3) == bytes.fromhex("4889ca"), "second string arg registers")
    require(rel32_call(0x41b304e) == 0x41c6610, "second string writer destination")
    require(at(0x41b3053, 4) == bytes.fromhex("4883f802"), "second string result compare")
    require(at(0x41b3057, 2) == bytes.fromhex("753e"), "second string error branch opcode")
    require(rel8(0x41b3057, 2) == 0x41b3097, "second string error branch destination")
    require(at(0x41b3059, 4) == bytes.fromhex("418b4620"), "counter load")
    require(at(0x41b305d, 3) == bytes.fromhex("83f8ff"), "counter limit compare")
    require(at(0x41b3060, 6) == bytes.fromhex("0f848b000000"), "counter limit branch")
    require(0x41b3066 + struct.unpack_from("<i", at(0x41b3060, 6), 2)[0] == 0x41b30f1,
            "counter limit branch destination")
    require(at(0x41b3066, 2) == bytes.fromhex("ffc0"), "counter increment")
    require(at(0x41b3068, 4) == bytes.fromhex("41894620"), "counter store")
    require(at(0x41b306c, 5) == bytes.fromhex("4d8d6c2404"), "head plus four")
    require(at(0x41b3071, 3) == bytes.fromhex("4c892b"), "head store")
    require(at(0x41b3074, 3) == bytes.fromhex("4d3926"), "head guard compare")
    require(at(0x41b3077, 2) == bytes.fromhex("753a"), "helper branch opcode")
    require(rel8(0x41b3077, 2) == 0x41b30b3, "helper branch destination")
    require(at(0x41b3079, 4) == bytes.fromhex("498b5628"), "writer input field")
    require(at(0x41b307d, 3) == bytes.fromhex("4889df"), "writer output register")
    require(at(0x41b3080, 3) == bytes.fromhex("4c89fe"), "writer serializer register")
    require(rel32_call(0x41b3083) == 0x3c453f0, "writer destination")
    require(at(0x41b3088, 2) == bytes.fromhex("eb18"), "post-call jump opcode")
    require(rel8(0x41b3088, 2) == 0x41b30a2, "post-call jump destination")
    require(at(0x41b308a, 4) == bytes.fromhex("48894308"), "first error result store")
    require(at(0x41b308e, 4) == bytes.fromhex("48895310"), "first error result store")
    require(at(0x41b3092, 3) == bytes.fromhex("4c8923"), "first error head store")
    require(at(0x41b3095, 2) == bytes.fromhex("eb0b"), "first error exit jump opcode")
    require(rel8(0x41b3095, 2) == 0x41b30a2, "first error exit jump destination")
    require(at(0x41b3097, 3) == bytes.fromhex("4c8923"), "second error head store")
    require(at(0x41b309a, 4) == bytes.fromhex("48894308"), "second error result store")
    require(at(0x41b309e, 4) == bytes.fromhex("48895310"), "second error result store")
    require(at(0x41b30a2, 3) == bytes.fromhex("4889d8"), "return value")
    require(at(0x41b30a5, 4) == bytes.fromhex("4883c420"), "epilogue stack restore")
    require(at(0x41b30a9, 10) == bytes.fromhex("5b415c415d415e415fc3"), "epilogue restores and return")
    require(at(0x41b30b3, 5) == bytes.fromhex("488d7c2408"), "helper output address")
    require(at(0x41b30b8, 3) == bytes.fromhex("4c89fe"), "helper serializer register")
    require(at(0x41b30bb, 3) == bytes.fromhex("4c89f2"), "helper input register")
    require(rel32_call(0x41b30be) == 0x3c45120, "second helper destination")
    require(at(0x41b30c3, 5) == bytes.fromhex("4c396c2408"), "helper result compare")
    require(at(0x41b30c8, 2) == bytes.fromhex("7514"), "helper mismatch branch opcode")
    require(rel8(0x41b30c8, 2) == 0x41b30de, "helper mismatch branch destination")
    require(at(0x41b30ca, 4) == bytes.fromhex("418b4620"), "helper path counter load")
    require(at(0x41b30ce, 3) == bytes.fromhex("83f8ff"), "helper path counter limit compare")
    require(at(0x41b30d1, 2) == bytes.fromhex("741e"), "helper path counter limit branch opcode")
    require(rel8(0x41b30d1, 2) == 0x41b30f1, "helper path counter limit branch destination")
    require(at(0x41b30d3, 2) == bytes.fromhex("ffc0"), "helper path counter increment")
    require(at(0x41b30d5, 4) == bytes.fromhex("41894620"), "helper path counter store")
    require(at(0x41b30d9, 3) == bytes.fromhex("4c892b"), "helper path head store")
    require(at(0x41b30dc, 2) == bytes.fromhex("ebc4"), "helper path exit jump opcode")
    require(rel8(0x41b30dc, 2) == 0x41b30a2, "helper path exit jump destination")
    require(at(0x41b30de, 5) == bytes.fromhex("488b442418"), "helper mismatch result load")
    require(at(0x41b30e3, 4) == bytes.fromhex("48894310"), "helper mismatch result store")
    require(at(0x41b30e7, 5) == bytes.fromhex("0f10442408"), "helper mismatch result copy")
    require(at(0x41b30ec, 3) == bytes.fromhex("0f1103"), "helper mismatch head copy")
    require(at(0x41b30ef, 2) == bytes.fromhex("ebb1"), "helper mismatch exit jump opcode")
    require(rel8(0x41b30ef, 2) == 0x41b30a2, "helper mismatch exit jump destination")
    lea = at(0x41b30f1, 7)
    require(lea[:3] == bytes.fromhex("488d3d"), "abort pointer load")
    abort_ptr = 0x41b30f8 + struct.unpack_from("<i", lea, 3)[0]
    require(abort_ptr == 0x6481ff8, "abort pointer target")
    call = at(0x41b30f8, 6)
    require(call[:2] == bytes.fromhex("ff15"), "abort indirect call opcode")
    slot = 0x41b30fe + struct.unpack_from("<i", call, 2)[0]
    require(slot == 0x64df520, "abort indirect call slot")
    return {"caller": "0x41b3000", "writer_call": "0x41b3083", "writer": hex(0x3c453f0),
            "input": "incoming RSI + 0x28 via R14", "writer_output": "incoming RDI via RBX",
            "writer_serializer": "incoming R8 via R15",
            "second_helper_call": "0x41b30be", "second_helper": "0x3c45120",
            "abort_branch": "0x41b30f1", "head": "0x8000000000000000"}


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
    start, fde = entries[bisect.bisect_right(starts, 0x41b3000)-1]
    require(start == 0x41b3000 and fde == int(pins["caller_fde"]["fde_va"], 16), "unwind index entry")
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
    require(initial == start and start+extent == 0x41b30fe, "decoded FDE extent")
    body = data[off(start):off(start)+extent]
    require(hashlib.sha256(body).hexdigest() == pins["caller_fde"]["body_sha256"], "caller body hash")
    w = pins["excerpt"]
    a, z = int(w["start"], 16), int(w["end"], 16)
    window = data[off(a):off(z)]
    require(z-a <= 512 and window.hex() == w["raw_hex"], "retained excerpt")
    observed = facts(window, a)
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
        require(any(va == 0x41b3083 and text.startswith("call") and "3c453f0" in text for va, raw, text in decoded), "aligned writer call")
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
