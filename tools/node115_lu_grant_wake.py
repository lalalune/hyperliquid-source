"""Static verifier for the node #115 lu grant-wake packet.

Answers hyperliquid-source packet #192's next question (a): who writes
waiter node +0x10 = 1. The writer is FDE 0x5bb35f0..0x5bb3c94: its reset
loop stores [node+0x10] = bpl (the grant flag) for every collected waiter
node and then futex-wakes each node's +0x20 word.

This verifier reads bytes only. It never executes the node binary. It
checks the binary digest, the exact FDE bytes, opcode spot checks, ELF
relocation addends for the GOT slots the FDE uses, the panic Location
structs, the packet hex reference, the packet records, and the caller
census (0 direct E8 callers, 66 GOT-indirect sites via slot 0x64e1000,
counted by an every-position byte scan over .text that matches the
objdump-boundary census exactly).

Usage: python3 tools/node115_lu_grant_wake.py [binary-path]
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-001-node115-lu-grant-wake"
DEFAULT_BINARY = REPO / "artifacts" / "node" / "115" / "hl-node"

BINARY_SIZE = 105896032
BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

FDE_START = 0x5BB35F0
FDE_END = 0x5BB3C94
FDE_BYTES = 1700
BODY_SHA256 = "026fbc7f26d2434e257dc9cbe5f7aa75a7afe89dace5cc3c541961d144d28e75"
RET_ADDR = 0x5BB3BC8
BODY_BYTES = 1497
TAIL_BYTES = 203

# file offset = VA - 0x1000 for .text
TEXT_OFF = lambda va: va - 0x1000


def _expect(data, va, want, message):
    off = TEXT_OFF(va)
    got = data[off:off + len(want)]
    if got != want:
        raise ValueError("%s: %#x has %s, want %s" % (message, va, got.hex(), want.hex()))


def _rip_target(va, instr_end, disp):
    return instr_end + disp


def parse_sections(data):
    """Return (sections, rela) where sections maps name -> (addr, offset, size)
    and rela maps r_offset -> (type, addend) for R_X86_64_RELATIVE entries."""
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("not a 64-bit little-endian ELF file")
    (e_shoff,) = struct.unpack_from("<Q", data, 0x28)
    (e_shentsize, e_shnum, e_shstrndx) = struct.unpack_from("<HHH", data, 0x3A)
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        (name, stype, _flags, addr, offset, size) = struct.unpack_from("<IIQQQQ", data, off)
        sections.append((name, stype, addr, offset, size))
    str_off = e_shoff + e_shstrndx * e_shentsize
    (_n, _t, _f, str_addr, shstr_off, _s) = struct.unpack_from("<IIQQQQ", data, str_off)
    del str_addr

    def get_str(name_off):
        end = data.index(b"\x00", shstr_off + name_off)
        return data[shstr_off + name_off:end].decode()

    by_name = {}
    for (name_off, stype, addr, offset, size) in sections:
        by_name[get_str(name_off)] = (addr, offset, size, stype)
    rela = {}
    for (addr, offset, size, stype) in by_name.values():
        if stype == 4:  # SHT_RELA
            for j in range(0, size, 24):
                (r_offset, r_info, r_addend) = struct.unpack_from("<QQq", data, offset + j)
                r_type = r_info & 0xFFFFFFFF
                if r_type == 8:  # R_X86_64_RELATIVE
                    rela[r_offset] = r_addend
    return by_name, rela


def va_to_off(by_name, va):
    for (addr, offset, size, _stype) in by_name.values():
        if addr <= va < addr + size:
            return offset + (va - addr)
    raise ValueError("VA %#x not in any section" % va)


def census(data, by_name):
    """Every-position scan over .text: 0 direct E8 callers of the FDE and
    66 GOT-indirect (call/jmp [rip+disp]) sites resolving to 0x64e1000."""
    (t_addr, t_off, t_size, _t) = by_name[".text"]
    text = data[t_off:t_off + t_size]
    base = t_addr
    slot = 0x64E1000
    target = FDE_START
    e8 = 0
    got = 0
    got_calls = 0
    got_jmps = 0
    for i in range(len(text) - 6):
        b0 = text[i]
        b1 = text[i + 1]
        if b0 == 0xE8:
            (rel,) = struct.unpack_from("<i", text, i + 1)
            if base + i + 5 + rel == target:
                e8 += 1
        elif b0 == 0xFF and b1 in (0x15, 0x25):
            (disp,) = struct.unpack_from("<i", text, i + 2)
            if base + i + 6 + disp == slot:
                got += 1
                if b1 == 0x15:
                    got_calls += 1
                else:
                    got_jmps += 1
    return e8, got, got_calls, got_jmps


def verify(data=None):
    if data is None:
        data = DEFAULT_BINARY.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != BINARY_SHA256:
        raise ValueError("digest mismatch: %s" % digest)
    if len(data) != BINARY_SIZE:
        raise ValueError("size mismatch: %d, want %d" % (len(data), BINARY_SIZE))

    fde = data[TEXT_OFF(FDE_START):TEXT_OFF(FDE_START) + FDE_BYTES]
    if len(fde) != FDE_BYTES or FDE_END - FDE_START != FDE_BYTES:
        raise ValueError("Exact FDE changed: range is not 1700 bytes")
    if hashlib.sha256(fde).hexdigest() != BODY_SHA256:
        raise ValueError("Exact FDE changed: body digest mismatch")
    if data[TEXT_OFF(RET_ADDR)] != 0xC3:
        raise ValueError("ret opcode changed: %#x" % RET_ADDR)
    if RET_ADDR + 1 - FDE_START != BODY_BYTES or FDE_END - (RET_ADDR + 1) != TAIL_BYTES:
        raise ValueError("body/tail split changed")

    # opcode spot checks (checked before the slow census so corruption fails fast)
    _expect(data, 0x5BB3605, bytes.fromhex("49be157c4a7fb979379e"), "golden ratio changed")
    _expect(data, 0x5BB3681, bytes.fromhex("f0480fb12c39"), "bucket claim cmpxchg changed")
    _expect(data, 0x5BB376A, bytes.fromhex("a808"), "accumulator bit-3 test changed")
    _expect(data, 0x5BB3777, bytes.fromhex("a804"), "accumulator bit-2 test changed")
    _expect(data, 0x5BB3790, bytes.fromhex("4901c5"), "accumulator add changed")
    _expect(data, 0x5BB37E9, bytes.fromhex("4c8924d1"), "vector node store changed")
    _expect(data, 0x5BB38FD, bytes.fromhex("4008cd"), "grant or changed")
    _expect(data, 0x5BB3902, bytes.fromhex("4020c5"), "grant and changed")
    _expect(data, 0x5BB3915, bytes.fromhex("488908"), "slot word store changed")
    _expect(data, 0x5BB393E, bytes.fromhex("400fb6fd"), "movzx edi,bpl changed")
    _expect(data, 0x5BB3983, bytes.fromhex("49897910"), "grant store changed")
    _expect(data, 0x5BB39C3, bytes.fromhex("48897910"), "grant store changed")
    _expect(data, 0x5BB39E5, bytes.fromhex("48897910"), "grant store changed")
    _expect(data, 0x5BB3A08, bytes.fromhex("48897910"), "grant store changed")
    _expect(data, 0x5BB3A2B, bytes.fromhex("48897910"), "grant store changed")
    _expect(data, 0x5BB3A5E, bytes.fromhex("f0480fc103"), "bucket release xadd changed")
    _expect(data, 0x5BB3B1B, bytes.fromhex("48837bf802"), "wake flag-2 skip changed")
    _expect(data, 0x5BB3B25, bytes.fromhex("bfca000000"), "futex number changed")
    _expect(data, 0x5BB3B2A, bytes.fromhex("ba81000000"), "futex op changed")
    _expect(data, 0x5BB3B2F, bytes.fromhex("b901000000"), "futex count changed")
    _expect(data, 0x5BB38B0, bytes.fromhex("c1e60d"), "xorshift 13 changed")
    _expect(data, 0x5BB38B7, bytes.fromhex("c1ef11"), "xorshift 17 changed")
    _expect(data, 0x5BB38BE, bytes.fromhex("c1e105"), "xorshift 5 changed")
    _expect(data, 0x5BB38C6, bytes.fromhex("4869f183de1b43"), "xorshift magic changed")
    _expect(data, 0x5BB38CD, bytes.fromhex("48c1ee32"), "xorshift shift 50 changed")
    _expect(data, 0x5BB38D1, bytes.fromhex("69f640420f00"), "jitter mod 10^6 changed")
    _expect(data, 0x5BB38DB, bytes.fromhex("81f900ca9a3b"), "deadline 10^9 compare changed")
    _expect(data, 0x5BB38EC, bytes.fromhex("81c1003665c4"), "deadline carry changed")

    # rip-relative GOT resolutions inside the FDE
    rip_checks = [
        (0x5BB3618, 0x5BB361F, 0x938B29, 0x64EC148, "table slot changed"),
        (0x5BB361F, 0x5BB3626, 0x938B32, 0x64EC158, "table-create slot changed"),
        (0x5BB362B, 0x5BB3632, 0x938B1E, 0x64EC150, "cleanup slot changed"),
        (0x5BB3632, 0x5BB3639, 0x938B27, 0x64EC160, "helper slot changed"),
        (0x5BB3B07, 0x5BB3B0E, 0x92CBAA, 0x64E06B8, "syscall slot changed"),
        (0x5BB3A95, 0x5BB3A9B, 0x92BA6D, 0x64DF508, "memcpy slot changed"),
        (0x5BB3BB1, 0x5BB3BB7, 0x92B8E9, 0x64DF4A0, "free slot changed"),
    ]
    for (va, end, disp, want, message) in rip_checks:
        if _rip_target(va, end, disp) != want:
            raise ValueError("%s" % message)

    # relocation addends for the family GOT slots
    by_name, rela = parse_sections(data)
    want_addends = {
        0x64EC148: 0x64FFF28,  # table-pointer static (same static as #188 lookup)
        0x64EC150: 0x5BB66B0,  # cleanup
        0x64EC158: 0x5BB6400,  # table creation
        0x64EC160: 0x5BB6790,  # contention helper (#189)
        0x64E1000: 0x5BB35F0,  # this FDE itself
    }
    for slot, want in want_addends.items():
        if rela.get(slot) != want:
            raise ValueError("relocation changed: slot %#x" % slot)

    # panic Location structs (file, line, col) in .data.rel.ro
    def location(va):
        off = va_to_off(by_name, va)
        (_ptr, _len, line, col) = struct.unpack_from("<QQII", data, off)
        return (line, col)

    want_locations = {
        0x64BD260: (352, 45),   # parking_lot.rs subtract (64 - shift)
        0x64BD290: (363, 23),   # parking_lot.rs index bounds
        0x64BD278: (352, 5),    # parking_lot.rs shift
        0x64BD248: (963, 31),   # raw_rwlock.rs +0x18 sum add
        0x64BD2C0: (1124, 13),  # smallvec push capacity
        0x64BD478: (2243, 17),  # smallvec index
    }
    for va, want in want_locations.items():
        if location(va) != want:
            raise ValueError("panic location changed: %#x" % va)
    msg_off = va_to_off(by_name, 0x94A2C1)
    if data[msg_off:msg_off + 40] != b"overflow when adding duration to instant":
        raise ValueError("deadline overflow message changed")

    # packet references
    hex_text = (PACKET / "fde35f0.hex").read_text()
    if bytes.fromhex("".join(hex_text.split())) != fde:
        raise ValueError("Body reference changed")
    record = json.loads((PACKET / "records.json").read_text())
    fde_rec = record["fde"]
    if (fde_rec["start"] != "0x5bb35f0" or fde_rec["end"] != "0x5bb3c94"
            or fde_rec["bytes"] != FDE_BYTES or fde_rec["body_sha256"] != BODY_SHA256
            or fde_rec["ret"] != "0x5bb3bc8" or fde_rec["body_bytes"] != BODY_BYTES
            or fde_rec["tail_bytes"] != TAIL_BYTES):
        raise ValueError("Exact FDE changed: records.json disagrees with binary")

    # caller census (slow pass, last)
    e8, got, got_calls, got_jmps = census(data, by_name)
    if e8 != 0 or got != 66 or got_calls != 65 or got_jmps != 1:
        raise ValueError("GOT census changed: e8=%d got=%d calls=%d jmps=%d" % (e8, got, got_calls, got_jmps))

    return {
        "fde": {"start": hex(FDE_START), "end": hex(FDE_END), "bytes": FDE_BYTES,
                "body_sha256": BODY_SHA256, "ret": hex(RET_ADDR),
                "body_bytes": BODY_BYTES, "tail_bytes": TAIL_BYTES},
        "census": {"e8_callers": e8, "got_sites": got, "got_calls": got_calls,
                   "got_jmps": got_jmps, "got_slot": "0x64e1000"},
    }


def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_BINARY
    record = verify(path.read_bytes())
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
