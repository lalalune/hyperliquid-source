"""Static verifier for the node #115 lu grant-wake callers packet.

Answers hyperliquid-source packet #193's (PR #2258) next question: which
caller path grants explicitly (esi = 1), and what unlock or timeout
operation does it belong to. The answer is that no static caller grants
explicitly: all 66 grant-wake GOT sites pass esi = 0, and the 58
mov esi,0x1 sites inside the same 26 caller FDEs all feed other callees.

The worked example is FDE 0x4fb52e0..0x4fb5435: a gate-release operation
(acquire slot 0 -> 8, indexed payload, release 8 -> 0, grant-wake fallback
with esi = 0 on release failure, on both the normal and unwind paths).

This verifier reads bytes only. It never executes the node binary. It
checks the binary digest, the exact FDE bytes, opcode spot checks, ELF
relocation addends for the GOT slots the census uses, the panic Location,
the packet hex reference, the packet records, the 66-site esi census
(every site's xor bytes and rdi-writer bytes, with the site set re-derived
by an every-position byte scan over .text), and the 58-site mov esi,1
census (byte scan inside the 26 caller FDE ranges, each site's next
indirect call resolving to a non-grant GOT slot).

Usage: python3 tools/node115_lu_grant_callers.py [binary-path]
"""

import hashlib
import json
import struct
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
PACKET = REPO / "research" / "work-items" / "RE-001-node115-lu-grant-callers"
DEFAULT_BINARY = REPO / "artifacts" / "node" / "115" / "hl-node"

BINARY_SIZE = 105896032
BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"

FDE_START = 0x4FB52E0
FDE_END = 0x4FB5435
FDE_BYTES = 341
BODY_SHA256 = "11531754ab1dd77cf9c351f947de43c62bf03221a5a328cb5ab8b23349e96705"
RET_ADDR = 0x4FB53BA
BODY_BYTES = 219
TAIL_BYTES = 122

GRANT_FDE = 0x5BB35F0
GRANT_SLOT = 0x64E1000

# file offset = VA - 0x1000 for .text
TEXT_OFF = lambda va: va - 0x1000


def _expect(data, va, want, message):
    off = TEXT_OFF(va)
    got = data[off:off + len(want)]
    if got != want:
        raise ValueError("%s: %#x has %s, want %s" % (message, va, got.hex(), want.hex()))


def parse_sections(data):
    """Return (sections, rela) where sections maps name -> (addr, offset, size)
    and rela maps r_offset -> addend for R_X86_64_RELATIVE entries."""
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
    (_n, _t, _f, _str_addr, shstr_off, _s) = struct.unpack_from("<IIQQQQ", data, str_off)

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
    """Every-position scan over .text: 0 direct E8 callers of the grant FDE
    and 66 GOT-indirect (call/jmp [rip+disp]) sites resolving to 0x64e1000.
    Returns (e8, got_sites, got_calls, got_jmps, site_set)."""
    (t_addr, t_off, t_size, _t) = by_name[".text"]
    text = data[t_off:t_off + t_size]
    base = t_addr
    e8 = 0
    got = 0
    got_calls = 0
    got_jmps = 0
    site_set = set()
    for i in range(len(text) - 6):
        b0 = text[i]
        b1 = text[i + 1]
        if b0 == 0xE8:
            (rel,) = struct.unpack_from("<i", text, i + 1)
            if base + i + 5 + rel == GRANT_FDE:
                e8 += 1
        elif b0 == 0xFF and b1 in (0x15, 0x25):
            (disp,) = struct.unpack_from("<i", text, i + 2)
            if base + i + 6 + disp == GRANT_SLOT:
                got += 1
                site_set.add(base + i)
                if b1 == 0x15:
                    got_calls += 1
                else:
                    got_jmps += 1
    return e8, got, got_calls, got_jmps, site_set


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
        raise ValueError("Exact FDE changed: range is not 341 bytes")
    if hashlib.sha256(fde).hexdigest() != BODY_SHA256:
        raise ValueError("Exact FDE changed: body digest mismatch")
    if data[TEXT_OFF(RET_ADDR)] != 0xC3:
        raise ValueError("ret opcode changed: %#x" % RET_ADDR)
    if RET_ADDR + 1 - FDE_START != BODY_BYTES or FDE_END - (RET_ADDR + 1) != TAIL_BYTES:
        raise ValueError("body/tail split changed")

    # opcode spot checks (checked before the slow census so corruption fails fast)
    _expect(data, 0x4FB52F7, bytes.fromhex("f0480fb14e10"), "gate acquire cmpxchg changed")
    _expect(data, 0x4FB53AA, bytes.fromhex("f0480fb10b"), "gate release cmpxchg changed")
    _expect(data, 0x4FB5413, bytes.fromhex("f0480fb10b"), "unwind release cmpxchg changed")
    _expect(data, 0x4FB53C9, bytes.fromhex("ff1521bc5201"), "timed-wait call changed")
    _expect(data, 0x4FB53E8, bytes.fromhex("ff2512bc5201"), "grant jmp changed")
    _expect(data, 0x4FB5427, bytes.fromhex("ff15d3bb5201"), "grant call changed")
    _expect(data, 0x4FB53DD, bytes.fromhex("31f6"), "jmp-site xor changed")
    _expect(data, 0x4FB5425, bytes.fromhex("31f6"), "unwind grant xor changed")
    _expect(data, 0x4FB530F, bytes.fromhex("e80c7ce1ff"), "flag helper call changed")
    _expect(data, 0x4FB539E, bytes.fromhex("e8fd32dfff"), "completion helper call changed")
    _expect(data, 0x4FB5407, bytes.fromhex("0f0b"), "unwind ud2 changed")

    # relocation addends for the census GOT slots
    by_name, rela = parse_sections(data)
    want_addends = {
        0x64E1000: 0x5BB35F0,  # grant-wake (#193)
        0x64E0FF0: 0x5BB2440,  # timed wait (#190)
        0x64DF9F0: 0x5C87D50,  # shared esi=1 helper
        0x64E0FF8: 0x1557260,  # esi=1 callee
        0x64E1070: 0x155A430,  # esi=1 callee
        0x64E1080: 0x1559E80,  # esi=1 callee
    }
    for slot, want in want_addends.items():
        if rela.get(slot) != want:
            raise ValueError("relocation changed: slot %#x" % slot)

    # panic Location struct (file, line, col) in .data.rel.ro
    loc_off = va_to_off(by_name, 0x649CC08)
    (_ptr, _len, line, col) = struct.unpack_from("<QQII", data, loc_off)
    if (line, col) != (64, 17):
        raise ValueError("panic location changed: 0x649cc08")
    msg_off = va_to_off(by_name, 0x9171A2)
    if data[msg_off:msg_off + 20] != b"Out of bounds access":
        raise ValueError("panic message changed")
    file_off = va_to_off(by_name, 0x4402CD)
    if data[file_off:file_off + 24] != b"base/src/l1_map/entry.rs":
        raise ValueError("panic file string changed")

    # packet references
    hex_text = (PACKET / "fde52e0.hex").read_text()
    if bytes.fromhex("".join(hex_text.split())) != fde:
        raise ValueError("Body reference changed")
    record = json.loads((PACKET / "records.json").read_text())
    fde_rec = record["fde"]
    if (fde_rec["start"] != "0x4fb52e0" or fde_rec["end"] != "0x4fb5435"
            or fde_rec["bytes"] != FDE_BYTES or fde_rec["body_sha256"] != BODY_SHA256
            or fde_rec["ret"] != "0x4fb53ba" or fde_rec["body_bytes"] != BODY_BYTES
            or fde_rec["tail_bytes"] != TAIL_BYTES):
        raise ValueError("Exact FDE changed: records.json disagrees with binary")

    # 66-site esi census: xor bytes, rdi-writer bytes, and the site set
    rec_sites = record["sites"]
    if len(rec_sites) != 66:
        raise ValueError("site count changed: %d" % len(rec_sites))
    for entry in rec_sites:
        site = int(entry["site"], 16)
        xor_addr = int(entry["xor_addr"], 16)
        if data[TEXT_OFF(xor_addr):TEXT_OFF(xor_addr) + 2] != bytes.fromhex("31f6"):
            raise ValueError("site xor changed: %s" % entry["site"])
        w = int(entry["rdi_writer"], 16)
        want = bytes.fromhex(entry["rdi_writer_bytes"])
        if data[TEXT_OFF(w):TEXT_OFF(w) + len(want)] != want:
            raise ValueError("rdi writer changed: %s" % entry["site"])
        if entry["kind"] == "jmp" and entry["site"] != "0x4fb53e8":
            raise ValueError("unexpected jmp site: %s" % entry["site"])

    # caller census (slow pass)
    e8, got, got_calls, got_jmps, site_set = census(data, by_name)
    if e8 != 0 or got != 66 or got_calls != 65 or got_jmps != 1:
        raise ValueError("GOT census changed: e8=%d got=%d calls=%d jmps=%d" % (e8, got, got_calls, got_jmps))
    if site_set != set(int(e["site"], 16) for e in rec_sites):
        raise ValueError("GOT site set changed vs records.json")

    # 58-site mov esi,1 census inside the 26 caller FDE ranges
    fde_ends = record["census"]["fde_ends"]
    mov_sites = []
    for fde_s in record["census"]["caller_fdes"]:
        start = int(fde_s, 16)
        end = int(fde_ends[fde_s], 16)
        blob = data[TEXT_OFF(start):TEXT_OFF(end)]
        i = 0
        while True:
            j = blob.find(b"\xbe\x01\x00\x00\x00", i)
            if j < 0:
                break
            mov_sites.append(start + j)
            i = j + 1
    rec_mov = record["mov_esi_1_census"]["sites"]
    if len(mov_sites) != 58 or len(rec_mov) != 58:
        raise ValueError("mov esi,1 count changed: scan=%d records=%d" % (len(mov_sites), len(rec_mov)))
    if set(mov_sites) != set(int(e["mov_site"], 16) for e in rec_mov):
        raise ValueError("mov esi,1 site set changed vs records.json")
    resolutions = record["mov_esi_1_census"]["got_resolutions"]
    for entry in rec_mov:
        nxt = int(entry["next_addr"], 16)
        got_slot = int(entry["next_got"], 16)
        if got_slot == GRANT_SLOT:
            raise ValueError("mov esi,1 feeds grant slot: %s" % entry["mov_site"])
        raw = data[TEXT_OFF(nxt):TEXT_OFF(nxt) + 6]
        if raw[0] != 0xFF or raw[1] != 0x15:
            raise ValueError("mov esi,1 next call changed: %s" % entry["mov_site"])
        (disp,) = struct.unpack_from("<i", raw, 2)
        if nxt + 6 + disp != got_slot:
            raise ValueError("mov esi,1 next GOT changed: %s" % entry["mov_site"])
        if rela.get(got_slot) != int(resolutions[entry["next_got"]], 16):
            raise ValueError("mov esi,1 GOT resolution changed: %s" % entry["next_got"])

    return {
        "fde": {"start": hex(FDE_START), "end": hex(FDE_END), "bytes": FDE_BYTES,
                "body_sha256": BODY_SHA256, "ret": hex(RET_ADDR),
                "body_bytes": BODY_BYTES, "tail_bytes": TAIL_BYTES},
        "census": {"e8_callers": e8, "got_sites": got, "got_calls": got_calls,
                   "got_jmps": got_jmps, "got_slot": "0x64e1000"},
        "esi_census": {"sites_with_esi_0": 66, "sites_with_esi_1": 0},
        "mov_esi_1_census": {"count": 58, "feeding_grant": 0},
    }


def main(argv):
    path = Path(argv[1]) if len(argv) > 1 else DEFAULT_BINARY
    record = verify(path.read_bytes())
    print(json.dumps(record, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
