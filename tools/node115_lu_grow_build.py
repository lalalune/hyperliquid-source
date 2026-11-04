#!/usr/bin/env python3
"""Static verifier for RE-001-node115-lu-grow-build.

Checks the node #115 binary (never executed) against the packet:
binary digest/size, FDE bytes and hashes, body/tail splits, ret bytes,
pinned opcode sites, GOT relocations, panic Locations, direct-caller
census (with displacement recomputation), claimed-range disjointness
from packets #183-#196, and packet/records agreement.
Returns exit 0 only when every check passes.
"""
import hashlib
import json
import os
import re
import struct
import subprocess
import sys

BINARY_SHA256 = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
BINARY_SIZE = 105896032

PACKET_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..",
    "research", "work-items", "RE-001-node115-lu-grow-build")

# name -> (start, end, ret or None, full sha, body sha or None)
FDES = {
    "grow": (0x5155EC0, 0x5156053, 0x5155FDD,
             "3ed34fc96c72a81a93bbc728b4c59dd56086fa7e2b31295e276175b79674fe58",
             "d39f3dda5f79e649a6f8b57065675f2467d9611f17e407bf553386067b7c74d8"),
    "build": (0x4CBD730, 0x4CBDCB0, 0x4CBDBE0,
              "b5f3e07d7c0da9d0fa6ec9e7e0973f768fce220a279cbf386c1fe9a368996bbc",
              "f22415432c1f16a1dbf5fa678c9da1c96d0ce22bbda8586da1632452c75d24a3"),
    "iter": (0x4D58320, 0x4D5845A, None,
             "b14162b03a5aaa422626b6e82e239daa1377f9b9d32cf4033e8a4d693d4f3b88",
             None),
    "drain": (0x5B9F6F0, 0x5B9F898, 0x5B9F83F,
              "df31a2f3aa27f8d54c6a49a055670b67ec3b00a85e93788c6b4c180c5ce1bfc7",
              "1ed4e60164b5060a72d661ee104d063d922a27a43fca9a6a5227d9c965b84e78"),
    "sort_small": (0x53EF680, 0x53EF73C, None,
                   "f3e884289978335f149eab5415e89aad3b37193d7a40426a402e0d4e78aba985",
                   None),
    "sort_large_wrap": (0x4F3FD80, 0x4F3FE90, 0x4F3FE52,
                        "d5bb2e20816db3d19088314d4c1445e22c81e78a5695e4796a51654b20e0d9d4",
                        None),
}

# (address, exact bytes) pinned opcode sites
BYTE_CHECKS = [
    (0x4DCD0BD, "e8 fe 8d 38 00"),   # flag helper -> grow
    (0x5155EE9, "e8 02 98 a4 00"),   # grow -> drain
    (0x5155F1A, "bf e8 00 00 00"),   # grow leaf alloc 232
    (0x5155FDE, "49 83 ff 15"),      # grow sort dispatch cmp len,21
    (0x5155FF4, "e8 87 96 29 00"),   # grow -> small sort
    (0x515601B, "ff 15 bf 5a 39 01"),  # grow -> large sort GOT
    (0x5155F89, "e8 a2 77 b6 ff"),   # grow -> build
    (0x5155F75, "c6 44 24 70 03"),   # grow range flag byte 3
    (0x4CBD88B, "e8 90 aa 09 00"),   # build -> iterator
    (0x4CBD896, "41 80 fe 02"),      # build flag == 2 check
    (0x4CBD8B1, "48 83 f8 0b"),      # build count == 11 check
    (0x4CBDBCB, "e8 50 60 fd ff"),   # build post-pass -> redistribute-left
    (0x4D58342, "80 fa 03"),         # iterator state == 3 check
    (0x4D5841C, "c6 46 30 02"),      # iterator state = 2
    (0x4D58422, "c6 46 30 03"),      # iterator state = 3 (end path)
    (0x4D58426, "c6 40 10 02"),      # iterator out flag = 2
    (0x53EF6D7, "41 0f c8"),         # small sort bswap
    (0x53EF6DA, "0f ce"),            # small sort bswap
    (0x4F3FDA6, "41 bc 15 16 05 00"),  # large wrapper min bound 333333
    (0x4F3FDB7, "49 81 fc ab 00 00 00"),  # large wrapper heap threshold 171
    (0x5B9F823, "4c 89 2b"),         # drain out length
    (0x5B9F826, "4c 89 7b 08"),      # drain out buffer
    (0x5B9F82A, "4c 89 63 10"),      # drain out count
]

# (call site, expected target) — displacement recomputed
E8_CALLERS = {
    0x4DCD0BD: 0x5155EC0,
    0x5155EE9: 0x5B9F6F0,
    0x5155F89: 0x4CBD730,
    0x5155FF4: 0x53EF680,
    0x515D223: 0x4CBD730,
    0x4CBD88B: 0x4D58320,
    0x4CBDBCB: 0x4C93C20,
    0x4F3FE21: 0x4F6D1E0,
    0x4DE6306: 0x53EF680,
    0x515D28E: 0x53EF680,
    0x4E6C40D: 0x4F6D1E0,
    0x4D2497B: 0x4C93C20,
    0x4D24F12: 0x4C93C20,
    0x4D24967: 0x4CA2500,
}

# GOT slot -> expected relocation addend (hex, no 0x)
GOT_CHECKS = {
    0x64DF480: "6355830",
    0x64DF490: "141e251",
    0x64DF498: "141e264",
    0x64DF4A0: "635de30",
    0x64DF730: "1680e60",
    0x64DF830: "1680c10",
    0x64EBAE0: "4f3fd80",
}

# Location struct VA -> (file string VA, file len, line, col)
LOCATIONS = {
    0x649A468: (0x4344F8, 91, 367, 9),
    0x649A4E0: (0x4344F8, 91, 698, 9),
    0x649A4F8: (0x4344F8, 91, 240, 77),
}

# (message VA, length, expected bytes prefix)
MESSAGES = [
    (0x913338, 25, b"assertion failed: len > 0"),
    (0x4585C0, 32, b"assertion failed: idx < CAPACITY"),
]

# Prior packets' claimed FDE ranges (#185, #187-#196, exact sizes only) —
# new claims must not overlap
PRIOR_RANGES = [
    (0x5CF3B90, 0x5CF3B90 + 162),    # #185 coop
    (0x5CFC310, 0x5CFC310 + 195),    # #185 proceed
    (0x5CFD8C0, 0x5CFD8C0 + 209),    # #187 wake
    (0x5BB42E0, 0x5BB42E0 + 899),    # #188 park
    (0x5BB6790, 0x5BB6790 + 329),    # #189 contention helper
    (0x5BB2440, 0x5BB2440 + 4525),   # #190 timed wait
    (0x5BB3CA0, 0x5BB3CA0 + 417),    # #191 timeout handler
    (0x5BB1A60, 0x5BB1A60 + 1706),   # #192 RwLock read wait
    (0x5BB35F0, 0x5BB35F0 + 1700),   # #193 grant-wake
    (0x4FB52E0, 0x4FB52E0 + 341),    # #194 gate-release
    (0x4DCCF20, 0x4DCCF20 + 992),    # #195 flag helper
    (0x4DA86A0, 0x4DA86A0 + 443),    # #195 completion helper
    (0x4D24790, 0x4D24790 + 2008),   # #196 leaf op
]


def fail(msg):
    raise AssertionError(msg)


def txt(va, n, data):
    off = va - 0x1000
    return data[off:off + n]


def dr(va, n, data):
    off = va - 0x2000
    return data[off:off + n]


def parse_objdump(path):
    """Return list of (addr, mnemonic-text) for real instructions only."""
    ins = []
    pat = re.compile(r"\s+([0-9a-f]+):\t[0-9a-f ]+\t(.*)")
    with open(path) as f:
        for line in f:
            m = pat.match(line)
            if m and m.group(2).strip():
                ins.append((int(m.group(1), 16), m.group(2).strip()))
    return ins


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # tools/ is repo-root/tools; packet dir is computed from this file
    # (this file lives in tools/, packet under research/work-items/)
    binpath = os.path.join(root, "artifacts", "node", "115", "hl-node")
    if not os.path.exists(binpath):
        # also try cwd-relative (make test runs from repo root)
        binpath = os.path.join("artifacts", "node", "115", "hl-node")
    with open(binpath, "rb") as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != BINARY_SHA256:
        fail("binary digest mismatch")
    if len(data) != BINARY_SIZE:
        fail("binary size mismatch")

    records = json.load(open(os.path.join(PACKET_DIR, "records.json")))

    # FDE bytes, hashes, rets, packet hex agreement
    for name, (s, e, ret, full_sha, body_sha) in FDES.items():
        raw = txt(s, e - s, data)
        if hashlib.sha256(raw).hexdigest() != full_sha:
            fail(f"{name} FDE sha mismatch")
        pkt = open(os.path.join(PACKET_DIR, name + ".hex")).read().strip()
        if pkt != raw.hex():
            fail(f"{name} packet hex mismatch")
        if ret is not None:
            if raw[ret - s] != 0xC3:
                fail(f"{name} ret byte not c3 at {hex(ret)}")
            body = raw[:ret + 1 - s]
            if body_sha and hashlib.sha256(body).hexdigest() != body_sha:
                fail(f"{name} body sha mismatch")
        # packet objdump instruction count agreement
        ins = parse_objdump(os.path.join(PACKET_DIR, name + ".objdump.txt"))
        if len(ins) != records[name]["instructions"]:
            fail(f"{name} objdump count {len(ins)} != records "
                 f"{records[name]['instructions']}")
        if ins[0][0] != s or ins[-1][0] < e - 32:
            fail(f"{name} objdump range does not span FDE")

    # iterator has two rets
    for r in (0x4D5842E, 0x4D58459):
        if txt(r, 1, data) != b"\xc3":
            fail(f"iter ret byte not c3 at {hex(r)}")

    # pinned bytes
    for addr, hexs in BYTE_CHECKS:
        got = txt(addr, len(hexs.split()), data).hex(" ")
        if got != hexs:
            fail(f"bytes at {hex(addr)}: {got} != {hexs}")

    # E8 caller displacement recomputation
    for site, target in E8_CALLERS.items():
        b = txt(site, 5, data)
        if b[0] != 0xE8:
            fail(f"not a call at {hex(site)}")
        disp = struct.unpack("<i", b[1:5])[0]
        if site + 5 + disp != target:
            fail(f"call at {hex(site)} targets {hex(site + 5 + disp)}, "
                 f"expected {hex(target)}")

    # GOT relocations
    rel = subprocess.run(["readelf", "-r", binpath],
                         capture_output=True, text=True).stdout
    relmap = {}
    for line in rel.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].startswith("00000"):
            relmap[parts[0]] = parts[-1]
    for slot, addend in GOT_CHECKS.items():
        key = "00000" + format(slot, "x")
        if relmap.get(key) != addend:
            fail(f"GOT slot {hex(slot)}: {relmap.get(key)} != {addend}")

    # panic Locations: file ptr relocation, len, line, col, message bytes
    for struct_va, (fva, flen, line, col) in LOCATIONS.items():
        key = "00000" + format(struct_va, "x")
        if relmap.get(key) != format(fva, "x"):
            fail(f"Location {hex(struct_va)} file ptr reloc mismatch")
        raw = dr(struct_va, 24, data)
        _fptr, flen_got, linecol = struct.unpack("<QQQ", raw)
        if flen_got != flen:
            fail(f"Location {hex(struct_va)} file len mismatch")
        if (linecol & 0xFFFFFFFF) != line or (linecol >> 32) != col:
            fail(f"Location {hex(struct_va)} line/col mismatch")
    for mva, mlen, prefix in MESSAGES:
        got = data[mva:mva + mlen]
        if got != prefix:
            fail(f"message at {hex(mva)} mismatch: {got!r}")

    # claimed-range disjointness from prior packets
    for name, (s, e, _r, _f, _b) in FDES.items():
        for ps, pe in PRIOR_RANGES:
            if s < pe and ps < e:
                fail(f"{name} range overlaps prior range {hex(ps)}..{hex(pe)}")

    # records agreement on sizes
    for name, (s, e, _r, _f, _b) in FDES.items():
        if records[name]["bytes"] != e - s:
            fail(f"{name} records size mismatch")

    print("grow-build verifier: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
