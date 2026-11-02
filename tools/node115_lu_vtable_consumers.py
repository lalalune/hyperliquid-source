#!/usr/bin/env python3
"""Verify the RE-001-node115-lu-vtable-consumers packet against node #115.

Static only: reads the node binary and the packet files, never executes the
node. Exits non-zero on the first failed check.
"""
import hashlib
import re
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / "research" / "work-items" / "RE-001-node115-lu-vtable-consumers"
NODE = ROOT / "artifacts" / "node" / "115" / "hl-node"

NODE_SHA = "a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301"
NODE_SIZE = 105896032

BODIES = {
    "consumer_caller2": (0x15D6230, 0x15D6310,
                         "4982a51852ff7709fdd0d104296add56d533678116639b9e048b58dd98c9958a"),
    "consumer_statemachine": (0x15D2FB0, 0x15D31C7,
                              "8b9ec6864d1b6d12a4966512a7032e37f85cf2d36231a9b8457a698153adc8a3"),
    "drop_dispatch": (0x15DACD0, 0x15DAD33,
                      "f2bec9916cea0d6777f085c003c668dc9c6bda5537e22b77432fbd4420295aad"),
    "drop_caller2": (0x15E04B0, 0x15E0537,
                     "b0ae26f9b7b2bbc3aabb3870508f6e021f4ee9623d99a60f9b1181f711299193"),
    "drop_statemachine": (0x15D9CA0, 0x15D9D27,
                          "48a28e67e9de8132092d95a6e3e456d14ddc7e80a37a6186f8153a3d75aac505"),
}

# (vtable base, drop addend, size, align, method addend, location slot,
#  line, column)
VTABLES = [
    (0x64012E8, 0x15E04B0, 160, 8, 0x15D5B00, 0x6401308, 159, 64),
    (0x64014A8, 0x15D9CA0, 168, 8, 0x15D6E00, 0x64014C8, 220, 26),
]

GOT_EXPECTED = {
    0x64DF480: 0x6355830,   # allocator
    0x64DF4A0: 0x635DE30,   # deallocator used by drop_dispatch
    0x64DF9F0: 0x5C87D50,   # once helper, shared with #185
    0x64DFDC8: 0x5CE8DA0,   # drop helper, shared with #183
    0x64DFDB8: 0x5CE86D0,   # drop helper, shared with #183
}

LEA_EXPECTED = {
    0x64012E8: [0x15D6272, 0x15D62E0],
    0x64014A8: [0x15D3076, 0x15D3136],
    0x6401300: [],
    0x64014C0: [],
}

E8_EXPECTED = {
    0x15D2FB0: [0x15D869B],
    0x15D6230: [0x1534F75],
    0x15E04B0: [0x15D62FD],
    0x15D9CA0: [0x15D31A1],
    0x15DACD0: None,  # count only: 25
    0x15D6730: None,  # count only: 24
}
E8_COUNTS = {0x15DACD0: 25, 0x15D6730: 24}


def fail(msg):
    raise SystemExit(f"FAIL: {msg}")


def main():
    data = NODE.read_bytes()
    if len(data) != NODE_SIZE:
        fail(f"node size {len(data)} != {NODE_SIZE}")
    if hashlib.sha256(data).hexdigest() != NODE_SHA:
        fail("node digest mismatch")

    def body(va0, va1):
        return data[va0 - 0x1000:va1 - 0x1000]  # .text

    def datarel(va):
        return data[va - 0x2000:va - 0x2000 + 8]  # .data.rel.ro / .got

    for name, (a, b, sha) in BODIES.items():
        bb = body(a, b)
        if len(bb) != b - a or hashlib.sha256(bb).hexdigest() != sha:
            fail(f"{name} body mismatch")
        pinned = bytes.fromhex((PACKET / f"{name}.hex").read_text().strip())
        if pinned != bb:
            fail(f"{name}.hex does not match binary body")

    # Twin tag-shift: caller-2 drop checks [rdi+0x98/0x90/0x88], state-machine
    # drop checks [rdi+0xa0/0x98/0x90]; both end in a tail jump to 0x15df190.
    dc = body(*BODIES["drop_caller2"][:2])
    ds = body(*BODIES["drop_statemachine"][:2])
    if dc[6] != 0x98 or ds[6] != 0xA0:
        fail("twin first tag offsets are not 0x98 / 0xa0")
    # Tail jumps: drop_caller2 jmp at file offset 0x15e0515-0x15e04b0 = 0x65,
    # drop_statemachine jmp at 0x15d9d05-0x15d9ca0 = 0x65; both target 0x15df190.
    for bb, name in ((dc, "drop_caller2"), (ds, "drop_statemachine")):
        jmp = bb[0x65:0x65 + 5]
        if jmp[0] != 0xE9:
            fail(f"{name} tail is not an E9 jmp")
        tgt = (0x15E04B0 if name == "drop_caller2" else 0x15D9CA0) + 0x65 + 5 \
            + struct.unpack_from("<i", jmp, 1)[0]
        if tgt != 0x15DF190:
            fail(f"{name} tail jump does not target 0x15df190")

    # Twin mnemonic skeletons must match (from the pinned objdump files).
    def mnemonics(name):
        seq = []
        for line in (PACKET / f"{name}.objdump.txt").read_text().splitlines():
            m = re.match(r"\s*[0-9a-f]+:\t[0-9a-f ]+\t(\S+)", line)
            if m:
                seq.append(m.group(1))
        return seq
    if mnemonics("drop_caller2") != mnemonics("drop_statemachine"):
        fail("drop twin mnemonic sequences differ")

    # .rela.dyn map: offset -> (type, addend)
    rela_off, rela_size = 0x6BE8, 0x163CC8
    relmap = {}
    for i in range(rela_size // 24):
        off, info, add = struct.unpack_from("<QQq", data, rela_off + i * 24)
        relmap[off] = (info & 0xFFFFFFFF, add)

    def resolve_slot(va):
        v = struct.unpack_from("<Q", datarel(va))[0]
        if v:
            return v, "file"
        t = relmap.get(va)
        if t and t[0] == 8:
            return t[1], "RELATIVE"
        fail(f"slot {va:#x} has no RELATIVE relocation")

    for base, drop, size, align, method, loc_slot, line, col in VTABLES:
        dv, _ = resolve_slot(base)
        if dv != drop:
            fail(f"vtable {base:#x} drop slot is {dv:#x}, expected {drop:#x}")
        sv = struct.unpack_from("<Q", datarel(base + 8))[0]
        av = struct.unpack_from("<Q", datarel(base + 16))[0]
        if sv != size or av != align:
            fail(f"vtable {base:#x} size/align are {sv}/{av}, expected {size}/{align}")
        mv, _ = resolve_slot(base + 24)
        if mv != method:
            fail(f"vtable {base:#x} method slot is {mv:#x}, expected {method:#x}")
        # Following Location: file pointer -> "base/src/lu.rs", len, line, col.
        fv, _ = resolve_slot(loc_slot)
        fstr = data[fv:fv + 14]
        if fstr != b"base/src/lu.rs":
            fail(f"location file string at {fv:#x} is {fstr!r}")
        lv = struct.unpack_from("<Q", datarel(loc_slot + 8))[0]
        pair = struct.unpack_from("<Q", datarel(loc_slot + 16))[0]
        if lv != 14 or (pair & 0xFFFFFFFF) != line or (pair >> 32) != col:
            fail(f"location at {loc_slot:#x} is len={lv} line/col={pair:#x}")

    for slot, target in GOT_EXPECTED.items():
        v, _ = resolve_slot(slot)
        if v != target:
            fail(f"GOT {slot:#x} resolves to {v:#x}, expected {target:#x}")

    # .text bounds: VA 0x1419300, file offset 0x1418300, size 0x4fd7700.
    tb = data[0x1418300:0x1418300 + 0x4FD7700]

    def lea_sites(target):
        hits = []
        for m in re.finditer(b"[\x48\x49\x4c\x4d]\x8d", tb):
            i = m.start()
            if i + 7 > len(tb):
                continue
            if (tb[i + 2] & 0xC7) != 0x05:
                continue
            disp = struct.unpack_from("<i", tb, i + 3)[0]
            if 0x1419300 + i + 7 + disp == target:
                hits.append(0x1419300 + i)
        return hits

    for target, expected in LEA_EXPECTED.items():
        got = lea_sites(target)
        if got != expected:
            fail(f"lea sites for {target:#x} are {[hex(s) for s in got]}, "
                 f"expected {[hex(s) for s in expected]}")

    def e8_sites(target):
        hits = []
        for m in re.finditer(b"\xe8", tb):
            i = m.start()
            if i + 5 > len(tb):
                continue
            r = struct.unpack_from("<i", tb, i + 1)[0]
            if 0x1419300 + i + 5 + r == target:
                hits.append(0x1419300 + i)
        return hits

    for target, expected in E8_EXPECTED.items():
        got = e8_sites(target)
        if expected is not None:
            if got != expected:
                fail(f"E8 sites for {target:#x} are {[hex(s) for s in got]}, "
                     f"expected {[hex(s) for s in expected]}")
        elif len(got) != E8_COUNTS[target]:
            fail(f"E8 count for {target:#x} is {len(got)}, "
                 f"expected {E8_COUNTS[target]}")

    print("Verified node #115 lu.rs vtable consumers packet: "
          "consumer_caller2 0x15d6230..0x15d6310 (224B), "
          "consumer_statemachine 0x15d2fb0..0x15d31c7 (535B), "
          "drop_dispatch 0x15dacd0..0x15dad33 (99B), "
          "drop twins 135B each")
    print("Vtables: 2 (160B caller-2, 168B state machine); "
          "lea sites: 2 + 2, fn-slot lea: 0 + 0; "
          "E8: consumers 1 + 1, twins 1 + 1, dispatch 25, worker 24")


if __name__ == "__main__":
    main()
