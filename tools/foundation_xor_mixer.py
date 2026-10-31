#!/usr/bin/env python3
"""Verify a digest-bound, static node #94 multiply/xor mixer evidence packet.

This checks retained bytes and data relationships, never executes target code,
never decodes a general function inventory, and makes no reconstruction claim.
The window has no outgoing calls and no branches: it reads a seed pointer from
one RELATIVE relocation slot, xors two inputs against the seed, runs three
128-bit multiplies, and returns the xor-fold of the final product. What the
result means (hash, checksum, tag, or anything else) is not claimed anywhere,
and the seed's runtime values are not claimed: the slot's file value is 0 and
its addend is the runtime address, applied only at load time.

This window is bound ALONE. No family census is claimed, and no other mixer
window is bound here.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
START, END = 0x4b27620, 0x4b27669
PAD_END = 0x4b27670
BODY = bytes.fromhex(
    '488b15b96dc4004c8b124c8b460c4d31d0488b0e488b46084833420849f7e04989c04989d1488b56044c31d248330f4889c848f7e24931d14d31c14c31c84883f01449f7e24831d0c3')
PAD = b'\xcc' * 7
# Exported FDE/CIE bytes, independently checked with GNU --dwarf=frames.
# These are narrow record locks, not a replacement for RE-001's FDE decoder.
# The window CIE and FDE encodings are zR: initial_location is a 4-byte signed
# PC-relative value, range is a 4-byte unsigned value. The caller FDE uses a
# zPLR CIE; its initial_location and range fields sit at the same record
# offsets, and the decoded PC/range below agree with GNU's dump exactly.
CIE = bytes.fromhex('1400000000000000017a5200017810011b0c070890010000')
FDE = bytes.fromhex('100000000065250004fcbe034900000000000000')
NEXT_FDE = bytes.fromhex('140000001465250040fcbe038a010000000357010e200000')
CALLER_CIE = bytes.fromhex('1c00000000000000017a504c5200017810079b29ca7b041b1b0c070890010000')
CALLER_FDE = bytes.fromhex('28010000e4c132008cd0ae03fe140000043f0d8dff410e10420e18420e20420e28420e30410e38470ec00983078c068d058e048f038602027c2e00024e2e00025d2e0002792e00024f2e0002a80e38410e30420e28420e20420e18420e10410e08410ec009025e2e00024f2e00782e00025b2e0002c22e0002532e0002db2e000320012e00702e0002542e0002632e0002f62e00025e2e0002962e00532e00026b2e005e2e00622e00027a2e00027b2e0002b02e0002b52e0002772e00033a012e0002bb2e00792e0002c92e0002772e004f2e004f2e00025a2e0002612e00562e0002fb2e1002440ec809420ed009490ec009502e00572e0002782e004d2e00502e00512e004d2e004d2e004d2e004d2e004d2e00522e0002702e00502e00772e00452e004a2e00482e0000')
CALLER_FDE_OFFSET = 0x6088f4
CALLER_START, CALLER_END = 0x4dd6ea0, 0x4dd839e
CALL_SITE = 0x4dd768f
CALL_BYTES = bytes.fromhex('e88cffd4ff')
SEED_SLOT = 0x576e3e0
# Scout correction: the scout note said 0x5852bc, but the retained RELATIVE
# record's addend is 0x5788348 (readelf prints it in hex without a prefix;
# 0x5788348 sits just inside .bss, which starts at 0x5788300).
SEED_ADDEND = 0x5788348
M64 = (1 << 64) - 1


def require(condition, message):
    if not condition:
        raise ValueError(message)


def mixer(in0, in1, seed0, seed8):
    """Python restatement of the retained instruction sequence, not execution.

    in0 is 8 bytes (rdi), in1 is 20 bytes (rsi): words at offsets 0, 4, 8, 12
    are read as little-endian u64s. seed0/seed8 are the two seed words.
    All multiplies are 128-bit (mul), folded with xor of hi and lo halves.
    """
    def u64(buf, off):
        return struct.unpack_from('<Q', buf, off)[0]
    d = u64(in1, 12) ^ seed0
    c = u64(in1, 8) ^ seed8
    t1 = (c * d) & ((1 << 128) - 1)
    t1lo, t1hi = t1 & M64, t1 >> 64
    b = u64(in1, 4) ^ seed0
    a = u64(in1, 0) ^ u64(in0, 0)
    t2 = (a * b) & ((1 << 128) - 1)
    t2lo, t2hi = t2 & M64, t2 >> 64
    # Fold order, locked instruction by instruction: r9 accumulates t1hi, then
    # t2hi, then t1lo; rax (t2lo) xors r9 and 0x14. So acc includes t1hi.
    # (The scout note omitted t1hi; the retained bytes show it is folded in.)
    acc = (t2lo ^ t2hi ^ t1lo ^ t1hi ^ 0x14) & M64
    t3 = (acc * seed0) & ((1 << 128) - 1)
    return (t3 & M64) ^ (t3 >> 64)


def analyze(data):
    """Structural checks, separate from identity so corruption controls reach them."""
    secs = sections(data)
    by_name = {s['name']: s for s in secs}

    def read(va, size):
        matches = [s for s in secs if s['type'] != 8 and s['address'] <= va
                   and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'Ambiguous or unmapped VA')
        s = matches[0]
        off = s['offset'] + va - s['address']
        return data[off:off + size]

    body = read(START, END - START)
    require(body == BODY, 'Mixer instruction window changed')
    require(read(END, PAD_END - END) == PAD, 'FDE padding changed')
    eh = by_name['.eh_frame']

    def check_fde(offset, raw, start, end):
        record = read(eh['address'] + offset, len(raw))
        require(record == raw, 'FDE record changed')
        pc = eh['address'] + offset + 8 + struct.unpack_from('<i', record, 8)[0]
        extent = struct.unpack_from('<I', record, 12)[0]
        require((pc, pc + extent) == (start, end), 'FDE PC/range changed')

    require(read(eh['address'] + 0x0, len(CIE)) == CIE, 'Window CIE changed')
    check_fde(0x2564fc, FDE, START, END)
    check_fde(0x256510, NEXT_FDE, PAD_END, 0x4b277fa)
    require(read(eh['address'] + 0x2dc714, len(CALLER_CIE)) == CALLER_CIE,
            'Caller CIE changed')
    check_fde(CALLER_FDE_OFFSET, CALLER_FDE, CALLER_START, CALLER_END)
    # Instruction bytes at fixed offsets inside the locked body, in order.
    # Offsets are relative to the FDE start 0x4b27620.
    require(body[0:7] == bytes.fromhex('488b15b96dc400'), 'Seed-pointer load changed')
    require(START + 7 + struct.unpack_from('<i', body, 3)[0] == SEED_SLOT,
            'Seed slot changed')
    require(body[7:10] == bytes.fromhex('4c8b12'), 'Seed[0] load changed')
    require(body[10:14] == bytes.fromhex('4c8b460c'), 'In1[12] load changed')
    require(body[14:17] == bytes.fromhex('4d31d0'), 'D xor changed')
    require(body[17:20] == bytes.fromhex('488b0e'), 'In1[0] load changed')
    require(body[20:24] == bytes.fromhex('488b4608'), 'In1[8] load changed')
    require(body[24:28] == bytes.fromhex('48334208'), 'C xor changed')
    require(body[28:31] == bytes.fromhex('49f7e0'), 'First mul changed')
    require(body[31:34] == bytes.fromhex('4989c0'), 't1lo move changed')
    require(body[34:37] == bytes.fromhex('4989d1'), 't1hi move changed')
    require(body[37:41] == bytes.fromhex('488b5604'), 'In1[4] load changed')
    require(body[41:44] == bytes.fromhex('4c31d2'), 'B xor changed')
    require(body[44:47] == bytes.fromhex('48330f'), 'A xor changed')
    require(body[47:50] == bytes.fromhex('4889c8'), 'A move changed')
    require(body[50:53] == bytes.fromhex('48f7e2'), 'Second mul changed')
    require(body[53:56] == bytes.fromhex('4931d1'), 't2hi fold changed')
    require(body[56:59] == bytes.fromhex('4d31c1'), 't1lo fold changed')
    require(body[59:62] == bytes.fromhex('4c31c8'), 't2lo fold changed')
    require(body[62:66] == bytes.fromhex('4883f014'), 'Constant xor changed')
    require(body[66:69] == bytes.fromhex('49f7e2'), 'Third mul changed')
    require(body[69:72] == bytes.fromhex('4831d0'), 'Final fold changed')
    require(body[72:73] == bytes.fromhex('c3'), 'Return changed')
    # No call or branch starts anywhere in the window. (The body's one 0xe8
    # byte is the low displacement byte of the seed load at offset 3, not an
    # instruction start, so the check below pins starts only.)
    starts = [0, 7, 10, 14, 17, 20, 24, 28, 31, 34, 37, 41, 44, 47, 50, 53,
              56, 59, 62, 66, 69, 72]
    require(all(body[s] not in (0xe8, 0xe9, 0xeb, 0x0f) and not
                0x70 <= body[s] <= 0x7f for s in starts),
            'Unexpected call or branch start in window')
    # Seed slot relocation: RELATIVE, addend is the runtime seed address.
    relsec = by_name['.rela.dyn']
    require(relsec['size'] % 24 == 0, 'Truncated RELA section')
    rels = {}
    raw = read(relsec['address'], relsec['size'])
    for off in range(0, len(raw), 24):
        address, info, addend = struct.unpack_from('<QQq', raw, off)
        require(address not in rels, 'Duplicate relocation address')
        rels[address] = (info, addend)
    require(SEED_SLOT in rels, 'Seed slot relocation missing')
    info, addend = rels[SEED_SLOT]
    require(info & 0xffffffff == 8, 'Seed slot is not RELATIVE')
    require(addend == SEED_ADDEND, 'Seed addend changed')
    window_slots = [a for a, (info, addend) in rels.items() if addend == START]
    require(window_slots == [], 'Unexpected slot maps to window')
    # Caller call bytes and target come before the incoming scan, so a
    # mutated call site reports its own check rather than the scan's.
    call = read(CALL_SITE, 5)
    require(call == CALL_BYTES, 'Caller call bytes changed')
    require(CALL_SITE + 5 + struct.unpack_from('<i', call, 1)[0] == START,
            'Caller call target changed')
    # Incoming calls: exactly one direct e8 call, no indirect slot calls.
    text = by_name['.text']
    code = read(text['address'], text['size'])
    direct = []
    pos = 0
    while (pos := code.find(b'\xe8', pos)) >= 0:
        rel = struct.unpack_from('<i', code, pos + 1)[0]
        if text['address'] + pos + 5 + rel == START:
            direct.append(text['address'] + pos)
        pos += 1
    require(direct == [CALL_SITE], 'Incoming direct calls changed')
    # Decoded-formula edges (restatement of the retained bytes, not execution).
    require(mixer(b'\x00' * 8, b'\x00' * 20, 0, 0) == 0, 'Zero edge changed')
    require(mixer(bytes(range(8)), bytes(range(20)),
                  0xdeadbeefcafef00d, 0x123456789abcdef0) == 0x9c4e42a7cec11b69,
            'Sample edge changed')
    require(mixer(bytes(range(8)), bytes(range(20)), 0,
                  0x123456789abcdef0) == 0, 'Zero-seed edge changed')
    require(mixer(b'\x00' * 8, b'\x00' * 20, 1, 0) == 0x14,
            'Unit-seed edge changed')
    return {
        'window': (START, END),
        'body_sha256': hashlib.sha256(body).hexdigest(),
        'call_sites': [CALL_SITE],
        'seed_slot': SEED_SLOT,
        'seed_addend': SEED_ADDEND,
    }


def inspect(binary):
    data = Path(binary).read_bytes()
    require(len(data) == 91774280, 'Target size changed')
    require(hashlib.sha256(data).hexdigest() == SHA256, 'Target digest changed')
    return analyze(data)


def main():
    parser = argparse.ArgumentParser(
        description='Verify a digest-bound, static node #94 xor-mixer '
                    'evidence packet.')
    parser.add_argument('--binary', default=str(TARGET))
    parser.add_argument('--check', help='Compare with retained JSON; fail on drift')
    args = parser.parse_args()
    result = inspect(args.binary)
    if args.check:
        retained = json.loads(Path(args.check).read_text())
        require(retained['target_sha256'] == SHA256, 'Retained digest changed')
        require(retained['function']['start_va'] == hex(START), 'Retained start changed')
        require(retained['function']['end_va_exclusive'] == hex(END), 'Retained end changed')
        require(retained['function']['bytes'] == END - START, 'Retained size changed')
        require(retained['function']['sha256'] == result['body_sha256'],
                'Retained body hash changed')
        require(retained['incoming_pattern_scan']['e8_candidates'] ==
                [hex(site) for site in result['call_sites']],
                'Retained callers changed')
        print('Foundation xor-mixer evidence reproduces exactly.')
    else:
        print(result)


if __name__ == '__main__':
    main()
