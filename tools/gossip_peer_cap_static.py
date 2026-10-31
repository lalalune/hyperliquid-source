#!/usr/bin/env python3
"""Static node #94 gossip peer cap in `maybe_reject_peer_reason`, checked from authenticated bytes.

Question: function `0x473f2e0` (reached through RELATIVE slot `0x57735f8`; the
can1357 lead names it `maybe_reject_peer_reason`) reads `n_gossip_peers` from
the tracked gossip override config and compares it with the current peer count.
What limit does it derive, which peers does it count, and what does it return
at the limit?  Where does the lead (`node/connections.rs`,
`node/gossip_config.rs`) differ?

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; immediates, RIP-relative and
branch targets, the rustc format template, the panic Location and RELATIVE
slots are decoded here.  A ModRM/SIB scan of the whole FDE pins every
`[rsp+0xe0]` operand.  Nothing from the binary is executed.
"""
import argparse
import json
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from artifacts import ROOT, check  # noqa: E402
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = 'artifacts/node/94/hl-node'
FDE = 0x473f2e0
U64_DISPLAY = 0x1570900
CALLER_SLOT = 0x57735f8
LIMIT_SLOT = 0xe0

WINDOWS = {
    'entry': (FDE, 0x473f2e0,
        '554157415641554154534881ec28010000899424d40000004889bc24c80000008974241048c1ee204088742414803900'
        '0f8480000000488b8424c80000004c8b304c8b68108b44241048898424f00000008b44241448898424f8000000498d7d'
        '10e8ca1e0000410fb64510498d5d18b90100000048895c24308844240f84c00f85f0040000'),
    'locked_tracker': (FDE, 0x473f7da,
        '498d5d204983bd9800000000746b498d8598000000488944241848c744243800000000c744244800000000c644244c00'
        '488d4424184889842488000000488d0512fcdeff488984249000000048c78424d800000000000000488d35ba43abfb48'
        '8d0d68f0fe00488d7c2438488d942488000000ff1525f10201'),
    'limit': (FDE, 0x473f853,
        '31c9803b0048898c24d80000000f8492000000488b43084883f809b908000000480f43c84883f964ba64000000480f42'
        'd148899424e00000004839c2745648c744243800000000c744244800000000c644244c00488d8424e000000048898424'
        '88000000488b05d2e702014889842490000000488d355e93aafb488d0da4f2fe00488d7c2438488d942488000000ff15'
        '91f00201bb18000000807c240f00741de98600000048c78424e000000008000000bb18000000807c240f00756ebb2000'
        '0000'),
    'count': (FDE, 0x473f97e,
        '498d7e10498b461089c183e108c1e9034883f8f00f93c208ca74154989ff31f6b900ca9a3bff153ffc02014c89ffeb0b'
        '488d4810f0480fb10f75e04d8b7e184d85ff4889bc24000100000f84d4020000498b46284885c00f84c7020000498b76'
        '204531f648c7c1ffffffff31d2eb190f1f0049ffc64c0f44f141bf0000000048ffc80f849f0200004885d27425440fb7'
        '82ba0000004c39c60f83c40000004989d04989f1e9e1000000660f1f8400000000004885f674384989f04c89fa4983e0'
        '0774314531c96666662e0f1f840000000000488b92f800000049ffc14d39c875f14889f74c29cf4883fe087315eb514c'
        '89faeb4c4889f74883fe0872430f1f440000488b92f8000000488b92f8000000488b92f8000000488b92f8000000488b'
        '92f8000000488b92f8000000488b92f8000000488b92f80000004883c7f875c231f64531ff440fb782ba0000004c39c6'
        '0f8248ffffff6666662e0f1f8400000000004c8b82b00000004d85c00f84bd05000049ffc7440fb78ab80000004c89c2'
        '66453b88ba00000073d84d85ff0f844f0100004b8d34c84881c6000100004d89fa4983e2070f84670100004531db0f1f'
        '4000488b16488db2f800000049ffc34d39da75ee4d89fa4d29da4983ff0872436690488b16488b92f8000000488b92f8'
        '000000488b92f8000000488b92f8000000488b92f8000000488b92f8000000488b92f8000000488db2f80000004983c2'
        'f875bf31f64f8d0c8943f68408bc00000001bf7f0000017508438bbc08bd000000897c2438498b7c1d284885ff0f842f'
        'feffff4d8b441d304c8d5f08440fb767364589e241c1e20249c7c1ffffffff0f1f004d85d2745b8b6c2438458b3b4983'
        'c3040fcd410fcf4439fd400f97c54080dd004c0fbefd4d85ff410f98c7400f9fc54428fd49ffc14983c2fc4080fd0174'
        'c1440fb6d54585d20f84cbfdffff4983e801731be9b9fdffff660f1f8400000000004d89e14983e8010f82a3fdffff4a'
        '8b7ccf38e96fffffff660f1f840000000000498d71014c89c24f8d0c8943f68408bc00000001bf7f0000010f8428ffff'
        'ffe92bffffff6666662e0f1f8400000000004d89fa4983ff080f83b3feffffe9effeffff4531f648c7c0f0ffffff488b'
        'bc2400010000f0480fc1074883e0f24883f8120f849d0300004c3bb424e0000000733541b703807c240f00488b7c2430'
        '0f859801000048c7c0f0fffffff0480fc1074883e0f241b7034883f8120f857b010000e98c030000'),
    'at_limit': (FDE, 0x473fd06,
        'bb18000000807c240f00756ebb200000004983bd9800000000745f498d8598000000488944241848c744243800000000'
        'c744244800000000c644244c00488d4424184889842488000000488d05d9f6deff4889842490000000488d358d3eabfb'
        '488d0d3bebfe00488d7c2438488d942488000000ff15f8eb0201488b8c24f800000048c1e12048038c24f00000004889'
        'c848c1e808f6c101b97f0000010f44c8894c2438498b441d284885c00f849b000000498b4c1d30488b7c24304c8d5808'
        '0fb770364189f041c1e00248c7c2ffffffff0f1f8400000000004d85c0744b448b4c2438458b134983c304410fc9410f'
        'ca4539d1410f97c14180d9004d0fbec94d85c9410f98c2410f9fc14528d148ffc24983c0fc4180f90174bf410fb6f185'
        'f6741eeb080f1f4400004889f24883e9010f8214020000488b44d038e97bffffff41b703807c240f007411eb294531ff'
        '488b7c2430807c240f00751a48c7c0f0fffffff0480fc1074883e0f24883f8120f84160200004180ff030f94c0848424'
        'd40000000f848f010000'),
    'set_miss': (FDE, 0x4740051,
        '4531ff807c240f000f8403feffffe918feffff'),
    'return': (FDE, 0x474001b,
        '4180f7034489f84881c4280100005b415c415d415e415f5dc3'),
    'u64_display': (U64_DISPLAY, U64_DISPLAY,
        '554889e54156534883ec204889f3488b3f488d75dc41be14000000ba14000000e84bfbffff4929c64c8d04284983c0dc'
        'ba010000004889dfbe0100000031c94d89f1ff1590d91f044883c4205b415e5dc3'),
}

# name: (va, hex) -- every entry must sit inside a checked window.
FACTS = {
    'flag_test': (0x473f30d, '803900'),
    'self_peers': (0x473f31e, '4c8b30'),
    'self_tracker': (0x473f321, '4c8b6810'),
    'tracker_byte': (0x473f346, '410fb64510'),
    'unlocked_config': (0x473f34b, '498d5d18'),
    'locked_config': (0x473f7da, '498d5d20'),
    'tracker_error_test': (0x473f7de, '4983bd9800000000'),
    'opt_tag': (0x473f855, '803b00'),
    'opt_value': (0x473f866, '488b4308'),
    'low_cmp': (0x473f86a, '4883f809'),
    'low': (0x473f86e, 'b908000000'),
    'low_cmov': (0x473f873, '480f43c8'),
    'high_cmp': (0x473f877, '4883f964'),
    'high': (0x473f87b, 'ba64000000'),
    'high_cmov': (0x473f880, '480f42d1'),
    'limit_store': (0x473f884, '48899424e0000000'),
    'clip_cmp': (0x473f88c, '4839c2'),
    'clip_arg': (0x473f8a7, '488d8424e0000000'),
    'none_store': (0x473f8f8, '48c78424e000000008000000'),
    'unlocked_offset': (0x473f8e7, 'bb18000000'),
    'unlocked_offset_none': (0x473f904, 'bb18000000'),
    'locked_offset': (0x473f910, 'bb20000000'),
    'peers_root': (0x473f9b9, '4d8b7e18'),
    'peers_len': (0x473f9ce, '498b4628'),
    'peers_height': (0x473f9db, '498b7620'),
    'count_zero': (0x473f9df, '4531f6'),
    'count_inc': (0x473f9f0, '49ffc6'),
    'count_saturate': (0x473f9f3, '4c0f44f1'),
    'count_left': (0x473f9fd, '48ffc8'),
    'node_len': (0x473fa0b, '440fb782ba000000'),
    'node_edge': (0x473fa50, '488b92f8000000'),
    'key_tag_next': (0x473fb97, '43f68408bc00000001'),
    'key_tag_first': (0x473fc6b, '43f68408bc00000001'),
    'key_localhost': (0x473fba0, 'bf7f000001'),
    'key_ipv4': (0x473fba7, '438bbc08bd000000'),
    'set_root': (0x473fbb3, '498b7c1d28'),
    'set_height': (0x473fbc1, '4d8b441d30'),
    'set_node_len': (0x473fbca, '440fb76736'),
    'set_bswap_key': (0x473fbf0, '0fcd'),
    'set_bswap_entry': (0x473fbf2, '410fcf'),
    'gate_cmp': (0x473fcc7, '4c3bb424e0000000'),
    'below_code': (0x473fcd1, '41b703'),
    'at_limit_unlocked_offset': (0x473fd06, 'bb18000000'),
    'at_limit_locked_offset': (0x473fd12, 'bb20000000'),
    'incoming_tag': (0x473fd9b, 'f6c101'),
    'incoming_localhost': (0x473fd9e, 'b97f000001'),
    'incoming_ipv4': (0x473fda3, '0f44c8'),
    'incoming_set_root': (0x473fdaa, '498b441d28'),
    'incoming_hit_code': (0x473fe47, '41b703'),
    'empty_set_code': (0x473fe53, '4531ff'),
    'miss_code': (0x4740051, '4531ff'),
    'result_test': (0x473fe7c, '4180ff03'),
    'return_value': (0x474001f, '4489f8'),
}

# name: (va, length, target) for rel8/rel32 branches; RIP-relative LEA/MOV/CALL use the same decoding.
FLOW = {
    'flag_clear_skips_cap': (0x473f310, 6, 0x473f396),
    'unlocked_to_limit': (0x473f35f, 6, 0x473f855),
    'none_to_default': (0x473f860, 6, 0x473f8f8),
    'unclipped_skips_log': (0x473f88f, 2, 0x473f8e7),
    'below_limit_else': (0x473fccf, 2, 0x473fd06),
    'count_found_skips_inc': (0x473fc26, 6, 0x473f9f7),
    'incoming_miss': (0x473fe37, 6, 0x4740051),
    'other_code_returns': (0x473fe8a, 6, 0x474001f),
}

RIP = {
    'clip_formatter_slot': (0x473f8b7, 7, 0x576e090),
    'clip_template': (0x473f8c6, 7, 0x1e8c2b),
    'clip_location': (0x473f8cd, 7, 0x572eb78),
    'clip_log_slot': (0x473f8e1, 6, 0x576e978),
    'tracker_template': (0x473f832, 7, 0x1f3bf3),
    'tracker_location': (0x473f839, 7, 0x572e8a8),
}

# ModRM/SIB addresses of every [rsp+0xe0] operand in the FDE.
CENSUS = [0x473f648, 0x473f71c, 0x473f886, 0x473f8a9, 0x473f8fa, 0x473fcc9]


class EvidenceError(RuntimeError):
    pass


def require(ok, message):
    if not ok:
        raise EvidenceError(message)


class Image:
    def __init__(self, data):
        self.data = data
        self.secs = sections(data)
        rela = next((s for s in self.secs if s['name'] == '.rela.dyn' and s['type'] == 4), None)
        require(rela is not None and rela['size'] % 24 == 0, 'no well-formed .rela.dyn')
        self.relative = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend
        _, fdes = eh_frame_records(data, self.secs)
        self.fdes = sorted((f['start'], f['end']) for f in fdes)

    def offset(self, va, size=1):
        hits = [s for s in self.secs if s['type'] != 8 and s['address'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(hits) == 1, f'VA {va:#x}+{size} is not in exactly one file-backed section')
        return hits[0]['offset'] + va - hits[0]['address']

    def read(self, va, size):
        off = self.offset(va, size)
        return self.data[off:off + size]

    def fde(self, start):
        hits = [f for f in self.fdes if f[0] == start]
        require(len(hits) == 1, f'{start:#x} is not exactly one FDE start')
        return hits[0]

    def target(self, va, length):
        if length == 2:
            return va + 2 + struct.unpack('<b', self.read(va + 1, 1))[0]
        return va + length + struct.unpack('<i', self.read(va + length - 4, 4))[0]


def windows(img):
    out = {}
    for name, (fde, va, hexs) in WINDOWS.items():
        raw = bytes.fromhex(hexs)
        start, end = img.fde(fde)
        require(start <= va and va + len(raw) <= end, f'{name} window {va:#x} is outside FDE {fde:#x}')
        require(img.read(va, len(raw)) == raw, f'{name} at {va:#x}: bytes changed')
        out[name] = va
    return out


def windowed(va, size):
    return any(va >= w[1] and va + size <= w[1] + len(bytes.fromhex(w[2])) for w in WINDOWS.values())


def facts(img):
    out = {}
    for name, (va, hx) in FACTS.items():
        raw = bytes.fromhex(hx)
        require(windowed(va, len(raw)), f'fact {name} at {va:#x} is outside every window')
        require(img.read(va, len(raw)) == raw, f'fact {name} at {va:#x}: bytes changed')
        out[name] = raw
    return out


def template(img, va):
    """Decode a rustc packed format template: literal-length bytes and 0xc0 placeholders, ending at 0x00."""
    pieces, pos = [], va
    for _ in range(64):
        b = img.read(pos, 1)[0]
        if b == 0xc0:
            pieces.append(None)
            n = img.read(pos + 1, 1)[0]
            pos += 2
        elif b == 0:
            return pieces
        elif b < 0x80:
            n = b
            pos += 1
        else:
            raise EvidenceError(f'template {va:#x}: unexpected byte {b:#x} at {pos:#x}')
        if n:
            lit = img.read(pos, n)
            require(all(0x20 <= c < 0x7f or c == 0x0a for c in lit), f'template {va:#x}: literal at {pos:#x} not text')
            pieces.append(lit)
            pos += n
        elif pieces and pieces[-1] is None and img.read(pos, 1)[0] != 0xc0:
            return pieces
    raise EvidenceError(f'template {va:#x}: no terminator')


def location(img, va):
    ptr = img.relative.get(va)
    require(ptr is not None, f'Location {va:#x} has no RELATIVE file pointer')
    n, line, col = struct.unpack('<QII', img.read(va + 8, 16))
    require(0 < n < 256, f'Location {va:#x} has length {n}')
    path = img.read(ptr, n)
    require(all(0x20 <= c < 0x7f for c in path), f'Location {va:#x} path is not text')
    return f'{path.decode()}:{line}:{col}'


def check_flow(img):
    out = {}
    for name, (va, n, want) in {**FLOW, **RIP}.items():
        require(windowed(va, n), f'{name} at {va:#x} is outside every window')
        got = img.target(va, n)
        require(got == want, f'{name} at {va:#x} goes to {got:#x}')
        out[name] = hex(got)
    return out


def imm32(raw):
    return struct.unpack('<I', raw[-4:])[0]


def check_limit(img, f):
    low, high = imm32(f['low']), imm32(f['high'])
    require(f['low_cmp'][-1] == low + 1, f'max bound compares with {f["low_cmp"][-1]}, not {low + 1}')
    require(f['high_cmp'][-1] == high, f'min bound compares with {f["high_cmp"][-1]}, not {high}')
    default = imm32(f['none_store'])
    tpl = img.target(*RIP['clip_template'][:2])
    pieces = template(img, tpl)
    require(pieces == [b'n_gossip_peers clipped to ', None], f'clip template {tpl:#x} changed')
    fmt = img.relative.get(RIP['clip_formatter_slot'][2])
    require(fmt == U64_DISPLAY, f'clip formatter slot resolves to {fmt}')
    loc = location(img, RIP['clip_location'][2])
    require(loc.endswith('node/src/connections.rs:513:13'), f'clip Location is {loc}')
    log = img.relative.get(RIP['clip_log_slot'][2])
    require(log is not None, 'clip log slot has no RELATIVE target')
    return dict(option_tag='[config+0x0] byte', option_value='[config+0x8]', low=low, high=high,
                none_default=default, slot=f'[rsp+{LIMIT_SLOT:#x}]',
                clip_log=dict(template=hex(tpl), text=pieces[0].decode() + '{}', argument='&[rsp+0xe0]',
                              formatter=hex(fmt), location=loc, call_slot=hex(RIP['clip_log_slot'][2]),
                              call_target=hex(log), condition='Some(v) and limit != v'))


def check_tracker(img, f):
    loc = location(img, RIP['tracker_location'][2])
    require(loc.endswith('base/src/file_mod_time_tracker.rs:63:13'), f'tracker Location is {loc}')
    tpl = img.target(*RIP['tracker_template'][:2])
    pieces = template(img, tpl)
    require(pieces == [b'Last load of FileModTimeTracker failed: ', None], f'tracker template {tpl:#x} changed')
    offs = {k: imm32(f[k]) for k in ('unlocked_offset', 'unlocked_offset_none', 'locked_offset',
                                     'at_limit_unlocked_offset', 'at_limit_locked_offset')}
    require(f['unlocked_config'][-1] == offs['unlocked_offset'] == offs['unlocked_offset_none']
            == offs['at_limit_unlocked_offset'], 'unlocked config offset is not 0x18 everywhere')
    require(f['locked_config'][-1] == offs['locked_offset'] == offs['at_limit_locked_offset'],
            'locked config offset is not 0x20 everywhere')
    require(f['set_root'][-1] == f['incoming_set_root'][-1] == 0x28 and f['set_height'][-1] == 0x30,
            'set is not at config +0x28/+0x30')
    return dict(self_tracker='[rdi+0x10] (r13)', tracker_byte='[r13+0x10]',
                config={'unlocked': hex(offs['unlocked_offset']), 'locked': hex(offs['locked_offset'])},
                set_offset='+0x28', set_height_offset='+0x30',
                error_log=dict(test='[r13+0x98] != 0', template=hex(tpl), location=loc))


def check_count(f):
    require(f['peers_root'][-1] == 0x18 and f['peers_height'][-1] == 0x20 and f['peers_len'][-1] == 0x28,
            'peer map is not root/height/len at self +0x18/+0x20/+0x28')
    require(f['key_tag_next'] == f['key_tag_first'] and f['key_tag_next'][4:6] == b'\xbc\x00'
            and f['key_tag_next'][-1] == 1, 'peer key tag test is not bit 0 of node +0xbc')
    require(struct.unpack('<I', f['key_ipv4'][4:8])[0] == 0xbd, 'peer key IPv4 is not at node +0xbd')
    require(imm32(f['key_localhost']) == imm32(f['incoming_localhost']) == 0x100007f,
            'localhost substitute is not 127.0.0.1')
    require(f['node_len'][4] == 0xba and f['node_edge'][3] == 0xf8, 'peer node layout changed')
    require(f['set_node_len'][-1] == 0x36, 'set node length is not at +0x36')
    return dict(peers='BTreeMap at [self]: root +0x18, height +0x20, length +0x28',
                peer_key='5-byte NodeIp at node +0xbc + 5*i: tag byte, IPv4 dword at +0xbd; node len u16 +0xba',
                key_to_ipv4='tag bit 0 set -> 127.0.0.1, else the stored IPv4',
                set='BTreeSet of 4-byte IPv4 at [config+0x28], height [config+0x30], keys +0x8, len u16 +0x36, '
                    'edges +0x38, compared big-endian (bswap)',
                counted='peers whose IPv4 is not in the set', saturating=True,
                gate='count < [rsp+0xe0] -> r15b = 3', at_limit='incoming IPv4 in set -> 3, else 0')


def census(img):
    start, end = img.fde(FDE)
    code = img.read(start, end - start)
    pat = struct.pack('<I', LIMIT_SLOT)
    got = [start + i for i in range(len(code) - 6)
           if code[i] & 0xc7 == 0x84 and code[i + 1] == 0x24 and code[i + 2:i + 6] == pat]
    require(got == CENSUS, f'[rsp+{LIMIT_SLOT:#x}] operands are {[hex(v) for v in got]}')
    return [hex(v) for v in got]


def callers(img):
    slots = sorted(k for k, v in img.relative.items() if v == FDE)
    require(slots == [CALLER_SLOT], f'RELATIVE slots holding {FDE:#x}: {[hex(s) for s in slots]}')
    return [hex(s) for s in slots]


def peer_limit(opt, low=8, high=100, default=8):
    """Limit stored at [rsp+0xe0]: None -> default; Some(v) -> min(max(v, low), high).  Returns (limit, logged)."""
    if opt is None:
        return default, False
    limit = min(max(opt, low), high)
    return limit, limit != opt


def lead_limit(v, high=100):
    """The lead's `n_gossip_peers.clamp(1, MAX_GOSSIP_PEERS_HARD)`."""
    return min(max(v, 1), high)


def key_ipv4(tag, ip):
    return 0x7f000001 if tag & 1 else ip


def counted_peers(peers, allowed):
    """Peers (tag, ipv4) whose IPv4 (localhost tag -> 127.0.0.1) is not in `allowed`."""
    return sum(1 for tag, ip in peers if key_ipv4(tag, ip) not in allowed)


def cap_code(peers, allowed, limit, incoming):
    """Low byte of the result on the flagged path: 3 when admitted by the cap, 0 when refused."""
    if counted_peers(peers, allowed) < limit:
        return 3
    return 3 if key_ipv4(*incoming) in allowed else 0


def analyse(data):
    img = Image(data)
    win = windows(img)
    f = facts(img)
    return dict(target=TARGET, fde=hex(FDE), callers=callers(img), windows={k: hex(v) for k, v in win.items()},
                flow=check_flow(img), limit=check_limit(img, f), tracker=check_tracker(img, f),
                count=check_count(f), census={f'[rsp+{LIMIT_SLOT:#x}]': census(img)},
                result=dict(register='r15d -> eax at 0x474001f', below_or_allowed=3, refused=0,
                            code3_and_edx_flag='further step at 0x473fe90 (unresolved)'))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--json', action='store_true')
    a = p.parse_args(argv)
    identity = next(i for i in json.loads((ROOT / 'provenance/artifacts.json').read_text())['files']
                    if i['path'] == TARGET)
    path = ROOT / TARGET
    check(path, identity)
    result = dict(analyse(path.read_bytes()), target_sha256=identity['sha256'])
    if a.json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    lm = result['limit']
    print(f"limit: None -> {lm['none_default']}; Some(v) -> min(max(v, {lm['low']}), {lm['high']})")
    print(f"clip log: {lm['clip_log']['text']} at {lm['clip_log']['location']}")
    print('count: peers not in the config IPv4 set; at the limit only set members are admitted')
    return 0


if __name__ == '__main__':
    sys.exit(main())
