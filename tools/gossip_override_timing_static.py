#!/usr/bin/env python3
"""Static node #94 timed gossip-override snapshot `0x45281c0`, checked from authenticated bytes.

Question: `0x45281c0` (only direct caller `0x4740670`) returns an optional
override map and two f64 durations.  What do the two durations measure?  When
is the map included?  The can1357 lead
(`update_and_get_overrides_with_file_tracker` in `node/connections.rs`) names
them `update_elapsed_secs` and `clone_elapsed_secs`.  Where does it differ?

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; immediates, call, branch and
RIP-relative targets, panic Locations, the rustc format template, RELATIVE and
GLOB_DAT slots are decoded here.  Nothing from the binary is executed.
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
SNAPSHOT_FDE = 0x45281c0
CALLER_FDE = 0x4740490
CLOCK_NOW = 0x4ee3800
CLOCK_SUB = 0x4ee3730
TRACKER_REFRESH = 0x471edd0
MAP_CLONE = 0x498e1f0
LOCKED_COPY = 0x45297f0
NANOS_PER_SEC = 0x20a220

WINDOWS = {
    'snapshot': (SNAPSHOT_FDE, 0x45281c0,
        '554157415641554154534881ec880000004989d44889fb0fb60188442407bf01000000e818b69b004989c54189d6498d'
        '8424a00200004889442408b10131c0f0410fb08c24a00200000f8550020000bf01000000e8e7b59b004989c789d54889'
        '442460895424684c896c24404489742448488d7c24104c8d6c2460488d5424404c89eee8e8b49b00807c241000660f57'
        'd27536f20f104424180f57d2f20f2a5424200f140517bccdfb660f5c052faccdfb660f28c8660f15c8f20f58c8f20f5e'
        '159b1fcefbf20f58d1f20f11542470498dbc24a8020000488d35c27c1f01e82d6b1f004983bc24f8020000007452498d'
        '8424f8020000488944246048c744241000000000c744242000000000c6442424004c896c2440488d0553710000488944'
        '2448488d350ab9ccfb488d0db8652001488d7c2410488d542440ff15786624014180bc24d802000000750cf644240701'
        '75054531f6eb4e4983bc24d002000000742b498bb424c00200004885f60f844e010000488d7c2448498b9424c8020000'
        '41be01000000e8a55e4600eb1848c74424480000000048c74424580000000041be010000004c8974244031c9b001488b'
        '7c2408f00fb00f0f85f7000000bf01000000e879b49b004889442478899424800000004c897c2460896c2468488d7c24'
        '10488d742478488d542460e880b39b000fb68424c0000000807c241000660f57c07536f20f104c24180f57c0f20f2a44'
        '24200f140da7bacdfb660f5c0dbfaacdfb660f28d1660f15d1f20f58d1f20f5e052b1ecefbf20f58c20f104c2440660f'
        '105424500f294c2410660f29542420f20f104c2470f20f114c2430f20f1144243884c0740bbf32000000ff15c8642401'
        '0f284424100f284c24200f285424300f1153200f114b100f11034889d84881c4880000005b415c415d415e415f5dc348'
        '8b7c2408ba00ca9a3bff15c16a2401e99bfdffff31f6ff15bc6a2401e9fcfeffff488d3d30d32001ff15e25f24010f0b'),
    'caller': (CALLER_FDE, 0x4740549,
        '498b56104883c210488d0d14affbfb488dbc248001000041b8050000004889d641b901000000e87c92deff488bac2488'
        '010000488b842490010000410fb64e2080f90248894424580f84920000004885c00f8489000000488d048080f9027529'
        'b101807d0002747aba05000000662e0f1f8400000000004839d07464807c150002488d520575f0eb59418b56210fb6f1'
        '4889d748c1e7084809f740f6c701741e89d231f6eb0a904883c6054839f07430384c350075f13854350175ebeb1e31f6'
        'eb0e0f1f4400004883c6054839f07410384c350075f13954350175ebb101eb0231c9488b842480010000488944241848'
        '8b9c2498010000884c2430498b56184883c210c70424010000004c8d0517aefbfb488dbc2480010000488d4c243041b9'
        '180000004889d6e84b7bdeff'),
    'clock_now': (CLOCK_NOW, 0x4ee3800,
        '554889e5534883ec18488d75e0ff1575b2880083f8ff7449488b55e84881fa00ca9a3b730b488b45e04883c4185b5dc3'),
    'clock_sub': (CLOCK_SUB, 0x4ee3730,
        '554889e5534883ec184889f04889fb488b36488b0a448b40088b7a084531c94139f8410f93c14531d24839ce410f9dc2'
        '450f44d14584d2744a418d8000ca9a3b4889ca48f7da4139f848f7d1410f43c0480f43ca4801f129f83d00ca9a3b720e'
        '4883f9ff744c48ffc105003665c448894b0889431048c703000000004883c4185b5dc3488d7de04889d64889c2e86eff'
        'ffff488b45e0488b4de88b55f04883f00148894b088953104889034883c4185b5dc3'),
}

# name: (va, hex) -- every entry must sit inside a checked window.
FACTS = {
    'flag_read': (0x45281d7, '0fb601'),
    't0_clock': (0x45281de, 'bf01000000'),
    'mutex_addr': (0x45281ee, '498d8424a0020000'),
    'lock_new': (0x45281fb, 'b101'),
    'lock_old': (0x45281fd, '31c0'),
    'lock': (0x45281ff, 'f0410fb08c24a0020000'),
    't1_clock': (0x452820f, 'bf01000000'),
    't1_secs': (0x452821e, '4889442460'),
    't1_nanos': (0x4528223, '89542468'),
    't0_secs': (0x4528227, '4c896c2440'),
    't0_nanos': (0x452822c, '4489742448'),
    'wait_out': (0x4528231, '488d7c2410'),
    'wait_lhs': (0x4528236, '4c8d6c2460'),
    'wait_rhs': (0x452823b, '488d542440'),
    'wait_err': (0x4528248, '807c241000'),
    'wait_nanos': (0x452825c, 'f20f2a542420'),
    'wait_store': (0x4528289, 'f20f11542470'),
    'tracker_arg': (0x452828f, '498dbc24a8020000'),
    'tracker_error': (0x45282a3, '4983bc24f802000000'),
    'include_byte': (0x4528300, '4180bc24d802000000'),
    'include_flag': (0x452830b, 'f644240701'),
    'none_tag': (0x4528312, '4531f6'),
    'map_len': (0x4528317, '4983bc24d002000000'),
    'map_root': (0x4528322, '498bb424c0020000'),
    'map_height': (0x4528338, '498b9424c8020000'),
    'clone_tag': (0x4528340, '41be01000000'),
    'empty_root': (0x452834d, '48c744244800000000'),
    'empty_tag': (0x452835f, '41be01000000'),
    'tag_store': (0x4528365, '4c89742440'),
    'unlock_new': (0x452836a, '31c9'),
    'unlock_old': (0x452836c, 'b001'),
    'unlock': (0x4528373, 'f00fb00f'),
    't2_clock': (0x452837d, 'bf01000000'),
    'hold_lhs_t1_secs': (0x4528393, '4c897c2460'),
    'hold_lhs_t1_nanos': (0x4528398, '896c2468'),
    'hold_out': (0x452839c, '488d7c2410'),
    'hold_lhs': (0x45283a1, '488d742478'),
    'hold_rhs': (0x45283a6, '488d542460'),
    'extra_flag': (0x45283b0, '0fb68424c0000000'),
    'hold_err': (0x45283b8, '807c241000'),
    'payload_lo': (0x45283f9, '0f104c2440'),
    'payload_hi': (0x45283fe, '660f10542450'),
    'payload_lo_store': (0x4528404, '0f294c2410'),
    'payload_hi_store': (0x4528409, '660f29542420'),
    'wait_load': (0x452840f, 'f20f104c2470'),
    'wait_place': (0x4528415, 'f20f114c2430'),
    'hold_place': (0x452841b, 'f20f11442438'),
    'extra_test': (0x4528421, '84c0'),
    'extra_arg': (0x4528425, 'bf32000000'),
    'out_0': (0x4528430, '0f28442410'),
    'out_1': (0x4528435, '0f284c2420'),
    'out_2': (0x452843a, '0f28542430'),
    'out_store_20': (0x452843f, '0f115320'),
    'out_store_10': (0x4528443, '0f114b10'),
    'out_store_0': (0x4528447, '0f1103'),
    'caller_self_tag': (0x4740584, '410fb64e20'),
    'caller_none_tag': (0x4740589, '80f902'),
    'caller_self_ip': (0x47405d2, '418b5621'),
    'caller_found': (0x4740625, 'b101'),
    'caller_not_found': (0x4740629, '31c9'),
    'caller_flag_store': (0x4740640, '884c2430'),
    'caller_base': (0x4740644, '498b5618'),
    'caller_base_off': (0x4740648, '4883c210'),
    'caller_stack_arg': (0x474064c, 'c7042401000000'),
    'caller_flag_ptr': (0x4740662, '488d4c2430'),
    'caller_name_len': (0x4740667, '41b918000000'),
    'clone_name_len': (0x4740560, '41b805000000'),
    'clock_struct': (0x4ee3809, '488d75e0'),
    'nanos_bound': (0x4ee381c, '4881fa00ca9a3b'),
    'sub_ok_tag': (0x4ee37a5, '48c70300000000'),
    'sub_err_flip': (0x4ee37cd, '4883f001'),
}

# name: (va, instruction length, target)
FLOW = {
    't0_now': (0x45281e3, 5, CLOCK_NOW),
    't1_now': (0x4528214, 5, CLOCK_NOW),
    't2_now': (0x4528382, 5, CLOCK_NOW),
    'wait_sub': (0x4528243, 5, CLOCK_SUB),
    'hold_sub': (0x45283ab, 5, CLOCK_SUB),
    'wait_err_zero': (0x4528251, 2, 0x4528289),
    'hold_err_zero': (0x45283c1, 2, 0x45283f9),
    'tracker_refresh': (0x452829e, 5, TRACKER_REFRESH),
    'include_byte_set': (0x4528309, 2, 0x4528317),
    'include_flag_set': (0x4528310, 2, 0x4528317),
    'null_root_panics': (0x452832d, 6, 0x4528481),
    'map_clone': (0x4528346, 5, MAP_CLONE),
    'extra_skipped': (0x4528423, 2, 0x4528430),
    'caller_copy': (0x474056f, 5, LOCKED_COPY),
    'caller_self_none': (0x4740591, 6, 0x4740629),
    'caller_call': (0x4740670, 5, SNAPSHOT_FDE),
}

RIP = {
    'wait_divisor': (0x452827d, 8, NANOS_PER_SEC),
    'hold_divisor': (0x45283ed, 8, NANOS_PER_SEC),
    'tracker_location': (0x4528297, 7, 0x571ff60),
    'tracker_template': (0x45282e2, 7, 0x1f3bf3),
    'tracker_error_location': (0x45282e9, 7, 0x572e8a8),
    'extra_slot': (0x452842a, 6, 0x576e8f8),
    'unwrap_location': (0x4528481, 7, 0x57357b8),
    'clone_name': (0x4740551, 7, 0x6fb46c),
    'snapshot_name': (0x4740653, 7, 0x6fb471),
    'clock_slot': (0x4ee380d, 6, 0x576ea88),
}


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
        self.glob_dat = {}
        for pos in range(rela['offset'], rela['offset'] + rela['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                self.relative[where] = addend
            elif info & 0xffffffff == 6:
                self.glob_dat[where] = info >> 32
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

    def symbol(self, slot):
        index = self.glob_dat.get(slot)
        if index is None:
            return None
        secs = {s['name']: s for s in self.secs}
        name = secs['.dynstr']['offset'] + struct.unpack_from('<I', self.data, secs['.dynsym']['offset'] + index * 24)[0]
        return self.data[name:self.data.index(b'\0', name)].decode()


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


def check_flow(img):
    out = {}
    for name, (va, n, want) in {**FLOW, **RIP}.items():
        require(windowed(va, n), f'{name} at {va:#x} is outside every window')
        got = img.target(va, n)
        require(got == want, f'{name} at {va:#x} goes to {got:#x}')
        out[name] = hex(got)
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


def imm32(raw):
    return struct.unpack('<I', raw[-4:])[0]


def disp32(raw, at):
    return struct.unpack('<I', raw[at:at + 4])[0]


def rsp8(raw):
    """Displacement of a `[rsp+disp8]` operand ending the instruction."""
    return raw[-1]


def check_clock(img, f):
    sym = img.symbol(RIP['clock_slot'][2])
    require(sym == 'clock_gettime', f'clock slot fills {sym}')
    ids = {k: imm32(f[k]) for k in ('t0_clock', 't1_clock', 't2_clock')}
    require(set(ids.values()) == {1}, f'clock ids are {ids}')
    require(imm32(f['nanos_bound']) == 10 ** 9, 'clock nanos bound is not 1e9')
    div = struct.unpack('<d', img.read(NANOS_PER_SEC, 8))[0]
    require(div == 1e9, f'nanos divisor is {div}')
    return dict(now=hex(CLOCK_NOW), source='clock_gettime(1 = CLOCK_MONOTONIC)', sub=hex(CLOCK_SUB),
                sub_result='tag 0 Ok(lhs - rhs), tag 1 when lhs < rhs', err_value=0.0,
                seconds='secs + nanos / 1e9', divisor=hex(NANOS_PER_SEC))


def check_timing(f):
    require(rsp8(f['t1_secs']) == rsp8(f['wait_lhs']) == rsp8(f['hold_rhs']) == 0x60, 't1 is not [rsp+0x60]')
    require(rsp8(f['t0_secs']) == rsp8(f['wait_rhs']) == 0x40, 't0 is not [rsp+0x40]')
    require(rsp8(f['hold_lhs']) == 0x78, 't2 is not [rsp+0x78]')
    require(rsp8(f['hold_lhs_t1_secs']) == 0x60, 't1 is not restored to [rsp+0x60] before the second sub')
    require(rsp8(f['wait_store']) == rsp8(f['wait_load']) == 0x70, 'wait duration is not [rsp+0x70]')
    require(rsp8(f['wait_out']) == rsp8(f['hold_out']) == 0x10 and f['wait_err'][3] == f['hold_err'][3] == 0x10
            and f['wait_nanos'][-1] == 0x20, 'sub result is not {tag [rsp+0x10], nanos [rsp+0x20]}')
    require(rsp8(f['wait_place']) == 0x30 and rsp8(f['hold_place']) == 0x38, 'durations are not placed at +0x30/+0x38')
    require(f['out_store_20'][-1] == 0x20 and f['out_store_10'][-1] == 0x10, 'output stores changed')
    lock_disp = disp32(f['lock'], 6)
    require(lock_disp == disp32(f['mutex_addr'], 4) == 0x2a0, f'lock byte is +{lock_disp:#x}')
    require(f['lock_new'] == bytes.fromhex('b101') and f['lock_old'] == bytes.fromhex('31c0'), 'lock is not 0 -> 1')
    require(f['unlock_new'] == bytes.fromhex('31c9') and f['unlock_old'] == bytes.fromhex('b001'), 'unlock is not 1 -> 0')
    return dict(t0='before the lock (0x45281e3)', t1='after the lock byte at base+0x2a0 is taken (0x4528214)',
                t2='after the lock byte is released (0x4528382)',
                first='t1 - t0: waiting for the lock', second='t2 - t1: tracker refresh, map clone and unlock',
                output={'+0x0': 'Option tag (r14)', '+0x8..+0x20': 'map words', '+0x20': 't1 - t0', '+0x28': 't2 - t1'})


def check_body(img, f):
    require(disp32(f['tracker_arg'], 4) == 0x2a8, 'tracker is not base+0x2a8')
    loc = location(img, RIP['tracker_location'][2])
    require(loc.endswith('node/src/connections.rs:163:45'), f'tracker refresh Location is {loc}')
    require(disp32(f['tracker_error'], 4) == 0x2f8, 'tracker error word is not base+0x2f8')
    tpl = template(img, RIP['tracker_template'][2])
    require(tpl == [b'Last load of FileModTimeTracker failed: ', None], f'tracker template changed: {tpl}')
    err_loc = location(img, RIP['tracker_error_location'][2])
    require(err_loc.endswith('base/src/file_mod_time_tracker.rs:63:13'), f'tracker error Location is {err_loc}')
    require(disp32(f['include_byte'], 4) == 0x2d8, 'include byte is not base+0x2d8')
    require(f['flag_read'] == bytes.fromhex('0fb601') and f['include_flag'][3] == 7, 'flag is not [rcx] -> [rsp+0x7]')
    offs = {k: disp32(f[k], 4) for k in ('map_root', 'map_height', 'map_len')}
    require(offs == {'map_root': 0x2c0, 'map_height': 0x2c8, 'map_len': 0x2d0}, f'map words are {offs}')
    require(imm32(f['clone_tag']) == imm32(f['empty_tag']) == 1 and f['none_tag'] == bytes.fromhex('4531f6'),
            'Option tags are not 0/1')
    unwrap = location(img, RIP['unwrap_location'][2])
    require(unwrap.endswith('library/alloc/src/collections/btree/map.rs:306:46'), f'unwrap Location is {unwrap}')
    prologue = img.read(SNAPSHOT_FDE, 17)
    require(prologue[:13] == bytes.fromhex('554157415641554154534881ec'), 'prologue is not six pushes and sub rsp')
    frame = 6 * 8 + imm32(prologue) + 8
    require(disp32(f['extra_flag'], 4) == frame == 0xc0, 'extra flag is not the first stack argument')
    extra = img.relative.get(RIP['extra_slot'][2])
    require(extra is not None, 'extra call slot has no RELATIVE target')
    require(imm32(f['extra_arg']) == 50, 'extra call argument is not 50')
    return dict(base='rdx (r12)', lock='base+0x2a0', tracker='base+0x2a8',
                tracker_refresh=dict(call=hex(TRACKER_REFRESH), location=loc),
                tracker_error=dict(test='[base+0x2f8] != 0', template=hex(RIP['tracker_template'][2]), location=err_loc),
                include='[base+0x2d8] != 0 or ([rcx] & 1)',
                map={'root': '+0x2c0', 'height': '+0x2c8', 'length': '+0x2d0'},
                included={'length 0': 'Some(empty map)', 'root set': f'Some(clone via {MAP_CLONE:#x})',
                          'root null, length > 0': f'unwrap panic at {unwrap}'},
                not_included='None (tag 0)',
                extra=dict(test='first stack argument byte ([rsp+0xc0])', call_slot=hex(RIP['extra_slot'][2]),
                           target=hex(extra), argument=50, result='discarded'))


def check_caller(img, f):
    names = {}
    for key, length_fact in (('clone_name', 'clone_name_len'), ('snapshot_name', 'caller_name_len')):
        n = imm32(f[length_fact])
        names[key] = img.read(RIP[key][2], n).decode()
    require(names == {'clone_name': 'clone', 'snapshot_name': 'update_and_get_overrides'}, f'names are {names}')
    require(f['caller_self_tag'][-1] == 0x20 and f['caller_self_ip'][-1] == 0x21 and f['caller_none_tag'][-1] == 2,
            'self NodeIp is not Option at [r14+0x20] with None tag 2')
    require(imm32(f['caller_stack_arg']) == 1, 'stack argument is not 1')
    require(f['caller_base'][-1] == 0x18 and f['caller_base_off'][-1] == 0x10, 'base is not [r14+0x18]+0x10')
    require(rsp8(f['caller_flag_store']) == rsp8(f['caller_flag_ptr']) == 0x30, 'flag is not &[rsp+0x30]')
    return dict(call=hex(FLOW['caller_call'][0]), base='[r14+0x18] + 0x10', flag='&[rsp+0x30]',
                flag_value='self NodeIp ([r14+0x20], tag 2 = None) is Some and appears in the list '
                           f'returned by {LOCKED_COPY:#x} ("clone")',
                stack_argument=1, name_args=names['snapshot_name'], name_length=0x18)


def callers(img):
    slots = sorted(k for k, v in img.relative.items() if v == SNAPSHOT_FDE)
    require(slots == [], f'RELATIVE slots holding {SNAPSHOT_FDE:#x}: {[hex(s) for s in slots]}')
    return dict(relative_slots=[], direct_call=hex(FLOW['caller_call'][0]))


def seconds(lhs, rhs):
    """f64 seconds of `lhs - rhs` for (secs, nanos) pairs; 0.0 when lhs < rhs."""
    if lhs < rhs:
        return 0.0
    secs, nanos = lhs[0] - rhs[0], lhs[1] - rhs[1]
    if nanos < 0:
        secs, nanos = secs - 1, nanos + 10 ** 9
    return secs + nanos / 1e9


def binary_durations(events):
    """(first, second) from event times: call, locked, refreshed, cloned, unlocked."""
    return events['locked'] - events['call'], events['unlocked'] - events['locked']


def lead_durations(events):
    """(update_elapsed_secs, clone_elapsed_secs) as the lead measures them."""
    return events['refreshed'] - events['locked'], events['cloned'] - events['refreshed']


def snapshot(include_byte, flag, length, root):
    if not (include_byte or flag & 1):
        return 'None'
    if length == 0:
        return 'Some(empty)'
    if root == 0:
        return 'panic'
    return 'Some(clone)'


def analyse(data):
    img = Image(data)
    win = windows(img)
    f = facts(img)
    return dict(target=TARGET, fde=hex(SNAPSHOT_FDE), callers=callers(img),
                windows={k: hex(v) for k, v in win.items()}, flow=check_flow(img), clock=check_clock(img, f),
                timing=check_timing(f), body=check_body(img, f), caller=check_caller(img, f))


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
    t = result['timing']
    print(f"first duration: {t['first']}; second duration: {t['second']}")
    print(f"map included when {result['body']['include']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
