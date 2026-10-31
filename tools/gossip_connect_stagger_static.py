#!/usr/bin/env python3
"""Static node #94 gossip connect deadlines in `0x4740490`, checked from authenticated bytes.

Question: `0x4740490` (span name `update_and_get_overrides`) takes a locked
copy of a peer list, the timed override snapshot `0x45281c0`, and schedules
each candidate peer with a deadline.  How is the deadline computed?  Does it
use the snapshot's two durations?  The can1357 lead
(`update_and_get_overrides_and_connect_peers`, `node/connections.rs`) spawns
every connect immediately.  Where does it differ?

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; immediates, f64 constants, call,
branch and RIP-relative targets, a panic Location and RELATIVE slots are
decoded here.  A ModRM/SIB scan of the whole caller FDE pins every
`[rsp+disp32]` operand that can touch the snapshot durations and the delay
factor.  Nothing from the binary is executed.
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
CALLER_FDE = 0x4740490
LOCKED_COPY = 0x45297f0
SNAPSHOT = 0x45281c0
WALL_NOW = 0x151cba0
ADD_SECS = 0x1459ca0
CLOCK_NOW = 0x4ee3800
MAP_SEARCH = 0x42b8d90
SCHEDULE = 0x47bb530
SNAPSHOT_OUT = 0x180
DURATIONS = (0x1a0, 0x1a8)

WINDOWS = {
    'entry': (CALLER_FDE, 0x4740490,
        '554157415641554154534881ecb80300004989f44989fe88542417488dbc24dc000000ff15e7e30201'),
    'lists': (CALLER_FDE, 0x4740549,
        '498b56104883c210488d0d14affbfb488dbc248001000041b8050000004889d641b901000000e87c92deff488bac2488'
        '010000488b842490010000410fb64e2080f90248894424580f84920000004885c00f8489000000488d048080f9027529'
        'b101807d0002747aba05000000662e0f1f8400000000004839d07464807c150002488d520575f0eb59418b56210fb6f1'
        '4889d748c1e7084809f740f6c701741e89d231f6eb0a904883c6054839f07430384c350075f13854350175ebeb1e31f6'
        'eb0e0f1f4400004883c6054839f07410384c350075f13954350175ebb101eb0231c9488b842480010000488944241848'
        '8b9c2498010000884c2430498b56184883c210c70424010000004c8d0517aefbfb488dbc2480010000488d4c243041b9'
        '180000004889d6e84b7bdeff49bf0000000000000080660f10842488010000660f298424b0020000488b842498010000'
        '48898424c0020000f684248001000001'),
    'factor': (CALLER_FDE, 0x47406a9,
        '0f8493000000488b8424c002000048898424680100000f288424b00200000f11842458010000488b4424184889842438'
        '0100004889ac2440010000488b442458488984244801000066480f6ec3660f62058237acfb48899c2450010000660f5c'
        '059227acfb660f28c8660f15c8f20f58c8f20f590d96a8acfb660f298c2470010000498b042448898424f00000004885'
        'c00f854f010000eb484c89bc2438010000660f57c0660f29842470010000488b4424184885c0740f488d34804889ef31'
        'd2ff15a0d802014c897c2418498b042448898424f00000004885c00f8505010000'),
    'deadline': (CALLER_FDE, 0x4740cf0,
        'f049ff45004d89ef0f8eaa0300004c89bc24300100004d39e675258b8424e4000000898424a0000000488b8424dc0000'
        '004889842498000000e93d0100006690488bb424580100004885f6742f488b442428488d8899000000488b9424600100'
        '00488dbc2480010000e83280b7ff83bc2480010000010f859e000000488b4c24280fb681990000008b899a00000048c7'
        'c2ffffffff31f6240174450f1f4400004839b424c0000000746940b701384435007508384c3501400f95c74883fafe0f'
        '84d402000048ffc24883c6054084ff75cfeb5c666666662e0f1f8400000000004839b424c0000000742940b701384435'
        '007508394c3501400f95c74883fafe0f849402000048ffc24883c6054084ff75cfeb1c488b542458eb15488b84248801'
        '0000488b8c2498010000488b54c80866480f6ec2660f62055430acfb660f5c056c20acfb660f28c8660f15c8f20f58c8'
        'f20f598c2470010000f20f10052f9eacfbf20f5dc1488dbc2498000000488db424dc000000ff154de10201488b7c2428'
        '4883c7488b8424a000000089842488010000488b84249800000048898424800100004c89bc2490010000488db4248001'
        '0000e889a607003c05'),
    'enumerate_panic': (CALLER_FDE, 0x4741089,
        '488d3d58c9fe00ff1582d00201'),
    'wall_now': (WALL_NOW, 0x151cba0,
        '5541574156534883ec384889fb31ffe84c6c9c0348894424188954242048c744242800000000c7442430000000004889'
        'e7488d742418488d542428e8506b9c03'),
    'add_secs': (ADD_SECS, 0x1459ca0,
        '534883ec304889fb8b460889442408488b0648890424f20f59056205dbfe'),
    'loop_regs': (CALLER_FDE, 0x47408d3,
        '4c8b74241849bc0000000000000080'),
    'reload': (CALLER_FDE, 0x4740bd4,
        '4c8bbc24e8000000f049ff074c8b6c2460488bac24800000004c8b74241849bc00000000000000800f8ffc000000e9a1'
        '040000488b44242848837830644c8b6c2460488bac24800000004c8b74241849bc0000000000000080'),
    'locked_copy': (LOCKED_COPY, 0x45297f0,
        '554157415641554154534881ec9800000044894c242c4989d54889fbbf01000000e8ea9f9b004989c74189d4498d85a0'
        '0200004889442410b10131c0f0410fb08da00200000f85e8010000bf01000000e8bb9f9b004889c54189d64889442440'
        '895424484c897c24504489642458488d7c2460488d742440488d542450e8be9e9b00498bb5b8020000b9050000004889'
        'f048f7e14989c40f90c04d85e40f98c108c1740d31ff4c89e6ff15194724010f0b48897424380f284424600f29842480'
        '0000008b442470894424284d8bbdb00200004d85e474214c89e7ff15084724014885c00f84710100004889c7488b4424'
        '384889442408eb0ebf0100000048c74424080000000048897c24304c89fe4c89e2ff15d94624014d8bbdc002000031c9'
        'b001f0410fb08da00200000f8517010000bf01000000e8d59e9b0048894424408954244848896c24504489742458488d'
        '7c2460488d742440488d542450e8de9d9b000f284424600f294424108b6c2470807c242c004c8b742430740bbf320000'
        '00ff15814f2401660f6f9c2480000000660f6fc3660f6f642410660f6cc4660f70c0a0660f72f01f660f6ecd660f6e54'
        '2428660f62d1f30fe6ca660f6ddc660f6f156af6cdfb660fdbd3660feb151eddcdfb660f73d320660feb1d51b2cdfb66'
        '0f5c1d59b2cdfb660f72e01f660f58da488b4424084889034c897308488b442438488943104c897b18660f5e0dafb8cd'
        'fb660f58cb660fdfc1f30f7f4320'),
}

# name: (va, hex) -- every entry must sit inside a checked window.
FACTS = {
    'now_arg': (0x47404ab, '488dbc24dc000000'),  # lea    rdi,[rsp+0xdc]
    'copy_base': (0x4740549, '498b5610'),  # mov    rdx,QWORD PTR [r14+0x10]
    'copy_base_off': (0x474054d, '4883c210'),  # add    rdx,0x10
    'copy_name_len': (0x4740560, '41b805000000'),  # mov    r8d,0x5
    'list_ptr': (0x4740574, '488bac2488010000'),  # mov    rbp,QWORD PTR [rsp+0x188]
    'list_len': (0x474057c, '488b842490010000'),  # mov    rax,QWORD PTR [rsp+0x190]
    'list_len_store': (0x474058c, '4889442458'),  # mov    QWORD PTR [rsp+0x58],rax
    'x_load': (0x4740638, '488b9c2498010000'),  # mov    rbx,QWORD PTR [rsp+0x198]
    'none_sentinel': (0x4740675, '49bf0000000000000080'),  # movabs r15,0x8000000000000000
    'tag_test': (0x47406a1, 'f684248001000001'),  # test   BYTE PTR [rsp+0x180],0x1
    'map_store': (0x47406c7, '0f11842458010000'),  # movups XMMWORD PTR [rsp+0x158],xmm0
    'x_to_f64': (0x47406f1, '66480f6ec3'),  # movq   xmm0,rbx
    'factor_store': (0x4740722, '660f298c2470010000'),  # movapd XMMWORD PTR [rsp+0x170],xmm1
    'none_factor': (0x474074a, '660f57c0'),  # xorpd  xmm0,xmm0
    'none_factor_store': (0x474074e, '660f29842470010000'),  # movapd XMMWORD PTR [rsp+0x170],xmm0
    'none_list': (0x4740770, '4c897c2418'),  # mov    QWORD PTR [rsp+0x18],r15
    'loop_list': (0x47408d3, '4c8b742418'),  # mov    r14,QWORD PTR [rsp+0x18]
    'loop_sentinel': (0x47408d8, '49bc0000000000000080'),  # movabs r12,0x8000000000000000
    'reload_list': (0x4740bed, '4c8b742418'),  # mov    r14,QWORD PTR [rsp+0x18]
    'reload_sentinel': (0x4740bf2, '49bc0000000000000080'),  # movabs r12,0x8000000000000000
    'reload_list_2': (0x4740c1e, '4c8b742418'),  # mov    r14,QWORD PTR [rsp+0x18]
    'reload_sentinel_2': (0x4740c23, '49bc0000000000000080'),  # movabs r12,0x8000000000000000
    'none_test': (0x4740d06, '4d39e6'),  # cmp    r14,r12
    'now_hi': (0x4740d0b, '8b8424e4000000'),  # mov    eax,DWORD PTR [rsp+0xe4]
    'now_lo': (0x4740d19, '488b8424dc000000'),  # mov    rax,QWORD PTR [rsp+0xdc]
    'map_root': (0x4740d30, '488bb42458010000'),  # mov    rsi,QWORD PTR [rsp+0x158]
    'peer_key': (0x4740d42, '488d8899000000'),  # lea    rcx,[rax+0x99]
    'map_height': (0x4740d49, '488b942460010000'),  # mov    rdx,QWORD PTR [rsp+0x160]
    'search_tag': (0x4740d5e, '83bc248001000001'),  # cmp    DWORD PTR [rsp+0x180],0x1
    'key_tag': (0x4740d71, '0fb68199000000'),  # movzx  eax,BYTE PTR [rcx+0x99]
    'key_ip': (0x4740d78, '8b899a000000'),  # mov    ecx,DWORD PTR [rcx+0x9a]
    'index_start': (0x4740d7e, '48c7c2ffffffff'),  # mov    rdx,0xffffffffffffffff
    'index_overflow_a': (0x4740dab, '4883fafe'),  # cmp    rdx,0xfffffffffffffffe
    'index_inc_a': (0x4740db5, '48ffc2'),  # inc    rdx
    'stride_a': (0x4740db8, '4883c605'),  # add    rsi,0x5
    'index_overflow_b': (0x4740deb, '4883fafe'),  # cmp    rdx,0xfffffffffffffffe
    'index_inc_b': (0x4740df5, '48ffc2'),  # inc    rdx
    'stride_b': (0x4740df8, '4883c605'),  # add    rsi,0x5
    'missing_index': (0x4740e03, '488b542458'),  # mov    rdx,QWORD PTR [rsp+0x58]
    'map_value_node': (0x4740e0a, '488b842488010000'),  # mov    rax,QWORD PTR [rsp+0x188]
    'map_value_idx': (0x4740e12, '488b8c2498010000'),  # mov    rcx,QWORD PTR [rsp+0x198]
    'map_value': (0x4740e1a, '488b54c808'),  # mov    rdx,QWORD PTR [rax+rcx*8+0x8]
    'k_to_f64': (0x4740e1f, '66480f6ec2'),  # movq   xmm0,rdx
    'scale': (0x4740e40, 'f20f598c2470010000'),  # mulsd  xmm1,QWORD PTR [rsp+0x170]
    'cap_min': (0x4740e51, 'f20f5dc1'),  # minsd  xmm0,xmm1
    'deadline_out': (0x4740e55, '488dbc2498000000'),  # lea    rdi,[rsp+0x98]
    'deadline_base': (0x4740e5d, '488db424dc000000'),  # lea    rsi,[rsp+0xdc]
    'peer_target': (0x4740e70, '4883c748'),  # add    rdi,0x48
    'deadline_lo': (0x4740e82, '488b842498000000'),  # mov    rax,QWORD PTR [rsp+0x98]
    'deadline_arg': (0x4740e9a, '488db42480010000'),  # lea    rsi,[rsp+0x180]
    'copy_lock': (0x452982c, 'f0410fb08da0020000'),  # lock cmpxchg BYTE PTR [r13+0x2a0],cl
    'copy_len': (0x4529872, '498bb5b8020000'),  # mov    rsi,QWORD PTR [r13+0x2b8]
    'copy_stride': (0x4529879, 'b905000000'),  # mov    ecx,0x5
    'copy_ptr': (0x45298bb, '4d8bbdb0020000'),  # mov    r15,QWORD PTR [r13+0x2b0]
    'copy_x': (0x4529907, '4d8bbdc0020000'),  # mov    r15,QWORD PTR [r13+0x2c0]
    'copy_unlock': (0x4529912, 'f0410fb08da0020000'),  # lock cmpxchg BYTE PTR [r13+0x2a0],cl
    'out_ptr': (0x45299e8, '4c897308'),  # mov    QWORD PTR [rbx+0x8],r14
    'out_len': (0x45299f1, '48894310'),  # mov    QWORD PTR [rbx+0x10],rax
    'out_x': (0x45299f5, '4c897b18'),  # mov    QWORD PTR [rbx+0x18],r15
    'wall_clock_id': (0x151cbad, '31ff'),  # xor    edi,edi
    'secs_to_nanos': (0x1459cb6, 'f20f59056205dbfe'),  # mulsd  xmm0,QWORD PTR [rip+0xfffffffffedb0562]
}

# name: (va, instruction length, target)
FLOW = {
    'locked_copy_call': (0x474056f, 5, LOCKED_COPY),
    'snapshot_call': (0x4740670, 5, SNAPSHOT),
    'none_branch': (0x47406a9, 6, 0x4740742),
    'some_deadline': (0x4740d09, 2, 0x4740d30),
    'none_deadline': (0x4740d29, 5, 0x4740e6b),
    'no_map_to_list': (0x4740d3b, 2, 0x4740d6c),
    'map_search': (0x4740d59, 5, MAP_SEARCH),
    'map_hit': (0x4740d66, 6, 0x4740e0a),
    'list_end_a': (0x4740d98, 2, 0x4740e03),
    'list_end_b': (0x4740dd8, 2, 0x4740e03),
    'overflow_a': (0x4740daf, 6, 0x4741089),
    'overflow_b': (0x4740def, 6, 0x4741089),
    'schedule': (0x4740ea2, 5, SCHEDULE),
    'wall_clock': (0x151cbaf, 5, CLOCK_NOW),
}

RIP = {
    'now_slot': (0x47404b3, 6, 0x576e8a0),
    'clone_name': (0x4740551, 7, 0x6fb46c),
    'snapshot_name': (0x4740653, 7, 0x6fb471),
    'factor_constant': (0x474071a, 8, 0x20afb8),
    'cap_constant': (0x4740e49, 8, 0x20ac80),
    'add_slot': (0x4740e65, 6, 0x576efb8),
    'enumerate_location': (0x4741089, 7, 0x572d9e8),
    'nanos_constant': (0x1459cb6, 8, 0x20a220),
}

# ModRM addresses of [rsp+disp32] operands in the caller FDE.
DURATION_CENSUS = [0x47404fe, 0x474063a, 0x4740693, 0x4740e14, 0x47411f9]
FACTOR_CENSUS = [0x47406b9, 0x4740725, 0x4740751, 0x4740e43]


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

    def f64(self, va):
        return struct.unpack('<d', self.read(va, 8))[0]


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


def location(img, va):
    ptr = img.relative.get(va)
    require(ptr is not None, f'Location {va:#x} has no RELATIVE file pointer')
    n, line, col = struct.unpack('<QII', img.read(va + 8, 16))
    require(0 < n < 256, f'Location {va:#x} has length {n}')
    path = img.read(ptr, n)
    require(all(0x20 <= c < 0x7f for c in path), f'Location {va:#x} path is not text')
    return f'{path.decode()}:{line}:{col}'


def disp32(raw, at):
    return struct.unpack('<I', raw[at:at + 4])[0]


def imm32(raw):
    return struct.unpack('<I', raw[-4:])[0]


def rsp_census(img, lo, hi):
    """ModRM addresses of every [rsp+disp32] operand with lo <= disp < hi in the caller FDE."""
    start, end = img.fde(CALLER_FDE)
    code = img.read(start, end - start)
    return [start + i for i in range(len(code) - 6) if code[i] & 0xc7 == 0x84 and code[i + 1] == 0x24
            and lo <= struct.unpack_from('<I', code, i + 2)[0] < hi]


def census_record(img, sites):
    return {hex(v): hex(struct.unpack('<I', img.read(v + 2, 4))[0]) for v in sites}


def check_locked_copy(f):
    offs = {k: disp32(f[k], 5) for k in ('copy_lock', 'copy_unlock')}
    require(set(offs.values()) == {0x2a0}, f'locked copy lock bytes are {offs}')
    fields = {k: disp32(f[k], 3) for k in ('copy_ptr', 'copy_len', 'copy_x')}
    require(fields == {'copy_ptr': 0x2b0, 'copy_len': 0x2b8, 'copy_x': 0x2c0}, f'locked copy fields are {fields}')
    require(FACTS['copy_x'][0] < FACTS['copy_unlock'][0], 'X is not read before the unlock')
    require(imm32(f['copy_stride']) == 5, 'list element is not 5 bytes')
    require((f['out_ptr'][-1], f['out_len'][-1], f['out_x'][-1]) == (8, 0x10, 0x18), 'locked copy output changed')
    return dict(base='[r14+0x10] + 0x10', lock='+0x2a0', list={'ptr': '+0x2b0', 'len': '+0x2b8', 'element': 5},
                x='+0x2c0 (u64, read before the unlock)', output={'+0x8': 'list ptr', '+0x10': 'list len', '+0x18': 'X'})


def check_factor(img, f):
    factor = img.f64(RIP['factor_constant'][2])
    require(factor == 0.001, f'factor constant is {factor}')
    require(disp32(f['x_load'], 4) == SNAPSHOT_OUT + 0x18, 'X is not copy output +0x18')
    require(f['x_to_f64'] == bytes.fromhex('66480f6ec3'), 'X is not converted from rbx')
    require(disp32(f['tag_test'], 3) == SNAPSHOT_OUT, 'tag test is not the snapshot output')
    require(disp32(f['factor_store'], 5) == disp32(f['none_factor_store'], 5) == disp32(f['scale'], 5) == 0x170,
            'factor is not [rsp+0x170]')
    got = rsp_census(img, 0x161, 0x180)
    require(got == FACTOR_CENSUS, f'[rsp+0x170] operands are {[hex(v) for v in got]}')
    require(f['none_sentinel'] == bytes.fromhex('49bf0000000000000080') and f['none_list'] == bytes.fromhex('4c897c2418'),
            'None path does not store 2**63 to [rsp+0x18]')
    return dict(slot='[rsp+0x170]', some=f'X * {factor}', none=0.0, census=census_record(img, got),
                none_list_sentinel='[rsp+0x18] = 2**63 (0x4740770)')


def check_deadline(img, f):
    cap = img.f64(RIP['cap_constant'][2])
    require(cap == 0.07, f'cap constant is {cap}')
    add = img.relative.get(RIP['add_slot'][2])
    require(add == ADD_SECS, f'add slot resolves to {add}')
    now = img.relative.get(RIP['now_slot'][2])
    require(now == WALL_NOW, f'now slot resolves to {now}')
    require(f['wall_clock_id'] == bytes.fromhex('31ff'), 'wall clock id is not 0')
    nanos = img.f64(RIP['nanos_constant'][2])
    require(nanos == 1e9, f'seconds multiplier is {nanos}')
    require(disp32(f['now_arg'], 4) == disp32(f['now_lo'], 4) == disp32(f['deadline_base'], 4) == 0xdc,
            'now is not [rsp+0xdc]')
    require(f['none_test'] == bytes.fromhex('4d39e6'), 'None test is not cmp r14,r12')
    for k in ('loop_list', 'reload_list', 'reload_list_2'):
        require(f[k] == bytes.fromhex('4c8b742418'), f'{k} is not r14 = [rsp+0x18]')
    for k in ('loop_sentinel', 'reload_sentinel', 'reload_sentinel_2'):
        require(f[k] == bytes.fromhex('49bc0000000000000080'), f'{k} is not r12 = 2**63')
    require(f['peer_key'][-4:] == struct.pack('<I', 0x99) and f['key_tag'][-4:] == struct.pack('<I', 0x99)
            and f['key_ip'][-4:] == struct.pack('<I', 0x9a), 'peer NodeIp is not at +0x99')
    require(disp32(f['map_root'], 4) == 0x158 and disp32(f['map_height'], 4) == 0x160
            and disp32(f['map_store'], 4) == 0x158, 'snapshot map is not [rsp+0x158]')
    require(f['index_start'] == bytes.fromhex('48c7c2ffffffff') and f['stride_a'][-1] == f['stride_b'][-1] == 5,
            'list walk changed')
    require(f['missing_index'] == bytes.fromhex('488b542458'), 'missing index is not the list length [rsp+0x58]')
    require(f['map_value'] == bytes.fromhex('488b54c808'), 'map value is not node+8+8*idx')
    require(f['cap_min'] == bytes.fromhex('f20f5dc1'), 'cap is not minsd(cap, k * factor)')
    require(f['peer_target'][-1] == 0x48, 'schedule target is not peer+0x48')
    loc = location(img, RIP['enumerate_location'][2])
    require(loc.endswith('library/core/src/iter/adapters/enumerate.rs:120:17'), f'enumerate Location is {loc}')
    return dict(now=dict(call=hex(WALL_NOW), clock='clock_gettime(0 = CLOCK_REALTIME)', slot='[rsp+0xdc]'),
                none='deadline = now', cap=cap, add=dict(call=hex(ADD_SECS), seconds_to_nanos=nanos),
                some='deadline = now + min(cap, k * [rsp+0x170])',
                k={'snapshot map has the peer NodeIp': 'its u64 value (search 0x42b8d90, tag != 1)',
                   'else, NodeIp in the locked list': 'its 0-based index',
                   'else': 'the list length'},
                peer_key='peer +0x99', index_overflow=loc, schedule=dict(call=hex(SCHEDULE), target='peer+0x48',
                                                                          argument='{deadline, Arc}'))


def check_durations(img):
    got = rsp_census(img, DURATIONS[0] - 0xf, DURATIONS[1] + 8)
    require(got == DURATION_CENSUS, f'[rsp+0x191..0x1b0) operands are {[hex(v) for v in got]}')
    record = census_record(img, got)
    below = [v for v in got if int(record[hex(v)], 16) < DURATIONS[0]]
    for v in below:
        prefix = img.read(v - 2, 2)
        require(prefix[0] in (0x48, 0x4c) and prefix[1] == 0x8b, f'operand at {v:#x} is not an 8-byte mov load')
    touching = [v for v in got if v not in below]
    require(all(v < FLOW['snapshot_call'][0] for v in touching), 'a duration operand follows the snapshot call')
    return dict(snapshot_output='[rsp+0x180]', durations=['[rsp+0x1a0]', '[rsp+0x1a8]'],
                operands=record, eight_byte_below_0x1a0=[hex(v) for v in below],
                touching=[hex(v) for v in touching], after_call='none')


def check_names(img, f):
    clone = img.read(RIP['clone_name'][2], imm32(f['copy_name_len'])).decode()
    snap = img.read(RIP['snapshot_name'][2], 0x18).decode()
    require((clone, snap) == ('clone', 'update_and_get_overrides'), f'names are {clone!r}, {snap!r}')
    return dict(locked_copy=clone, snapshot=snap)


def k_value(map_value, list_index, list_len):
    if map_value is not None:
        return map_value
    if list_index is not None:
        return list_index
    return list_len


def delay(snapshot_some, x, k, cap=0.07, factor=0.001):
    """Seconds added to the wall-clock now for one candidate."""
    if not snapshot_some:
        return 0.0
    return min(cap, k * (x * factor))


def analyse(data):
    img = Image(data)
    win = windows(img)
    f = facts(img)
    return dict(target=TARGET, fde=hex(CALLER_FDE), windows={k: hex(v) for k, v in win.items()},
                flow=check_flow(img), names=check_names(img, f), locked_copy=check_locked_copy(f),
                factor=check_factor(img, f), deadline=check_deadline(img, f), durations=check_durations(img))


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
    d = result['deadline']
    print(f"deadline: snapshot None -> now; Some -> now + min({d['cap']}, k * X * {result['factor']['some'].split()[-1]})")
    print(f"snapshot durations read after the call: {result['durations']['after_call']}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
