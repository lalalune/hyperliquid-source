#!/usr/bin/env python3
"""Static node #94 firewall/validator mismatch log gate in `0x4b28ff0`, checked from authenticated bytes.

Question: `0x4b28ff0` builds two IP sets, takes both set differences and
emits `firewall does not match validators` (`firewall_ips.rs:65:13`).  When
does it log, and what does it return?  The can1357 lead
(`node/firewall_ips.rs`) logs and returns `Err` whenever either difference is
non-empty.  Where does the binary differ?

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; call, branch and RIP-relative
targets, f64 constants, the packed format templates, a panic Location and
RELATIVE slots are decoded here.  Nothing from the binary is executed.
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
LOG_FDE = 0x4b28ff0
CALLER_FDE = 0x4524f70
DIFFERENCE = 0x44c1ce0
ELAPSED = 0x1447130
WALL_NOW = 0x151cba0
SINCE = 0x151d1b0
ABCI_BUILD = 0x45c3d20
LEVEL_STATIC = 0x577b288
LOG_EMIT = 0x143d010

WINDOWS = {
    'gate': (LOG_FDE, 0x4b28ff0,
        '554157415641554154534881ec680100004c89c34989fe4c8b3d1a59c400418b475085c07526410fb6474883f8117770'
        'bf068002000fa3c773664881c4680100005b415c415d415e415f5dc34c89bc24c8000000488d8424c800000048890424'
        '498d7f50488d05b521b5004c8d05d621b5004989e14989f4be0100000089d54c89ca4989cd4889c1ff153a58c4004c89'
        'e689ea4c89e9410fb6474883f81176904989f489d54989cf'),
    'body': (LOG_FDE, 0x4b29098,
        '498b06498b4e0831d24889c64885c00f95c27404498b76104889142448c744240800000000488944241048894c241848'
        '8954242048c744242800000000488944243048894c24384889742440488dbc24280100004889e6e83c6992ff418b4424'
        '108944241166410f100424660f11442401c6042401400fb6f5488dbc24c80000004889e14c89faff1523aac4004c8ba4'
        '24c80000004c8bac24d000000031c04d85e40f95c04c8bbc24d80000004c89f9490f44cc4889042448c7442408000000'
        '004c896424104c896c2418488944242048c7442428000000004c896424304c896c243848894c2440488dbc2440010000'
        '4889e6e8f06492ff4d85e4742d48c7442408000000004c896424104c896c241848c7442428000000004c896424304c89'
        '6c2438b801000000eb0531c04531ff4889042448894424204c897c24404c8dbc24b00000004989e44c89ff4c89e6e8c5'
        '0fe2ff4883bc24b00000000075ea488b8c24e00000004885c9743d488b9424e8000000488b8424f000000048c7442408'
        '0000000048894c2410488954241848c74424280000000048894c24304889542438b901000000eb0431c931c048890c24'
        '48894c242048894424404c8dbc24b00000004989e40f1f004c89ff4c89e6e845e6e1ff4883bc24b00000000075ea488b'
        '8c24f80000004885c9743d488b942400010000488b84240801000048c74424080000000048894c2410488954241848c7'
        '4424280000000048894c24304889542438b901000000eb0431c931c048890c2448894c242048894424404c8dbc24b000'
        '00004989e40f1f004c89ff4c89e6e8c5e5e1ff4883bc24b00000000075ea4889e7488db42440010000488d9424280100'
        '00e8d28999ff4c8dac24100100004989e44c89ef4c89e6e89c6892ff4c89b424b0000000488bb424100100004885f674'
        '19488b942418010000488d7c2418b902000000e8000779ffeb0c48c7442418000000004531ed4c8d742408488d842420'
        '01000048894424084c896c24104c893c244c8dbc24c80000006666666666662e0f1f8400000000004c89a424c8000000'
        '4c89f74c89fee81dc6e2ff4885c075e84889e7488db42428010000488d942440010000e8208999ff4c8db424b0000000'
        '4889e64c89f7e8ed6792ff4883bc242001000000750f4883bc24c0000000060f86240100004c8dbc24a00000004c89ff'
        'ff15a254c4008b430885c0747bf20f1003f20f11842458010000488b4b0c8b9424a8000000899424d0000000488b9424'
        'a000000048899424c800000089042448894c240448b8010000001c0000004889442410488d051bdb6efb488944241848'
        'c744242030000000488dbc24c80000004889e6ff154f54c400660f2e8424580100000f86910000004883c3088b8424a8'
        '000000894308488b8424a000000048890348c78424c800000000000000c78424d800000000000000c68424dc00000000'
        '488d84241001000048898424600100004c89b424a0000000488d84246001000048890424488d05fd28a6ff4889442408'
        '4c897c24104889442418488d351f116dfb488d0d90efc000488dbc24c80000004889e2ff156754c400'),
    'tail': (LOG_FDE, 0x4b29620, '4889df4c89f6e86569e2ff4883bc24c80000000075eae9eff9ffff'),
    'tipping': (DIFFERENCE, 0x44c201e, '4c8b4610488b6a104889ee48c1ee044939f00f86eb010000'),
    'elapsed': (ELAPSED, 0x1447130,
        '534883ec508b460889442408488b06488904248b5e1039070f9cc00f85830000008b47043b4424040f92c075778b4708'
        '3b4424087272ff15347932044885c0400f98c685d20f9fc14020f10fb6f14801c64869c640420f00660f57c070408db2'
        '003665c484c90f44f24863ce4869c9d34d62104889ca48c1ea3f48c1f92601d14863c94801c80f90c1f6c10175100f57'
        'c0f2480f2ac0f20f5e05923cdcfe4883c4505bc3'),
    'elapsed_panic': (ELAPSED, 0x14471d4,
        '84c0748e48897c2418488d05ccd6000048894424204889e148894c24284889442430488d35b92adbfe488d7c2438488d'
        '542418ff15336e3204'),
    'caller': (CALLER_FDE, 0x452502e,
        '4d8b6500498b6d084d8b7510498b5d184983bfb8050000007453498d87b8050000488944244848c744241000000000c7'
        '44242000000000c644242400488d44244848890424488d05b6a300004889442408488d356debccfb488d0d1b98200148'
        '8d7c24104889e2ff15dd9824014981c788050000418b44241089442420410f1004240f294424104981c6f80800000fb6'
        '95f2080000488d7424104c89ff4c89f14989d8e81a3f600048c7c0f0ffffff'),
    'wall_now': (WALL_NOW, 0x151cba0, '5541574156534883ec384889fb31ffe84c6c9c03'),
}

# name: (va, hex) -- every entry must sit inside a checked window.
FACTS = {
    'throttle_arg': (0x4b29001, '4c89c3'),  # mov    rbx,r8
    'arg0_keep': (0x4b29004, '4989fe'),  # mov    r14,rdi
    'level_byte': (0x4b29016, '410fb64748'),  # movzx  eax,BYTE PTR [r15+0x48]
    'level_bound': (0x4b2901b, '83f811'),  # cmp    eax,0x11
    'level_mask': (0x4b29020, 'bf06800200'),  # mov    edi,0x28006
    'level_bt': (0x4b29025, '0fa3c7'),  # bt     edi,eax
    'fw_root': (0x4b29098, '498b06'),  # mov    rax,QWORD PTR [r14]
    'fw_height': (0x4b2909b, '498b4e08'),  # mov    rcx,QWORD PTR [r14+0x8]
    'fw_len': (0x4b290ac, '498b7610'),  # mov    rsi,QWORD PTR [r14+0x10]
    'fw_out': (0x4b290e4, '488dbc2428010000'),  # lea    rdi,[rsp+0x128]
    'abci_src': (0x4b290f4, '418b442410'),  # mov    eax,DWORD PTR [r12+0x10]
    'abci_tag': (0x4b29109, 'c6042401'),  # mov    BYTE PTR [rsp],0x1
    'abci_flag': (0x4b2910d, '400fb6f5'),  # movzx  esi,bpl
    'abci_state': (0x4b2911c, '4c89fa'),  # mov    rdx,r15
    'abci_out': (0x4b29180, '488dbc2440010000'),  # lea    rdi,[rsp+0x140]
    'diff1_out': (0x4b292f6, '4889e7'),  # mov    rdi,rsp
    'diff1_self': (0x4b292f9, '488db42440010000'),  # lea    rsi,[rsp+0x140]
    'diff1_other': (0x4b29301, '488d942428010000'),  # lea    rdx,[rsp+0x128]
    'diff1_set': (0x4b2930e, '4c8dac2410010000'),  # lea    r13,[rsp+0x110]
    'pass_arg0': (0x4b29324, '4c89b424b0000000'),  # mov    QWORD PTR [rsp+0xb0],r14
    'pass_len_ptr': (0x4b29363, '488d842420010000'),  # lea    rax,[rsp+0x120]
    'diff2_self': (0x4b293ab, '488db42428010000'),  # lea    rsi,[rsp+0x128]
    'diff2_other': (0x4b293b3, '488d942440010000'),  # lea    rdx,[rsp+0x140]
    'diff2_set': (0x4b293c0, '4c8db424b0000000'),  # lea    r14,[rsp+0xb0]
    'abci_minus_len': (0x4b293d3, '4883bc242001000000'),  # cmp    QWORD PTR [rsp+0x120],0x0
    'fw_minus_len': (0x4b293de, '4883bc24c000000006'),  # cmp    QWORD PTR [rsp+0xc0],0x6
    'now_out': (0x4b293ed, '4c8dbc24a0000000'),  # lea    r15,[rsp+0xa0]
    'last_date': (0x4b293fe, '8b4308'),  # mov    eax,DWORD PTR [rbx+0x8]
    'last_test': (0x4b29401, '85c0'),  # test   eax,eax
    'interval': (0x4b29405, 'f20f1003'),  # movsd  xmm0,QWORD PTR [rbx]
    'interval_store': (0x4b29409, 'f20f11842458010000'),  # movsd  QWORD PTR [rsp+0x158],xmm0
    'last_rest': (0x4b29412, '488b4b0c'),  # mov    rcx,QWORD PTR [rbx+0xc]
    'cmp_interval': (0x4b29471, '660f2e842458010000'),  # ucomisd xmm0,QWORD PTR [rsp+0x158]
    'store_base': (0x4b29480, '4883c308'),  # add    rbx,0x8
    'store_hi': (0x4b2948b, '894308'),  # mov    DWORD PTR [rbx+0x8],eax
    'store_lo': (0x4b29496, '488903'),  # mov    QWORD PTR [rbx],rax
    'arg0_ptr': (0x4b294b8, '488d842410010000'),  # lea    rax,[rsp+0x110]
    'arg1_ptr': (0x4b294c8, '4c89b424a0000000'),  # mov    QWORD PTR [rsp+0xa0],r14
    'caller_r12': (0x452502e, '4d8b6500'),  # mov    r12,QWORD PTR [r13+0x0]
    'caller_rbp': (0x4525032, '498b6d08'),  # mov    rbp,QWORD PTR [r13+0x8]
    'caller_r14': (0x4525036, '4d8b7510'),  # mov    r14,QWORD PTR [r13+0x10]
    'caller_rbx': (0x452503a, '498b5d18'),  # mov    rbx,QWORD PTR [r13+0x18]
    'caller_rdi': (0x452509b, '4981c788050000'),  # add    r15,0x588
    'caller_state': (0x45250b5, '4981c6f8080000'),  # add    r14,0x8f8
    'caller_flag': (0x45250bc, '0fb695f2080000'),  # movzx  edx,BYTE PTR [rbp+0x8f2]
    'caller_rdi_mov': (0x45250c8, '4c89ff'),  # mov    rdi,r15
    'caller_rcx': (0x45250cb, '4c89f1'),  # mov    rcx,r14
    'caller_r8': (0x45250ce, '4989d8'),  # mov    r8,rbx
    'caller_after': (0x45250d6, '48c7c0f0ffffff'),  # mov    rax,0xfffffffffffffff0
    'self_len': (0x44c201e, '4c8b4610'),  # mov    r8,QWORD PTR [rsi+0x10]
    'other_len': (0x44c2022, '488b6a10'),  # mov    rbp,QWORD PTR [rdx+0x10]
    'tip_shift': (0x44c2029, '48c1ee04'),  # shr    rsi,0x4
    'tip_cmp': (0x44c202d, '4939f0'),  # cmp    r8,rsi
    'elapsed_date': (0x1447146, '3907'),  # cmp    DWORD PTR [rdi],eax
    'elapsed_secs': (0x1447154, '3b442404'),  # cmp    eax,DWORD PTR [rsp+0x4]
    'elapsed_frac': (0x1447160, '3b442408'),  # cmp    eax,DWORD PTR [rsp+0x8]
    'micros': (0x1447181, '4869c640420f00'),  # imul   rax,rsi,0xf4240
    'div1000': (0x144719c, '4869c9d34d6210'),  # imul   rcx,rcx,0x10624dd3
    'div1000_shift': (0x14471aa, '48c1f926'),  # sar    rcx,0x26
    'wall_clock_id': (0x151cbad, '31ff'),  # xor    edi,edi
}

# name: (va, instruction length, target)
FLOW = {
    'level_init': (0x4b29014, 2, 0x4b2903c),
    'level_high': (0x4b2901e, 2, 0x4b29090),
    'level_clear': (0x4b29028, 2, 0x4b29090),
    'fw_collect': (0x4b290ef, 5, 0x444fa30),
    'abci_collect': (0x4b2918b, 5, 0x444f680),
    'diff1': (0x4b29309, 5, DIFFERENCE),
    'diff1_collect': (0x4b2931f, 5, 0x444fbc0),
    'pass_start': (0x4b2934b, 5, 0x42b9a50),
    'pass_step': (0x4b2939e, 5, 0x49559c0),
    'diff2': (0x4b293bb, 5, DIFFERENCE),
    'diff2_collect': (0x4b293ce, 5, 0x444fbc0),
    'abci_minus_nonempty': (0x4b293dc, 2, 0x4b293ed),
    'small_skip': (0x4b293e7, 6, 0x4b29511),
    'first_log': (0x4b29403, 2, 0x4b29480),
    'throttle_skip': (0x4b2947a, 6, 0x4b29511),
    'tail_ret': (0x4b29636, 5, 0x4b2902a),
    'tip_search': (0x44c2030, 6, 0x44c2221),
    'elapsed_date_ne': (0x144714b, 6, 0x14471d4),
    'elapsed_secs_ne': (0x144715b, 2, 0x14471d4),
    'elapsed_frac_lt': (0x1447164, 2, 0x14471d8),
    'caller_call': (0x45250d1, 5, LOG_FDE),
    'wall_clock': (0x151cbaf, 5, 0x4ee3800),
}

RIP = {
    'level_slot': (0x4b29007, 7, 0x576e928),
    'once_slot': (0x4b29078, 6, 0x576e8b8),
    'abci_slot': (0x4b2911f, 6, 0x5773b48),
    'now_slot': (0x4b293f8, 6, 0x576e8a0),
    'raw_mdg_path': (0x4b2944b, 7, 0x216f6d),
    'elapsed_slot': (0x4b2946b, 6, 0x576e8c0),
    'formatter': (0x4b294dc, 7, 0x458bde0),
    'template': (0x4b294f2, 7, 0x1fa618),
    'location': (0x4b294f9, 7, 0x5738490),
    'log_slot': (0x4b2950b, 6, 0x576e978),
    'since_slot': (0x1447166, 6, 0x576eaa0),
    'million': (0x14471c6, 8, 0x20ae60),
    'time_sub_template': (0x14471f6, 7, 0x1f9cb6),
    'caller_log_slot': (0x4525095, 6, 0x576e978),
}

SLOTS = {'level_slot': LEVEL_STATIC, 'abci_slot': ABCI_BUILD, 'now_slot': WALL_NOW, 'elapsed_slot': ELAPSED,
         'log_slot': LOG_EMIT, 'since_slot': SINCE}


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
    for name, want in SLOTS.items():
        got = img.relative.get(RIP[name][2])
        require(got == want, f'{name} resolves to {got}')
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
            require(all(0x20 <= c < 0x7f for c in lit), f'template {va:#x}: literal at {pos:#x} not text')
            pieces.append(lit.decode())
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


def disp32(raw, at):
    return struct.unpack('<I', raw[at:at + 4])[0]


def check_level_gate(f):
    mask = struct.unpack('<I', f['level_mask'][1:])[0]
    require(mask == 0x28006, f'level mask is {mask:#x}')
    require(f['level_bound'][-1] == 0x11 and f['level_byte'][-1] == 0x48, 'level byte gate changed')
    returns = [v for v in range(0x12) if mask >> v & 1]
    return dict(static=hex(LEVEL_STATIC), once_state='+0x50 (non-zero runs the init call through slot 0x576e8b8 first)',
                byte='+0x48', returns_early_for=returns, continues_for='any other value, including > 0x11')


def check_sets(f):
    require(disp32(f['fw_out'], 4) == 0x128 and disp32(f['abci_out'], 4) == 0x140, 'set slots changed')
    require(f['fw_root'] == bytes.fromhex('498b06') and f['fw_height'][-1] == 8 and f['fw_len'][-1] == 0x10,
            'firewall set is not built from the arg0 map')
    require(f['abci_flag'] == bytes.fromhex('400fb6f5') and f['abci_state'] == bytes.fromhex('4c89fa'),
            'abci builder arguments changed')
    return {'[rsp+0x128]': dict(name='firewall', source='arg0 (rdi) BTreeMap {root, height, len}', collect='0x444fa30'),
            '[rsp+0x140]': dict(name='abci', source=f'{ABCI_BUILD:#x}(arg1 20-byte value, arg2 byte, arg3 state)',
                                collect='0x444f680')}


def check_difference(f):
    require(f['self_len'] == bytes.fromhex('4c8b4610') and f['other_len'] == bytes.fromhex('488b6a10'),
            'lengths are not self+0x10 and other+0x10')
    require(f['tip_shift'][-1] == 4 and f['tip_cmp'] == bytes.fromhex('4939f0'), 'tipping test changed')
    d1 = (disp32(f['diff1_self'], 4), disp32(f['diff1_other'], 4), disp32(f['diff1_set'], 4))
    d2 = (disp32(f['diff2_self'], 4), disp32(f['diff2_other'], 4), disp32(f['diff2_set'], 4))
    require(d1 == (0x140, 0x128, 0x110), f'first difference is {d1}')
    require(d2 == (0x128, 0x140, 0xb0), f'second difference is {d2}')
    return dict(self_is='rsi', other_is='rdx',
                why='self.len <= other.len >> 4 selects the search iterator (std ITER_PERFORMANCE_TIPPING_SIZE_DIFF = 16)',
                abci_minus_firewall='[rsp+0x110] = [rsp+0x140] - [rsp+0x128], then the 0x42b9a50/0x49559c0 pass',
                firewall_minus_abci='[rsp+0xb0] = [rsp+0x128] - [rsp+0x140]')


def check_gate(f):
    require(disp32(f['abci_minus_len'], 4) == 0x120 and f['abci_minus_len'][-1] == 0, 'abci_minus test changed')
    require(disp32(f['fw_minus_len'], 4) == 0xc0 and f['fw_minus_len'][-1] == 6, 'firewall_minus bound changed')
    require(disp32(f['pass_len_ptr'], 4) == 0x120, 'pass length pointer is not [rsp+0x120]')
    return dict(skip='len(abci_minus_firewall) == 0 and len(firewall_minus_abci) <= 6', bound=6)


def check_throttle(img, f):
    require(f['throttle_arg'] == bytes.fromhex('4c89c3'), 'throttle state is not r8')
    require(f['arg0_keep'] == bytes.fromhex('4989fe') and f['pass_arg0'] == bytes.fromhex('4c89b424b0000000'),
            'pass does not get the arg0 pointer')
    require(f['interval'] == bytes.fromhex('f20f1003'), 'interval is not f64 [r8]')
    require(f['last_date'] == bytes.fromhex('8b4308') and f['last_rest'] == bytes.fromhex('488b4b0c'),
            'last timestamp is not r8+0x8..0x14')
    require(disp32(f['interval_store'], 5) == disp32(f['cmp_interval'], 5) == 0x158, 'interval slot changed')
    require(f['store_base'][-1] == 8 and f['store_hi'][-1] == 8, 'timestamp store changed')
    million = img.f64(RIP['million'][2])
    require(million == 1e6, f'elapsed divisor is {million}')
    require(struct.unpack('<I', f['micros'][3:])[0] == 1000000, 'seconds are not scaled by 1e6')
    require(f['div1000'][3:] == bytes.fromhex('d34d6210') and f['div1000_shift'][-1] == 0x26, 'nanos/1000 changed')
    require(f['wall_clock_id'] == bytes.fromhex('31ff'), 'wall clock id is not 0')
    sub = template(img, RIP['time_sub_template'][2])
    require(sub == ['Time Sub ', None, ' ', None], f'Time Sub template is {sub}')
    path = img.read(RIP['raw_mdg_path'][2], 0x30)
    require(path.endswith(b'/base/src/raw_mdg.rs'), f'elapsed path is {path!r}')
    return dict(state='r8 (caller [r13+0x18])', interval='f64 at +0x0', last='12-byte wall time at +0x8 (+0x8 == 0 is None)',
                now=dict(call=hex(WALL_NOW), clock='clock_gettime(0 = CLOCK_REALTIME)'),
                elapsed=dict(call=hex(ELAPSED), since=hex(SINCE), unit='(secs * 1e6 + nanos / 1000) / 1e6',
                             panic='Time Sub {} {} when now < last'),
                rule='None -> log; else log only if elapsed > interval (ucomisd/jbe, NaN skips)',
                update='now is stored to +0x8 only on the log path', path=path.decode())


def check_log(img, f):
    parts = template(img, RIP['template'][2])
    require(parts == ['firewall does not match validators @@ [abci_minus_firewall: ', None,
                      '] @ [firewall_minus_abci: ', None, ']'], f'template is {parts}')
    first = img.read(RIP['template'][2], 1)[0]
    loc = location(img, RIP['location'][2])
    require(loc.endswith('firewall_ips.rs:65:13'), f'Location is {loc}')
    require(disp32(f['arg0_ptr'], 4) == 0x110 and f['arg1_ptr'] == bytes.fromhex('4c89b424a0000000'),
            'log arguments changed')
    return dict(template=parts, first_byte=hex(first), first_byte_is='literal length 60 (0x3c, ASCII "<")',
                args={'abci_minus_firewall': '[rsp+0x110]', 'firewall_minus_abci': '[rsp+0xb0]'},
                formatter=hex(RIP['formatter'][2]), location=loc, emit=hex(LOG_EMIT))


def check_caller(f):
    regs = {k: f[k][-1] for k in ('caller_r12', 'caller_rbp', 'caller_r14', 'caller_rbx')}
    require(regs == {'caller_r12': 0, 'caller_rbp': 8, 'caller_r14': 0x10, 'caller_rbx': 0x18}, f'caller loads {regs}')
    require(disp32(f['caller_rdi'], 3) == 0x588 and disp32(f['caller_state'], 3) == 0x8f8
            and disp32(f['caller_flag'], 3) == 0x8f2, 'caller offsets changed')
    require(f['caller_after'] == bytes.fromhex('48c7c0f0ffffff'), 'caller does not overwrite rax after the call')
    return dict(fde=hex(CALLER_FDE), call='0x45250d1',
                args=dict(rdi='r15 + 0x588 (firewall map)', rsi='copy of 20 bytes at [[r13]]',
                          edx='byte [[r13+0x8] + 0x8f2]', rcx='[r13+0x10] + 0x8f8', r8='[r13+0x18] (throttle state)'),
                result='unused: the caller overwrites rax at 0x45250d6, the instruction after the call; the callee '
                       'main path jumps from 0x4b29636 to the level-gate epilogue 0x4b2902a')


def check_callers(img):
    text = next((x for x in img.secs if x['name'] == '.text'), None)
    require(text is not None, 'no .text section')
    code = img.data[text['offset']:text['offset'] + text['size']]
    calls, pos = [], code.find(b'\xe8')
    while 0 <= pos < len(code) - 4:
        if text['address'] + pos + 5 + struct.unpack_from('<i', code, pos + 1)[0] == LOG_FDE:
            calls.append(text['address'] + pos)
        pos = code.find(b'\xe8', pos + 1)
    slots = sorted(k for k, v in img.relative.items() if v == LOG_FDE)
    require(calls == [FLOW['caller_call'][0]], f'direct callers are {[hex(v) for v in calls]}')
    require(not slots, f'RELATIVE slots hold {LOG_FDE:#x}: {[hex(v) for v in slots]}')
    return dict(direct_e8=[hex(v) for v in calls], relative_slots=[], scanned='.text, every e8 rel32')


def logs(abci_minus_len, firewall_minus_len, elapsed=None, interval=0.0):
    """Whether one call emits the log. `elapsed` is None when no earlier log time is stored."""
    if abci_minus_len == 0 and firewall_minus_len <= 6:
        return False
    if elapsed is None:
        return True
    return elapsed > interval


def elapsed_seconds(secs, nanos):
    """The 0x1447130 conversion of a (secs, nanos) duration, truncated to microseconds."""
    neg = secs < 0 and nanos > 0
    whole = (secs + neg) * 1_000_000
    frac = nanos - 1_000_000_000 if neg else nanos
    return (whole + int(frac / 1000)) / 1e6


def analyse(data):
    img = Image(data)
    win = windows(img)
    f = facts(img)
    return dict(target=TARGET, fde=hex(LOG_FDE), windows={k: hex(v) for k, v in win.items()},
                flow=check_flow(img), level_gate=check_level_gate(f), sets=check_sets(f),
                difference=check_difference(f), gate=check_gate(f), throttle=check_throttle(img, f),
                log=check_log(img, f), caller=check_caller(f),
                callers=check_callers(img))


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
    print(f"skip: {result['gate']['skip']}")
    print(f"throttle: {result['throttle']['rule']}")
    print(f"log: {result['log']['location']}; result {result['caller']['result'].split(':')[0]}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
