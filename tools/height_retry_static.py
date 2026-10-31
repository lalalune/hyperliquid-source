#!/usr/bin/env python3
"""Static node #94 `gossip rpc height` retry loop, checked from authenticated bytes.

Question: the startup future `0x22689f0` wraps its peer height query in an
`AsyncSleepRetry` record {peer list, "gossip rpc height", 10, 2.0}.  Does the
loop bound its attempts by that 10, what does it sleep between attempts, and
what does the `n_tries=` field of its failure log print?  Where does the
can1357 lead (`net_utils/async_sleep_retry.rs`) differ?

Only the Python standard library is used.  Every fact is an exact byte window
at a fixed VA inside a parsed .eh_frame FDE; immediates, RIP-relative and
branch targets, rustc format templates and RELATIVE formatter slots are
decoded here.  A ModRM byte scan of the whole FDE pins every `[rbx+disp32]`
operand on the retry state.  Nothing from the binary is executed.
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
STARTUP_FDE = 0x22689f0
U64_DISPLAY = 0x1570900

WINDOWS = {
    'record': (STARTUP_FDE, 0x2268b78,
        '4c8bb3883b0000488d83903b00004c89b3903b0000488d8b983b0000488983983b0000488d05b1ed16fe488983a03b00'
        '0048c783a83b00001100000048c783b03b00000a00000048b80000000000000040488983b83b000048898bc03b0000'),
    'init': (STARTUP_FDE, 0x2268c15,
        '488b8bc03b000048c783283c0000ffffffff48898b603c0000488d836a3c000048898424a0000000c6836a3c00000048'
        '8d83c83b0000488984249800000048c7c0ffffffff66c783683c0000000148898b303c0000488983383c00004883f801'
        '4883d0004c89a3403c000048c783c83b000000000000488983d03b000031c94839c10f82b40f0000'),
    'resume': (STARTUP_FDE, 0x2268d08,
        '488b83283c0000488b8b603c0000e93fffffff'),
    'exhausted_log': (STARTUP_FDE, 0x2268dd7,
        '488d8c24183c0000660f1083483c0000660f110148898424103c0000488d83383c00004889442420488d8424103c0000'
        '4889842420010000488d052a5004004889842428010000488d4424204889842430010000488d056e1d44004889842438'
        '010000488d35ff2ef8fd488dbc2400770000488d942420010000ff15e9515003'),
    'sleep': (STARTUP_FDE, 0x2269bcc,
        'f20f1183e03c0000660f57c9660f2ec175027b40f20f1183e83c0000c683683d000000488dbbe83c0000488bb424c000'
        '0000e88dd4fcff84c00f85cb0c000080bb683d000003750c488dbbf03c0000e83040feffc683703d000001c683683c00'
        '0000488dbb883c0000e83613feff'),
    'attempt': (STARTUP_FDE, 0x2269c3a,
        '488b8bc83b0000488b83d03b00004839c10f834cf0ffff488d4101488983c83b000048898b583c0000488b83303c0000'
        '488b00'),
    'failure': (STARTUP_FDE, 0x226a753,
        '488d83d83b0000488d8b883c00000f1040400f1183c83c0000660f1000660f1048100f1050200f1058300f119bb83c00'
        '000f1193a83c0000660f118b983c0000660f1183883c0000488b83303c00004883c008488d93583c0000488984242001'
        '00004889ac24280100004889942430010000488b05c4385003488984243801000048898c2440010000488b051d8e5003'
        '4889842448010000488d35647af8fd488dbc24103c0000488d942420010000ff153838500349bc000000000000008048'
        '8b8424203c0000488b8c24b0000000488941100f108424103c00000f1101c683683c0000000f1001488b411048898424'
        '300100000f298424200100004c8db3403c0000488bb3403c00004c39e674144885f6740f488bbb483c000031d2ff159a'
        '375003c683693c000001488b842430010000498946100f28842420010000410f1106488b83303c0000f20f104020f20f'
        '1183d83c00004c8db3703d0000c683703d000000e910f3ffff'),
    'u64_display': (U64_DISPLAY, 0x1570900,
        '554889e54156534883ec204889f3488b3f488d75dc41be14000000ba14000000e84bfbffff4929c64c8d04284983c0dc'
        'ba010000004889dfbe0100000031c94d89f1ff1590d91f044883c4205b415e5dc3'),
}
DESC = (0x2268b9b, b'gossip rpc height')
# (branch or call VA, instruction length, expected target)
FLOW = {
    'first_attempt': (0x2268c97, 6, 0x2269c51), 'resume_to_init': (0x2268d16, 5, 0x2268c5a),
    'bound_reached_to_exhausted': (0x2269c4b, 6, 0x2268c9d), 'failure_to_sleep': (0x226a8b7, 5, 0x2269bcc),
    'zero_sleep_skip_ne': (0x2269bdc, 2, 0x2269be0), 'zero_sleep_skip_np': (0x2269bde, 2, 0x2269c20),
    'sleep_poll_call': (0x2269bfe, 5, 0x2237090), 'sleep_pending': (0x2269c05, 6, 0x226a8d6),
}
RETRY_TEMPLATE = (0x226a7eb, 0x1f2256)
EXHAUSTED_TEMPLATE = (0x2268e3a, 0x1ebd40)
NTRIES_FORMATTER_SLOT = 0x576e090
# disp32 -> ModRM VAs of every [rbx+disp32] operand in the startup FDE.
CENSUS = {
    0x3b88: [0x2268b7a, 0x22696fe], 0x3b90: [0x2268b81, 0x2268b88], 0x3b98: [0x2268b8f, 0x2268b96],
    0x3ba0: [0x2268ba4], 0x3ba8: [0x2268bab], 0x3bb0: [0x2268bb6], 0x3bb8: [0x2268bcb],
    0x3bc0: [0x2268bd2, 0x2268c17],
    0x3bc8: [0x2268c46, 0x2268c82, 0x2268ceb, 0x2269aeb, 0x2269b52, 0x2269c3c, 0x2269c57],
    0x3bd0: [0x2268c8d, 0x2269c43], 0x3c28: [0x2268c1e, 0x2268d0a],
    0x3c30: [0x2268c65, 0x2269c65, 0x226a79d, 0x226a897], 0x3c38: [0x2268c6c, 0x2268df5],
    0x3c58: [0x2269c5e, 0x226a7a8], 0x3c60: [0x2268c29, 0x2268d11],
}

# Every FDE holding a `mov [rbx+d],10; movabs rax,2.0` retry record (the 8-site census of PR #211).
# bound: `mov rax,-1` .. `jb`; count: the 10 store; pointer_loads: each `mov reg,[rbx+pointer_slot]`
# up to the instruction that overwrites reg or leaves the block.  census*: ModRM VAs of every
# [rbx+disp32] operand on the slot (None: the slot is a disp8 and is not scanned).
SITES = {
    0x22c54a0: dict(
        bound=(0x22c5620, '48c7c0ffffffff66c783a0000000000148894b40488943484883f8014883d0004c89735048c74328000000004889433031c94839c10f82df040000'),
        count=(0x22c55c2, '48c783880100000a000000'),
        pointer_slot=0x40, bound_slot=0x30, count_slot=0x188,
        pointer_loads=[(0x22c5b46, '488b4340488b00'), (0x22c5d26, '488b43404883c008'), (0x22c5dea, '488b4340f20f104020f20f1183c80000004c8dbb60010000c6836001000000e9adfcffff')],
        censusP=None,
        censusB=None,
        censusC=[0x22c55c4],
    ),
    0x438ed70: dict(
        bound=(0x438f328, '48c7c0ffffffff66c783d8020000000148898b78020000488983800200004883f8014883d0004889ab8802000048c78360020000000000004889836802000031c94839c10f82d31b0000'),
        count=(0x438f2c1, '48c783c00300000a000000'),
        pointer_slot=0x278, bound_slot=0x268, count_slot=0x3c0,
        pointer_loads=[(0x438ff3d, '488b8378020000488b8b980200000fb693a0020000488b7010488b8690000000'), (0x4390924, '488b8b78020000488b8380020000e952f3ffff'), (0x4390f57, '488b8378020000488b00'), (0x4391163, '488b83780200004883c008'), (0x4391260, '488b8378020000f20f104020f20f118300030000c6839803000000488dbb00030000488db424e0010000e8914bfaff')],
        censusP=[0x438f33a, 0x438fb18, 0x438fc76, 0x438ff3f, 0x4390926, 0x4390f59, 0x4391165, 0x4391262],
        censusB=[0x438f362, 0x438f5ed, 0x438fb06, 0x438fc49, 0x4390f37],
        censusC=[0x438f2c3],
    ),
    0x47b4950: dict(
        bound=(0x47b4bdf, '48c7c0ffffffff66c783f8020000000148898b98020000488983a00200004883f8014883d0004c89bba802000048c78380020000000000004889838802000031c94839c10f82b41b0000'),
        count=(0x47b4b79, '48c783e00300000a000000'),
        pointer_slot=0x298, bound_slot=0x288, count_slot=0x3e0,
        pointer_loads=[(0x47b57b0, '488b8398020000488b8bb80200000fb693c0020000488b7010488b8690000000'), (0x47b619a, '488b8b98020000488b83a0020000e956f3ffff'), (0x47b67ef, '488b8398020000488b00'), (0x47b69fb, '488b83980200004883c008'), (0x47b6af8, '488b8398020000f20f104020f20f118320030000c683b803000000488dbb20030000488bb42498000000e8a9bbf6ff')],
        censusP=[0x47b4bf1, 0x47b5394, 0x47b54f0, 0x47b57b2, 0x47b619c, 0x47b67f1, 0x47b69fd, 0x47b6afa],
        censusB=[0x47b4c19, 0x47b4ea4, 0x47b5382, 0x47b54c4, 0x47b67cf],
        censusC=[0x47b4b7b],
    ),
    0x2039060: dict(
        bound=(0x2039321, '48c7c0ffffffff66c78378020000000148898ba8010000488983b00100004883f8014883d0004c89abb801000048c78390010000000000004889839801000031c94839c10f821b030000'),
        count=(0x20392ba, '48c783600100000a000000'),
        pointer_slot=0x1a8, bound_slot=0x198, count_slot=0x160,
        pointer_loads=[(0x2039698, '488b83a8010000488b00'), (0x2039739, '488b83a80100004883c008'), (0x2039815, '488b83a8010000f30f7e4020660fd683a0020000c6833803000000488dbba00200004c89e6e8e124f5ff')],
        censusP=[0x2039333, 0x203969a, 0x203973b, 0x2039817, 0x2039c1c],
        censusB=[0x203935b, 0x2039678],
        censusC=[0x20391a8, 0x20392bc, 0x20399cc, 0x2039bd6, 0x2039bfb],
    ),
    0x4387f40: dict(
        bound=(0x4388201, '48c7c0ffffffff66c78378020000000148898ba8010000488983b00100004883f8014883d0004c89abb801000048c78390010000000000004889839801000031c94839c10f821b030000'),
        count=(0x438819a, '48c783600100000a000000'),
        pointer_slot=0x1a8, bound_slot=0x198, count_slot=0x160,
        pointer_loads=[(0x4388578, '488b83a8010000488b00'), (0x4388619, '488b83a80100004883c008'), (0x43886f5, '488b83a8010000f30f7e4020660fd683a0020000c6833803000000488dbba00200004c89e6e801d7faff')],
        censusP=[0x4388213, 0x438857a, 0x438861b, 0x43886f7, 0x4388afc],
        censusB=[0x438823b, 0x4388558],
        censusC=[0x4388088, 0x438819c, 0x43888ac, 0x4388ab6, 0x4388adb],
    ),
    0x439fa90: dict(
        bound=(0x439fbf5, '48c7c0ffffffff66c78390010000000148898bc0000000488983c80000004883f8014883d0004c89b3d000000048c783a800000000000000488983b000000031c94839c10f8263020000'),
        count=(0x439fb54, '48c783900000000a000000'),
        pointer_slot=0xc0, bound_slot=0xb0, count_slot=0x90,
        pointer_loads=[(0x439feb4, '488b83c0000000488b00'), (0x439ff50, '488b83c00000004883c008'), (0x43a0023, '488b83c0000000f20f104020f20f1183b8010000c6835002000000488dbbb80100004c89e6e8d35df9ff')],
        censusP=[0x439fc07, 0x439feb6, 0x439ff52, 0x43a0025],
        censusB=[0x439fc2f, 0x439fe94],
        censusC=[0x439fb56, 0x439fb77],
    ),
    0x4b399a0: dict(
        bound=(0x4b39cf0, '48c7c0ffffffff66c78350030000000148898b80020000488983880200004883f8014883d00048b9000000000000008048898b9002000048c78368020000000000004889837002000031c94839c10f8228070000'),
        count=(0x4b39c79, '48c783500200000a000000'),
        pointer_slot=0x280, bound_slot=0x270, count_slot=0x250,
        pointer_loads=[(0x4b3a482, '488b8380020000488b00'), (0x4b3aad8, '488b83800200004883c008'), (0x4b3abe3, '488b8380020000f20f104020f20f1183780300004c8db310040000c6831004000000e9e0f7ffff')],
        censusP=[0x4b39d02, 0x4b3a484, 0x4b3aada, 0x4b3abe5],
        censusB=[0x4b39d34, 0x4b3a45e],
        censusC=[0x4b39c7b, 0x4b39c9c],
    ),
    0x22689f0: dict(
        bound=(0x2268c53, '48c7c0ffffffff66c783683c0000000148898b303c0000488983383c00004883f8014883d0004c89a3403c000048c783c83b000000000000488983d03b000031c94839c10f82b40f0000'),
        count=(0x2268bb4, '48c783b03b00000a000000'),
        pointer_slot=0x3c30, bound_slot=0x3bd0, count_slot=0x3bb0,
        pointer_loads=[(0x2269c63, '488b83303c0000488b00'), (0x226a79b, '488b83303c00004883c008'), (0x226a895, '488b83303c0000f20f104020f20f1183d83c00004c8db3703d0000c683703d000000e910f3ffff')],
        censusP=[0x2268c65, 0x2269c65, 0x226a79d, 0x226a897],
        censusB=[0x2268c8d, 0x2269c43],
        censusC=[0x2268bb6],
    ),
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

    def i32(self, va):
        return struct.unpack('<i', self.read(va, 4))[0]


def windows(img):
    out = {}
    for name, (fde, va, hexs) in WINDOWS.items():
        raw = bytes.fromhex(hexs)
        start, end = img.fde(fde)
        require(start <= va and va + len(raw) <= end, f'{name} window {va:#x} is outside FDE {fde:#x}')
        require(img.read(va, len(raw)) == raw, f'{name} at {va:#x}: bytes changed')
        out[name] = va
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


def placeholder_before(pieces, literal):
    """Index of the placeholder immediately preceding `literal`."""
    idx = 0
    for i, p in enumerate(pieces):
        if p is None:
            idx += 1
        elif p == literal:
            require(i > 0 and pieces[i - 1] is None, f'literal {literal!r} is not preceded by a placeholder')
            return idx - 1
    raise EvidenceError(f'literal {literal!r} not in template')


def placeholder_after(pieces, literal):
    """Index of the placeholder immediately following `literal`."""
    idx = 0
    for i, p in enumerate(pieces):
        if p is None:
            idx += 1
        elif p == literal:
            require(i + 1 < len(pieces) and pieces[i + 1] is None, f'literal {literal!r} is not followed by a placeholder')
            return idx
    raise EvidenceError(f'literal {literal!r} not in template')


def census(img):
    start, end = img.fde(STARTUP_FDE)
    code = img.read(start, end - start)
    out = {}
    for disp, want in CENSUS.items():
        pat = struct.pack('<I', disp)
        got = [start + i for i in range(len(code) - 4) if code[i] & 0xc7 == 0x83 and code[i + 1:i + 5] == pat]
        require(got == want, f'[rbx+{disp:#x}] operands are {[hex(v) for v in got]}')
        out[f'[rbx+{disp:#x}]'] = [hex(v) for v in got]
    return out


def check_record(img):
    lea, text = DESC
    src = img.target(lea, 7)
    require(img.read(src, len(text)) == text and img.i32(0x2268ba9 + 7) == len(text), f'descriptor at {src:#x} changed')
    tries = img.i32(0x2268bb4 + 7)
    sleep = struct.unpack('<d', img.read(0x2268bbf + 2, 8))[0]
    require((tries, sleep) == (10, 2.0), f'record holds ({tries}, {sleep})')
    return dict(base='[rbx+0x3b98]', fields={'+0x0': '&[rbx+0x3b90] (peer list pointer from [rbx+0x3b88])',
                                              '+0x8': f'descriptor {src:#x} "{text.decode()}"', '+0x10': len(text),
                                              '+0x18': tries, '+0x20': sleep},
                pointer_stores=['[rbx+0x3bc0]', '[rbx+0x3c60]', '[rbx+0x3c30]'])


def check_bound(img):
    raw = img.read(0x2268c1c, 11)
    require(raw == bytes.fromhex('48c783283c0000ffffffff'), 'resume bound [rbx+0x3c28] is not -1')
    raw = img.read(0x2268c53, 7)
    require(raw == bytes.fromhex('48c7c0ffffffff'), 'fresh bound rax is not -1')
    require(img.read(0x2268c71, 8) == bytes.fromhex('4883f8014883d000'), 'max(.., 1) sequence changed')
    return dict(raw_tries=hex(2 ** 64 - 1), raw_slot='[rbx+0x3c38]', bound_slot='[rbx+0x3bd0]',
                bound=hex(max_one(2 ** 64 - 1)), counter_slot='[rbx+0x3bc8]', counter_start=0,
                logged_index_slot='[rbx+0x3c58]')


def check_logs(img):
    lea, want = RETRY_TEMPLATE
    tpl = img.target(lea, 7)
    require(tpl == want, f'retry template LEA {lea:#x} goes to {tpl:#x}')
    pieces = template(img, tpl)
    require(pieces[:5] == [b'AsyncSleepRetry::retry desc=[', None, b'] n_tries=', None, b' failed: '],
            'retry template head changed')
    ntries_index = placeholder_after(pieces, b'] n_tries=')
    fmt = img.relative.get(NTRIES_FORMATTER_SLOT)
    require(fmt == U64_DISPLAY, f'n_tries formatter slot resolves to {fmt}')
    require(img.target(0x1570920, 5) == 0x1570470, 'u64 display digit call changed')
    require(img.read(0x226a7a6, 7) == bytes.fromhex('488d93583c0000') and
            img.read(0x226a7bd, 8) == bytes.fromhex('4889942430010000') and
            img.target(0x226a7c5, 7) == NTRIES_FORMATTER_SLOT, 'n_tries argument is not &[rbx+0x3c58] with slot 0x576e090')
    require(img.read(0x2268df3, 12) == bytes.fromhex('488d83383c00004889442420') and
            img.target(0x2268e2b, 7) == 0x26aaba0, 'n_retries argument is not &[rbx+0x3c38] via [rsp+0x20]')
    lea, want = EXHAUSTED_TEMPLATE
    tpl2 = img.target(lea, 7)
    require(tpl2 == want, f'exhausted template LEA {lea:#x} goes to {tpl2:#x}')
    pieces2 = template(img, tpl2)
    require(pieces2 == [b'async_sleep_retry retries exhausted: ', None, b' @@ [n_retries: ', None, b']'],
            'exhausted template changed')
    return dict(retry_template=hex(tpl), retry_ntries_arg_index=ntries_index,
                retry_args={'0': '[rbx+0x3c30]+0x8 (descriptor)', '1': '&[rbx+0x3c58] (attempt index)',
                            '2': '&[rbx+0x3c88] (error)'},
                ntries_formatter=hex(fmt), exhausted_template=hex(tpl2),
                exhausted_n_retries_index=placeholder_after(pieces2, b' @@ [n_retries: '),
                exhausted_n_retries_arg='&[rbx+0x3c38] (raw tries, -1) via [rsp+0x20], formatter 0x26aaba0')


def check_flow(img):
    out = {}
    for name, (va, n, want) in FLOW.items():
        got = img.target(va, n)
        require(got == want, f'{name} at {va:#x} goes to {got:#x}')
        out[name] = hex(got)
    return out


def modrm_census(img, fde, disp):
    start, end = img.fde(fde)
    code = img.read(start, end - start)
    pat = struct.pack('<I', disp)
    return [start + i for i in range(len(code) - 4) if code[i] & 0xc7 == 0x83 and code[i + 1:i + 5] == pat]


def check_sites(img):
    out = {}
    for fde, site in SITES.items():
        start, end = img.fde(fde)
        windows_ = [('bound', *site['bound']), ('count', *site['count'])]
        windows_ += [('pointer_load', va, hx) for va, hx in site['pointer_loads']]
        for kind, va, hx in windows_:
            raw = bytes.fromhex(hx)
            require(start <= va and va + len(raw) <= end, f'{fde:#x} {kind} window {va:#x} outside FDE')
            require(img.read(va, len(raw)) == raw, f'{fde:#x} {kind} at {va:#x}: bytes changed')
        bound = bytes.fromhex(site['bound'][1])
        require(bound.startswith(bytes.fromhex('48c7c0ffffffff')) and bytes.fromhex('4883f8014883d000') in bound
                and bound[-6:-4] == b'\x0f\x82', f'{fde:#x} bound is not max(-1, 1)')
        count = bytes.fromhex(site['count'][1])
        require(count[-4:] == struct.pack('<i', 10), f'{fde:#x} count store is not 10')
        for va, hx in site['pointer_loads']:
            raw = bytes.fromhex(hx)
            hits = [i for i in range(len(raw) - 1) if raw[i] & 0xc7 == 0x40 and raw[i + 1] == 0x18]
            require(not hits, f'{fde:#x} pointer load at {va:#x} has a [reg+0x18] operand')
        census = {}
        for key, slot in (('censusP', 'pointer_slot'), ('censusB', 'bound_slot'), ('censusC', 'count_slot')):
            if site[key] is None:
                census[slot] = None
                continue
            got = modrm_census(img, fde, site[slot])
            require(got == site[key], f'{fde:#x} [rbx+{site[slot]:#x}] operands are {[hex(v) for v in got]}')
            census[slot] = [hex(v) for v in got]
        out[hex(fde)] = dict(bound_window=hex(site['bound'][0]), count_store=hex(site['count'][0]),
                             slots={k: hex(site[k]) for k in ('pointer_slot', 'bound_slot', 'count_slot')},
                             pointer_loads=[hex(va) for va, _ in site['pointer_loads']], census=census)
    return out


def max_one(x):
    """`cmp rax,1; adc rax,0` on u64: x if x >= 1 else 1."""
    return x + (1 if x < 1 else 0)


def attempts(bound, failures):
    """Logged n_tries values for `failures` consecutive failures under `bound` (0-based attempt index)."""
    logged, counter = [], 0
    while counter < bound and len(logged) < failures:
        logged.append(counter)
        counter += 1
    return logged, counter >= bound and len(logged) < failures


def analyse(data):
    img = Image(data)
    return dict(target=TARGET, windows={k: hex(v) for k, v in windows(img).items()},
                record=check_record(img), bound=check_bound(img), logs=check_logs(img),
                flow=check_flow(img), census=census(img), sites=check_sites(img),
                sleep=dict(source='[[rbx+0x3c30]+0x20] = record +0x20', copied_to=['[rbx+0x3cd8]', '[rbx+0x3ce0]'],
                           zero_skips_sleep=True))


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
    r, b = result['record'], result['bound']
    print(f"record: {r['fields']['+0x8']}, tries field {r['fields']['+0x18']}, sleep {r['fields']['+0x20']}")
    print(f"attempt bound: max({b['raw_tries']}, 1) = {b['bound']}; the tries field is never read in {STARTUP_FDE:#x}")
    print('failure log n_tries: the 0-based attempt index; every failure sleeps the record +0x20 (2.0)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
