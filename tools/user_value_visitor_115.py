#!/usr/bin/env python3
"""Node #115 per-user value: the rmp-serde map visitor 0x1a212f0 and its output layout.

Open PR #6223 found the writer 0x3beac00 that emits the per-user value with
six one-byte keys u, p, D, l, S, r at output offsets +0x48, +0x0, +0x28,
+0x68, +0x50, +0x60, each skipped at its default. Open PR #6230 found that the
map visitor 0x1a212f0 matches those six keys as field indexes 0..5. This tool
follows each field index to its decode call, its stack slot and the final
stores to the output (rbx), and checks:

1. The field-index jump table 0x5227e0 has seven arms (0..5 and ignore 6).
2. Each arm calls one decoder and keeps the result in a fixed stack slot.
3. The success path copies the stack value to rbx+0x0..+0x78 (one block).
   Through it, u -> +0x48, p -> +0x0, D -> +0x28, l -> +0x68, S -> +0x50,
   r -> +0x60. These are the #6223 writer offsets.
4. A missing field is never an error: each one gets a default, and each
   default is the value the writer skips (for l, the date 0xf6401a appears
   in both functions).
5. The p decoder 0x191bf90 matches keys p and n, and also the 16-byte keys
   perp_to_position and n_open_positions (an inline 16-byte compare and the
   byte-key fallback 0x184c9b0). The S decoder 0x1adf620 matches s and r with
   a length-1 guard only.

The captured binary is not executed. objdump and readelf are not started.
Addresses are ELF virtual addresses.
"""
import argparse
import json
import struct
from pathlib import Path

from artifacts import ROOT, check, manifest_item
from elf_index import sections, unwind_index

RELATIVE = 'artifacts/node/115/hl-node'
TARGET = ROOT / RELATIVE
PACKET = ROOT / 'research/work-items/RE-008-user-value-visitor-115'
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'

VISITOR = 0x1a212f0
WRITER = 0x3beac00
P_VISITOR = 0x191bf90
P_BYTES_KEY = 0x184c9b0
S_VISITOR = 0x1adf620

# Fixed instruction byte runs (va -> hex).
PINS = {
    # field-index dispatch: mov al,2 (D); lea rcx,[0x5227e0]; jmp
    0x1a21c86: 'b0020fb6c0488d0d4e0bb0fe486304814801c8ffe0',
    # u (index 0): seen flag [rsp+0x1c0]; decoder 0x17cb550 with a 4-byte name; slot [rsp+0x1e8]
    0x1a219cd: '4883bc24c0010000010f849e150000',
    0x1a219dc: 'b904000000488dbc24800000004c89f6488d15a586a3fee8589bdaff',
    0x1a21a0a: '488b84248800000048898424e8010000',
    # p (index 1): seen when [rsp+0x30] != None niche (r15); decoder 0x191bf90; slot [rsp+0x30..0x58]
    0x1a22018: '4c397c24300f85ce0e0000488dbc24800000004c89f631d2e85b9fefff',
    0x1a22098: '48c1e003488d34c0',                      # free stride cap*0x48
    # D (index 2): seen when [rsp+0x110] != None niche; decoder 0x18d4f40; slot [rsp+0x110..0x130]
    0x1a2213a: '4c39bc24100100000f85ef0d0000410fb65624488dbc24800000004c89f6e8e32debff',
    0x1a221b6: '48c1e003488d3440',                      # free stride cap*0x18
    # l (index 3): seen when dword [rsp+0x100] != 0; decoder 0x17ce890 with a 4-byte name
    0x1a221cb: ('83bc2400010000000f858c0c0000b904000000488dbc24800000004c89f6488d15887da3fee89bc6daff'
                '0fb68424800000004883f8090f85b10800008b84248400000089842400010000488b84248800000048898424e0010000'),
    # S (index 4): seen flag [rsp+0x108]; decoder 0x1adf620; slots [rsp+0x1d8], [rsp+0x1d0]
    0x1a220d5: ('4883bc2408010000010f843b0d0000488dbc24800000004c89f631d2e82ad50b000fb68424800000004883f809'
                '0f85a3080000488b84248800000048898424d8010000488b84249000000048898424d0010000b8010000004889842408010000'),
    # r (index 5): seen flag [rsp+0x1b8]; integer read through slot 0x64e2580; slot [rsp+0x130]
    0x1a2222a: '4883bc24b801000001',
    0x1a222ec: 'ff158e02ac040fb6842480000000488bb424880000003c090f856d0a00004889b42430010000b80100000048898424b8010000',
    # ignore (index 6): skip one value through 0x19ccaf0
    0x1a220ad: '488dbc24800000004c89f6ba01000000e82eaafaff',
    # end of map: u and r default 0; p missing -> cap 0, ptr 8, rest 0
    0x1a2248c: ('488b4c243031c0f68424c0010000014c8b9424e80100004c0f44d0f68424b801000001488b942430010000480f44d0'
                '48899424300100004c39f90f85e101000031c9ba080000000f57c0'),
    # D missing -> cap 0, ptr 8; l missing -> 0xf6401a and time 0; S missing -> 0, 0
    0x1a226da: ('488bb4241001000031ff4c39fe480f44f74c0f458c241801000074100f108c24200100000f298c24f0010000'
                '8bac240001000085ed41b81a40f600440f45c54c0f44dff6842408010000014c0f44e74c0f44ef'),
    # copy of the stack value [rsp+0x138..0x1b0] to rbx+0x0..0x78
    0x1a227bb: ('488b8424a801000048894370488b842498010000488943608b8424a00100008943688b8424a401000089436c'
                '0f108424880100000f1143500f108424780100000f1143400f108424380100000f108c24480100000f10942458010000'
                '0f109c24680100000f115b300f1153200f114b100f1103'),
    # second exit: staging copy and the copy to rbx
    0x1a2289d: ('488b8424a801000048898424f0000000488b84249801000048898424e00000008b8424a0010000898424e8000000'
                '8b8424a4010000898424ec0000000f108424880100000f298424d00000000f108424780100000f298424c0000000'
                '0f108424380100000f108c24480100000f109424580100000f109c24680100000f299c24b00000000f299424a0000000'
                '0f298c24900000000f29842480000000'),
    0x1a2294f: ('488b8424f000000048894370'
                '0f288424e00000000f1143600f288424d00000000f1143500f288424c00000000f1143400f288424800000000f288c2490000000'
                '0f289424a00000000f289c24b0000000e97bfeffff'),
    # array form (same function): first element through the u decoder, second through the p decoder;
    # a short array sets the l default 0xf6401a
    0x1a214d4: '488d15bd8ba3fe488d7c2430b9040000004c89f6e863a0daff',
    0x1a2151e: 'e86daaefff',
    0x1a22419: 'c78424080100001a40f600',
    # array form: the value is built in the same stack slots [rsp+0x138..0x1ac]; an empty
    # remainder jumps to the second exit 0x1a2289d
    0x1a2253a: ('0f288424100100000f288c24200100000f118c24700100000f1184246001000048899424380100004c89a42440010000'
                '4c89bc24480100004889bc24500100004889ac24580100004c898424800100000f284424200f1184248801000048898c24'
                '980100008b8c2408010000898c24a0010000488b8c240001000048898c24a401000085c00f84d8020000'),
    # p decoder 0x191bf90: str key -> length 16 / 1; utf-8 failure -> byte key 0x184c9b0
    0x191c614: 'ff158e36bc04837c2450017529488d7c24284889ee4c89fae87f03f3ff',
    0x191c654: '4883f9100f84c80100004883f9010f85ed010000',
    0x191c826: 'f30f6f00660f7405de97b3fe660fd7c881f9ffff00007464f30f6f00660f7405b63fb3fe660fd7c0',
    0x184c9b0: '4883fa10742683fa010f8521010000',
    # S decoder 0x1adf620: two one-byte key sites, r and s
    0x1adfb3e: '0fb645003c720f94c1b20228ca3c730fb6c2b9000000000f44c1',
    0x1adfbd6: '4883fa010f858efbffff0fb6003c720f94c13c730f8561010000',
    # writer 0x3beac00 (#6223): l default test and S zero test
    0x3beac88: 'b91a40f60041334d68410b4d6c0f94c2',
    0x3beac98: '498b4d584531ff490b4d50',
}

INDEX_TABLE, INDEX_LEA = 0x5227e0, 0x1a21c8b
ARMS = {0: 'u', 1: 'p', 2: 'D', 3: 'l', 4: 'S', 5: 'r', 6: 'ignore'}
CALLS = {   # direct call site -> (target, field)
    0x1a219f3: (0x17cb550, 'u'),
    0x1a22030: (P_VISITOR, 'p'),
    0x1a22158: (0x18d4f40, 'D'),
    0x1a221f0: (0x17ce890, 'l'),
    0x1a220f1: (S_VISITOR, 'S'),
    0x1a220bd: (0x19ccaf0, 'ignore'),
    0x191c62c: (P_BYTES_KEY, 'p key bytes'),
}
SLOT_CALLS = {0x1a222ec: (0x64e2580, 'r'), 0x191c614: (0x64dfca8, 'p key utf-8')}
NAME_LEAS = {0x1a219ec: (0x45a098, 4, 'u'), 0x1a221e9: (0x459f78, 4, 'l')}
ALIAS_LEAS = {0x191c82a: 0x456010, 0x191c842: 0x450800}
L_DEFAULT = {'visitor': 0x1a2270f, 'writer': 0x3beac88}

# Stack slot (rsp offset of the assembled value) -> output offset is rsp - 0x138.
FIELDS = [
    # field, index, arm, decoder, stack value start, output offset, size, default, writer skip (#6223)
    ('u', 0, 0x1a219cd, '0x17cb550', 0x180, 0x48, 8, '0', 'value 0'),
    ('p', 1, 0x1a22018, '0x191bf90', 0x138, 0x00, 0x28, 'cap 0, ptr 8, head 0, len 0, n 0',
     'p.p equals the empty value and n is 0'),
    ('D', 2, 0x1a2213a, '0x18d4f40', 0x160, 0x28, 0x20, 'cap 0, ptr 8, head 0, len 0', 'empty'),
    ('l', 3, 0x1a221cb, '0x17ce890', 0x1a0, 0x68, 0xc, 'dword 0xf6401a, then 0 (8 bytes)',
     'dword +0x68 is 0xf6401a and +0x6c, +0x70 are 0'),
    ('S', 4, 0x1a220d5, '0x1adf620', 0x188, 0x50, 0x10, '0, 0', '+0x50 and +0x58 both 0'),
    ('r', 5, 0x1a2222a, 'slot 0x64e2580', 0x198, 0x60, 8, '0', 'value 0'),
]
WRITER_OFFSETS = {'u': 0x48, 'p': 0x0, 'D': 0x28, 'l': 0x68, 'S': 0x50, 'r': 0x60}   # from #6223
COPY_START, COPY_END = 0x1a227bb, 0x1a2282e   # final copy of the value to rbx
# Second exit (0x1a2289d): the value is staged at [rsp+0x80..0xf4], then copied to
# rbx; the last four stores reuse 0x1a2281f.. of the first copy.
RELAY = [(0x1a2289d, 0x1a22939), (0x1a2294f, 0x1a2299f), (0x1a2281f, 0x1a2282e)]


def read_va(data, va, size):
    matches = [s for s in sections(data)
               if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
    if len(matches) != 1:
        raise ValueError(f'expected one file-backed mapping at {va:#x}')
    off = matches[0]['offset'] + va - matches[0]['address']
    return data[off:off + size]


def rel32(data, va, length):
    return va + length + struct.unpack('<i', read_va(data, va + length - 4, 4))[0]


def extents(data):
    _, entries = unwind_index(data)
    starts = {e['start']: e['next_index_upper_bound'] for e in entries}
    out = {}
    for fn in (VISITOR, WRITER, P_VISITOR, P_BYTES_KEY, S_VISITOR):
        if fn not in starts:
            raise ValueError(f'no unwind entry at {fn:#x}')
        out[fn] = starts[fn]
    return out


def pin_check(data):
    for va, want in PINS.items():
        raw = bytes.fromhex(want)
        if read_va(data, va, len(raw)) != raw:
            raise ValueError(f'instruction bytes changed at {va:#x}')


def index_table(data):
    if rel32(data, INDEX_LEA, 7) != INDEX_TABLE:
        raise ValueError('field-index table lea moved')
    arms = {}
    for i in range(7):
        arms[ARMS[i]] = INDEX_TABLE + struct.unpack('<i', read_va(data, INDEX_TABLE + 4 * i, 4))[0]
    for name, _, arm, *_ in FIELDS:
        if arms[name] != arm:
            raise ValueError(f'field {name} arm is {arms[name]:#x}, not {arm:#x}')
    if arms['ignore'] != 0x1a220ad:
        raise ValueError('ignore arm moved')
    return {k: hex(v) for k, v in arms.items()}


def calls(data, ext):
    out = {}
    for site, (target, field) in CALLS.items():
        if read_va(data, site, 1) != b'\xe8' or rel32(data, site, 5) != target:
            raise ValueError(f'call at {site:#x} is not to {target:#x}')
        out[hex(site)] = {'field': field, 'target': hex(target)}
    for site, (slot, field) in SLOT_CALLS.items():
        if read_va(data, site, 2) != b'\xff\x15' or rel32(data, site, 6) != slot:
            raise ValueError(f'slot call at {site:#x} is not through {slot:#x}')
        out[hex(site)] = {'field': field, 'slot': hex(slot)}
    for site in out:
        va = int(site, 16)
        if not any(fn <= va < end for fn, end in ext.items()):
            raise ValueError(f'call site {site} outside the mapped functions')
    return out


def names(data):
    out = {}
    for site, (target, length, field) in NAME_LEAS.items():
        if read_va(data, site, 3) != b'\x48\x8d\x15' or rel32(data, site, 7) != target:
            raise ValueError(f'name lea at {site:#x} moved')
        out[field] = {'lea': hex(site), 'address': hex(target), 'length': length,
                      'bytes': read_va(data, target, length).decode('ascii')}
    return out


def byte_chains(data, start, end):
    """Decode `cmp eax, c0` + `cmp byte [rsi+i], ci` chains in the byte-key fallback."""
    code = read_va(data, start, end - start)
    firsts = [code[i + 2] for i in range(len(code) - 2) if code[i:i + 2] == b'\x83\xf8']
    chains, cur = [], []
    i = 0
    while i < len(code) - 3:
        if code[i:i + 2] == b'\x80\x7e':
            idx, ch = code[i + 2], code[i + 3]
            if idx == 1 and cur:
                chains.append(cur)
                cur = []
            cur.append((idx, ch))
            i += 4
        else:
            i += 1
    if cur:
        chains.append(cur)
    out = []
    for chain in chains:
        if [k for k, _ in chain] != list(range(1, 16)):
            raise ValueError('byte-key chain is not 15 consecutive bytes')
        tail = bytes(c for _, c in chain)
        heads = [h for h in firsts if bytes([h]) + tail in (b'perp_to_position', b'n_open_positions')]
        if len(heads) != 1:
            raise ValueError('byte-key chain head not found')
        out.append((bytes([heads[0]]) + tail).decode('ascii'))
    return sorted(out)


def pcmpeqb_count(data, start, end):
    code = read_va(data, start, end - start)
    return sum(1 for i in range(len(code) - 3) if code[i:i + 4] == b'\x66\x0f\x74\x05')


def p_aliases(data, ext):
    inline = {}
    for site, target in ALIAS_LEAS.items():
        if read_va(data, site, 4) != b'\x66\x0f\x74\x05' or rel32(data, site, 8) != target:
            raise ValueError(f'pcmpeqb at {site:#x} moved')
        inline[hex(site)] = read_va(data, target, 16).decode('ascii')
    if list(inline.values()) != ['perp_to_position', 'n_open_positions']:
        raise ValueError(f'unexpected 16-byte keys {inline}')
    chains = byte_chains(data, P_BYTES_KEY, ext[P_BYTES_KEY])
    if chains != ['n_open_positions', 'perp_to_position']:
        raise ValueError(f'byte-key fallback keys {chains}')
    s_sites = pcmpeqb_count(data, S_VISITOR, ext[S_VISITOR])
    if s_sites:
        raise ValueError('S decoder has a 16-byte compare')
    return {
        'p_decoder': hex(P_VISITOR),
        'one_byte_keys': {'p': 0, 'n': 1, 'other': 2},
        'sixteen_byte_keys_inline': inline,
        'sixteen_byte_key_index': {'perp_to_position': 0, 'n_open_positions': 1},
        'byte_key_fallback': {'function': hex(P_BYTES_KEY), 'keys': chains},
        'pcmpeqb_rip_sites': {'p_decoder': pcmpeqb_count(data, P_VISITOR, ext[P_VISITOR]),
                              's_decoder': s_sites},
        's_decoder': {'function': hex(S_VISITOR), 'one_byte_keys': {'s': 0, 'r': 1, 'other': 2},
                      'key_sites': ['0x1adfb3e', '0x1adfbe0'], 'long_key_compare': False},
    }


XMM_RM = {0x84: 0, 0x8c: 1, 0x94: 2, 0x9c: 3}      # [rsp+disp32] with xmm0..3
XMM_RBX = {0x43: 0, 0x4b: 1, 0x53: 2, 0x5b: 3}     # [rbx+disp8] with xmm0..3


def decode_moves(data, segments):
    """Follow plain moves through registers and stack slots to stores into rbx.

    Values are tracked per byte, so a 16-byte load of two staged halves keeps
    both sources. Returns {rbx byte offset: source rsp byte offset}.
    """
    regs, staged, out = {}, {}, {}

    def load(off, width):
        return [staged.get(off + k, off + k) for k in range(width)]

    def store_stack(off, value):
        for k, src in enumerate(value):
            staged[off + k] = src

    def store_rbx(off, value):
        for k, src in enumerate(value):
            out[off + k] = src

    for start, end in segments:
        code = read_va(data, start, end - start)
        i = 0
        while i < len(code):
            c = code[i:]
            if c[:4] == b'\x48\x8b\x84\x24':
                regs['rax'] = load(struct.unpack_from('<I', c, 4)[0], 8); i += 8
            elif c[:3] == b'\x8b\x84\x24':
                regs['eax'] = load(struct.unpack_from('<I', c, 3)[0], 4); i += 7
            elif c[:2] in (b'\x0f\x10', b'\x0f\x28') and c[2] in XMM_RM and c[3] == 0x24:
                regs[XMM_RM[c[2]]] = load(struct.unpack_from('<I', c, 4)[0], 16); i += 8
            elif c[:4] == b'\x48\x89\x84\x24':
                store_stack(struct.unpack_from('<I', c, 4)[0], regs['rax']); i += 8
            elif c[:3] == b'\x89\x84\x24':
                store_stack(struct.unpack_from('<I', c, 3)[0], regs['eax']); i += 7
            elif c[:2] in (b'\x0f\x11', b'\x0f\x29') and c[2] in XMM_RM and c[3] == 0x24:
                store_stack(struct.unpack_from('<I', c, 4)[0], regs[XMM_RM[c[2]]]); i += 8
            elif c[:3] == b'\x48\x89\x43':
                store_rbx(c[3], regs['rax']); i += 4
            elif c[:2] == b'\x89\x43':
                store_rbx(c[2], regs['eax']); i += 3
            elif c[:3] == b'\x0f\x11\x03':
                store_rbx(0, regs[0]); i += 3
            elif c[:2] == b'\x0f\x11' and c[2] in XMM_RBX:
                store_rbx(c[3], regs[XMM_RBX[c[2]]]); i += 4
            else:
                raise ValueError(f'unexpected byte in copy at {start + i:#x}')
    return out


def runs(byte_map):
    """Compress {dst: src} into (src, dst, width) runs."""
    out = []
    for dst in sorted(byte_map):
        src = byte_map[dst]
        if out and out[-1][1] + out[-1][2] == dst and out[-1][0] + out[-1][2] == src:
            out[-1][2] += 1
        else:
            out.append([src, dst, 1])
    return [tuple(r) for r in out]


def decode_copy(data):
    return decode_moves(data, [(COPY_START, COPY_END)])


def decode_relay(data):
    return decode_moves(data, RELAY)


def layout(data):
    first = decode_copy(data)
    relay = decode_relay(data)
    if relay != first:
        raise ValueError('second exit does not copy the same stack bytes to the same offsets')
    copy = runs(first)
    for src, dst, width in copy:
        if dst != src - 0x138:
            raise ValueError(f'copy [rsp+{src:#x}] -> rbx+{dst:#x} breaks the rsp-0x138 shift')
    if sorted(first) != list(range(0x78)):
        raise ValueError('copy does not span rbx+0x0..0x78')
    rows = {}
    for name, index, arm, decoder, stack, out, size, default, skip in FIELDS:
        if not any(src <= stack < src + w for src, _, w in copy):
            raise ValueError(f'field {name} stack value {stack:#x} is not copied')
        if stack - 0x138 != out or WRITER_OFFSETS[name] != out:
            raise ValueError(f'field {name} lands at {stack - 0x138:#x}, writer reads {WRITER_OFFSETS[name]:#x}')
        rows[name] = {'index': index, 'arm': hex(arm), 'decoder': decoder,
                      'stack_value': hex(stack), 'output_offset': hex(out), 'size': hex(size),
                      'default_when_missing': default, 'writer_skips_when': skip,
                      'matches_6223_offset': True}
    strides = {'p': read_va(data, 0x1a2209c, 4), 'D': read_va(data, 0x1a221ba, 4)}
    if strides != {'p': bytes.fromhex('488d34c0'), 'D': bytes.fromhex('488d3440')}:
        raise ValueError('item free strides changed')
    rows['p']['item_size'] = '0x48'
    rows['D']['item_size'] = '0x18'
    return rows, [{'from_rsp': hex(a), 'to_rbx': hex(b), 'width': w} for a, b, w in copy]


def l_default(data):
    v = struct.unpack('<I', read_va(data, L_DEFAULT['visitor'] + 2, 4))[0]
    w = struct.unpack('<I', read_va(data, L_DEFAULT['writer'] + 1, 4))[0]
    if v != w or v != 0xf6401a:
        raise ValueError('l default differs between visitor and writer')
    return {'visitor_site': hex(L_DEFAULT['visitor']), 'writer_site': hex(L_DEFAULT['writer']),
            'value': hex(v), 'year_field': v >> 13}


def bind(data):
    pin_check(data)
    ext = extents(data)
    rows, copy = layout(data)
    return {
        'target': {'path': RELATIVE, 'sha256': SHA256},
        'functions': {hex(k): hex(v) for k, v in ext.items()},
        'field_index_table': {'table': hex(INDEX_TABLE), 'arms': index_table(data)},
        'calls': calls(data, ext),
        'decoder_names': names(data),
        'layout': rows,
        'final_copy': copy,
        'l_default': l_default(data),
        'sub_decoders': p_aliases(data, ext),
        'pins': len(PINS),
        'gates_changed': False,
    }


def render(result):
    return (json.dumps(result, indent=2, sort_keys=True) + '\n').encode()


def generate(binary=TARGET, output=PACKET):
    identity = manifest_item(ROOT, RELATIVE)
    check(binary, identity)
    if identity['sha256'] != SHA256:
        raise ValueError('pinned node #115 digest changed')
    result = bind(binary.read_bytes())
    output.mkdir(parents=True, exist_ok=True)
    (output / 'evidence.json').write_bytes(render(result))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=PACKET)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args(argv)
    expected = (PACKET / 'evidence.json').read_bytes() if args.check else None
    result = generate(output=args.out)
    if args.check and (args.out / 'evidence.json').read_bytes() != expected:
        raise SystemExit('evidence.json does not match the committed packet')
    print(f"fields={len(result['layout'])} pins={result['pins']} "
          f"p_aliases={sorted(result['sub_decoders']['sixteen_byte_keys_inline'].values())}")
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
