#!/usr/bin/env python3
"""Authenticate node115 crit_msg_state configuration (0x150ad00 -> 0x14c2b50 -> 0x154c4e0 -> 0x15444d0).

Static reads of the pinned ELF only; the capture is never executed or emulated.
"""
import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections  # noqa: E402
from fde_extents import eh_frame_records  # noqa: E402

TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032

# role -> (start, end, .eh_frame FDE record VA, body SHA-256); complete FDEs
BODIES = {
    'payload': (0x15444d0, 0x154498b, 0x104facc, '5929d210e678aafc0dbbe6aaba64944cfe7ce37992913ee7797d0b09b815f97e'),
    'configure': (0x150ad00, 0x150b305, 0x104b92c, 'c01b4b7405fad32a62db8e4df88040ad03075d91fee1edcb44f8c4b61a581cc7'),
    'lazy_mutex_run': (0x14c2b50, 0x14c2c47, 0x1046ce0, '074affff6e4b9cdde4a45cde23119c255abf8f58d91fed46e8362100e5af0efc'),
    'chain_display': (0x1778c60, 0x1778cca, 0xcce7d8, '928ae9f6c3500053b7333a92774c89b03859595193aadeb5b84b2694826ff099'),
    'str_display': (0x15ebba0, 0x15ebbb3, 0xcbc9f8, 'd6974989f446c3a376ca22e23d3f5d3c3744b9d15284072762999e6ccc1198bc'),
    'string_display': (0x15433a0, 0x15433b4, 0xcb5808, '0ed7cf38c51c13383d0ab1a7874b3b7142cfd20692059e7024dcd03edff52da7'),
}
# role -> (retained begin, end, owning FDE start, end, FDE record VA)
SUPPORT = {
    'wrapper_calls': (0x154c669, 0x154c687, 0x154c4e0, 0x154c6f9, 0x1050248),
    'default_fields': (0x150c0fc, 0x150c16e, 0x150c020, 0x150c1de, 0x104ba54),
}
SLOTS = {  # RELATIVE slot -> addend
    0x64e0b38: 0x150ad00,  # configure_context, called by four RIP-relative sites
    0x64e0b40: 0x64f0210,  # configuration global (Once dword +0x1c0)
    0x64e0b48: 0x1562670,  # address lookup (hostname -I / public-IP services)
    0x64efeb8: 0x150c020,  # lazy-mutex object +0x00: value initializer
    0x64efec0: 0x465b31,   # lazy-mutex object +0x08: name pointer "crit_msg_state"
    0x64e0f30: 0x1778c60,  # Chain Display
    0x63fc1e8: 0x43fea4,   # Location file pointer: base/src/crit_msg.rs
    0x64df6e8: 0x141e3a0, 0x64df4a0: 0x635de30, 0x64df480: 0x6355830, 0x64df498: 0x141e264,
    0x64e01f8: 0x5bb59d0, 0x64e0f38: 0x5bb5650, 0x64df730: 0x1680e60, 0x64df720: 0x167fa70,
    0x64dffe0: 0x154cd10, 0x64df4b8: 0x5c9b900,
}
IMPORTS = {0x64df508: 'memcpy'}
LITERALS = {
    'template': (0x43566f, bytes.fromhex('c00720636861696e3dc006206970733d5bc00120c0015d00')),
    'assertion': (0x465b3f, b'assertion failed: !(self.is_production && self.crash_on_crit)'),
    'name': (0x465b31, b'crit_msg_state'),
    'name_length': (0x64efec8, struct.pack('<Q', 14)),
    'crit_msg_path': (0x43fea4, b'base/src/crit_msg.rs'),
    'assert_location_tail': (0x63fc1f0, struct.pack('<QII', 20, 648, 13)),
    'lazy_mutex_template': (0x448a8e, b'\x0clazy mutex: \xc0\x01\n\x00'),
    'not_applied': (0x465b90, b'crit msg initialization not applied'),
    'local': (0x482133, b'Local'), 'sandbox': (0x482138, b'Sandbox'),
    'testnet': (0x48213f, b'Testnet'), 'mainnet': (0x482146, b'Mainnet'),
    'spaces16': (0x456a60, b' ' * 16), 'underscores16': (0x454290, b'_' * 16),
    'spaces8': (0x456360, b' ' * 8 + bytes(8)), 'underscores8': (0x453360, b'_' * 8 + bytes(8)),
    'hostname': (0x46777a, b"hostname -I | awk '{print $1}'"), 'ifconfig': (0x467798, b'ifconfig.me'),
    'ipify': (0x4677a3, b'api.ipify.org'), 'icanhazip': (0x4677b0, b'icanhazip.com'),
}
TABLES = {  # base -> entries (relative to base)
    'chain_cases': (0x465704, (0x150b209, 0x150ad51, 0x150ad7c, 0x150adb7, 0x150c679, 0x150c679, 0x150c697, 0x150c697)),
    'chain_names': (0x4820f4, (0x1778c76, 0x1778cb5, 0x1778c8b, 0x1778ca0)),
}
INCOMING = {  # target -> expected qualified sites (E8/E9 direct, FF15/FF25 through RELATIVE slots)
    0x15444d0: [0x154c66e, 0x154c682],
    0x14c2b50: [0x150b110],
    0x154c4e0: [0x14c2c18],
    0x150ad00: [0x2ae4580, 0x2aeb2f7, 0x2cb6907, 0x2cde645],
}
OBJECT_USERS = {0x64efeb8: [0x150ad00, 0x150b310]}  # RIP-relative references to the lazy-mutex object, by FDE
SLOT_USERS = {0x64e0f30: [0x15444d0, 0x17480e0, 0x2d01520, 0x4526e40, 0x5a35f50]}  # Chain Display slot loads
IP_NAMES = ('hostname', 'ifconfig', 'ipify', 'icanhazip')
IP_STRING_USERS = [0x1562670]

# layout claim -> (obligation, memory displacement the operand must carry)
LAYOUT = {
    'object.lock_byte': ('payload_15444f0', 0x48), 'object.value': ('payload_15444fc', 0x50),
    'object.init_fn': ('payload_154450d', 0x00), 'record.object': ('payload_15444e4', 0x50),
    'record.role_ref': ('payload_1544536', 0x30), 'record.chain_ref': ('payload_154453a', 0x38),
    'record.address_a_ref': ('payload_154453e', 0x40), 'record.address_b_ref': ('payload_1544542', 0x48),
    'value.label_ptr(+0x08)': ('payload_15445a2', 0x58), 'value.field_a(+0xf0)': ('payload_15445c0', 0x140),
    'value.field_b(+0x108)': ('payload_15445fb', 0x158), 'value.is_production(+0x190)': ('payload_154452e', 0x1e0),
    'value.crash_on_crit(+0x191)': ('payload_15448ae', 0x1e1), 'value.role_tag_cap(+0x18)': ('payload_1544860', 0x68),
    'value.role_tag_ptr(+0x20)': ('payload_1544864', 0x70), 'value.role_tag_len(+0x28)': ('payload_1544868', 0x78),
    'config.sandbox_first': ('configure_150ad67', 0xd0), 'config.testnet_first': ('configure_150ad92', 0xb8),
    'config.mainnet_first': ('configure_150adcd', 0xa0), 'config.second': ('configure_150af2f', 0xa0),
    'config.once': ('configure_150ad58', 0x1c0), 'default.flags': ('default_fields_150c0fc', 0x190),
    'default.field_a': ('default_fields_150c122', 0xf0), 'default.field_b': ('default_fields_150c129', 0x108),
    'default.role_tag': ('default_fields_150c156', 0x18),
}
VALUE_SIZE_OBLIGATION, VALUE_SIZE = 'payload_1544516', 0x198
CHAINS = ('Local', 'Sandbox', 'Testnet', 'Mainnet')
# Clean-room ELF/export-reader structure follows packet RE-001-node115-critical-message-repeat-throttle (MIT);
# every span, constant and claim here is newly measured.


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        names = [s['name'] for s in self.sections]
        require(len(names) == len(set(names)), 'duplicate section names')

    def off(self, va, size=1):
        hits = [s for s in self.sections if s['type'] != 8 and s['address'] and
                s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(hits) == 1, f'ambiguous or unbacked VA {va:#x}')
        return hits[0]['offset'] + va - hits[0]['address']

    def get(self, va, size):
        off = self.off(va, size)
        return self.data[off:off + size]

    def relocs(self):
        sec, = [s for s in self.sections if s['name'] == '.rela.dyn']
        require(sec['size'] % 24 == 0, 'partial RELA record')
        out = {}
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.data, off)
            require(slot not in out, 'duplicate relocation slot')
            out[slot] = (info, addend, off)
        return out


def windows():
    out = {k: v[:2] for k, v in BODIES.items()}
    out.update({k: v[:2] for k, v in SUPPORT.items()})
    return out


def all_windows():
    out = {k: (s, e, s, e) for k, (s, e, _, _) in BODIES.items()}
    out.update({k: v[:4] for k, v in SUPPORT.items()})
    return out


def fde_records(image):
    out = {k: v[2] for k, v in BODIES.items()}
    out.update({k: v[4] for k, v in SUPPORT.items()})
    return out


def decoder():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    return md


def export_rows(image, name, begin, end):
    """Both exports must cover [begin, end) byte for byte with the same instruction starts."""
    providers = []
    for provider in ('gnu', 'llvm'):
        cursor, rows = begin, []
        for line in (PACKET / f'{name}.{provider}.txt').read_text().splitlines():
            m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$', line)
            if not m:
                continue
            va, raw, asm = int(m[1], 16), bytes.fromhex(m[2]), m[3].strip()
            require(va == cursor and va + len(raw) <= end, 'export range: ' + name)
            require(image.get(va, len(raw)) == raw, 'export bytes: ' + name)
            if asm:
                if rows and rows[-1][1] == b'\xf0' and rows[-1][2] == 'lock':  # LLVM prints LOCK on its own row
                    pva, prefix, _ = rows.pop()
                    rows.append((pva, prefix + raw, 'lock ' + asm))
                else:
                    rows.append((va, raw, asm))
            else:
                require(bool(rows), 'orphan export continuation: ' + name)
                a, prev, text = rows[-1]
                rows[-1] = (a, prev + raw, text)
            cursor += len(raw)
        require(cursor == end, 'incomplete export: ' + name)
        providers.append(rows)
    require([r[:2] for r in providers[0]] == [r[:2] for r in providers[1]], 'decoder boundaries differ: ' + name)
    return providers[0]


def obligations():
    return json.loads((PACKET / 'obligations.json').read_text())


def check_obligations(image, starts=None):
    for name, r in obligations().items():
        va, end, raw = int(r['va'], 16), int(r['end'], 16), bytes.fromhex(r['bytes'])
        require(len(raw) == end - va and image.get(va, len(raw)) == raw, 'instruction obligation: ' + name)
        if 'target' in r:
            fmt = '<b' if r['rel_size'] == 1 else '<i'
            got = end + struct.unpack_from(fmt, raw, r['rel_offset'])[0]
            require(got == int(r['target'], 16), 'operand target: ' + name)
        if starts is not None:
            require(va in starts and end in starts | {e for _, e in windows().values()}, 'obligation boundary: ' + name)


def displacement(raw, va):
    insn, = list(decoder().disasm(raw, va))
    mems = [op.mem.disp for op in insn.operands if op.type == capstone.x86.X86_OP_MEM]
    require(len(mems) == 1, f'one memory operand at {va:#x}')
    return mems[0]


def layout():
    obl = obligations()
    out = {}
    for claim, (name, want) in LAYOUT.items():
        r = obl[name]
        got = displacement(bytes.fromhex(r['bytes']), int(r['va'], 16))
        require(got == want, f'layout {claim}: {got:#x} != {want:#x}')
        out[claim] = {'obligation': name, 'displacement': hex(got)}
    r = obl[VALUE_SIZE_OBLIGATION]
    require(bytes.fromhex(r['bytes']) == b'\xba' + struct.pack('<I', VALUE_SIZE), 'value size')
    out['value.size'] = {'obligation': VALUE_SIZE_OBLIGATION, 'immediate': hex(VALUE_SIZE)}
    return out


def check_data(image):
    relocs = image.relocs()
    bound = []
    for slot, target in SLOTS.items():
        require(relocs.get(slot, (None, None))[:2] == (8, target), f'RELATIVE binding {slot:#x}')
        bound.append({'slot': hex(slot), 'addend': hex(target), 'rela_file_offset': hex(relocs[slot][2])})
    dynsym, = [s for s in image.sections if s['name'] == '.dynsym']
    dynstr, = [s for s in image.sections if s['name'] == '.dynstr']
    imports = []
    for slot, name in IMPORTS.items():
        info, addend, _ = relocs.get(slot, (0, 1, 0))
        require(info & 0xffffffff == 6 and addend == 0, f'GLOB_DAT binding {slot:#x}')
        n = dynstr['offset'] + struct.unpack_from('<I', image.data, dynsym['offset'] + 24 * (info >> 32))[0]
        require(image.data[n:image.data.index(b'\0', n)] == name.encode(), 'import name ' + name)
        imports.append({'slot': hex(slot), 'symbol': name})
    lits = []
    for name, (va, want) in LITERALS.items():
        require(image.get(va, len(want)) == want, 'literal ' + name)
        lits.append({'role': name, 'va': hex(va), 'bytes': want.hex()})
    tables = {}
    for name, (base, want) in TABLES.items():
        got = tuple(base + struct.unpack('<i', image.get(base + 4 * i, 4))[0] for i in range(len(want)))
        require(got == want, 'table ' + name)
        tables[name] = {'base': hex(base), 'entries': [hex(x) for x in got]}
    return bound, imports, lits, tables


def incoming(image, fdes):
    text, = [s for s in image.sections if s['name'] == '.text']
    raw = image.data[text['offset']:text['offset'] + text['size']]
    base = text['address']
    md, cache = decoder(), {}
    starts = sorted(f['start'] for f in fdes)
    by_start = {f['start']: f for f in fdes}

    def owner(va):
        hits = [f for f in fdes if f['start'] <= va < f['end']]
        return hits[0] if len(hits) == 1 else None

    def insn_at(f, va):
        if f['start'] not in cache:
            body = image.get(f['start'], f['end'] - f['start'])
            cache[f['start']] = list(md.disasm(body, f['start']))
        hit = [i for i in cache[f['start']] if i.address <= va < i.address + i.size]
        return hit[0] if hit else None

    def resolved(insn):
        out = set()
        if insn.mnemonic in ('call', 'jmp') and insn.operands[0].type == capstone.x86.X86_OP_IMM:
            out.add(('direct', insn.operands[0].imm))
        for op in insn.operands:
            if op.type == capstone.x86.X86_OP_MEM and op.mem.base == capstone.x86.X86_REG_RIP:
                out.add(('rip', insn.address + insn.size + op.mem.disp))
        return out

    direct = set(INCOMING)
    slot_of = {s: t for s, t in SLOTS.items() if t in direct}
    rip = set(slot_of) | set(OBJECT_USERS) | set(SLOT_USERS) | {LITERALS[n][0] for n in IP_NAMES}
    hits = {}
    for m in re.finditer(rb'[\xe8\xe9]', raw):
        p = m.start()
        if p + 5 <= len(raw) and base + p + 5 + struct.unpack_from('<i', raw, p + 1)[0] in direct:
            hits.setdefault(('direct', base + p + 5 + struct.unpack_from('<i', raw, p + 1)[0]), set()).add(base + p)
    for m in re.finditer(rb'[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]', raw):
        p = m.start() + 1
        if p >= 2 and p + 4 <= len(raw):
            x = base + p + 4 + struct.unpack_from('<i', raw, p)[0]
            if x in rip:
                hits.setdefault(('rip', x), set()).add(base + p)
    qualified = {}
    for key, sites in hits.items():
        for va in sites:
            f = owner(va)
            insn = insn_at(f, va) if f else None
            if insn is not None and key in resolved(insn) and (key[0] == 'rip' or insn.address == va):
                qualified.setdefault(key, set()).add((insn.address, f['start'], insn.mnemonic))
    calls = {}
    for target, want in INCOMING.items():
        rows = set(qualified.get(('direct', target), set()))
        for slot, t in slot_of.items():
            if t == target:
                rows |= {r for r in qualified.get(('rip', slot), set()) if r[2] in ('call', 'jmp')}
        got = sorted(rows)
        require([r[0] for r in got] == want, f'incoming census {target:#x}: {[hex(r[0]) for r in got]}')
        calls[hex(target)] = [{'site': hex(a), 'owner_fde': hex(o), 'mnemonic': m} for a, o, m in got]

    def users(va):
        return sorted({r[1] for r in qualified.get(('rip', va), set())})

    objects = {}
    for va, want in list(OBJECT_USERS.items()) + list(SLOT_USERS.items()):
        require(users(va) == want, f'RIP-relative users {va:#x}: {[hex(x) for x in users(va)]}')
        objects[hex(va)] = [hex(x) for x in users(va)]
    ips = sorted({o for n in IP_NAMES for o in users(LITERALS[n][0])})
    require(ips == IP_STRING_USERS, f'address-service string users: {[hex(x) for x in ips]}')
    del starts, by_start
    return {'calls': calls, 'rip_relative_users': objects, 'address_string_users': [hex(x) for x in ips],
            'limits': 'E8/E9 rel32 and RIP-relative call/jmp through RELATIVE slots, plus RIP-relative operand '
                      'users; each site must be a capstone instruction inside exactly one FDE that resolves to the '
                      'target. Register-indirect or vtable dispatch is not counted.'}


def relations(lay):
    """Operand-derived projections; not an emulation of the target."""
    field = {k: int(v['displacement'], 16) for k, v in lay.items() if 'displacement' in v}
    select = {'Sandbox': (field['config.sandbox_first'], 'copy of first'),
              'Testnet': (field['config.testnet_first'], field['config.second']),
              'Mainnet': (field['config.mainnet_first'], field['config.second'])}

    def configure(state, chain, role, config, addresses):
        if chain == 0:
            return state
        first_off, second_off = select[CHAINS[chain]]
        first = config.get(first_off)
        second = first if second_off == 'copy of first' else config.get(second_off)
        value = dict(state or default())
        value['is_production'] = True
        value['label'] = f'{role} chain={CHAINS[chain]} ips=[{addresses[0]} {addresses[1]}]'
        value['field_a'], value['field_b'] = first, second
        if value['crash_on_crit']:
            raise AssertionError(LITERALS['assertion'][1].decode())
        value['role_tag'] = role.encode().replace(b' ', b'_').decode()
        return value

    def default():
        return dict(label='N/A (non-production)', role_tag='', field_a=None, field_b=None,
                    is_production=False, crash_on_crit=False)

    config = {0xd0: 'd0', 0xb8: 'b8', 0xa0: 'a0'}
    cases = []
    for chain in range(4):
        got = configure(None, chain, 'hl node', config, ('203.0.113.7', '10.0.0.2'))
        cases.append({'chain': CHAINS[chain], 'result': got})
    try:
        configure(dict(default(), crash_on_crit=True), 3, 'r', config, ('a', 'b'))
        assertion = 'no panic'
    except AssertionError as error:
        assertion = str(error)
    local = configure(dict(default(), crash_on_crit=True), 0, 'r', config, ('a', 'b'))
    tags = {r: r.encode().replace(b' ', b'_').decode() for r in ('', ' ', 'a b', 'x' * 31 + ' ' * 9 + 'y', 'a\tb')}
    return {'selection': {k: [hex(v[0]), v[1] if isinstance(v[1], str) else hex(v[1])] for k, v in select.items()},
            'cases': cases, 'crash_on_crit_production': assertion, 'crash_on_crit_local': local,
            'role_tags': tags,
            'basis': 'Field offsets are the decoded displacements of the LAYOUT obligations; a changed operand '
                     'changes these projections.'}


def observe(data, *, body_hashes=True, exports=True):
    image = Image(data)
    _, fdes = eh_frame_records(data, image.sections)
    bodies, starts = [], set()
    for name, (start, end, fde_va, digest) in BODIES.items():
        hit = [f for f in fdes if f['start'] == start]
        require(len(hit) == 1 and hit[0]['end'] == end and hit[0]['fde'] == fde_va, 'FDE binding: ' + name)
        raw = image.get(start, end - start)
        if body_hashes:
            require(sha(raw) == digest, 'body digest: ' + name)
        row = {'role': name, 'start': hex(start), 'end': hex(end), 'bytes': len(raw), 'sha256': sha(raw),
               'fde_record': hex(fde_va), 'cie_record': hex(hit[0]['cie']), 'file_offset': hex(image.off(start))}
        if exports:
            rows = export_rows(image, name, start, end)
            starts.update(a for a, _, _ in rows)
            row['instructions'] = len(rows)
            row['returns'] = [hex(a) for a, _, asm in rows if asm == 'ret']
        bodies.append(row)
    support = []
    for name, (begin, end, fs, fe, fde_va) in SUPPORT.items():
        hit = [f for f in fdes if f['start'] == fs]
        require(len(hit) == 1 and hit[0]['end'] == fe and hit[0]['fde'] == fde_va, 'FDE binding: ' + name)
        row = {'role': name, 'retained': [hex(begin), hex(end)], 'owning_fde': [hex(fs), hex(fe)]}
        if exports:
            rows = export_rows(image, name, begin, end)
            starts.update(a for a, _, _ in rows)
            row['instructions'] = len(rows)
        support.append(row)
    check_obligations(image, starts if exports else None)
    lay = layout()
    bound, imports, lits, tables = check_data(image)
    if exports:
        frame, = [s for s in image.sections if s['name'] == '.eh_frame']
        heads = re.findall(r'^([0-9a-f]+) .*FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)$',
                           (PACKET / 'fdes.readelf.txt').read_text(), re.MULTILINE)
        got = sorted(tuple(int(x, 16) for x in h) for h in heads)
        want = sorted([(v[2] - frame['address'], [f for f in fdes if f['start'] == v[0]][0]['cie'] - frame['address'],
                        v[0], v[1]) for v in BODIES.values()] +
                      [(v[4] - frame['address'], [f for f in fdes if f['start'] == v[2]][0]['cie'] - frame['address'],
                        v[2], v[3]) for v in SUPPORT.values()])
        require(got == want, 'readelf FDE headers')
    return {
        'schema': 1, 'target': 'artifacts/node/115/hl-node', 'target_sha256': sha(data),
        'coordinates': 'linked ELF VA; half-open ranges',
        'bodies': bodies, 'support_windows': support,
        'measured_bytes': sum(r['bytes'] for r in bodies),
        'measured_instructions': sum(r.get('instructions', 0) for r in bodies) if exports else None,
        'obligations': len(obligations()), 'layout': lay, 'relative_bindings': bound, 'imports': imports,
        'literals': lits, 'tables': tables,
        'incoming': incoming(image, fdes) if exports else None,
        'relations': relations(lay),
        'captured_code_executed_or_emulated': False,
    }


def build(data):
    require(len(data) == SIZE and sha(data) == DIGEST, 'wrong node115 SHA-256 or size')
    return observe(data)


MUTATIONS = [  # (va, replacement bytes, what a wrong reading would be)
    (0x15444f0, bytes.fromhex('f0410fb04d40'), 'lock byte at object+0x40'),
    (0x1544516, bytes.fromhex('ba18010000'), 'value size 0x118 (the node94 size)'),
    (0x154452e, bytes.fromhex('41c685e001000000'), 'is_production stored as 0'),
    (0x15445c0, bytes.fromhex('4d8dbd58010000'), 'first field into value+0x108'),
    (0x15445f7, bytes.fromhex('4983c610'), 'second field read from record+0x10'),
    (0x15448ae, bytes.fromhex('410fb685e0010000'), 'assertion reads is_production twice'),
    (0x15448cc, bytes.fromhex('be3c000000'), 'assertion message length 0x3c'),
    (0x15447c2, bytes.fromhex('be2d000000'), 'spaces mapped to "-"'),
    (0x15447d5, bytes.fromhex('4080ff09'), 'tabs instead of spaces'),
    (0x1544860, bytes.fromhex('49896d68'), 'role tag capacity from rbp'),
    (0x1544536, bytes.fromhex('4d8b6638'), 'role read from record+0x38'),
    (0x150ad67, bytes.fromhex('49399fb8000000'), 'Sandbox reads +0xb8'),
    (0x150ad92, bytes.fromhex('49399fa0000000'), 'Testnet reads +0xa0 first'),
    (0x150af2f, bytes.fromhex('49399c24b8000000'), 'second field from +0xb8'),
    (0x150b070, bytes.fromhex('4c89e6'), 'Sandbox second copied from the configuration, not the clone'),
    (0x150b0c0, bytes.fromhex('4889442468'), '&role at record+0x38'),
    (0x150b104, bytes.fromhex('488d3db54dfe04'), 'a different lazy-mutex object'),
    (0x14c2c01, bytes.fromhex('4c897c2450'), 'record+0x50 = object+0x18'),
    (0x14c2b81, bytes.fromhex('7553'), 'closure runs when the state check is nonzero'),
    (0x1778c7d, bytes.fromhex('ba04000000'), 'Local printed with length 4'),
    (0x154c66e, bytes.fromhex('e85d7dffff'), 'wrapper calls a neighbour of the payload'),
    (0x150c122, bytes.fromhex('48898308010000'), 'default None only at +0x108'),
]


def controls(data):
    image = Image(data)
    relocs = image.relocs()
    cases = [(image.off(va), new, label) for va, new, label in MUTATIONS]
    for name, r in obligations().items():
        end = int(r['end'], 16)
        cases.append((image.off(end - 1), bytes([image.get(end - 1, 1)[0] ^ 1]), 'flip last byte of ' + name))
    for slot in SLOTS:
        off = relocs[slot][2] + 16
        cases.append((off, bytes([data[off] ^ 1]), f'RELATIVE addend {slot:#x}'))
    for name, (va, want) in LITERALS.items():
        cases.append((image.off(va), bytes([want[0] ^ 1]), 'literal ' + name))
    for name, (base, want) in TABLES.items():
        cases.append((image.off(base + 4 * (len(want) - 1)), bytes([image.get(base + 4 * (len(want) - 1), 1)[0] ^ 4]),
                      'table ' + name))
    rejected = []
    for off, new, label in cases:
        changed = bytearray(data)
        changed[off:off + len(new)] = new
        require(bytes(changed) != data, 'no-op control: ' + label)
        try:
            observe(bytes(changed), body_hashes=False, exports=False)
        except ValueError as error:
            rejected.append({'control': label, 'file_offset': hex(off), 'bytes': new.hex(), 'rejection': str(error)})
        else:
            raise ValueError('corruption survived: ' + label)
    return {'whole_image_body_and_export_guards_bypassed': True, 'semantic_mutations': len(MUTATIONS),
            'rejected': rejected, 'survived': []}


def encoded(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument('--write', action='store_true')
    p.add_argument('--controls', action='store_true')
    a = p.parse_args(argv)
    data = TARGET.read_bytes()
    outputs = {'records.json': build(data)}
    if a.controls:
        outputs['controls.json'] = controls(data)
    for name, value in outputs.items():
        if a.write:
            (PACKET / name).write_text(encoded(value))
        else:
            require((PACKET / name).read_text() == encoded(value), 'regeneration mismatch: ' + name)
    r = outputs['records.json']
    print(f"PASS: {len(r['bodies'])} complete FDEs / {r['measured_bytes']} bytes / "
          f"{r['measured_instructions']} instructions; {r['obligations']} obligations")
    if a.controls:
        print(f"PASS: {len(outputs['controls.json']['rejected'])} corruption controls rejected")
    return 0


if __name__ == '__main__':
    sys.exit(main())
