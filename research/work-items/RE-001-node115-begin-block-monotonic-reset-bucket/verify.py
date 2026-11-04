#!/usr/bin/env python3
"""Authenticate node115 begin-block-monotonic-reset-bucket; static reads only, no capture execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
ROOT = Path(__file__).resolve().parents[3]
PACKET = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records
TARGET = ROOT / 'artifacts/node/115/hl-node'
DIGEST = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
BODIES = {'begin_block_owner': (46004464, 46051233, 18383980, '225649f70f438609a3bf19555e1a01ce18bee7dfa80fb5179ba16225e4fa437c'), 'guard_context': (69378016, 69379624, 19496628, 'd19a750aa230fac3b86c6ab7a37ad98ce667b384b7ecd9ffdd0348bd0d2dea54')}
SLOTS = {105795824: 57444224, 105429368: 4516105, 105795240: 72502848, 105805976: 72189328, 105805984: 93725568, 105772192: 104193584, 105805992: 71790832, 105775464: 105839704, 105772184: 21095012, 105175576: 4514591, 105773552: 97025360, 105775608: 96164304, 105772160: 104159280, 105175888: 4438154, 105779216: 22312240, 105800008: 71023824, 105779136: 23241360, 105798264: 71861232, 105806000: 59486576, 105795184: 96190992, 105779064: 23243168, 105777824: 23236816, 105794840: 71026176, 105806008: 71774880, 105806016: 62890256, 105084648: 4434262, 105773104: 23596048, 105084224: 4515506, 105175440: 4493134, 105773168: 23600576, 105772320: 23600544, 105779000: 96163408, 105084672: 4434262, 105841088: 22449632, 104850040: 4514591, 105806024: 62875984, 105342584: 4402031, 105781392: 104791616, 105795312: 70579584, 105806032: 62874064, 105806040: 62900192, 105806048: 62898432, 105806056: 70576800, 105777784: 23627584, 105772776: 21095328, 105778192: 97038672, 105806064: 62893760, 105343192: 4402031, 105779056: 22993248, 105779824: 23241056, 105806072: 72185952, 105806080: 62817888, 105779032: 22444752, 105806088: 62816192, 105777432: 105842368, 105806096: 62874912, 105806104: 71800208, 105805840: 63214112, 105066304: 4413712, 105066352: 4413712, 105430336: 4413712, 105429440: 4413712, 105806112: 72002880, 105806120: 63124768, 105806128: 62853808, 105795664: 69317344, 105806136: 63158160, 105802448: 66826912, 105806144: 63135712, 105806152: 57076704, 105174840: 4496971, 105802176: 57073424, 105804168: 93725568, 105806160: 57255040, 105174816: 4496971, 105174744: 4496971, 105806168: 57249504, 105174768: 4496971, 105800856: 57254416, 105174792: 4496971, 105804192: 69294208, 105804176: 57225264, 105806176: 57237984, 105806184: 93729040, 105806192: 57235584, 105773816: 104791744, 105806200: 93725120, 105772176: 21094993, 105432568: 72222736, 105429392: 4410392, 105772704: 23596080, 104927816: 4514591, 105429608: 4448075, 105398592: 69411024, 105397792: 4406198, 105174440: 4493011, 105772576: 23596223, 105084200: 4515506, 105429416: 4410392, 105175128: 4402031, 105142704: 4438273, 105142584: 4438273, 105085472: 4438273, 105066328: 4413712, 105343536: 4402031, 105773128: 23600704, 104841544: 4479034, 105772912: 23595984, 105772224: 23596203, 105398328: 4514591, 105398456: 4438154}
SUPPORT = {}
LITERALS = {'source_0x44e909': (4516105, b'l1/src/dex_registry/dex_registry.rs'), 'location_0x648b978': (105429376, b'#\x00\x00\x00\x00\x00\x00\x00%\x00\x00\x000\x00\x00\x00'), 'source_0x44e31f': (4514591, b'/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/std/src/sync/once.rs'), 'location_0x644da18': (105175584, b'L\x00\x00\x00\x00\x00\x00\x00\xdb\x00\x00\x00\x14\x00\x00\x00'), 'source_0x43b88a': (4438154, b'base/src/bucket_guard.rs'), 'location_0x644db50': (105175896, b'\x18\x00\x00\x00\x00\x00\x00\x00v\x00\x00\x00\x15\x00\x00\x00'), 'source_0x43a956': (4434262, b'/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/alloc/src/collections/btree/navigate.rs'), 'location_0x64376e8': (105084656, b'_\x00\x00\x00\x00\x00\x00\x000\x02\x00\x00/\x00\x00\x00'), 'source_0x44e6b2': (4515506, b'l1/src/books.rs'), 'location_0x6437540': (105084232, b'\x0f\x00\x00\x00\x00\x00\x00\x00\x13\x00\x00\x00/\x00\x00\x00'), 'source_0x448f4e': (4493134, b'l1/src/asset/pdi.rs'), 'location_0x644d990': (105175448, b'\x13\x00\x00\x00\x00\x00\x00\x00 \x00\x00\x00\x0e\x00\x00\x00'), 'location_0x6437700': (105084680, b'_\x00\x00\x00\x00\x00\x00\x00\xad\x00\x00\x00$\x00\x00\x00'), 'location_0x63fe278': (104850048, b'L\x00\x00\x00\x00\x00\x00\x00\xdb\x00\x00\x00\x14\x00\x00\x00'), 'source_0x432b6f': (4402031, b'l1/src/spot_meta.rs'), 'location_0x6476678': (105342592, b'\x13\x00\x00\x00\x00\x00\x00\x00N\x02\x00\x00\x19\x00\x00\x00'), 'location_0x64768d8': (105343200, b'\x13\x00\x00\x00\x00\x00\x00\x00w\x00\x00\x00!\x00\x00\x00'), 'source_0x435910': (4413712, b'l1/src/qtys/mod.rs'), 'location_0x6432f40': (105066312, b'\x12\x00\x00\x00\x00\x00\x00\x00A\x03\x00\x00\x01\x00\x00\x00'), 'location_0x6432f70': (105066360, b'\x12\x00\x00\x00\x00\x00\x00\x00B\x03\x00\x00\x01\x00\x00\x00'), 'location_0x648bd40': (105430344, b'\x12\x00\x00\x00\x00\x00\x00\x00A\x03\x00\x00\x01\x00\x00\x00'), 'location_0x648b9c0': (105429448, b'\x12\x00\x00\x00\x00\x00\x00\x00B\x03\x00\x00\x01\x00\x00\x00'), 'source_0x449e4b': (4496971, b'l1/src/exchange/begin_block.rs'), 'location_0x644d738': (105174848, b'\x1e\x00\x00\x00\x00\x00\x00\x00\n\x01\x00\x003\x00\x00\x00'), 'location_0x644d720': (105174824, b'\x1e\x00\x00\x00\x00\x00\x00\x00t\x05\x00\x006\x00\x00\x00'), 'location_0x644d6d8': (105174752, b'\x1e\x00\x00\x00\x00\x00\x00\x00\x80\x05\x00\x00(\x00\x00\x00'), 'location_0x644d6f0': (105174776, b'\x1e\x00\x00\x00\x00\x00\x00\x00\x85\x05\x00\x00(\x00\x00\x00'), 'location_0x644d708': (105174800, b'\x1e\x00\x00\x00\x00\x00\x00\x00\x8f\x05\x00\x00\x1c\x00\x00\x00'), 'source_0x434c18': (4410392, b'l1/src/dex_registry/clearinghouses.rs'), 'location_0x648b990': (105429400, b'%\x00\x00\x00\x00\x00\x00\x00\x0b\x00\x00\x00\x1d\x00\x00\x00'), 'location_0x6411248': (104927824, b'L\x00\x00\x00\x00\x00\x00\x00\xdb\x00\x00\x00\x14\x00\x00\x00'), 'source_0x43df4b': (4448075, b'l1/src/qtys/impl_ntl.rs'), 'location_0x648ba68': (105429616, b'\x17\x00\x00\x00\x00\x00\x00\x00\x1a\x00\x00\x00\x01\x00\x00\x00'), 'source_0x433bb6': (4406198, b'l1/src/dex_registry/perp_dex.rs'), 'location_0x6483e20': (105397800, b'\x1f\x00\x00\x00\x00\x00\x00\x00"\x00\x00\x00!\x00\x00\x00'), 'source_0x448ed3': (4493011, b'l1/src/clearinghouse/oracle/oracle.rs'), 'location_0x644d5a8': (105174448, b'%\x00\x00\x00\x00\x00\x00\x00\xb6\x01\x00\x00\x12\x00\x00\x00'), 'location_0x6437528': (105084208, b'\x0f\x00\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x10\x00\x00\x00'), 'location_0x648b9a8': (105429424, b'%\x00\x00\x00\x00\x00\x00\x00\x11\x00\x00\x00!\x00\x00\x00'), 'location_0x644d858': (105175136, b'\x13\x00\x00\x00\x00\x00\x00\x00N\x02\x00\x00\x19\x00\x00\x00'), 'source_0x43b901': (4438273, b'/home/ubuntu/hl/code_Mainnet/z_vendor/hashbrown-0.15.2/src/raw/mod.rs'), 'location_0x64459b0': (105142712, b'E\x00\x00\x00\x00\x00\x00\x00\xb9\t\x00\x00\t\x00\x00\x00'), 'location_0x6445938': (105142592, b'E\x00\x00\x00\x00\x00\x00\x00\xa9\x00\x00\x00+\x00\x00\x00'), 'location_0x6437a20': (105085480, b'E\x00\x00\x00\x00\x00\x00\x00\xc9\t\x00\x00\t\x00\x00\x00'), 'location_0x6432f58': (105066336, b'\x12\x00\x00\x00\x00\x00\x00\x00O\x03\x00\x00\x01\x00\x00\x00'), 'location_0x6476a30': (105343544, b'\x13\x00\x00\x00\x00\x00\x00\x00\x1f\x04\x00\x00\t\x00\x00\x00'), 'source_0x44583a': (4479034, b'/home/ubuntu/hl/code_Mainnet/z_vendor/chrono/src/naive/date/mod.rs'), 'location_0x63fc148': (104841552, b'B\x00\x00\x00\x00\x00\x00\x00\r\x08\x00\x00&\x00\x00\x00'), 'location_0x6484038': (105398336, b'L\x00\x00\x00\x00\x00\x00\x00\xdb\x00\x00\x00\x14\x00\x00\x00'), 'location_0x64840b8': (105398464, b'\x18\x00\x00\x00\x00\x00\x00\x00v\x00\x00\x00\x15\x00\x00\x00'), 'guard_name': (4537728, b'reset_recent_ois'), 'guard_metadata_context': (4535600, b'{\x14\xaeG\xe1z\x84?\x9a\x99\x99\x99\x99\x99\xa9?'), 'literal_context_0x60e23a': (6349370, b'cancel_aggressive_orders_at_oi_caprefresh_main_perp_dex_stale_oraclequote token '), 'literal_context_0x60e21e': (6349342, b'prune_book_empty_user_statescancel_aggressive_orders_at_oi_caprefresh_main_perp_'), 'literal_context_0x7bac52': (8105042, b'gas_auction_restartGasAuctionbucket_guardstart_gas_weiend_gas_weitokeninitial_ga'), 'literal_context_0x60e203': (6349315, b'refresh_hip3_stale_mark_pxsprune_book_empty_user_statescancel_aggressive_orders_'), 'literal_context_0x7d3212': (8204818, b'called `Result::unwrap()` on an `Err` value0001020304050607080910111213141516171'), 'literal_context_0x7c95fa': (8164858, b'called `Result::unwrap()` on an `Err` value0001020304050607080910111213141516171'), 'literal_context_0x5f21ca': (6234570, b'called `Result::unwrap()` on an `Err` valueSignableContentVerifySignatureVerifyQ'), 'literal_context_0x465a95': (4610709, b'`NaiveDate - TimeDelta` overflowedLocal time out of range for `NaiveDateTime`%Y-')}
IMPORTS = {105772296: (7, 'memcpy'), 105773904: (12, 'memcmp'), 105772880: (10, 'memset')}
INCOMING = {'begin_block_owner': [], 'guard_context': []}
# Image/export helpers adapted from MIT-authored packets #2111, #2141, #2154 and #2184/#2200.
# All target spans, constants and semantic deductions below are newly measured.
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
        matches = [s for s in self.sections if s['type'] != 8 and
                   s['address'] <= va and va + size <= s['address'] + s['size']]
        require(len(matches) == 1, 'ambiguous or unbacked VA')
        return matches[0]['offset'] + va - matches[0]['address']

    def get(self, va, size):
        offset = self.off(va, size)
        raw = self.data[offset:offset + size]
        require(len(raw) == size, 'truncated VA bytes')
        return raw

    def relocs(self):
        sec, = [s for s in self.sections if s['name'] == '.rela.dyn']
        require(sec['size'] % 24 == 0, 'partial RELA record')
        result = {}
        for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', self.data, off)
            require(slot not in result, 'duplicate relocation slot')
            result[slot] = (info, addend, off)
        return result


def export_rows(image, name, start, end):
    """Require byte-complete independent exports with equal instruction starts."""
    providers = []
    for provider in ('gnu', 'llvm'):
        cursor, rows = start, []
        for line in (PACKET / f'{name}.{provider}.txt').read_text().splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}[ \t]+)+)(.*)$', line)
            if not match:
                continue
            va, raw, asm = int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()
            require(va == cursor and va + len(raw) <= end, 'export range: ' + name)
            require(image.get(va, len(raw)) == raw, 'export bytes: ' + name)
            if asm:
                # LLVM 18 prints LOCK as a separate one-byte pseudo-instruction.
                # Join only a literal F0/lock row to its immediately adjacent opcode.
                if rows and rows[-1][1] == b'\xf0' and rows[-1][2] == 'lock':
                    prefix_va, prefix, _ = rows.pop()
                    require(prefix_va + 1 == va, 'noncontiguous LOCK prefix')
                    rows.append((prefix_va, prefix + raw, 'lock ' + asm))
                else:
                    rows.append((va, raw, asm))
            else:
                require(bool(rows), 'orphan export continuation')
                a, previous, text = rows[-1]
                rows[-1] = (a, previous + raw, text)
            cursor += len(raw)
        require(cursor == end, 'incomplete export: ' + name)
        providers.append(rows)
    require([(a, b) for a, b, _ in providers[0]] == [(a, b) for a, b, _ in providers[1]],
            'independent decoder boundaries differ: ' + name)
    return providers[0]


def call_candidates(image, target, prefix):
    text, = [s for s in image.sections if s['name'] == '.text']
    raw = image.data[text['offset']:text['offset'] + text['size']]
    pos, found = 0, []
    while True:
        pos = raw.find(prefix, pos)
        if pos < 0 or pos + len(prefix) + 4 > len(raw):
            return found
        va = text['address'] + pos
        to = va + len(prefix) + 4 + struct.unpack_from('<i', raw, pos + len(prefix))[0]
        if to == target:
            found.append(va)
        pos += 1


def dynamic_symbol(image, info):
    sym, = [s for s in image.sections if s['name'] == '.dynsym']
    strings, = [s for s in image.sections if s['name'] == '.dynstr']
    index = info >> 32
    require((index + 1) * 24 <= sym['size'], 'dynamic symbol index')
    off = sym['offset'] + index * 24
    name, flags, other, shndx, value, size = struct.unpack_from('<IBBHQQ', image.data, off)
    require(name < strings['size'], 'dynamic string index')
    start = strings['offset'] + name
    end = image.data.find(b'\0', start, strings['offset'] + strings['size'])
    require(end >= start, 'unterminated dynamic symbol')
    return {'name': image.data[start:end].decode('ascii'), 'symbol_index': index,
            'symbol_file_offset': hex(off), 'name_file_offset': hex(start),
            'info': flags, 'other': other, 'section_index': shndx,
            'value': hex(value), 'size': size}



def incoming(image, fdes):
    """Qualified .text encoded-form census; not arbitrary dynamic dispatch."""
    import capstone
    decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    cache, result, bindings = {}, [], []
    for name in INCOMING:
        target = BODIES[name][0]
        slots = [s for s, (info, value, _) in image.relocs().items() if info == 8 and value == target]
        expected = INCOMING[name]
        require(slots == expected, 'incoming RELATIVE census: ' + name)
        bindings.append({'role': name, 'target': hex(target), 'slots': [hex(s) for s in slots]})
        forms = [(target, b'\xe8')] + [(s, pre) for s in slots for pre in (b'\xff\x15', b'\xff\x25')]
        for address, prefix in forms:
            for site in call_candidates(image, address, prefix):
                owners = [f for f in fdes if f['start'] <= site < f['end']]
                require(len(owners) == 1, 'incoming FDE ownership')
                f, = owners
                if f['start'] not in cache:
                    raw = image.get(f['start'], f['end'] - f['start'])
                    rows = list(decoder.disasm_lite(raw, f['start']))
                    require(sum(row[1] for row in rows) == len(raw), 'incoming complete decode')
                    cache[f['start']] = {row[0]: row for row in rows}
                row = cache[f['start']].get(site)
                require(row and row[1] == len(prefix) + 4 and row[2] in ('call', 'jmp'), 'incoming instruction boundary')
                result.append({'role': name, 'site': hex(site), 'target_or_slot': hex(address),
                               'instruction': row[2] + ' ' + row[3], 'bytes': image.get(site, row[1]).hex(), 'owner': f})
    return {'qualified_candidates': result, 'relative_bindings': bindings,
            'limits': 'Only E8 and RIP-relative FF15/FF25 forms in .text; no arbitrary register/vtable caller or runtime-reachability claim.'}


def observe(data, *, body_hashes=True, exports=True):
    image = Image(data)
    _, fdes = eh_frame_records(data, image.sections)
    relocs = image.relocs()
    bodies, boundaries, ends = [], set(), set()
    for name, (start, end, fde_va, digest) in BODIES.items():
        fs = [f for f in fdes if f['start'] == start]
        require(len(fs) == 1 and fs[0]['end'] == end and fs[0]['fde'] == fde_va,
                'FDE binding: ' + name)
        raw = image.get(start, end - start)
        if body_hashes:
            require(sha(raw) == digest, 'body digest: ' + name)
        row = {'role': name, 'start': hex(start), 'end': hex(end), 'bytes': len(raw),
               'sha256': sha(raw), 'file_offset': hex(image.off(start)), 'enclosing_fde': fs[0]}
        if exports:
            decoded = export_rows(image, name, start, end)
            starts = {a for a, _, _ in decoded}
            boundaries.update(starts)
            ends.update(a + len(b) for a, b, _ in decoded)
            row['instructions'], row['calls_and_tail_jumps'], row['returns'] = len(decoded), [], []
            row['scope'] = 'Begin-block loop visits 0x510-byte rows, selecting only a raw INT64_MIN sentinel at row+0x378. A nonnegative millisecond scalar derived from the captured timestamp is divided by row+0x3c0. Row+0x3c8 changes only when the quotient exceeds it, before a strict-advance flag is handed to the existing reset_recent_ois guard. Zero divisor is not guarded at this site. Generic date conversion and guard cleanup are supporting context; actual financial OI semantics and completion of the callback remain unresolved.'
            for va, raw, asm in decoded:
                branch = re.match(r'j\w+\s+([0-9a-f]+)\s', asm)
                if branch:
                    require(int(branch[1], 16) in starts or asm.startswith('jmp'), 'conditional branch outside decoded FDE')
                if asm == 'ret':
                    row['returns'].append(hex(va))
                if not re.match(r'call\s', asm) and raw[:2] != b'\xff\x25':
                    continue
                call = {'site': hex(va), 'bytes': raw.hex(), 'disassembly': asm}
                if raw[:1] == b'\xe8':
                    to = va + 5 + struct.unpack_from('<i', raw, 1)[0]
                    call['direct_target'] = hex(to)
                    call['target_fde'] = next((f for f in fdes if f['start'] == to), None)
                elif raw[:2] in (b'\xff\x15', b'\xff\x25'):
                    slot = va + 6 + struct.unpack_from('<i', raw, 2)[0]
                    require(slot in relocs, 'unbound call slot')
                    info, target, off = relocs[slot]
                    call.update(slot=hex(slot), relocation_info=hex(info), addend=hex(target),
                                relocation_file_offset=hex(off))
                    if info & 0xffffffff != 8:
                        call['symbol'] = dynamic_symbol(image, info)
                else:
                    call['qualification'] = 'Register-indirect call; concrete target remains unresolved'
                row['calls_and_tail_jumps'].append(call)
        bodies.append(row)
    obligations = json.loads((PACKET / 'obligations.json').read_text())
    for name, r in obligations.items():
        start, end, raw = int(r['va'], 16), int(r['end'], 16), bytes.fromhex(r['bytes'])
        require(len(raw) == end - start and image.get(start, len(raw)) == raw,
                'instruction obligation: ' + name)
        if exports:
            require(start in boundaries and end in ends, 'instruction span boundary: ' + name)
    bindings = []
    for slot, target in SLOTS.items():
        require(relocs.get(slot, ())[:2] == (8, target), 'RELATIVE binding: ' + hex(slot))
        bindings.append({'slot': hex(slot), 'target': hex(target),
                         'relocation_file_offset': hex(relocs[slot][2])})
    imports = []
    for slot, (index, name) in IMPORTS.items():
        require(relocs.get(slot, ())[:2] == ((index << 32) | 6, 0), 'GLOB_DAT binding: ' + name)
        symbol = dynamic_symbol(image, relocs[slot][0])
        require(symbol['name'] == name and symbol['info'] == 18 and symbol['other'] == 0 and
                symbol['section_index'] == 0 and symbol['value'] == '0x0' and symbol['size'] == 0,
                'undefined dynamic function: ' + name)
        imports.append({'slot': hex(slot), 'relocation_info': hex(relocs[slot][0]), 'symbol': symbol})
    literals = []
    for name, (va, expected) in LITERALS.items():
        require(image.get(va, len(expected)) == expected, 'literal binding: ' + name)
        literals.append({'role': name, 'va': hex(va), 'file_offset': hex(image.off(va)),
                         'bytes': expected.hex(), 'length': len(expected)})
    if exports:
        frame, = [s for s in image.sections if s['name'] == '.eh_frame']
        headers = re.findall(r'^([0-9a-f]+) .*FDE cie=([0-9a-f]+) pc=([0-9a-f]+)\.\.([0-9a-f]+)$',
                             (PACKET / 'fdes.readelf.txt').read_text(), re.MULTILINE)
        actual = sorted(tuple(int(x, 16) for x in row) for row in headers)
        expected = sorted((r['enclosing_fde']['fde'] - frame['address'],
                           r['enclosing_fde']['cie'] - frame['address'],
                           int(r['start'], 16), int(r['end'], 16)) for r in bodies)
        require(actual == expected, 'independent readelf FDE headers')
    return {'schema': 1, 'target_sha256': sha(data), 'coordinates': 'ELF VA; exclusive ends',
            'bodies': bodies, 'measured_bytes': sum(r['bytes'] for r in bodies),
            'obligations': len(obligations), 'relative_bindings': bindings,
            'literals': literals, 'dynamic_imports': imports,
            'incoming': incoming(image, fdes) if exports else None,
            'captured_code_executed_or_emulated': False}


def build(data):
    require(len(data) == 105896032 and sha(data) == DIGEST, 'wrong node115 SHA-256 or size')
    return observe(data)


def controls(data):
    image, offsets = Image(data), []
    relocs = image.relocs()
    for name, r in json.loads((PACKET / 'obligations.json').read_text()).items():
        offsets.append((image.off(int(r['end'], 16) - 1), 'instruction ' + name))
    offsets += [(relocs[s][2] + 16, 'relative ' + hex(s)) for s in SLOTS]
    offsets += [(image.off(a), 'literal ' + name) for name, (a, _) in LITERALS.items()]
    offsets += [(image.off(b[2]) + 12, 'FDE range ' + name) for name, b in BODIES.items()]
    for slot, (index, name) in IMPORTS.items():
        symbol = dynamic_symbol(image, relocs[slot][0])
        offsets += [(relocs[slot][2] + 8, 'import relocation kind ' + name),
                    (relocs[slot][2] + 12, 'import symbol index ' + name),
                    (int(symbol['symbol_file_offset'], 16), 'import symbol name offset ' + name),
                    (int(symbol['name_file_offset'], 16), 'import symbol text ' + name)]
    result = []
    for off, label in offsets:
        changed = bytearray(data)
        changed[off] ^= 1
        try:
            observe(changed, body_hashes=False, exports=False)
        except ValueError as error:
            result.append({'control': label, 'file_offset': hex(off), 'rejection': str(error)})
        else:
            raise ValueError('corruption survived: ' + label)
    return {'whole_image_body_and_export_guards_bypassed': True, 'rejected': result, 'survived': []}


def encoded(value):
    return json.dumps(value, indent=2, sort_keys=True) + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true')
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    data = TARGET.read_bytes()
    result = build(data)
    outputs = {'records.json': result}
    if args.controls:
        outputs['controls.json'] = controls(data)
    for name, value in outputs.items():
        text = encoded(value)
        if args.write:
            (PACKET / name).write_text(text)
        else:
            require((PACKET / name).read_text() == text, 'regeneration mismatch: ' + name)
    print(f"PASS: {len(result['bodies'])} complete FDEs / {result['measured_bytes']} bytes")
    if args.controls:
        print(f"PASS: {len(outputs['controls.json']['rejected'])} deep corruption controls")


if __name__ == '__main__':
    main()
