#!/usr/bin/env python3
"""Authenticate node115 settled-history-json-admission; static reads only, no capture execution."""
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
BODIES = {'history_json_reader': (32031424, 32041933, 17575548, 'adfde4d62b4fe714517c90b395de59e2f03c443f7cc42a6e559e08c38d35b220'), 'spot_parent_context': (32435360, 32452603, 17582784, 'b1a7d9fc5043bf9c0dd0e5411da1563317fd66f391cfd4539be0fea2cf3af1a0'), 'spot_key_classifier': (36580016, 36580634, 13606876, 'eb9390d3baccb7bc0a41290c08f74d6facd05f7797f71a21d1c0cee69659a2cc'), 'history_default': (30904704, 30905308, 17493672, '409d44aea3617f6bcb2fd9e5e7d3643d0ac48d9fcc2d0b364d1e702e8098c391'), 'sequence_history_adapter': (30877952, 30878075, 13536372, 'ebad79a38ab34a798a4fc96d468bd99d29642b57631b7ee3a0f8c68593db3c73'), 'map_access': (31167312, 31167667, 13545368, '1e23a314bda58a3a1e6dd067d951d15fc34e747541a804bfdeb8289db13dd042'), 'sequence_access': (31188736, 31189039, 13550008, '768a75a30e03624993e4fedb3679c6185f3a384be394fa4d6cc44e16bcb02d42'), 'map_finish': (30899056, 30899235, 13538208, 'a775b47c5ab355ab0591d3b75c1868a45b9e16e9b85dd9b4b3cb2fc79947f654'), 'sequence_finish': (30899440, 30899696, 13538304, '1729e871268532b845cd0f6ff6b6ec03787aed90d5b7173d6a1d197cb7dc8e69'), 'unknown_value_context': (30889312, 30890828, 13537268, 'd07b39647cdc7b8a9ac74e4528f0b8647e4146b6b2d47fccb16d35a653be0d5f'), 'sots_child_context': (31708160, 31708925, 17569240, '45cf332646974057c73831d33b7b4cff82b5078ca6ded1ffaa5b42ffe8118544'), 'sotq_child_context': (31693536, 31694223, 17567772, '200f5a39620afc115a3ea5b7aa1aa98d012c881e5051685b8852cebb0661808b'), 'sqts_child_context': (31652496, 31653310, 17563324, '3b96894af72f4b247b84e630635dd714ce6961b63191f2a8ed22b13a05c09da1'), 'sqp_child_context': (31705408, 31706237, 17568988, 'a64489f006bcc713d03a14e91bf61b60f515615cd6f5c715706ae55c99010441'), 'sqpq_child_context': (31688288, 31689117, 17567160, 'd83455819c879fd8547ca135406b7b802cc3fb2ed41f0525bd673a4fc017fc10')}
SLOTS = {105777400: 96824160, 105772192: 104193584, 104998936: 6119426, 104999400: 4416992, 105772320: 23600544, 105006168: 4471744, 105773128: 23600704, 105006144: 4471744, 105142704: 4438273, 105142584: 4438273, 105772224: 23596203, 104997928: 6115488, 104999472: 4522320, 105780008: 96824784, 104988240: 4471744, 105772848: 23596640, 104988264: 4471744, 104999784: 4471744, 105785240: 72736256, 105785248: 72746192}
SUPPORT = {}
LITERALS = {'source_0x4365e0': (4416992, b'/home/ubuntu/hl/code_Mainnet/z_vendor/serde_json/src/read.rs'), 'location_0x64229e8': (104999408, b'<\x00\x00\x00\x00\x00\x00\x00:\x02\x00\x00\t\x00\x00\x00'), 'source_0x443bc0': (4471744, b'/home/ubuntu/hl/code_Mainnet/z_vendor/serde_json/src/de.rs'), 'location_0x6424458': (105006176, b':\x00\x00\x00\x00\x00\x00\x009\x07\x00\x00\x11\x00\x00\x00'), 'location_0x6424440': (105006152, b':\x00\x00\x00\x00\x00\x00\x00.\x07\x00\x00\x11\x00\x00\x00'), 'source_0x43b901': (4438273, b'/home/ubuntu/hl/code_Mainnet/z_vendor/hashbrown-0.15.2/src/raw/mod.rs'), 'location_0x64459b0': (105142712, b'E\x00\x00\x00\x00\x00\x00\x00\xb9\t\x00\x00\t\x00\x00\x00'), 'location_0x6445938': (105142592, b'E\x00\x00\x00\x00\x00\x00\x00\xa9\x00\x00\x00+\x00\x00\x00'), 'location_0x641fe50': (104988248, b':\x00\x00\x00\x00\x00\x00\x00\xa2\x04\x00\x00"\x00\x00\x00'), 'location_0x641fe68': (104988272, b':\x00\x00\x00\x00\x00\x00\x00\x98\x04\x00\x00&\x00\x00\x00'), 'location_0x6422b68': (104999792, b':\x00\x00\x00\x00\x00\x00\x00\xd6\x06\x00\x00\x11\x00\x00\x00'), 'parent_key_table': (6099116, b'R\xde\x91\x01\x87\xe1\x91\x01r\xe0\x91\x01\xcd\xe0\x91\x01^\xdf\x91\x01\xe8\xe1\x91\x01\xa4\xe2\x91\x01+\xe1\x91\x01\\\xe3\x91\x01\x17\xe0\x91\x01\x00\xe3\x91\x01\x03\xdf\x91\x01\xbc\xdf\x91\x01F\xe2\x91\x01\xb3\xde\x91\x01'), 'parent_length_table': (6200232, b')\x8f\xcf\x01\xe0\x8f\xcf\x01<\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01}\x8f\xcf\x01\x9a\x90\xcf\x01<\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01\xc3\x90\xcf\x01<\x91\xcf\x01<\x91\xcf\x01\xaa\x8f\xcf\x01\x01\x90\xcf\x01<\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01d\x90\xcf\x01\x13\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01<\x91\xcf\x01\xe4\x90\xcf\x01'), 'history_type': (6119426, b'struct SettledOutcomeHistory with 5 elements'), 'sots': (4562776, b'sots'), 'sotq': (4563264, b'sotq'), 'sqts': (4562688, b'sqts'), 'sqp': (6119423, b'sqp'), 'sqpq': (4563188, b'sqpq'), 'literal_context_0x459f58': (4562776, b'sotsusdcjsoncurrTpslNoopInitpollTimedatedvpdznfnfullread\\011\\012sendbasehttpuser'), 'literal_context_0x45a140': (4563264, b'sotqtypeMain is Uid:LivedatacboeBin8Ext8NOEXstat (0xslowUtf8oberAsn1pmdlIpv6Done'), 'literal_context_0x5d5fff': (6119423, b'sqpstruct SettledOutcomeHistory with 5 elementshscquestionTemplateInstancenamedO'), 'literal_context_0x5d1e1e': (6102558, b'user_statesleader_commissionis_closedlockup_durationallow_depositsrelationshipal'), 'literal_context_0x5d5017': (6115351, b'token_to_max_supplytoken_fees_collectednative_tokenspot_dusting_opted_out_userse'), 'literal_context_0x5d502a': (6115370, b'token_fees_collectednative_tokenspot_dusting_opted_out_usersevm_transfer_escrows'), 'literal_context_0x5d5066': (6115430, b'evm_transfer_escrowseectoken_to_pending_evm_contractpmrsohstruct SpotClearinghou'), 'literal_context_0x5d504a': (6115402, b'spot_dusting_opted_out_usersevm_transfer_escrowseectoken_to_pending_evm_contract'), 'literal_context_0x5d507d': (6115453, b'token_to_pending_evm_contractpmrsohstruct SpotClearinghouse with 14 elementsstru'), 'literal_context_0x5d4329': (6112041, b'daily_exchange_scaled_and_raw_vlmshalted_assetsoverride_max_signed_distances_fro'), 'literal_context_0x5d507a': (6115450, b'eectoken_to_pending_evm_contractpmrsohstruct SpotClearinghouse with 14 elementss'), 'literal_context_0x5d503e': (6115390, b'native_tokenspot_dusting_opted_out_usersevm_transfer_escrowseectoken_to_pending_'), 'literal_context_0x5d509a': (6115482, b'pmrsohstruct SpotClearinghouse with 14 elementsstruct HashHardQuorum with 3 elem'), 'literal_context_0x5d509d': (6115485, b'sohstruct SpotClearinghouse with 14 elementsstruct HashHardQuorum with 3 element'), 'literal_context_0x5eac5d': (6204509, b'daily_exchange_scaled_and_raw_vlmstoken_to_max_supplytoken_fees_collectednative_'), 'literal_context_0x5d1dd0': (6102480, b'internal error: entered unreachable codedescriptioncreate_timevault_userleaderus')}
IMPORTS = {105772296: (7, 'memcpy')}
INCOMING = {'history_json_reader': [], 'spot_parent_context': [], 'spot_key_classifier': [], 'history_default': [], 'sequence_history_adapter': [], 'map_access': [], 'sequence_access': [], 'map_finish': [], 'sequence_finish': [], 'unknown_value_context': [], 'sots_child_context': [], 'sotq_child_context': [], 'sqts_child_context': [], 'sqp_child_context': [], 'sqpq_child_context': []}
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
            row['scope'] = 'The settled-history JSON admission contract binds the parent soh variant to the five-field child: absent whole history invokes an empty constructor, but a present child requires all five fields, rejects known duplicates before value parsing, ignores unknown values only when the walker succeeds, and accepts a positional sequence of exactly five children. Closing-error precedence and depth/whitespace framing are recorded. Nested child grammars, escaping, allocation/TLS seed equivalence, full parent schema and round trips remain explicit boundaries; no target execution or emulation.'
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
