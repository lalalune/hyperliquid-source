#!/usr/bin/env python3
"""Static node-94 oracle configuration change: regenerate byte evidence and models."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import elf_index
import fde_extents

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
BINARY = ROOT / 'artifacts/node/94/hl-node'
FUNCTIONS = {
    0x1eeb7d0: (0x1eeb90c, '224c2f32219cb65a20feab7a9301fc394dadfc53b0f6b679487d35c7323d2715', 'optional-change decoder'),
    0x1f571a0: (0x1f575a4, '51a16cc4f399c0bde06b29cdc659965ad2975314dfa3389e65015ea8a8447abd', 'variant decoder'),
    0x39783b0: (0x3978595, '3eb515eabcc57b660bcad3270b16faeb6dd850fca4918356fc0ef90794533531', 'change validator'),
    0x3bff4c0: (0x3bff684, '815bc5e63b9964a91a3f2e93b94232aba131262109980b20c4b7191c854feeb4', 'default and override writer'),
}
WINDOWS = {
    0x1f571b7: '488d7c2410e80f46f9ff',
    0x1f57246: '488d153b8d7303488d0d64797303',
    0x1f57378: '488943480f1143384c896b084c8963104c897b18488b4424484889432048896b2848894b3048c7036e000000',
    0x1eeb86a: '488d1539604ffe4c8d0590727b03488d7c2440488d742420b92600000041b903000000e8fea11d00',
    0x39783c0: '0fb66e284c8b36488b5e0831c9483b4e1071584d85f6741348bacccccccccccccc0c4839d30f83d40000004885c9741c660f57c0660f2ec10f872e010000660f2e0d2a2389fc0f832001000048894808f20f1148104c897018488958204088682866c7008601e95c010000',
    0x397842b: '488b56204883fa64760966b94301e9fc0000004989c7488b7618488d7c2420ff1588addf010fb74c242081f986010000757d',
    0x397845d: '8b442424f20f104424288b4c243089442410f20f11442414894c241c488d7c2410ff15e4b4df0166c7442420ab00a8010f84a0000000488d7c2420f20f11442408e86da0defff20f104c2408b9010000004c89f84d85f60f851effffffe92cffffff',
    0x39784bf: '66c740060000c740020000000066c7003f0148895808e9ad000000',
    0x397852c: '66c7003f01eb5466b9ab004c89f866895002897004',
    0x3bff4d3: '488d4f188b46203c0375038b4328803e00488d7e08480f45cff20f1001488d4b20488d7e18807e1000480f45cf488b09f20f11431848894b20884328',
    0x3bff580: '4c89ff4889de4c89f1e8d2e779ff4c89ff4c89e6e817077bff488b8424980000004885c07462488b8c24a8000000488b54c808488d0c89488bb4c880000000498976200f1044c8600f104cc870410f114e10410f11064889542450488b4424584883f802742248891424807c247803758f480b44246875884c89ff4889de4c89eae85adb7affeb86',
    0x235801f: '66410f104708f3410f6f4f18f3410f6f5728660f7f9424e0020000660f7f8c24d0020000660f298424c00200004d8d67384981c5b80500004c89ef31f6ff151ebd41034889442418488d7c2420488db424c0020000ff154ebd4103',
    0x23580cd: '498b4748483d112700000f82372d0000',
    0x235af44: '4883fd650f83c41800004c89ef4c89e64889ea488b4c2418ff15b68341030fb74424203d860100000f85d7180000',
    0x235af8a: '4c89ef488db42420020000ff152d8e4103',
    0x235afab: '488d4c2428488b4120488943200f10010f1049100f114b100f1103660f1003f30f6f4b10660f29842400090000660f7f8c2410090000488b432048898424200900004c89ef488db424f00300004c89f2488d8c2400090000e8a8e04f00',
    0x235ba8d: '488b7c24184881c7a8000000488db424d0080000488d542420e8153a8a01',
}
BRANCHES = (0x39783d1, 0x39783d6, 0x39783e5, 0x39783ee, 0x39783f8,
            0x3978406, 0x3978433, 0x397845b, 0x397848d, 0x39784b4,
            0x3bff4dc, 0x3bff522, 0x3bff5a4, 0x3bff5e4, 0x3bff5ef, 0x3bff5f6)
LIMIT = 0x0ccccccccccccccc
MASK = (1 << 64) - 1


def checked_data(data):
    if hashlib.sha256(data).hexdigest() != SHA:
        raise ValueError('node 94 input digest mismatch')
    return data


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = elf_index.sections(data)
        _, records = fde_extents.eh_frame_records(data, self.sections)
        self.fdes = {r['start']: r['end'] for r in records}
        self.fde_records = {r['start']: r for r in records}
        rela = [s for s in self.sections if s['name'] == '.rela.d' + 'yn']
        if len(rela) != 1 or rela[0]['type'] == 8 or rela[0]['size'] % 24:
            raise ValueError('bad relocation section')
        self.relocs = {}
        self.relocation_records = {}
        s = rela[0]
        for pos in range(s['offset'], s['offset'] + s['size'], 24):
            where, info, addend = struct.unpack_from('<QQq', data, pos)
            if info & 0xffffffff == 8:
                if where in self.relocs:
                    raise ValueError('duplicate relative relocation')
                self.relocs[where] = addend
                if where in (0x5773dc8, 0x57731d8, 0x5773968, 0x568ff88):
                    self.relocation_records[where] = {'file_offset': hex(pos), 'bytes': data[pos:pos+24].hex()}

    def offset(self, va, size=1, executable=False):
        if size <= 0 or va < 0:
            raise ValueError('invalid byte range')
        matches = [s for s in self.sections if s['type'] != 8 and s['address'] and
                   s['address'] <= va and va + size <= s['address'] + s['size'] and
                   (not executable or s['flags'] & 4)]
        if len(matches) != 1:
            raise ValueError('unbacked or ambiguous address range')
        return matches[0]['offset'] + va - matches[0]['address']

    def read(self, va, size, executable=False):
        off = self.offset(va, size, executable)
        return self.data[off:off + size]

    def relative32(self, va, prefix):
        n = len(prefix) + 4
        b = self.read(va, n, True)
        if b[:len(prefix)] != prefix:
            raise ValueError('unexpected relative instruction')
        return va + n + struct.unpack_from('<i', b, len(prefix))[0]

    def branch(self, va):
        b = self.read(va, 2, True)
        if 0x70 <= b[0] <= 0x7f:
            raw = b
            target = va + 2 + struct.unpack_from('<b', b, 1)[0]
            cc = b[0] & 15
        elif b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
            raw = self.read(va, 6, True)
            target = va + 6 + struct.unpack_from('<i', raw, 2)[0]
            cc = b[1] & 15
        else:
            raise ValueError('not a supported conditional branch')
        return {'site': hex(va), 'bytes': raw.hex(), 'condition_code': cc, 'target': hex(target)}

    def check(self):
        rows = []
        for start, (end, digest, role) in sorted(FUNCTIONS.items()):
            if self.fdes.get(start) != end:
                raise ValueError('unexpected FDE interval')
            raw = self.read(start, end - start, True)
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError('unexpected function body')
            record = self.fde_records[start]
            fde = record['fde']
            n = struct.unpack('<I', self.read(fde, 4))[0]
            if n == 0xffffffff or not 0 < n < 4096:
                raise ValueError('unexpected FDE record length')
            rows.append({'start': hex(start), 'end_exclusive': hex(end), 'file_offset': hex(self.offset(start, len(raw), True)),
                         'fde_va': hex(fde), 'fde_file_offset': hex(self.offset(fde, n+4)),
                         'fde_bytes': self.read(fde, n+4).hex(), 'cie_va': hex(record['cie']),
                         'lsda_va': hex(record['lsda']) if record['lsda'] is not None else None,
                         'role': role, 'sha256': digest, 'bytes': raw.hex()})
        for va, expected in WINDOWS.items():
            raw = bytes.fromhex(expected)
            if self.read(va, len(raw), True) != raw:
                raise ValueError('instruction window mismatch')
        return rows


def float_class(bits):
    """Classify raw binary64 for the pinned ordered compare pair; no host float needed."""
    if not 0 <= bits <= MASK:
        raise ValueError('not a binary64 word')
    sign, exponent, fraction = bits >> 63, (bits >> 52) & 2047, bits & ((1 << 52) - 1)
    if exponent == 2047:
        raise ValueError('nonfinite converter output is outside the model')
    if bits == 0x8000000000000000:
        return 'negative_zero', True
    if sign:
        return 'negative', False
    if bits < 0x3ff0000000000000:
        return 'zero_to_below_one', True
    return 'one_or_greater', False


def subject_check(bits, expected):
    return float_class(bits)[1] == (expected == 'accept')


def gate(present, length, parse_status, conversion_ok, cap_tag, cap, bits):
    if not 0 <= cap <= MASK or not 0 <= length <= MASK:
        raise ValueError('invalid u64')
    if present:
        float_class(bits)
        if length > 100:
            return 'length_0x143'
        if parse_status != 0x186:
            return 'parser_' + hex(parse_status)
        if not conversion_ok:
            return 'conversion_0xab'
    if cap_tag and cap >= LIMIT:
        return 'cap_0x13f'
    if present and not float_class(bits)[1]:
        return 'fraction_0x13f'
    return 'success_0x186'


def merged(old, change):
    """Writer before its override-tree iteration; flags are raw words, mode a byte."""
    old_f, old_n, old_m = old
    flag_f, new_f, flag_n, new_n, mode = change
    return (new_f if flag_f else old_f, new_n if flag_n else old_n, old_m if mode == 3 else mode)


def collect(data):
    im = Image(checked_data(data))
    functions = im.check()
    if im.relative32(0x1f571bc, b'\xe8') != 0x1eeb7d0:
        raise ValueError('variant-to-change call changed')
    slot = im.relative32(0x2358074, b'\xff\x15')
    slot2 = im.relative32(0x235af95, b'\xff\x15')
    if slot != 0x5773dc8 or slot2 != slot or im.relocs.get(slot) != 0x39783b0:
        raise ValueError('validator call changed')
    if im.relative32(0x235b003, b'\xe8') != 0x28590b0:
        raise ValueError('change-map call changed')
    if im.relative32(0x235baa6, b'\xe8') != 0x3bff4c0:
        raise ValueError('writer call changed')
    parser = im.relative32(0x397844a, b'\xff\x15')
    converter = im.relative32(0x397847e, b'\xff\x15')
    if parser != 0x57731d8 or im.relocs.get(parser) != 0x3799510:
        raise ValueError('parser call changed')
    if converter != 0x5773968 or im.relocs.get(converter) != 0x4ead680:
        raise ValueError('converter call changed')
    for call, target in ((0x3bff589, 0x339dd60), (0x3bff594, 0x33afcb0), (0x3bff601, 0x33ad160)):
        if im.relative32(call, b'\xe8') != target:
            raise ValueError('tree helper call changed')
    target = im.relative32(0x1f57246, b'\x48\x8d\x15')
    if target != 0x568ff88:
        raise ValueError('variant diagnostic reference changed')
    textva = im.relocs.get(target)
    n = struct.unpack('<Q', im.read(target + 8, 8))[0]
    variant = im.read(textva, n)
    if variant != b'struct variant VoteGlobalAction::SetReferenceOracleConfig with 2 elements':
        raise ValueError('variant diagnostic changed')
    nameva = im.relative32(0x1eeb86a, b'\x48\x8d\x15')
    if im.read(nameva, 38) != b'UnvalidatedReferenceOracleConfigChange':
        raise ValueError('change type text changed')
    table = 0x3dd1b8
    cell = table + 4 * (0x6e - 0x12)
    dest = table + struct.unpack('<i', im.read(cell, 4))[0]
    if dest != 0x235801f:
        raise ValueError('dispatcher entry changed')
    if im.read(0x20a730, 8) != bytes.fromhex('000000000000f03f'):
        raise ValueError('upper bound is not binary64 one')
    return im, functions, {'variant_text_va': hex(textva), 'variant_descriptor_va': hex(target),
        'variant_text': variant.decode('ascii'), 'unvalidated_type_va': hex(nameva),
        'unvalidated_type': 'UnvalidatedReferenceOracleConfigChange', 'raw_tag': hex(0x6e),
        'jump_table_va': hex(table), 'jump_cell_va': hex(cell), 'jump_destination_va': hex(dest),
        'validator_slot': hex(slot), 'validator_target': hex(im.relocs[slot]),
        'parser_slot': hex(parser), 'parser_target': hex(im.relocs[parser]),
        'converter_slot': hex(converter), 'converter_target': hex(im.relocs[converter]),
        'relocation_records': {hex(k): im.relocation_records[k] for k in (slot, parser, converter, target)},
        'list_length_ceiling': 10000, 'string_length_ceiling': 100,
        'integer_exclusive_bound': hex(LIMIT), 'float_upper_bits': '3ff0000000000000'}


def tsv(path, header, rows):
    with path.open('w', newline='', encoding='ascii') as f:
        w = csv.writer(f, delimiter='\t', lineterminator='\n')
        w.writerow(header)
        w.writerows(rows)


def generate(out):
    im, funcs, links = collect(BINARY.read_bytes())
    out.mkdir(parents=True, exist_ok=True)
    branches = [im.branch(a) for a in BRANCHES]
    doc = {'artifact_sha256': SHA, 'coordinate_system': 'node 94 ELF virtual address',
           'functions': funcs, 'links': links, 'conditional_branches': branches,
           'limits': 'FDE intervals are unwind ranges. Callees, dispatcher outside selected windows, tree internals, input reachability and target execution are excluded.'}
    (out / 'evidence.json').write_text(json.dumps(doc, indent=2, sort_keys=True) + '\n', encoding='ascii')
    tsv(out / 'windows.tsv', ['virtual_address', 'file_offset', 'bytes'],
        [(hex(a), hex(im.offset(a, len(bytes.fromhex(h)), True)), h) for a,h in sorted(WINDOWS.items())])
    tsv(out / 'branches.tsv', ['site', 'bytes', 'condition_code', 'target'],
        [(r['site'], r['bytes'], r['condition_code'], r['target']) for r in branches])
    values = [0, 1, 0x3fefffffffffffff, 0x3ff0000000000000, 0x3ff0000000000001,
              0x8000000000000000, 0x8000000000000001, 0xbfefffffffffffff,
              0xbff0000000000000]
    caps = [0, LIMIT - 1, LIMIT, MASK]
    rows = []
    for p in (0, 1):
        for bits in values:
            for tag in (0, 1):
                for cap in caps:
                    rows.append((p, f'{bits:016x}', tag, hex(cap), float_class(bits)[0], gate(p, 100, 0x186, True, tag, cap, bits)))
    domains = [
        (0, 0x3fefffffffffffff, 'finite_zero_to_below_one', 'accept'),
        (0x3ff0000000000000, 0x7fefffffffffffff, 'finite_one_or_greater', 'reject'),
        (0x8000000000000000, 0x8000000000000000, 'negative_zero', 'accept'),
        (0x8000000000000001, 0xffefffffffffffff, 'finite_negative', 'reject'),
    ]
    for low, high, label, result in domains:
        if high < low or subject_check(low, result) is False or subject_check(high, result) is False:
            raise ValueError('invalid finite-domain partition')
    if sum(high-low+1 for low,high,_,_ in domains) != 2 * 2047 * (1 << 52):
        raise ValueError('finite-domain partition count mismatch')
    tsv(out / 'finite-domain.tsv', ['first_bits','last_bits','class','result','bit_patterns'],
        [(f'{lo:016x}', f'{hi:016x}', label, result, hi-lo+1) for lo,hi,label,result in domains])
    tsv(out / 'gate-cases.tsv', ['fraction_present', 'fraction_bits', 'cap_tag', 'cap', 'float_class', 'result'], rows)
    failures = [(p,n,s,c,t,v,b,gate(p,n,s,c,t,v,b)) for p,n,s,c,t,v,b in (
        (0,101,0x999,False,1,LIMIT,0x3ff0000000000000),
        (1,101,0x999,False,1,LIMIT,0x3ff0000000000000),
        (1,100,0x55,False,1,LIMIT,0x3ff0000000000000),
        (1,100,0x186,False,1,LIMIT,0x3ff0000000000000),
        (1,100,0x186,True,1,LIMIT,0x3ff0000000000000),
        (1,100,0x186,True,1,LIMIT-1,0x3ff0000000000000),
        (1,100,0x186,True,1,LIMIT-1,0))]
    tsv(out / 'failure-order.tsv', ['present','length','parse_tag','conversion_ok','cap_tag','cap','float_bits','result'], failures)
    rows = []
    for f in (0,1,2):
        for n in (0,1,2):
            for m in (0,1,2,3,255):
                rows.append((f,n,m,*merged((11,22,1),(f,33,n,44,m))))
    tsv(out / 'default-merge.tsv', ['fraction_tag','integer_tag','mode','stored_fraction_bits','stored_integer','stored_mode'],rows)


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    generate(args.out)

if __name__ == '__main__':
    main()
