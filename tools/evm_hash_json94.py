#!/usr/bin/env python3
"""Extract selected EVM snapshot JSON block-hash writer decisions from node 94."""
import argparse
import hashlib
import json
import re
from pathlib import Path
import struct

from elf_index import sections, unwind_index
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'artifacts/node/94/hl-node'
DIGEST = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
FUNCTIONS = {
    0x25e3020: 'collect and dispatch',
    0x291d140: 'JSON row sequence',
    0x28fac00: 'first row item',
    0x21b7410: 'first item byte formatter',
    0x2806390: 'second row item',
    0x1f69970: 'vector hex path',
    0x2620800: 'JSON field reader',
    0x26a2860: 'outer row collector',
    0x1b7e660: 'row reader',
    0x1b6c990: 'first item sequence adapter',
    0x1b9d1a0: 'second item sequence adapter',
    0x28fbe50: 'first item reader',
    0x28f7cd0: 'first item radix and limb parser',
    0x28317c0: 'digit classifier',
    0x2807e70: 'second item reader',
    0x280aae0: '32-byte sequence reader',
    0x1b7a6b0: 'sequence byte adapter',
    0x1bab430: 'numeric byte reader',
    0x280fe20: 'first 32-byte decode adapter',
    0x28839f0: 'second 32-byte decode adapter',
}
# Selected instruction-aligned windows. They do not constitute a full decoder.
PINS = {
 0x28fbf9f: '4c8ba424800000004983fc037522410fb7076633058a05affd410fb64f02320d8105affd0fb6c96609c10f8406030000',
 0x28fc2d5: '0f57c00f2944245048c74424600000000031c0e916fdffff',
 0x28fc003: '488943080f284424500f114310488b4424604889432031c0',
 0x28fbfcf: '488d7c24104c89fe4c89e2e8f1bcffff837c2410010f841b030000',
 0x28f7cde: '4883fa0248897c2408b80a00000077047408eb4c807e02bf7e464c8d7602488d5afeb81000000066813e3078743866813e30587431b80800000066813e306f742566813e304f741eb80200000066813e3062741266813e3042740bb80a0000004889d34989f6',
 0x28f7da0: '49ffc64c89e7e8159af3ffa8010f857d000000',
 0x28f7e30: '488b4424204839c20f83b50000004989c0488b4424104989d149f7e04889d14989c24c89e849f7e04889d64989c54c89f849f7e04889d74989c74889e849f7e04989d04d01ca4c895424104911cd4911f74889c54811fd4983d000488d4c24500f84fdfeffff',
 0x28f7ea2: '488b5424604883fa05751a488b4424084c8968104c8978184889682031c9488b542410eb16488b442408488d48100f104424680f1101b90100000048890848895008',
 0x28f7ef3: '48c744241802000000488d4c2430488901488b742418488b4c2430488b44240848897008488950104889481848c70001000000',
 0x28317c0: '488b0f488b018338050f85e0000000488b49084883392573148d4ed083f90a732089f24883c2d0b801000000c38d4ebf83f91a732089f24883c2bfb801000000c38d4e9f83f91a732089f24883c2a9b801000000c3',
 0x2807ef4: '448d47a54183f820763383ff220f841d01000083ff2d0f85d40000004883f8040f84fd040000',
 0x2807f42: '410fb64e4884c90f84d5040000fec941884e480f84a00400004883f8040f84b20400004883c0fc49894628488d7c24084c89f6ba01000000e8612b0000',
 0x280ab10: '4c89ff4c89e6e895fb36ff803c24007547807c2401010f85b70000000fb6442402428844342049ffc64983fe2075d14889e7488d742410e864fb36ff0fb62c244084ed7521807c240100741abf21000000e8fa470000eb05',
 0x280abe3: '4c89f7e875470000',
 0x1b7a792: '4183fa5d750e66c70300004889d84883c4205bc3807808007448c6400800eb064183f85d744a488d7c2408e86e0c0300807c240800',
 0x1bab4d3: 'e8a836f8ff488b4c24284883f903753b488b44243048894308c603014883c4385b415ec3488d15a2d2ad03488d74240f4c89f7e8c542f8ff4889c74c89f6e8ba4b2b0048894308b001eb30488b44243083f901741983f902752b483d000100007214',
 0x280803e: '488d7c24084c89f2ff15546cf602488b442408488b7424104883f802750c48897308c60301e984000000488b542418488d7c2430a8017407e8a57d0000eb05e86eb90700807c2430010f841a030000',
 0x280fe28: '488d7c24204889e141b820000000ff158407f602837c2420037527',
 0x28839f8: '488d7c24204889e141b820000000ff15b4cbee02837c2420037524',
 0x1cc7f52: '4883fe3a0f855e0700004885c00f84fa0700004989462831ed4c89f6e88d889500488b442418837c241001',
 0x2620881: '448d47a54183f8200f87b2000000488d3582a5dcfd4e6304864901f041ffe0',
 0x26208cb: '488dbc24f00000004c89f6ba01000000e8801f0800',
 0x26a28c0: '4c89ff4c89e6e895bd4dff488b4c2470488b4424784883f9020f84b9000000',
 0x1b7e70e: '4183f85d750c48c70300000000e966010000807e08000f8406020000c6460800eb0983fe5d0f841a0200004839c8732b',
 0x1b7e78f: '83fe5b0f8574010000410fb64e4884c90f841f020000fec941884e480f84710100004885c0',
 0x1b7e7c8: '488d7c2408488d742470e8b9e1feff488b4424084883f802743da8010f8459010000',
 0x1b7e809: '488d7c2408488d742470e888e90100807c24080074794c8b7c241041bc01000000',
 0x1b7e898: 'f6442409010f84c3000000',
 0x1b7e943: '488d159ea2b003488d74240731ffeb24',
 0x1b7e966: '488d157ba2b003488d742407bf01000000e8a4583300',
 0x1b6ca72: '4183fa5d750d48c703000000004883c4305bc3807808007454c6400800eb064183f85d7456488d7c2408e8aff3d800807c240800',
 0x1b9d282: '4183fa5d750e66c70300004889d84883c4305bc3807808007452c6400800eb064183f85d7454488d7c2408e8beabc600807c240800',
 0x2206c7c: '4881c3201b00004c8b7c24084d8b37498b06498b76104829f04883f8010f864f010000498b460866c704303a204883c602498976104889df4c89fee864c33d00',
 0x25e3027: '4889f3488b0f4885c97435488b5708488b471048c74424280000000048894c2430488954243848c74424480000000048894c24504889542458b901000000eb0431c931c048894c242048894c244048894424604c8d742408488d7424204c89f7e8c441f8ff4889df4c89f6e8a9a03300',
 0x291d14e: '488b5f184883fbff0f84f10500004989fd488b4e08488b6e104c8b37488d430148894718c64720004d8b7e104d393e0f844e050000498b460842c604385b49ffc74d897e104885ed0f8470040000',
 0x291d193: '4885ed0f847004000048c1e5044801cdb0014c896c240848896c241890488b114889542420488b51084889542428498b6d00',
 0x291d2c8: '488b450842c604305b49ffc64c8975104c3975000f84400200004883c11048894c2410488b450842c604300a',
 0x291d370: '488b7c2420488b5c24084889dee87ed8fdff',
 0x291d400: '488b7c24284c8b6c24084c89eee87e8feeff4885c00f85a702000041c6452001',
 0x291d4c9: '4c8b6c2408498b460842c604385d49ffc74d897e1041c645200131c0488b4c24104839e90f85bdfcffff',
 0x291d740: '488d3d81b2da02ff15030ae502488d3d44b2da02ff15be09e502',
 0x28fac0e: '488b1e488d471f807f1f0048893c2474094989c6488d4720eb23488d4f1e807f1e0074054989ceeb14488d471d807f1d000f84990100004989c64889c848ffc84889442430',
 0x28fac53: 'bf42000000ff157a33e7024885c00f840f040000',
 0x28fac94: '488d3555c8dc02488d150a468ffd488d7c2438488d4c2410ff155633e702',
 0x28facd7: '4c8d3d12c8dc024c8d2523f990fd4c8d6c2410488d6c2438488b1d1233e702',
 0x28fad00: '4939ce745e49ffce4c89742430488d4424304889442438488d05f2c68bff48894424404c89ef4c89fe4c89e24889e9ffd384c0488b0c2474c7',
 0x28fafb6: '4c8b342441803e000f8587fcffff4c8d3550b0affdba010000004889df4c89f6e8c5cbc1ff488d35e1baaffdba030000004889dfe831a2fcff',
 0x280639a: '0f57c00f114424380f114424280f114424180f1144240866c74424063078',
 0x28063ce: 'b801000000488d0d4622a0fd660f1f4400000fb65407ff89d683e60f0fb6340ec1ea040fb6140a8854440640887444070fb6140789d683e60f0fb6340ec1ea040fb6140a8854440840887444094883c0024883f82175bbeb22',
 0x280643a: '488d542408be20000000e8273576ff',
 0x2806449: '488b1b488b73104839337443488b4308c604302248ffc648897310488d742406ba420000004889dfe8aaed0b00488b73104839337437488b4308c604302248ffc648897310',
 0x21b7411: '488b070fb6004531c9488d0dff1105fe6666666666662e0f1f8400000000000fb6d0c0e80489d783e70f0fb63c0f42887c0c0749ffc980fa0f77e44e8d040c',
 0x1f699a0: 'f30f6f140f660f6fda660f72d304660fdbd0660f6fe1660f3800e2660fdbd8660f6fd1660f3800d3660f6fda660f60dc660f68d4f30f7f1c4af30f7f544a104883c1104839c875b8',
}
CALLS = {
 0x28fbfda: 0x28f7cd0, 0x28f7da6: 0x28317c0,
 0x2807f7a: 0x280aae0, 0x280ab16: 0x1b7a6b0,
 0x280ab47: 0x1b7a6b0, 0x1b7a7bd: 0x1bab430,
 0x2808076: 0x280fe20, 0x280807d: 0x28839f0,
 0x1cc7f6e: 0x2620800, 0x26208db: 0x26a2860,
 0x26a28c6: 0x1b7e660, 0x1b7e7d2: 0x1b6c990,
 0x1b7e813: 0x1b9d1a0, 0x1b6ca9c: 0x28fbe50,
 0x1b9d2ad: 0x2807e70,
 0x2206cb7: 0x25e3020, 0x25e3087: 0x2567250,
 0x25e3092: 0x291d140, 0x291d37d: 0x28fac00,
 0x291d40d: 0x2806390, 0x2806444: 0x1f69970,
}
RIPS = {
 0x262088f: ('488d35', 0x3eae18),
 0x2807f31: ('488d35', 0x3f1db4),
 0x1f69981: ('660f6f05', 0x2030c0),
 0x1f69989: ('660f6f0d', 0x208620),
 0x28063d3: ('488d0d', 0x208620),
 0x28fac9b: ('488d15', 0x1ef2ac),
 0x28facde: ('4c8d25', 0x20a608),
 0x21b741a: ('488d0d', 0x208620),
}
BRANCHES = {
 0x28fbfab: 0x28fbfcf, 0x28fbfc9: 0x28fc2d5,
 0x28f7d0a: 0x28f7d44, 0x28f7d11: 0x28f7d44,
 0x28f7d1d: 0x28f7d44, 0x28f7d24: 0x28f7d44,
 0x28f7d30: 0x28f7d44, 0x28f7d37: 0x28f7d44,
 0x28f7e38: 0x28f7ef3, 0x28f7e90: 0x28f7d93,
 0x280ab1f: 0x280ab68, 0x280ab26: 0x280abe3,
 0x280ab3d: 0x280ab10, 0x280ab53: 0x280ab76,
 0x280ab5a: 0x280ab76, 0x1bab533: 0x1bab549,
 0x1bab547: 0x1bab588,
 0x280805a: 0x2808068, 0x2808074: 0x280807d,
 0x2808087: 0x28083a7, 0x280fe41: 0x280fe6a, 0x2883a11: 0x2883a37,
 0x26a28d9: 0x26a2998, 0x1b7e712: 0x1b7e720,
 0x1b7e792: 0x1b7e90c, 0x1b7e7e0: 0x1b7e81f,
 0x1b7e7e4: 0x1b7e943, 0x1b7e81d: 0x1b7e898,
 0x1b7e89d: 0x1b7e966, 0x1b6ca76: 0x1b6ca85,
 0x1b9d286: 0x1b9d296,
 0x25e3030: 0x25e3067, 0x291d156: 0x291d74d,
 0x291d196: 0x291d60c, 0x291d415: 0x291d6c2,
 0x291d4ed: 0x291d1b0, 0x28fac1d: 0x28fac28,
 0x28fac3f: 0x28fadde, 0x28fafbe: 0x28fac4b,
 0x28fac61: 0x28fb076, 0x28fad37: 0x28fad00,
 0x2806423: 0x28063e0, 0x1f699e6: 0x1f699a0,
}

def digest(data):
    return hashlib.sha256(data).hexdigest()


def va_bytes(data, secs, address, size):
    if address < 0 or size < 0:
        raise ValueError('negative range')
    found = [s for s in secs if s['type'] != 8 and s['size'] and
             s['address'] <= address and address + size <= s['address'] + s['size']]
    if len(found) != 1:
        raise ValueError('unmapped, ambiguous, or non-file-backed range')
    s = found[0]
    off = s['offset'] + address - s['address']
    if off + size > len(data):
        raise ValueError('range outside input')
    return data[off:off + size]


def rel_call(data, secs, site):
    insn = va_bytes(data, secs, site, 5)
    if insn[0] != 0xe8:
        raise ValueError('not rel32 call')
    return site + 5 + struct.unpack_from('<i', insn, 1)[0]


def rip_target(data, secs, site, prefix):
    expected = bytes.fromhex(prefix)
    insn = va_bytes(data, secs, site, len(expected) + 4)
    if not insn.startswith(expected):
        raise ValueError('unexpected RIP-relative instruction')
    return site + len(insn) + struct.unpack_from('<i', insn, len(expected))[0]


def indirect_slot(data, secs, site):
    insn = va_bytes(data, secs, site, 6)
    if insn[:2] != b'\xff\x15':
        raise ValueError('not RIP-relative indirect call')
    return site + 6 + struct.unpack_from('<i', insn, 2)[0]


def branch(data, secs, site):
    b = va_bytes(data, secs, site, 2)
    if 0x70 <= b[0] <= 0x7f:
        return site + 2 + struct.unpack('<b', b[1:])[0]
    if b[0] == 0x0f and 0x80 <= b[1] <= 0x8f:
        return site + 6 + struct.unpack('<i', va_bytes(data, secs, site + 2, 4))[0]
    raise ValueError('not a conditional branch')


def limb_step_model(limbs, base, digit):
    """Model only the selected four-word multiply/add step, not string parsing."""
    if len(limbs) != 4 or base not in (2, 8, 10, 16) or not 0 <= digit < base:
        raise ValueError('invalid synthetic limb step')
    if any(not 0 <= word < (1 << 64) for word in limbs):
        raise ValueError('invalid synthetic word')
    result = []
    carry = digit
    for word in limbs:
        product = word * base + carry
        result.append(product & ((1 << 64) - 1))
        carry = product >> 64
    if carry:
        raise OverflowError('synthetic 256-bit overflow')
    return tuple(result)


def collect(data, check_digest=True):
    if check_digest and digest(data) != DIGEST:
        raise ValueError('node 94 digest mismatch')
    secs, index = unwind_index(data)
    _, fdes = eh_frame_records(data, secs)
    indexed = {(x['start'], x['fde']) for x in index}
    chosen = [f for f in fdes if f['start'] in FUNCTIONS]
    if (len(chosen) != len(FUNCTIONS) or {f['start'] for f in chosen} != set(FUNCTIONS) or
            any((f['start'], f['fde']) not in indexed for f in chosen)):
        raise ValueError('selected FDE missing or not indexed')
    funcs = []
    for f in sorted(chosen, key=lambda x: x['start']):
        start, end = f['start'], f['end']
        if end <= start or not any(s['name'] == '.text' and s['type'] != 8 and
                                   s['address'] <= start < end <= s['address'] + s['size']
                                   for s in secs):
            raise ValueError('selected FDE outside text')
        body = va_bytes(data, secs, start, end - start)
        funcs.append({'role': FUNCTIONS[start], 'start': hex(start), 'end_exclusive': hex(end),
                      'fde': hex(f['fde']), 'bytes': len(body), 'sha256': digest(body)})
    windows = []
    for site, expected in sorted(PINS.items()):
        want = bytes.fromhex(expected)
        actual = va_bytes(data, secs, site, len(want))
        if actual != want:
            raise ValueError('selected instruction bytes changed at ' + hex(site))
        windows.append({'va': hex(site), 'bytes': actual.hex()})
    calls = []
    for site, want in sorted(CALLS.items()):
        target = rel_call(data, secs, site)
        if target != want:
            raise ValueError('call target changed')
        calls.append({'site': hex(site), 'target': hex(target)})
    branches = []
    for site, want in sorted(BRANCHES.items()):
        target = branch(data, secs, site)
        if target != want:
            raise ValueError('branch destination changed')
        branches.append({'site': hex(site), 'target': hex(target)})
    literals = {}
    for name, va, size, expected in [('hex_alphabet', 0x208620, 16, b'0123456789abcdef'),
                                      ('zero_item', 0x3f6ac3, 3, b'0x0'),
                                      ('zero_reader', 0x3ec542, 3, b'0x0'),
                                      ('quote', 0x3f601b, 1, b'"'),
                                      ('first_format', 0x1ef2ac, 5, bytes.fromhex('023078c000')),
                                      ('later_format', 0x20a608, 8, bytes.fromhex('c320000069020000')),
                                      ('nibble_mask', 0x2030c0, 16, b'\x0f'*16)]:
        raw = va_bytes(data, secs, va, size)
        if raw != expected:
            raise ValueError('literal changed: ' + name)
        literals[name] = {'va': hex(va), 'hex': raw.hex()}
    # Read each byte compare in the first-item high-to-low scan. The first
    # three branches are split by the entry blocks; offsets 28..1 use jne.
    scan_start, scan_end = 0x28fac00, 0x28fb0be
    body = va_bytes(data, secs, scan_start, scan_end - scan_start)
    compares = []
    for hit in re.finditer(rb'\x80[\x7a\x7f].\x00', body, re.S):
        site = scan_start + hit.start()
        disp = hit.group()[2]
        if not (1 <= disp <= 31):
            raise ValueError('unexpected byte scan displacement')
        row = {'site': hex(site), 'offset': disp}
        if disp <= 28:
            destination = branch(data, secs, site + 4)
            if destination != (0x28fac32 if disp % 2 == 0 else 0x28fac45):
                raise ValueError('byte scan branch changed')
            row['nonzero_target'] = hex(destination)
        compares.append(row)
    if [r['offset'] for r in compares] != list(range(31, 0, -1)):
        raise ValueError('byte scan coverage changed')
    if va_bytes(data, secs, 0x28fafba, 4) != bytes.fromhex('41803e00'):
        raise ValueError('byte scan zero-offset comparison changed')
    limb_bytes = va_bytes(data, secs, 0x28f7e30, len(bytes.fromhex(PINS[0x28f7e30])))
    multiply_count = limb_bytes.count(bytes.fromhex('49f7e0'))
    carry_count = sum(limb_bytes.count(bytes.fromhex(op)) for op in
                      ('4911cd', '4911f7', '4811fd', '4983d000'))
    if (multiply_count, carry_count) != (4, 4):
        raise ValueError('limb multiply and carry shape changed')
    limb_chain = {'window': '0x28f7e30', 'multiply_instructions': multiply_count,
                  'carry_instructions': carry_count}
    rip_records = []
    for site, (prefix, want) in sorted(RIPS.items()):
        target = rip_target(data, secs, site, prefix)
        if target != want:
            raise ValueError('RIP-relative target changed')
        rip_records.append({'site': hex(site), 'target': hex(target), 'prefix': prefix})
    # These are two bounded template layouts, not a general format parser.
    first = va_bytes(data, secs, 0x1ef2ac, 5)
    later = va_bytes(data, secs, 0x20a608, 8)
    first_template = {'literal': first[1:3].decode('ascii'), 'tag': first[3]}
    options, width = struct.unpack_from('<IH', later, 1)
    later_template = {'tag': later[0], 'options': hex(options), 'quantity': width}
    table = rip_target(data, secs, 0x2807f31, '488d35')
    bracket_target = table + struct.unpack('<i', va_bytes(data, secs, table, 4))[0]
    input_byte = (-struct.unpack('<b', va_bytes(data, secs, 0x2807ef7, 1))[0]) & 0xff
    if input_byte != 0x5b or bracket_target != 0x2807f42:
        raise ValueError('array dispatch target changed')
    outer_table = rip_target(data, secs, 0x262088f, '488d35')
    outer_input = (-struct.unpack('<b', va_bytes(data, secs, 0x2620884, 1))[0]) & 0xff
    outer_target = outer_table + struct.unpack('<i', va_bytes(data, secs, outer_table, 4))[0]
    if outer_input != 0x5b or outer_target != 0x26208a0:
        raise ValueError('outer array dispatch target changed')
    outer_dispatch = {'table': hex(outer_table), 'input_byte': outer_input,
                      'target': hex(outer_target)}
    slots = []
    for site in (0x280fe36, 0x2883a06):
        slot = indirect_slot(data, secs, site)
        if slot != 0x57705c0:
            raise ValueError('shared decoder slot changed')
        slots.append({'site': hex(site), 'slot': hex(slot)})
    # Synthetic illustration of the scalar nibble operations, not target output.
    sample = bytes(range(32))
    alphabet = bytes.fromhex(literals['hex_alphabet']['hex'])
    encoded = b'0x' + bytes(ch for n in sample for ch in (alphabet[n >> 4], alphabet[n & 15]))
    model = {'scope': 'synthetic scalar second-item model, not target execution',
             'input_hex': sample.hex(), 'text': encoded.decode('ascii'),
             'row_json_no_whitespace': json.dumps(['0x0', encoded.decode('ascii')], separators=(',', ':'))}
    limb_model = {'scope': 'synthetic four-word step, not target execution',
                  'base': 16, 'input_words_low_first': [hex(0), hex(0), hex(0), hex(0)],
                  'digit': 15, 'output_words_low_first': [hex(x) for x in limb_step_model((0, 0, 0, 0), 16, 15)]}
    return {'target_sha256': DIGEST, 'coordinate_system': 'linked ELF virtual address',
            'functions': funcs, 'windows': windows, 'calls': calls,
            'branches': branches, 'limb_model': limb_model, 'outer_array_dispatch': outer_dispatch, 'limb_chain': limb_chain, 'first_item_byte_scan': compares, 'rip_references': rip_records, 'format_descriptors': {'first': first_template, 'later': later_template}, 'array_dispatch': {'table': hex(table), 'input_byte': input_byte, 'target': hex(bracket_target)}, 'indirect_slots': slots, 'literals': literals, 'scalar_model': model,
            'limits': 'Selected static path only. No execution or complete input grammar.'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', required=True, type=Path)
    args = ap.parse_args()
    result = collect(BINARY.read_bytes())
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'records.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')

if __name__ == '__main__':
    main()
