#!/usr/bin/env python3
"""Authenticate node115 settled-outcome-history-text; static reads only, no capture execution."""
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
BODIES = {'spot_parent_context': (62902304, 62903104, 15006760, '9a944f329ed344b6d61c51b8321a3e3bd9bf131b4f7690327569ad14da06254c'), 'soh_field_context': (64140112, 64140313, 15046736, '62056b18a377761f1bd4c2d04ff391860395ae3f5c85ee8f2abc1e6fa5904a09'), 'history_object': (62930416, 62930781, 15008092, 'bf8d07f3ba7e0e4a81d4032a2f9d99f16cec95ac4af23dac496c82c8a7efe0d9'), 'sqpq_field': (64150640, 64150695, 15049788, '73692437df0aabba92576da2293047b08b047d8a5120e3ff4beee6f2f7a0542b'), 'sots_rows': (73779904, 73781657, 15660168, '3db81738bfb7867344ef851433e2ae6b31fe542f27acfed95faca49ff4ec4e7c'), 'sotq_rows': (73785792, 73787687, 15660660, '46aa17032de21d6d9b270ef593179c735b76484eca65dc2f6d58dddf4fb35f42'), 'sqts_rows': (73702272, 73704025, 15652944, 'a8a3c46985d55297ca4e2f45568c954d7e77b35fcbfb91a122712c56dcc3a6da'), 'sqp_ring': (73764000, 73764955, 15658744, '7741286a4b70c8d18a1fa5377766098cb0750070f90e9c44c9f68128ac9d28f5'), 'sqpq_ring': (73771488, 73772443, 15659144, 'e9d7aa18b08c4078b7108f50572d2cc766d05b6f12c1298fef39b3ce30aaa96a'), 'settled_outcome_record': (62927856, 62928534, 15007748, 'b64dbad033d61041dc0b58183a6b0a85f2eb4e2b7633f720879ea22e8908a43c'), 'settled_question_record': (62929936, 62930267, 15008008, '72e34b3dc9792de28091dc2ac0019b84be755ec642299740351b18e907aea6e3'), 'outcome_record': (62935216, 62935596, 15008468, 'fbc0609b95f20b05091c60420f20f8de6f61639c8c470a2fc5803d2d6d3b64e0'), 'outcome_side_pair': (73714896, 73715847, 15654188, '19781e55aff4bf213c42d31e5f2f9b55dd2ccf80f0b330b15b34c780417359b2'), 'outcome_side_record': (62935904, 62936477, 15008604, 'e5a0a6b7a6bfc8e61d6e302c1faf46628f03eb91ad42bd09a04f2b317b85fc7f'), 'text_field': (73807360, 73807682, 15662944, '7296a735262a3bae4dc698843852b2441854fce52ca99c58a0c5e4b31deb3658'), 'text_escape_context': (73861296, 73861848, 15668716, '9a9d0a4e143736aa30ced858efa91fd6132cccce21d0fc303438de886c1610c2'), 'fraction_field': (73678544, 73678934, 15650052, '065c922154bc8f5e8ca286d0476c2fae6209a29d9bc1c5db6392e584f05775a9'), 'optional_address_field': (73692336, 73692609, 15651600, '2c3b93ad96ecef24d1d1ea25ab92272265c2dcaa4df8afd745e47d0c24cd1fe2'), 'address_text': (65959312, 65959572, 15134864, '3aa11d0eee15201c0dbb639d356b284bd6bab82dc88dd3f620c9122347ab1fdf'), 'address_hex': (48937808, 48938206, 14282292, 'a4ade37e9aec972480063da782bee7d212fa6a8aeac7a864ef3c36e1439fadf7'), 'question_scalar': (73701184, 73701435, 15652728, 'd26cf255b56e616ba7c314eaf3003a1527ba2614769dca19e097c275340737cf'), 'side_token_scalar': (73689232, 73689483, 15651128, '6c09e9a505532a6038c7f210f6f182480118dbf6d37dfbed2ffe7c66d90ea079'), 'question_outcome_set': (73681024, 73682337, 15650252, '2d828c5eef922145ae15c92afc07f254abc0fa72c006a38af0118c98226fd2e4'), 'set_cursor_context': (58477216, 58477687, 18955292, '9d65292540df2dbb9bd3a64071152bcc6f96d83651128ad6aaa82b3815660ea1'), 'queue_scalar': (64305472, 64305949, 15068052, 'f768296a748734b86a562c6927b5492ea632951467725567a0af44f78c4417a7'), 'unsigned_decimal': (64055760, 64056082, 15041148, 'dbcb1440fd4c9b790211f185271d81530a2d4cfba52626f6c65fdddc1f52d85f'), 'token_decimal': (70261072, 70261394, 15299888, '801c4041952c94a657cb11120db48b53cafb6d94c19b6fb0c5a3b7f8758bdf6d'), 'field_format_context': (74529696, 74530216, 15702020, '21eced419eea01ef21f3c2c60955afdce4e54305595e6ec3af6b99b35a04a953'), 'object_end_context': (64150912, 64151242, 15049864, '88268c9099513dad87822d260f379b360c089f4354e5d043c852c269393e586e')}
SLOTS = {105777928: 96815104, 105462480: 4496083, 105772848: 23596640, 105351136: 4496083, 105772320: 23600544, 105461904: 4496083, 105773128: 23600704, 105461856: 4496083, 105462552: 4496083, 105351112: 4496083, 105780184: 9727436, 105780192: 9727692, 105780176: 97576128, 105794824: 48937808, 105253656: 4451363, 105772400: 23599072, 105253584: 4451363, 105253680: 4451363, 105772576: 23596223, 105253704: 4451363, 105253608: 4451363, 105253632: 4451363, 105311192: 4434262, 105773104: 23596048, 105294432: 4434262, 105356688: 4496083, 105349496: 4451140, 105398656: 4451140, 105462456: 4496083}
SUPPORT = {}
LITERALS = {'source_0x449ad3': (4496083, b'/home/ubuntu/hl/code_Mainnet/z_vendor/serde_json/src/ser.rs'), 'location_0x6493ad0': (105462488, b';\x00\x00\x00\x00\x00\x00\x00\x98\x02\x00\x00*\x00\x00\x00'), 'location_0x64787e0': (105351144, b';\x00\x00\x00\x00\x00\x00\x00\xe6\x07\x00\x00\t\x00\x00\x00'), 'location_0x6493890': (105461912, b';\x00\x00\x00\x00\x00\x00\x00\xc5\x07\x00\x00\t\x00\x00\x00'), 'location_0x6493860': (105461864, b';\x00\x00\x00\x00\x00\x00\x00\xbb\x07\x00\x00\t\x00\x00\x00'), 'location_0x6493b18': (105462560, b';\x00\x00\x00\x00\x00\x00\x00\x0c\x02\x00\x00*\x00\x00\x00'), 'location_0x64787c8': (105351120, b';\x00\x00\x00\x00\x00\x00\x00\xf0\x07\x00\x00\t\x00\x00\x00'), 'source_0x43ec23': (4451363, b'/home/ubuntu/hl/code_Mainnet/z_vendor/impl-serde/src/serialize.rs'), 'location_0x6460b18': (105253664, b'A\x00\x00\x00\x00\x00\x00\x00>\x00\x00\x00/\x00\x00\x00'), 'location_0x6460ad0': (105253592, b'A\x00\x00\x00\x00\x00\x00\x00)\x00\x00\x00\x05\x00\x00\x00'), 'location_0x6460b30': (105253688, b'A\x00\x00\x00\x00\x00\x00\x008\x00\x00\x00\t\x00\x00\x00'), 'location_0x6460b48': (105253712, b'A\x00\x00\x00\x00\x00\x00\x009\x00\x00\x00\t\x00\x00\x00'), 'location_0x6460ae8': (105253616, b'A\x00\x00\x00\x00\x00\x00\x00/\x00\x00\x00\x18\x00\x00\x00'), 'location_0x6460b00': (105253640, b'A\x00\x00\x00\x00\x00\x00\x004\x00\x00\x00\x05\x00\x00\x00'), 'source_0x43a956': (4434262, b'/rustc/59807616e1fa2540724bfbac14d7976d7e4a3860/library/alloc/src/collections/btree/navigate.rs'), 'location_0x646ebd8': (105311200, b'_\x00\x00\x00\x00\x00\x00\x00\x16\x02\x00\x00/\x00\x00\x00'), 'location_0x646aa60': (105294440, b'_\x00\x00\x00\x00\x00\x00\x00\xa1\x00\x00\x00$\x00\x00\x00'), 'location_0x6479d90': (105356696, b';\x00\x00\x00\x00\x00\x00\x00\xfe\x01\x00\x00*\x00\x00\x00'), 'source_0x43eb44': (4451140, b'/home/ubuntu/hl/code_Mainnet/z_vendor/itoa/src/lib.rs'), 'location_0x6478178': (105349504, b'5\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x00\x00\x01\x00\x00\x00'), 'location_0x6484180': (105398664, b'5\x00\x00\x00\x00\x00\x00\x00\xe0\x00\x00\x00\x01\x00\x00\x00'), 'location_0x6493ab8': (105462464, b';\x00\x00\x00\x00\x00\x00\x00\x81\x02\x00\x00*\x00\x00\x00'), 'history_type': (8104891, b'struct SettledOutcomeHistory'), 'sots': (4562776, b'sots'), 'sotq': (4563264, b'sotq'), 'sqts': (4562688, b'sqts'), 'sqp': (8106445, b'sqp'), 'sqpq': (4563188, b'sqpq'), 'soh': (8104607, b'soh'), 'hex_alphabet': (4545856, b'0123456789abcdef'), 'decimal_pairs': (8111224, b'00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899'), 'token_decimal_pairs': (8164901, b'00010203040506070809101112131415161718192021222324252627282930313233343536373839404142434445464748495051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899'), 'literal_context_0x7b9caf': (8101039, b'user_statesreferrer_statesreferral_bucket_millistotal_fees_collectedtotal_spot_f'), 'literal_context_0x7ba9f7': (8104439, b'daily_exchange_scaled_and_raw_vlmstoken_to_max_supplytoken_fees_collectednative_'), 'literal_context_0x7baa19': (8104473, b'token_to_max_supplytoken_fees_collectednative_tokenspot_dusting_opted_out_userse'), 'literal_context_0x7baa2c': (8104492, b'token_fees_collectednative_tokenspot_dusting_opted_out_usersevm_transfer_escrows'), 'literal_context_0x7baa4c': (8104524, b'spot_dusting_opted_out_usersevm_transfer_escrowseectoken_to_pending_evm_contract'), 'literal_context_0x7baa7c': (8104572, b'eectoken_to_pending_evm_contractpmrsohstruct ScalarUpdatesenum OutcomeSubDeploye'), 'literal_context_0x7db8e6': (8239334, b'internal error: entered unreachable codea Display implementation returned an err'), 'literal_context_0x7baa9f': (8104607, b'sohstruct ScalarUpdatesenum OutcomeSubDeployerActionVariantstruct TopUpStrictIso'), 'literal_context_0x459f58': (4562776, b'sotsusdcjsoncurrTpslNoopInitpollTimedatedvpdznfnfullread\\011\\012sendbasehttpuser'), 'literal_context_0x45a140': (4563264, b'sotqtypeMain is Uid:LivedatacboeBin8Ext8NOEXstat (0xslowUtf8oberAsn1pmdlIpv6Done'), 'literal_context_0x7b9b9a': (8100762, b'ooidfield index 0 <= i < 2limitPxporderTypecloidEnabledvariant index 0 <= i < 2s'), 'literal_context_0x7b9d7f': (8101247, b'forderfield index 0 <= i < 3utamousgdsogtdetceipmcsrevpvacienum DelayedActionBro'), 'literal_context_0x7b9af9': (8100601, b'ddescriptiondisplay_namenkstruct ExtraAgentstruct FeeTrackeraassetbisBuysszrredu'), 'literal_context_0x7bad69': (8105321, b'DSinternal error: entered unreachable codedelayed_actionsuser_to_n_delayed_actio'), 'literal_context_0x7ba759': (8103769, b'uunifiedAccountportfolioMarginvariant index 0 <= i < 5tuple struct PortfolioMarg'), 'literal_context_0x7b9b41': (8100673, b'sszrreduceOnlymminutesrandomizettestrsteaerciewotshstruct AgentTrackerstruct Use'), 'literal_context_0x7b9b11': (8100625, b'nkstruct ExtraAgentstruct FeeTrackeraassetbisBuysszrreduceOnlymminutesrandomizet'), 'literal_context_0x7b9b60': (8100704, b'ttestrsteaerciewotshstruct AgentTrackerstruct UserFeeStateooidfield index 0 <= i'), 'literal_context_0x7c1933': (8132915, b'0x0x0internal error: entered unreachable codedescriptioncreate_timevault_userlea'), 'literal_context_0x6408a6': (6555814, b'assertion failed: v.len() > 1 + bytes.len() * 20x prefix is missingthere should '), 'literal_context_0x7bd562': (8115554, b'internal error: entered unreachable codecalled `Result::unwrap()` on an `Err` va'), 'literal_context_0x7bc478': (8111224, b'00010203040506070809101112131415161718192021222324252627282930313233343536373839'), 'literal_context_0x7c9625': (8164901, b'00010203040506070809101112131415161718192021222324252627282930313233343536373839')}
IMPORTS = {105772296: (7, 'memcpy')}
INCOMING = {'spot_parent_context': [], 'soh_field_context': [], 'history_object': [], 'sqpq_field': [], 'sots_rows': [], 'sotq_rows': [], 'sqts_rows': [], 'sqp_ring': [], 'sqpq_ring': [], 'settled_outcome_record': [], 'settled_question_record': [], 'outcome_record': [], 'outcome_side_pair': [], 'outcome_side_record': [], 'text_field': [], 'text_escape_context': [], 'fraction_field': [], 'optional_address_field': [], 'address_text': [], 'address_hex': [105794824], 'question_scalar': [], 'side_token_scalar': [], 'question_outcome_set': [], 'set_cursor_context': [], 'queue_scalar': [], 'unsigned_decimal': [], 'token_decimal': [], 'field_format_context': [], 'object_end_context': []}
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
            row['scope'] = 'The settled-history text object emits five ordered fields: three dense row collections as arrays of key/value pairs and two logical ring queues. Its settled outcome and question values have explicit nested schemas. Empty containers remain present; floats map nonfinite values to null, and optional20-byte addresses map absence to null or presence to full lowercase hex. Static successful-output shape only: no reader/default claims, transition/payout policy, exact float spelling, set insertion invariants, allocator failure semantics or captured target execution.'
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
