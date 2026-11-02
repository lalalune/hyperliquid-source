#!/usr/bin/env python3
"""Node94 chain/command construction: static bytes, not instruction execution."""
import argparse
import bisect
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_GRP_JUMP
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

from elf_index import sections
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/node/94/hl-node'
PACKET = ROOT / 'research/work-items/RE-012-chain-cli-94'
SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
RANGES = {
    'caller_context': (0x21dfc30, 0x21dfd8c),
    'chain': (0x4578bd0, 0x4578e2a),
    'commands': (0x4583030, 0x4583f52),
    'presence_lookup_context': (0x452f440, 0x452f591),
    'value_lookup_context': (0x452f5a0, 0x452f736),
    'bool_adapter': (0x4583f60, 0x4583fb6),
    'owned_string_adapter': (0x4583fc0, 0x4584030),
    'amount_adapter': (0x4584030, 0x4584136),
    'node_ip_adapter': (0x4584140, 0x4584172),
    'signer_adapter': (0x4584180, 0x45841f7),
    'commission_adapter': (0x4584200, 0x4584306),
}
PRIMARY = ('chain', 'commands')
TABLE = 0x6f5dcc
MISS = 0x4583580
# Each chunk is (input offset, bytes read, storage kind, constant address).
# Short SIMD tails compare zero-extended loads with a full 16-byte constant;
# their zero padding is separately authenticated below.
NAMES = (
    ('delegate', 0x4583069, 0x458307c, [(0, 8, 'immediate', 0x458306b)], [6]),
    ('staking-deposit', 0x458310f, 0x4583133, [(0, 8, 'immediate', 0x4583111), (7, 8, 'immediate', 0x458311e)], [7]),
    ('send-signed-action', 0x4583178, 0x458359c, [(0, 16, 'data', 0x207190), (16, 2, 'simd_tail', 0x2042a0)], [5]),
    ('staking-withdrawal', 0x45831a8, 0x45836af, [(0, 16, 'data', 0x204080), (16, 2, 'simd_tail', 0x204090)], [8]),
    ('check-reachability', 0x45831d8, 0x4583207, [(0, 16, 'data', 0x2078a0), (16, 2, 'simd_tail', 0x2043a0)], [11]),
    ('run-validator', 0x4583246, 0x45835f4, [(0, 8, 'immediate', 0x4583248), (5, 8, 'immediate', 0x4583255)], [3]),
    ('print-address', 0x458326a, 0x458328e, [(0, 8, 'immediate', 0x458326c), (5, 8, 'immediate', 0x4583279)], [9]),
    ('translate-abci-state', 0x45832a5, 0x4583613, [(0, 16, 'data', 0x206020), (16, 4, 'simd_tail', 0x206690)], [4]),
    ('compute-l4-snapshots', 0x45832d2, 0x45832fe, [(0, 16, 'data', 0x208ae0), (16, 4, 'simd_tail', 0x208e40)], [13]),
    ('compute-referrer-states', 0x45833cf, 0x45833fb, [(0, 16, 'data', 0x2062d0), (7, 16, 'data', 0x206010)], [12]),
    ('send-slack-alert', 0x458345a, 0x4583475, [(0, 16, 'data', 0x205c50)], [10]),
    ('run-non-validator', 0x45834d1, 0x4583500, [(0, 16, 'data', 0x206d90), (16, 1, 'simd_tail', 0x2065b0)], [2]),
    ('approve-non-expiring-agent', 0x458351c, 0x4583544, [(0, 16, 'data', 0x206000), (10, 16, 'data', 0x204d10)], [15]),
    ('change-validator-profile', 0x4583554, 0x458366e, [(0, 16, 'data', 0x203350), (16, 8, 'simd_tail', 0x206d80)], [0, 1]),
)
TAG_WRITES = {
    'delegate': 0x4583ad4, 'staking-deposit': 0x45838a8,
    'send-signed-action': 0x45838cd, 'staking-withdrawal': 0x45836e1,
    'check-reachability': 0x458323a, 'run-validator': 0x4583607,
    'print-address': 0x4583299, 'translate-abci-state': 0x4583ca6,
    'compute-l4-snapshots': 0x45833bc, 'compute-referrer-states': 0x4583ceb,
    'send-slack-alert': 0x45839ec, 'run-non-validator': 0x4583513,
    'approve-non-expiring-agent': 0x458354b,
}
OPTION_TEXTS = (
    'chain', 'key', 'validator', 'wei', 'wei', 'abci-state-fln',
    'abci-state-fln', 'out-fln', 'include-users', 'include-trigger-orders',
    'abci-state-fln', 'msg', 'action', 'in-fln', 'abci-state-fln', 'wei',
    'out-fln', 'out-fln', 'node-ip', 'name', 'undelegate', 'description',
    'unjailed', 'disable-delegations', 'commission-bps', 'signer',
)
CHAIN_NAMES = ((0x26512f, 'Local', 0), (0x265134, 'Sandbox', 1),
               (0x26513b, 'Testnet', 2), (0x265142, 'Mainnet', 3))
BOUND_CALLS = {0x21dfd2f: (0x5773918, 0x4578bd0),
               0x4578d4b: (0x5776a78, 0x4583030),
               0x4583601: (0x5776a80, 0x4579310),
               0x458350d: (0x5776a80, 0x4579310)}
# Selected semantic guards complement the complete-body identity. Each is
# independently meaningful when structural checks are exercised below SHA.
ANCHORS = {
    'name_length_unsigned_guard': (0x4583044, '488b4e084883c1f84883f9120f872a050000'),
    'unmatched_tag': (0x4583580, '48c70310000000'),
    'profile_commission_presence': (0x4583b90, '4885c074154889c74889d6e8600600004989c5bd01000000eb0231ed'),
    'profile_first_word_is_presence': (0x4583c42, '48892b4c896b08'),
    'chain_missing': (0x4578bfb, '4885c00f84d3010000'),
    'chain_width_guard': (0x4578c04, '4883fa0774234883fa05755f'),
    'chain_local_tag': (0x4578c29, '31edeb6f'),
    'chain_sandbox_tag': (0x4578c94, '40b501eb03'),
    'chain_testnet_tag': (0x4578c99, '40b502'),
    'chain_mainnet_tag': (0x4578c68, '40b50309c8742d'),
    'chain_key_absent_sentinel': (0x4578cc8, '49bf0000000000000080'),
    'chain_no_child': (0x4578d29, '31c0ba0100000031c9'),
    'chain_rejects_command_tag16': (0x4578d51, '837c2420100f8488000000'),
    'chain_output_tail': (0x4578da9, '4088ab900000004c897b784c89a3800000004c89bb880000004889d8'),
    'caller_output_copy_152': (0x21dfd3d, '488db424a0020000ba980000004889dfff158de25803'),
    'caller_parser_error_tag': (0x21dfcae, '48b8010000000000008048390424752d'),
    'caller_error_first_word_16': (0x21dfce2, '48c70310000000eb68'),
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def unique(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs), 'duplicate JSON key')
    return result


class Image:
    def __init__(self, data):
        self.data = bytes(data)
        self.sections = sections(self.data)
        self.by_name = {s['name']: s for s in self.sections}
        require(len(self.by_name) == len(self.sections), 'duplicate section name')
        require(struct.unpack_from('<H', self.data, 18)[0] == 62, 'not x86-64')
        self.cies, self.fdes = eh_frame_records(self.data, self.sections)
        self.fdes.sort(key=lambda f: f['start'])
        self.starts = [f['start'] for f in self.fdes]
        require(len(set(self.starts)) == len(self.starts), 'duplicate FDE start')
        self.relocations = {}
        for sec in self.sections:
            if sec['type'] != 4:
                continue
            require(sec['size'] % 24 == 0, 'partial RELA')
            for off in range(sec['offset'], sec['offset'] + sec['size'], 24):
                dst, info, addend = struct.unpack_from('<QQq', self.data, off)
                require(dst not in self.relocations, 'duplicate relocation destination')
                self.relocations[dst] = dict(slot=hex(dst), kind=info & 0xffffffff,
                    symbol_index=info >> 32, addend=addend, file_offset=hex(off),
                    record_hex=self.data[off:off + 24].hex())
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True

    def offset(self, va, length):
        require(type(length) is int and length > 0, 'nonpositive read')
        hits = [s['offset'] + va - s['address'] for s in self.sections
                if s['type'] != 8 and s['address'] <= va and va + length <= s['address'] + s['size']]
        require(len(hits) == 1, f'unmapped/ambiguous read {va:#x}+{length}')
        return hits[0]

    def read(self, va, length):
        off = self.offset(va, length)
        return self.data[off:off + length]

    def owner(self, va):
        index = bisect.bisect_right(self.starts, va) - 1
        if index >= 0 and va < self.fdes[index]['end']:
            return self.fdes[index]
        return None

    def decode(self, start, end):
        raw = self.read(start, end - start)
        decoded = list(self.md.disasm(raw, start))
        require(decoded and sum(i.size for i in decoded) == len(raw), 'incomplete decode')
        starts = {i.address for i in decoded}
        for ins in decoded:
            if ins.group(CS_GRP_JUMP) and ins.operands[0].type == X86_OP_IMM:
                target = ins.operands[0].imm
                require(not start <= target < end or target in starts, 'branch inside instruction')
        return decoded

    def binding(self, slot):
        row = self.relocations.get(slot)
        if row is None:
            return None
        row = dict(row)
        if row['symbol_index']:
            sym = self.by_name['.dynsym']
            index = row['symbol_index']
            require(index * 24 + 24 <= sym['size'], 'dynsym out of bounds')
            name = struct.unpack_from('<I', self.data, sym['offset'] + index * 24)[0]
            strings = self.by_name['.dynstr']
            require(name < strings['size'], 'dynstr out of bounds')
            off = strings['offset'] + name
            end = self.data.find(b'\0', off, strings['offset'] + strings['size'])
            require(end >= 0, 'unterminated dynsym name')
            row['symbol'] = self.data[off:end].decode('ascii')
        elif row['kind'] == 8:
            row['target'] = hex(row['addend'])
            owner = self.owner(row['addend'])
            if owner:
                row['target_fde'] = [hex(owner['start']), hex(owner['end'])]
        return row


def instruction(ins):
    return {'va': hex(ins.address), 'bytes': bytes(ins.bytes).hex(),
            'mnemonic': ins.mnemonic, 'operands': ins.op_str}


def extract(image):
    """Structural analysis beneath input admission, exposed for byte corruption tests."""
    bodies, decoded = [], {}
    for name, (start, end) in RANGES.items():
        owner = image.owner(start)
        require(owner and (owner['start'], owner['end']) == (start, end), 'FDE extent changed')
        ins = image.decode(start, end)
        decoded[name] = ins
        fde_raw_size = struct.unpack('<I', image.read(owner['fde'], 4))[0] + 4
        cie_raw_size = struct.unpack('<I', image.read(owner['cie'], 4))[0] + 4
        bodies.append({'name': name, 'role': 'primary' if name in PRIMARY else 'supporting context',
            'start': hex(start), 'end_exclusive': hex(end), 'bytes': end - start,
            'sha256': digest(image.read(start, end - start)), 'instructions': len(ins),
            'fde_va': hex(owner['fde']), 'fde_hex': image.read(owner['fde'], fde_raw_size).hex(),
            'cie_va': hex(owner['cie']), 'cie_hex': image.read(owner['cie'], cie_raw_size).hex(),
            'lsda': hex(owner['lsda']) if owner['lsda'] else None})
    sites = {i.address: i for name in PRIMARY for i in decoded[name]}
    anchors = []
    for label, (va, expected) in ANCHORS.items():
        raw = bytes.fromhex(expected)
        require(image.read(va, len(raw)) == raw, 'semantic anchor changed: ' + label)
        anchors.append({'label': label, 'va': hex(va), 'hex': raw.hex()})
    table_raw = image.read(TABLE, 19 * 4)
    table = [TABLE + v for v in struct.unpack('<19i', table_raw)]
    require(all(v in sites for v in table), 'jump table target is not an instruction')
    expected_table = [0x4583069, MISS, MISS, MISS, MISS, 0x4583246, MISS, 0x458310f,
        0x458345a, 0x45834d1, 0x4583178, MISS, 0x45832a5, MISS, MISS,
        0x45833cf, 0x4583554, MISS, 0x458351c]
    require(table == expected_table, 'length dispatch table changed')
    names = []
    for name, compare_start, matched, chunks, tags in NAMES:
        value = [None] * len(name)
        reads = []
        for position, width, kind, va in chunks:
            raw = image.read(va, 16 if kind == 'simd_tail' else width)
            if kind == 'simd_tail':
                require(raw[width:] == bytes(16 - width), 'SIMD tail zero extension changed')
            require(position + width <= len(value), 'comparison exceeds name')
            for k, byte in enumerate(raw[:width], position):
                require(value[k] in (None, byte), 'overlapping name chunks disagree')
                value[k] = byte
            reads.append({'input_offset': position, 'input_bytes': width, 'kind': kind,
                          'constant_va': hex(va), 'constant_hex': raw.hex()})
        require(all(x is not None for x in value), 'comparison leaves name bytes uncovered')
        observed = bytes(value).decode('ascii')
        require(observed == name, 'command spelling changed')
        require(compare_start in sites and matched in sites, 'name path boundary changed')
        if name in TAG_WRITES:
            tag_va = TAG_WRITES[name]
            raw = image.read(tag_va, 7)
            require(raw[:3] == bytes.fromhex('48c703'), 'first-word store encoding changed')
            actual_tags = [struct.unpack_from('<I', raw, 3)[0]]
            require(actual_tags == tags, 'command first word changed')
        else:
            tag_va = 0x4583c42
            actual_tags = [0, struct.unpack('<I', image.read(0x4583ba4, 4))[0]]
            require(actual_tags == tags, 'profile presence word changed')
        names.append({'name': observed, 'length': len(value), 'comparison_start': hex(compare_start),
            'matched_successor': hex(matched), 'normal_first_qword_values': tags,
            'first_word_store': hex(tag_va),
            'comparison_chunks': reads})
    chain_names = []
    for va, text, value in CHAIN_NAMES:
        raw = image.read(va, len(text))
        require(raw == text.encode(), 'chain spelling changed')
        chain_names.append({'text': text, 'va': hex(va), 'hex': raw.hex(),
                            'length': len(text), 'stored_byte': value})
    require(image.read(0x6f6141, 7) == b'hl-node', 'caller program name changed')
    calls, rip, locations, options, stores = [], [], [], [], []
    for name, insns in decoded.items():
        for index, ins in enumerate(insns):
            if ins.mnemonic in ('call', 'jmp'):
                row = {'owner': name, **instruction(ins)}
                op = ins.operands[0]
                if op.type == X86_OP_IMM:
                    row['direct_target'] = hex(op.imm)
                    owner = image.owner(op.imm)
                    if owner:
                        row['target_fde'] = [hex(owner['start']), hex(owner['end'])]
                elif op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    slot = ins.address + ins.size + op.mem.disp
                    row['slot'] = hex(slot)
                    row['binding'] = image.binding(slot)
                else:
                    row['resolution'] = 'runtime indirect target, not resolved'
                calls.append(row)
            for op in ins.operands:
                if op.type != X86_OP_MEM or op.mem.base != X86_REG_RIP:
                    continue
                va = ins.address + ins.size + op.mem.disp
                row = {'owner': name, 'instruction': hex(ins.address), 'referent': hex(va),
                       'width': op.size, 'binding': image.binding(va)}
                row['bytes_at_referent'] = image.read(va, max(1, op.size)).hex()
                rip.append(row)
                rel = image.binding(va)
                if ins.mnemonic == 'lea' and rel and rel['kind'] == 8:
                    raw = image.read(va + 8, 16)
                    length, line, col = struct.unpack('<QII', raw)
                    if 0 < length < 300 and 0 < line < 10000 and 0 < col < 10000:
                        try:
                            path = image.read(rel['addend'], length).decode('ascii')
                        except (ValueError, UnicodeDecodeError):
                            continue
                        if path.endswith('.rs'):
                            locations.append({'site': hex(ins.address), 'record': hex(va),
                                'path': path, 'path_va': hex(rel['addend']), 'length': length,
                                'line': line, 'column': col, 'record_hex': image.read(va, 24).hex(),
                                'binding': rel})
            if name in PRIMARY and ins.mnemonic == 'lea' and ins.op_str.startswith('rsi, [rip'):
                if index + 1 < len(insns):
                    following = insns[index + 1]
                    if following.mnemonic == 'mov' and following.op_str.startswith('edx, ') and following.operands[1].type == X86_OP_IMM:
                        length = following.operands[1].imm
                        va = ins.address + ins.size + ins.operands[1].mem.disp
                        if 0 < length < 100:
                            literal = image.read(va, length)
                            options.append({'owner': name, 'site': hex(ins.address), 'length_site': hex(following.address),
                                'literal_va': hex(va), 'length': length, 'bytes': literal.hex(),
                                'text': literal.decode('ascii'), 'following_instructions': [instruction(x) for x in insns[index:index + 5]]})
            if name in PRIMARY and ins.operands and ins.operands[0].type == X86_OP_MEM:
                mem = ins.operands[0].mem
                if ins.reg_name(mem.base) == 'rbx' and ins.mnemonic.startswith(('mov', 'stos')):
                    stores.append({'owner': name, **instruction(ins), 'offset': mem.disp, 'width': ins.operands[0].size})
    bindings = [image.binding(slot) for slot in image.relocations
                if image.relocations[slot]['kind'] == 8 and image.relocations[slot]['addend'] in (RANGES['chain'][0], RANGES['commands'][0])]
    require({(int(x['slot'], 16), x['addend']) for x in bindings} ==
            {(0x5773918, 0x4578bd0), (0x5776a78, 0x4583030)}, 'entry naming relocations changed')
    require(tuple(x['text'] for x in options) == OPTION_TEXTS, 'option spelling/order changed')
    for site, (slot, target) in BOUND_CALLS.items():
        rows = [x for x in calls if x['va'] == hex(site) and x['mnemonic'] == 'call']
        require(len(rows) == 1 and rows[0].get('slot') == hex(slot)
                and rows[0].get('binding', {}).get('kind') == 8
                and rows[0]['binding']['addend'] == target, 'bound call edge changed')
    return {'target_sha256': SHA256, 'coordinate_system': 'linked ELF virtual addresses',
        'captured_binary_executed': False, 'emulator_used': False,
        'primary_bytes': sum(b['bytes'] for b in bodies if b['role'] == 'primary'),
        'semantic_anchors': anchors, 'chain_values': chain_names,
        'caller_program_literal': {'va': '0x6f6141', 'hex': image.read(0x6f6141, 7).hex()},
        'bodies': bodies, 'length_dispatch': {'table_va': hex(TABLE), 'raw_hex': table_raw.hex(),
            'minimum': 8, 'maximum': 26, 'entries': [{'length': n + 8, 'target': hex(v)} for n, v in enumerate(table)],
            'miss_target': hex(MISS)}, 'commands': names,
        'options': options, 'output_stores': stores, 'calls_and_jumps': calls,
        'rip_references': rip, 'source_locations': locations, 'entry_relocations': bindings,
        'relocations_scanned': len(image.relocations),
        'instructions': {name: [instruction(i) for i in insns] for name, insns in decoded.items()}}


def analyze(data):
    require(len(data) == 91774280 and digest(data) == SHA256, 'node94 identity mismatch')
    return extract(Image(data))


def native_bytes(text, start, end):
    """Only collect actual disassembler instruction byte columns; no text emulation."""
    rows = []
    for line in text.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}(?:\s+|$))+)', line)
        if m and start <= int(m[1], 16) < end:
            raw = bytes.fromhex(m[2])
            rows.append((int(m[1], 16), raw))
    cursor = start
    for va, raw in rows:
        require(va == cursor and raw, 'native disassembly gap/overlap')
        cursor += len(raw)
    require(cursor == end, 'native disassembly incomplete')
    return rows


def export(binary, output):
    data = Path(binary).read_bytes()
    report = analyze(data)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    gnu = os.environ.get('GNU_OBJDUMP', 'objdump')
    llvm = os.environ.get('LLVM_OBJDUMP', 'llvm-objdump')
    exports, commands = {}, []
    # Both providers consume exactly the already authenticated byte snapshot.
    with tempfile.TemporaryDirectory() as directory:
        snapshot = Path(directory) / 'node94'
        snapshot.write_bytes(data)
        for label, exe in [('gnu', gnu), ('llvm', llvm)]:
            for name, (start, end) in RANGES.items():
                args = [exe, '-d', '--start-address=' + hex(start), '--stop-address=' + hex(end)]
                args += ['-M', 'intel', '--insn-width=16'] if label == 'gnu' else ['--x86-asm-syntax=intel']
                args.append(str(snapshot))
                process = subprocess.run(args, capture_output=True)
                stdout = process.stdout.replace(str(snapshot).encode(), b'<authenticated-node94>')
                stderr = process.stderr.replace(str(snapshot).encode(), b'<authenticated-node94>')
                require(process.returncode == 0, f'{label} export failed: {stderr.decode(errors="replace")}')
                rows = native_bytes(stdout.decode(), start, end)
                expected = [(int(i['va'], 16), bytes.fromhex(i['bytes'])) for i in report['instructions'][name]]
                require(rows == expected, f'{label} instruction boundaries/bytes disagree')
                exports[f'{name}.{label}.txt'] = stdout
                commands.append({'provider': label, 'name': name,
                    'argv': [str(x).replace(str(snapshot), '<authenticated-node94>') for x in args],
                    'exit_code': process.returncode, 'stdout_sha256': digest(stdout),
                    'stderr_hex': stderr.hex(), 'instruction_rows': len(rows)})
    for name, value in exports.items():
        (output / name).write_bytes(value)
    (output / 'records.json').write_text(json.dumps(report, indent=2) + '\n')
    (output / 'native-commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    report = export(args.binary, args.output) if args.output else analyze(args.binary.read_bytes())
    if args.check:
        expected = json.loads((PACKET / 'records.json').read_text(), object_pairs_hook=unique)
        require(report == expected, 'committed static evidence differs')
    print(json.dumps({'primary_bytes': report['primary_bytes'], 'bodies': len(report['bodies']),
        'commands': len(report['commands']), 'options': len(report['options']),
        'captured_binary_executed': False}, sort_keys=True))


if __name__ == '__main__':
    main()
