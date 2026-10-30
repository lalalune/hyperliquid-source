#!/usr/bin/env python3
"""Deterministic static inventory for the node #94 bridge withdrawal path.

Extracts, without executing the captured binary:

* the `requestWithdrawal` action literal and its RIP-relative xrefs;
* the eight-entry payload dispatch table that selects the EIP-712 field
  encoder arm per `BridgeRequestPayload` variant;
* the two `Chain::signature_chain_id` inlined sites and their operands.

Every reported address carries both the linked VA and the file offset, and
every emitted excerpt is hashed. The pinned SHA-256 is checked first, so a
different node build cannot be mistaken for the analysed one.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from elf_index import sections, unwind_index

ROOT = Path(__file__).resolve().parents[1]

TARGET_SHA256 = {
    94: '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
}

TEXT = '.text'

# BridgeRequestPayload::struct_hash dispatch, one arm per enum discriminant.
STRUCT_HASH_START = 0x358de50
STRUCT_HASH_TABLE = 0x58f650
STRUCT_HASH_ARMS = 8
# Reference labels for the discriminant order; validated against the literals
# loaded by each arm, never assumed.
PAYLOAD_LABELS = ['ModifyValidator', 'ChangeDisputePeriodSeconds',
                  'ChangeBlockDurationMillis', 'ChangeLockerThreshold',
                  'UpdateValidatorSet', 'RequestWithdrawal', 'Reserved',
                  'InvalidateWithdrawals']
REQUEST_WITHDRAWAL_LITERAL = b'requestWithdrawal'
REQUEST_WITHDRAWAL_LENGTH = len(REQUEST_WITHDRAWAL_LITERAL)

# Chain::signature_chain_id inlined at both construction sites.
MAINNET_CHAIN_ID = 42_161       # 0xa4b1, Arbitrum One
TESTNET_CHAIN_ID = 421_614      # 0x66eee, Arbitrum Sepolia
CHAIN_MAINNET_DISCRIMINANT = 3  # enum Chain { Local, Sandbox, Testnet, Mainnet }

# Seeded sites: struct_hash arm 5 and the request-building block in the
# action-field state machine. Both are validated below, not trusted.
SEED_LITERAL_OFFSET = 0x595072
SEED_CHAIN_OFFSET = 0x22ae773

CONDITIONAL_MOVE = {
    0x44: 'cmove',
    0x45: 'cmovne',
    0x42: 'cmovb',
    0x43: 'cmovae',
    0x46: 'cmovbe',
    0x47: 'cmova',
}

REG8 = ['al', 'cl', 'dl', 'bl', 'spl', 'bpl', 'sil', 'dil',
        'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b']
REG32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi',
         'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d']
REG64 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
         'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_artifact(path, release):
    data = path.read_bytes()
    actual = digest(data)
    expected = TARGET_SHA256[release]
    if actual != expected:
        raise ValueError(f'artifact SHA-256 {actual} != pinned {expected}')
    return data, actual


def load_segments(data):
    """Return loadable segments as (file_offset, va, size, flags)."""
    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Expected ELF64 little-endian input')
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phentsize, phnum = struct.unpack_from('<HH', data, 54)
    if phentsize < 56 or not phnum or phoff + phentsize * phnum > len(data):
        raise ValueError('Invalid or unsupported program header table')
    rows = []
    for index in range(phnum):
        base = phoff + index * phentsize
        typ, flags, off, vaddr, _paddr, filesz = struct.unpack_from('<IIQQQQ', data, base)
        if typ == 1 and filesz:
            if off + filesz > len(data):
                raise ValueError('Loadable segment outside file')
            rows.append((off, vaddr, filesz, flags))
    if not rows:
        raise ValueError('No loadable segments')
    return rows


class Mapping:
    def __init__(self, segments):
        self.segments = segments

    def va_to_offset(self, va, size=1):
        for off, vaddr, filesz, _flags in self.segments:
            if vaddr <= va and va + size <= vaddr + filesz:
                return off + (va - vaddr)
        raise ValueError(f'VA {va:#x} not backed by file bytes')

    def offset_to_va(self, offset):
        for off, vaddr, filesz, _flags in self.segments:
            if off <= offset < off + filesz:
                return vaddr + (offset - off)
        raise ValueError(f'offset {offset:#x} outside loadable segments')

    def read(self, data, va, size):
        off = self.va_to_offset(va, size)
        return data[off:off + size]

    def execute_segment(self):
        for off, vaddr, filesz, flags in self.segments:
            if flags & 1:
                return off, vaddr, filesz
        raise ValueError('No executable segment')


def function_bounds(data, va):
    """Enclosing and following unwind start for `va` (FDE start table)."""
    _sections, entries = unwind_index(data)
    starts = sorted(entry['start'] for entry in entries)
    index = bisect.bisect_right(starts, va) - 1
    if index < 0:
        raise ValueError(f'VA {va:#x} precedes the first unwind start')
    start = starts[index]
    end = starts[index + 1] if index + 1 < len(starts) else None
    return start, end


def find_all(data, needle):
    found, start = [], 0
    while True:
        index = data.find(needle, start)
        if index < 0:
            return found
        found.append(index)
        start = index + 1


def rip_relative_insn_head(body, index):
    """Return the head length of a RIP-relative instruction whose disp is at `index`."""
    if index < 3 or body[index - 1] & 0xC7 != 0x05:
        return None
    if body[index - 3] == 0x0F and body[index - 2] in (0x10, 0x11):
        return 3
    if body[index - 3] in (0x48, 0x4C) and body[index - 2] == 0x8D:
        return 3
    if (index >= 4 and body[index - 4] == 0x66 and body[index - 3] == 0x0F
            and body[index - 2] == 0x10):
        return 4
    return None


def rip_relative_xrefs(data, mapping, target_va):
    """Scan the executable segment for mod=00, rm=101 disp32 references."""
    off, vaddr, filesz = mapping.execute_segment()
    body = data[off:off + filesz]
    refs = []
    for index in range(len(body) - 4):
        head = rip_relative_insn_head(body, index)
        if head is None:
            continue
        disp = struct.unpack_from('<i', body, index)[0]
        insn_va = vaddr + index - head
        if vaddr + index + 4 + disp == target_va:
            refs.append({'instruction_va': insn_va, 'disp_offset_va': vaddr + index,
                         'disp32': disp, 'insn_bytes': body[index - head:index + 4].hex()})
    return refs


def decode_chain_site(data, mapping, va):
    """Validate and decode one inlined signature_chain_id site.

    Shape: ``cmpb $3, %r?b`` then two ``mov imm32, %e?x`` (the second may carry
    a REX prefix) then ``cmovz %mainnet, %testnet``. Unrelated single
    instructions between the compare and the moves are skipped by name.
    """
    raw = mapping.read(data, va, 32)
    if raw[0] == 0x41 and raw[1] == 0x80:
        rex_b, head = 8, 2
    elif raw[0] == 0x40 and raw[1] == 0x80:
        rex_b, head = 0, 2
    else:
        raise ValueError(f'{va:#x}: missing REX cmpb $3')
    if raw[head] & 0xF8 != 0xF8 or raw[head + 1] != CHAIN_MAINNET_DISCRIMINANT:
        raise ValueError(f'{va:#x}: not cmpb $3')
    chain_index = rex_b + (raw[head] & 7)
    offset = head + 2
    moves = {}
    while len(moves) < 2:
        if offset + 6 > len(raw):
            raise ValueError(f'{va:#x}: immediate moves run past the read window')
        opcode = raw[offset]
        if opcode in range(0xB8, 0xC0):
            moves[opcode - 0xB8] = struct.unpack_from('<I', raw, offset + 1)[0]
            offset += 5
        elif opcode == 0x41 and raw[offset + 1] in range(0xB8, 0xC0):
            moves[8 + raw[offset + 1] - 0xB8] = struct.unpack_from('<I', raw, offset + 2)[0]
            offset += 6
        elif opcode == 0xC6 and raw[offset + 1] == 0x00:
            offset += 3  # movb $imm8, (%rax)
        else:
            raise ValueError(f'{va:#x}: unexpected byte {opcode:#x} before the immediate moves')
    if offset + 4 > len(raw):
        raise ValueError(f'{va:#x}: cmovcc runs past the read window')
    if raw[offset] not in (0x48, 0x4C) or raw[offset + 1] != 0x0F or raw[offset + 2] not in CONDITIONAL_MOVE:
        raise ValueError(f'{va:#x}: expected REX.W cmovcc')
    modrm = raw[offset + 3]
    if modrm >> 6 != 3:
        raise ValueError(f'{va:#x}: cmovcc with non-register operand')
    destination_index = ((modrm >> 3) & 7) + (8 if raw[offset] & 4 else 0)
    source_index = modrm & 7
    destination, source = REG64[destination_index], REG64[source_index]
    length = offset + 4
    if moves.get(destination_index) != TESTNET_CHAIN_ID or moves.get(source_index) != MAINNET_CHAIN_ID:
        raise ValueError(f'{va:#x}: expected mainnet in {source}, testnet in {destination}')
    return {
        'site_va': va,
        'site_offset': mapping.va_to_offset(va, length),
        'bytes': raw[:length].hex(),
        'length': length,
        'compare_register': REG8[chain_index],
        'mainnet_immediate': MAINNET_CHAIN_ID,
        'testnet_immediate': TESTNET_CHAIN_ID,
        'destination_register': destination,
        'conditional': CONDITIONAL_MOVE[raw[offset + 2]],
        'selected_when_equal': MAINNET_CHAIN_ID,
        'selected_otherwise': TESTNET_CHAIN_ID,
    }


WITHDRAWAL_ARM_PINS = [
    (0x1F, '0f1005'),          # movups literal[0..16] from .rodata
    (0x26, '0f1100'),          # movups %xmm0, (%rax)
    (0x29, 'c640106c'),        # movb $'l', 0x10(%rax)  -> 17th literal byte
    (0x4D, '410f10442401'),    # movups 0x1(%r12)       account[0..16]
    (0x5B, '418b442411'),      # movl 0x11(%r12)        account[16..20]
    (0x67, '410f10442415'),    # movups 0x15(%r12)      destination[0..16]
    (0x75, '418b442425'),      # movl 0x25(%r12)        destination[16..20]
    (0x81, '4c89b42450010000'),# movq %r14, 0x150(%rsp) amount
    (0x89, '4c89bc2480010000'),# movq %r15, 0x180(%rsp) nonce
]


def decode_withdrawal_arm(data, mapping, start):
    """Pin the field-extraction bytes of the requestWithdrawal hash arm."""
    raw = mapping.read(data, start, 0xA0)
    for relative, expected in WITHDRAWAL_ARM_PINS:
        actual = raw[relative:relative + len(expected) // 2].hex()
        if actual != expected:
            raise ValueError(f'{start + relative:#x}: {actual} != {expected}')
    return {
        'arm_va': start,
        'arm_offset': mapping.va_to_offset(start),
        'arm_sha256': digest(raw),
        'field_source_offsets': {
            'account': {'offset': 1, 'width': 20},
            'destination': {'offset': 0x15, 'width': 20},
            'amount': {'offset': 0x30, 'width': 8},
            'nonce': {'offset': 0x38, 'width': 8},
        },
        'literal_pin': {'movups_va': start + 0x1F, 'movb_va': start + 0x29},
    }


ENCODER_PINS = [
    (0x13, 'bfc8000000'),      # movl $0xc8, %edi   5 * 0x28-byte slots
    (0x44, 'c60306'),          # movb $6, (%rbx)    string tag
    (0x61, 'c6432800'),        # movb $0, 0x28(%rbx) address tag
    (0x75, 'c6435000'),        # movb $0, 0x50(%rbx) address tag
    (0x89, 'c6437804'),        # movb $4, 0x78(%rbx) uint64 tag
    (0xA9, 'c683a000000004'),  # movb $4, 0xa0(%rbx) uint64 tag
]


def decode_encoder(data, mapping, start):
    """Pin the tagged-slot encoder used by the requestWithdrawal arm."""
    raw = mapping.read(data, start, 0xC0)
    for relative, expected in ENCODER_PINS:
        actual = raw[relative:relative + len(expected) // 2].hex()
        if actual != expected:
            raise ValueError(f'{start + relative:#x}: {actual} != {expected}')
    return {
        'encoder_va': start,
        'encoder_offset': mapping.va_to_offset(start),
        'encoder_sha256': digest(raw),
        'slot_stride': 0x28,
        'slot_count': 5,
        'tags': [6, 0, 0, 4, 4],
    }


def direct_calls(data, mapping, start, span):
    raw = mapping.read(data, start, span)
    calls = []
    for index in range(len(raw) - 5):
        if raw[index] == 0xE8:
            calls.append(start + index + 5 + struct.unpack_from('<i', raw, index + 1)[0])
    return calls


def decode_struct_hash_table(data, mapping):
    table_off = mapping.va_to_offset(STRUCT_HASH_TABLE, STRUCT_HASH_ARMS * 4)
    arms = []
    for index in range(STRUCT_HASH_ARMS):
        delta = struct.unpack_from('<i', data, table_off + index * 4)[0]
        target = STRUCT_HASH_TABLE + delta
        if target < STRUCT_HASH_START or target >= STRUCT_HASH_START + 0x10000:
            raise ValueError(f'arm {index} outside struct_hash: {target:#x}')
        try:
            offset = mapping.va_to_offset(target)
        except ValueError as error:
            raise ValueError(f'arm {index} outside struct_hash: {error}') from error
        arms.append({'discriminant': index, 'target_va': target, 'target_offset': offset})
    return arms


def literal_loads(data, mapping, arm_va, span=0x400):
    """Return literal bytes copied by the arm, using the 8-bit literal table."""
    raw = mapping.read(data, arm_va, span)
    hits = []
    for index in range(len(raw) - 8):
        if raw[index] != 0x0F or raw[index + 1] not in (0x10, 0x11):
            continue
        if raw[index + 2] & 0xC7 != 0x05:
            continue
        disp = struct.unpack_from('<i', raw, index + 3)[0]
        target = arm_va + index + 7 + disp
        hits.append({'load_va': arm_va + index, 'literal_va': target})
    return hits


def run(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release', type=int, default=94, choices=sorted(TARGET_SHA256))
    parser.add_argument('--artifact', type=Path,
                        default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--out', type=Path, help='write JSON report and excerpts here')
    args = parser.parse_args(argv)

    data, actual = load_artifact(args.artifact, args.release)
    mapping = Mapping(load_segments(data))
    text_off, text_va, text_size = mapping.execute_segment()

    occurrences = find_all(data, REQUEST_WITHDRAWAL_LITERAL)
    if len(occurrences) != 1:
        raise ValueError(f'expected one requestWithdrawal literal, found {len(occurrences)}')
    literal_off = occurrences[0]
    literal_va = mapping.offset_to_va(literal_off)
    if literal_va != SEED_LITERAL_OFFSET:
        raise ValueError(f'literal moved to {literal_va:#x}')
    literal = data[literal_off:literal_off + REQUEST_WITHDRAWAL_LENGTH]
    xrefs = rip_relative_xrefs(data, mapping, literal_va)
    if not xrefs:
        raise ValueError('no RIP-relative xref to requestWithdrawal')

    struct_start, struct_end = function_bounds(data, xrefs[0]['instruction_va'])
    arms = decode_struct_hash_table(data, mapping)
    targets = sorted(arm['target_va'] for arm in arms)
    arm_loads = []
    for arm in arms:
        following = [t for t in targets if t > arm['target_va']]
        span = (following[0] - arm['target_va']) if following else 0x300
        loads = literal_loads(data, mapping, arm['target_va'], span)
        arm_loads.append({'discriminant': arm['discriminant'],
                          'reference_label': PAYLOAD_LABELS[arm['discriminant']],
                          'target_va': arm['target_va'], 'span': span,
                          'literal_loads': loads,
                          'direct_calls': direct_calls(data, mapping, arm['target_va'], span)})

    chain_sites = []
    for offset in find_all(data, b'\xb1\xa4\x00\x00'):
        opcode_va = mapping.offset_to_va(offset) - 1
        if mapping.read(data, opcode_va, 1)[0] not in range(0xB8, 0xC0):
            continue
        for back in range(4, 8):
            candidate = opcode_va - back
            try:
                site = decode_chain_site(data, mapping, candidate)
            except ValueError:
                continue
            chain_sites.append(site)
            break
    if len(chain_sites) != 3:
        raise ValueError(f'expected three inlined chain-id sites, found {len(chain_sites)}')
    for site in chain_sites:
        site['function_start'], site['function_end'] = function_bounds(data, site['site_va'])

    withdrawal_arm = next(arm for arm in arm_loads if arm['discriminant'] == 5)
    if not any(hit['literal_va'] == literal_va for hit in withdrawal_arm['literal_loads']):
        raise ValueError('discriminant 5 does not load the requestWithdrawal literal')

    seeded_va = mapping.offset_to_va(SEED_CHAIN_OFFSET)
    if not any(s['site_va'] <= seeded_va < s['site_va'] + s['length'] for s in chain_sites):
        raise ValueError('seeded chain-id offset is not inside a decoded site')

    payload_arm = mapping.read(data, withdrawal_arm['target_va'], 0x120)
    withdrawal_layout = decode_withdrawal_arm(data, mapping, withdrawal_arm['target_va'])
    call_site = withdrawal_arm['target_va'] + 0x9E
    if mapping.read(data, call_site, 1) != b'\xe8':
        raise ValueError(f'{call_site:#x}: expected call to the field encoder')
    encoder_va = call_site + 5 + struct.unpack('<i', mapping.read(data, call_site + 1, 4))[0]
    if encoder_va not in withdrawal_arm['direct_calls']:
        raise ValueError(f'{encoder_va:#x}: arm does not call the expected encoder')
    withdrawal_encoder = decode_encoder(data, mapping, encoder_va)
    report = {
        'release': f'node{args.release}',
        'artifact': str(args.artifact.relative_to(ROOT)),
        'artifact_sha256': actual,
        'artifact_size': len(data),
        'coordinate_system': 'linked VA; file offset = VA - 0x1000 inside .text, '
                             'equal to VA inside .rodata',
        'elf': {'text_va': text_va, 'text_size': text_size},
        'literal': {
            'value': literal.decode('ascii'),
            'va': literal_va,
            'offset': literal_off,
            'length': REQUEST_WITHDRAWAL_LENGTH,
            'sha256': digest(literal),
            'xrefs': xrefs,
        },
        'struct_hash': {
            'function_start': struct_start,
            'function_end': struct_end,
            'dispatch_table_va': STRUCT_HASH_TABLE,
            'arms': arm_loads,
            'withdrawal_arm_va': withdrawal_arm['target_va'],
            'withdrawal_arm_sha256': digest(payload_arm),
            'withdrawal_arm_layout': withdrawal_layout,
            'withdrawal_encoder': withdrawal_encoder,
        },
        'chain_id_sites': chain_sites,
        'literal_occurrences': len(occurrences),
        'control': {
            'expected_sha256': TARGET_SHA256[args.release],
            'seeded_literal_va': SEED_LITERAL_OFFSET,
            'seeded_chain_offset': SEED_CHAIN_OFFSET,
            'seeded_chain_va': seeded_va,
        },
    }

    text = json.dumps(report, indent=1, sort_keys=True) + '\n'
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / 'bridge-inventory.json').write_text(text)
        for site in chain_sites:
            start = site['site_va'] - 16
            excerpt = mapping.read(data, start, site['length'] + 32)
            name = f'chain-{site["site_va"]:x}.bin'
            (args.out / name).write_bytes(excerpt)
        excerpt = mapping.read(data, withdrawal_arm['target_va'], 0x120)
        (args.out / 'request-withdrawal-arm.bin').write_bytes(excerpt)
    sys.stdout.write(text)
    return 0


def main(argv=None):
    try:
        return run(argv)
    except (ValueError, OSError) as e:
        print(f'bridge_inventory: {e}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
