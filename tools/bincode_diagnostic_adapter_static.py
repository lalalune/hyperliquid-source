"""Static scan/interval/flag certificates for the node94 622-byte adapter.

This decodes an owned raw slice and binds specific native operand relations.
It is not an instruction interpreter, callback runner or rendering emulator.
"""
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import os

BASE, END = 0x157D000, 0x157D26E
U64 = (1 << 64) - 1


class ContractError(ValueError):
    pass


def require(ok, message):
    if not ok:
        raise ContractError(message)


def native(body):
    require(len(body) == END - BASE, 'Adapter raw span is not complete')
    version = subprocess.run(['objdump', '--version'], check=True, capture_output=True, text=True).stdout.splitlines()[0]
    require('GNU objdump' in version, 'GNU objdump is required')
    with tempfile.TemporaryDirectory(prefix='diagnostic-adapter-') as folder:
        raw = Path(folder) / 'adapter.raw'
        with raw.open('xb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(body)
        argv = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                '--insn-width=16', '--adjust-vma=' + hex(BASE), str(raw)]
        listing = subprocess.run(argv, check=True, capture_output=True, text=True).stdout
        require(raw.read_bytes() == body, 'Owned adapter raw bytes changed')
        listing = listing.replace(str(raw), '<node94-622-byte-adapter>')
    rows, cursor = [], BASE
    for line in listing.splitlines():
        fields = line.split('\t')
        if len(fields) < 3 or not fields[0].strip().endswith(':'):
            continue
        try:
            va, value = int(fields[0].strip()[:-1], 16), bytes.fromhex(fields[1])
        except ValueError:
            continue
        require(value and va == cursor and '(bad)' not in fields[2], 'Adapter native row tiling changed')
        require(body[va - BASE:va - BASE + len(value)] == value, 'Adapter native row bytes changed')
        rows.append({'va': va, 'bytes': value.hex(), 'assembly': fields[2]})
        cursor += len(value)
    require(cursor == END, 'Adapter native decode is incomplete')
    return rows, listing, version, argv[:-1] + ['<owned-622-byte-adapter>']


def edges(rows):
    starts = {r['va'] for r in rows}
    branches, calls, returns = {}, [], []
    names = {2: 'below', 3: 'above_or_equal', 4: 'equal', 5: 'not_equal',
             6: 'below_or_equal', 7: 'above'}
    for row in rows:
        va, raw = row['va'], bytes.fromhex(row['bytes'])
        kind, target, cc = None, None, None
        if 0x70 <= raw[0] <= 0x7F:
            kind, cc = 'conditional', raw[0] & 15
            target = va + 2 + struct.unpack('<b', raw[1:2])[0]
        elif raw[:1] == b'\xeb':
            kind, target = 'jump', va + 2 + struct.unpack('<b', raw[1:2])[0]
        elif raw[:1] == b'\xe9':
            kind, target = 'jump', va + 5 + struct.unpack('<i', raw[1:5])[0]
        elif raw[:1] == b'\x0f' and 0x80 <= raw[1] <= 0x8F:
            kind, cc = 'conditional', raw[1] & 15
            target = va + 6 + struct.unpack('<i', raw[2:6])[0]
        if kind:
            require(target in starts, 'Adapter branch is not instruction-aligned')
            branches[va] = {'kind': kind, 'condition': names.get(cc, str(cc)) if cc is not None else None,
                            'target': target, 'fallthrough': va + len(raw) if cc is not None else None}
        if raw[0] == 0xFF and ((raw[1] >> 3) & 7) == 2:
            calls.append(va)
        if raw == b'\xc3':
            returns.append(va)
    return {'branches': branches, 'calls': calls, 'returns': returns}


def operand_facts(body, rows, read_literal):
    starts = {r['va'] for r in rows}
    roles = {}

    def at(va, n):
        return body[va - BASE:va - BASE + n]

    def fixed(va, value, role):
        expected = bytes.fromhex(value)
        require(va in starts and at(va, len(expected)) == expected, role + ' operand relation changed')
        for pc in starts:
            if va <= pc < va + len(expected):
                roles.setdefault(pc, []).append(role)

    def imm(va, prefix, width=1, signed=False):
        fixed(va, prefix, hex(va))
        return int.from_bytes(at(va + len(bytes.fromhex(prefix)), width), 'little', signed=signed)

    # These are selected complete dataflow chains, not a hash of the whole body.
    fixed(0x157D000, '554889e54157415641554154534883ec48', 'Adapter prologue/frame protection')
    fixed(0x157D033, '488945b0488b07488945b8', 'Cached flag pointer and destination slots')
    fixed(0x157D042, '488945c0488975d0488d4608488945a84531ff31c04531c048895598',
          'Cached vtable/input/length and initial emitted/scan/continuation state')
    fixed(0x157D060, '42807c2fff', 'Piece last-byte address')
    fixed(0x157D066, '0f94c04a8d34074d29c5488b4db08801488b7db84c89ea488b45c0',
          'Last-byte flag computation/store precedes payload arguments')
    fixed(0x157D084, '4d89e084c0488b55984d89f5', 'Payload TEST-AL and restored cursor/length/mask')
    fixed(0x157D09A, '8b45cc', 'Continuation reload preserves payload TEST flags')
    fixed(0x157D0AB, '4c39fa', 'Search scan cursor bounded by length')
    fixed(0x157D0B0, '4d89fc488b7dd0', 'Defensive out-of-domain search fallback')
    fixed(0x157D0C0, '488b7dd0', 'Input pointer reload at search entry')
    fixed(0x157D0D0, '4d89e74c39e2', 'Defensive recheck retry cursor')
    fixed(0x157D0DC, '4889d14c29f94a8d043f', 'Remaining length and current input pointer')
    fixed(0x157D0EC, '4c39fa', 'Small-search empty interval guard')
    fixed(0x157D0F5, '31f6', 'Small-search initial byte index')
    fixed(0x157D10A, '48ffc64839f1', 'Small-search compare-before-increment order and bound')
    fixed(0x157D128, '4929c3', 'Alignment distance subtracts the current pointer')
    fixed(0x157D12D, '4d89c4', 'Aligned wide search protects the emitted cursor')
    fixed(0x157D134, '4531db488b7da84c01ff', 'Aligned wide offset and saved input-plus-eight base')
    fixed(0x157D145, '4d89c14d31f14989da4d29ca4d09c2',
          'First wide word XOR/subtract/OR-original relation')
    fixed(0x157D154, '4e8b041f4d31f04989d94d29c14d09c14d21ea4d21ca4d39ea',
          'Second wide word XOR/subtract/OR-XOR and combined high-bit skip predicate')
    fixed(0x157D173, '4939f3', 'Wide-loop offset is compared with remaining-minus-width')
    fixed(0x157D180, '31f6', 'Alignment prefix starts at byte zero')
    fixed(0x157D196, '48ffc64939f3', 'Alignment prefix advances by one under its distance bound')
    fixed(0x157D19E, '4d89c4', 'Unaligned wide/fallback search protects the emitted cursor')
    fixed(0x157D1A5, '4939f3', 'Unaligned wide admission compares distance to remaining-minus-width')
    fixed(0x157D1B0, '4c89de4c39d9488b7dd04d89e0',
          'Fallback begins at current wide offset and restores input/emitted cursor')
    fixed(0x157D1C6, '48ffc64839f1', 'Fallback scalar compare-before-increment order and bound')
    fixed(0x157D1D0, '4e8d243e49ffc44901f74939d7', 'Found index/end and strict chunk progress')
    fixed(0x157D1ED, '4d89ee31c04d89e74d89e5',
          'Newline piece saves mask and selects next cursor/end with continuation zero')
    fixed(0x157D200, '4989d44d89ee', 'No-newline end is the full input length')
    fixed(0x157D208, '4d89e74d89c44989d54c39c2',
          'Final tail keeps old emitted cursor only until its done exit')
    fixed(0x157D216, '8945cc488b45b0', 'Save continuation before loading the actual flag pointer')
    fixed(0x157D227, '488b7db8', 'Indentation uses the cached destination pointer')
    fixed(0x157D232, '488b45c04c8945a0', 'Indentation uses cached vtable and protects emitted cursor')
    fixed(0x157D23D, '4c8b45a0488b7dd084c0',
          'Restore emitted/input pointer before indentation return AL test')
    fixed(0x157D249, '4d39c5', 'Selected-end versus emitted-cursor zero-piece branch')
    fixed(0x157D252, '31c0', 'Out-of-domain zero-piece flag value')
    fixed(0x157D259, '31c0', 'Success return clears EAX')
    fixed(0x157D25F, '4883c4485b415c415d415e415f5dc3', 'Actual frame restore and common RET')
    delimiters = {hex(va): imm(va, prefix) for va, prefix in [
        (0x157D060, '42807c2fff'), (0x157D100, '803c30'), (0x157D190, '803c30'),
        (0x157D1C0, '803c30'), (0x157D1E3, '803c30')]}
    literal = 0x157D22B + 7 + imm(0x157D22B, '488d35', 4, True)
    indent_len = imm(0x157D222, 'ba', 4)
    require(0 <= indent_len <= 8, 'Indentation slice exceeds the inspected control domain')
    return {
        'HI': imm(0x157D011, '49bd', 8), 'LFWORD': imm(0x157D01B, '49be', 8),
        'C': imm(0x157D025, '48bb', 8), 'restored_LFWORD': imm(0x157D090, '49be', 8),
        'flag_pointer_offset': imm(0x157D02F, '488b47'),
        'vtable_offset': imm(0x157D03E, '488b47'),
        'delimiters': delimiters, 'continuation_mask': imm(0x157D0A3, 'a8'),
        'small_threshold': imm(0x157D0E6, '4883f9', signed=True),
        'alignment_addend': imm(0x157D120, '4c8d58', signed=True),
        'alignment_mask': imm(0x157D124, '4983e3', signed=True),
        'aligned_width_subtract': imm(0x157D130, '488d71', signed=True),
        'unaligned_width_subtract': imm(0x157D1A1, '488d71', signed=True),
        'first_word_displacement': imm(0x157D140, '4e8b441f', signed=True),
        'wide_skip_stride': imm(0x157D16F, '4983c3', signed=True),
        'tail_continuation': imm(0x157D206, 'b0'),
        'flag_compare': imm(0x157D21D, '8038'),
        'indentation': {'pointer': literal, 'length': indent_len,
                        'bytes_hex': read_literal(literal, indent_len).hex()},
        'writer_method_offsets': {hex(pc): imm(pc, 'ff50') for pc in [0x157D081, 0x157D23A]},
        'failure_AL': imm(0x157D25D, 'b0'), 'native_dataflow_rows': roles,
    }


# All branches have a role in the qualified scan or an explicit defensive case.
BRANCH_RELATIONS = {
    0x157D05E: (None, 0x157D0A3), 0x157D09D: ('not_equal', 0x157D25D),
    0x157D0A5: ('not_equal', 0x157D259), 0x157D0AE: ('above_or_equal', 0x157D0C0),
    0x157D0B7: (None, 0x157D203), 0x157D0C4: (None, 0x157D0DC),
    0x157D0D6: ('below', 0x157D203), 0x157D0EA: ('above', 0x157D120),
    0x157D0EF: ('equal', 0x157D200), 0x157D104: ('equal', 0x157D1D0),
    0x157D110: ('not_equal', 0x157D100), 0x157D112: (None, 0x157D200),
    0x157D12B: ('not_equal', 0x157D180), 0x157D16D: ('not_equal', 0x157D1B0),
    0x157D176: ('below_or_equal', 0x157D140), 0x157D178: (None, 0x157D1B0),
    0x157D194: ('equal', 0x157D1D0), 0x157D19C: ('not_equal', 0x157D190),
    0x157D1A8: ('below_or_equal', 0x157D137), 0x157D1BD: ('equal', 0x157D200),
    0x157D1C4: ('equal', 0x157D1D0), 0x157D1CC: ('not_equal', 0x157D1C0),
    0x157D1CE: (None, 0x157D200), 0x157D1DD: ('above_or_equal', 0x157D0D0),
    0x157D1E7: ('not_equal', 0x157D0D0), 0x157D1F8: (None, 0x157D216),
    0x157D214: ('equal', 0x157D259), 0x157D220: ('equal', 0x157D249),
    0x157D247: ('not_equal', 0x157D25D), 0x157D24C: ('not_equal', 0x157D060),
    0x157D254: (None, 0x157D069), 0x157D25B: (None, 0x157D25F),
}


def mask_certificate(c, lfword, hi):
    """Finite byte/borrow proof of a universal no-false-negative implication."""
    require(lfword.to_bytes(8, 'little') == b'\x0a' * 8, 'Wide newline XOR constant is not the scalar delimiter')
    require(hi.to_bytes(8, 'little') == b'\x80' * 8, 'Wide mask does not select byte high bits')
    constants = c.to_bytes(8, 'little')
    cases = []
    for index in range(8):
        for borrow in ([0] if index == 0 else [0, 1]):
            difference = (constants[index] - borrow) & 255
            original_or = difference | 0x0A
            xor_or = difference  # The matching byte of word XOR LFWORD is zero.
            require(not ((original_or | xor_or) & 0x80),
                    f'Wide no-false-negative borrow lemma fails at byte {index}, borrow {borrow}')
            cases.append({'index': index, 'incoming_borrow': borrow, 'constant_byte': constants[index],
                          'matching_xor_byte': 0, 'difference_byte': difference,
                          'first_OR_high_bit': (original_or >> 7) & 1,
                          'second_OR_high_bit': (xor_or >> 7) & 1})
    return {'cases': cases, 'universal_step': 'Any LF byte forces a zero bit in the combined HI comparison; therefore a full-HI skip contains no LF.',
            'false_positives_allowed': True, 'instruction_interpreter': False}


def wide_predicate(word0, word1, c, lfword, hi):
    """The extracted word equation for mathematical corruption witnesses."""
    x0, x1 = word0 ^ lfword, word1 ^ lfword
    return (((((c - x0) & U64) | word0) & hi) & (((c - x1) & U64) | x1)) == hi


def interval_certificate(facts):
    width = -facts['aligned_width_subtract']
    require(width == -facts['unaligned_width_subtract'] == 16, 'Aligned/unaligned wide interval widths differ')
    require(facts['small_threshold'] == width - 1, 'Small/wide threshold permits an unproved load interval')
    require((facts['alignment_addend'], facts['alignment_mask']) == (7, -8),
            'Alignment prefix distance is not in the proved zero-to-seven interval')
    first = 8 + facts['first_word_displacement']
    intervals = [[first, first + 8], [8, 16]]
    require(intervals == [[0, 8], [8, width]], 'Two wide loads do not partition the complete skipped interval')
    require(facts['wide_skip_stride'] == width, 'Wide skip stride creates an unchecked or nonprogressing interval')
    # This is arithmetic over all alignment residues, not target execution.
    residues = []
    for residue in range(8):
        distance = ((residue + facts['alignment_addend']) & facts['alignment_mask']) - residue
        require(0 <= distance <= 7, 'Alignment arithmetic left the proved prefix bound')
        residues.append({'pointer_mod8': residue, 'prefix_length': distance})
    return {'width': width, 'load_intervals_relative_to_current_offset': intervals,
            'alignment_residues': residues,
            'wide_admission': 't <= remaining-16 before both reads',
            'skip_progress': 't increases by16; prior skipped/prefix intervals contain no LF',
            'fallback': 'Scalar comparison starts at t and precedes each increment; the first match is the global first LF.',
            'chunk_progress': 'A found LF gives end=start+i+1, hence emitted<end<=length.',
            'tail_cutpoint': 'A final-tail success exits on continuation bit before reusing stale R8.',
            'empty_piece_branch_unreachable_under_invariant': True}


def check(facts, graph):
    for key, expected in [('flag_pointer_offset', 16), ('vtable_offset', 8), ('continuation_mask', 1),
                          ('tail_continuation', 1), ('flag_compare', 0), ('failure_AL', 1)]:
        require(facts[key] == expected, key + ' relation changed')
    require(set(facts['delimiters'].values()) == {10}, 'Scalar/found/piece delimiter relation changed')
    require(facts['restored_LFWORD'] == facts['LFWORD'], 'Payload continuation restores a different newline constant')
    require(facts['indentation'] == {'pointer': 0x20A058, 'length': 4, 'bytes_hex': '20202020'},
            'Four-space write-request relation changed')
    require(set(facts['writer_method_offsets'].values()) == {0x18}, 'Cached-vtable writer method relation changed')
    require(set(graph['branches']) == set(BRANCH_RELATIONS), 'A scan/output branch lacks a named proof role')
    for pc, (condition, target) in BRANCH_RELATIONS.items():
        b = graph['branches'][pc]
        require((b['condition'], b['target']) == (condition, target),
                f'Scan/output control relation changed at {pc:#x}')
    require(graph['calls'] == [0x157D081, 0x157D23A] and graph['returns'] == [0x157D26D],
            'Adapter has an unclosed call or return')
    return {'mask': mask_certificate(facts['C'], facts['LFWORD'], facts['HI']),
            'intervals': interval_certificate(facts)}


def extract_span(body, read_literal):
    rows, listing, version, argv = native(body)
    graph = edges(rows)
    facts = operand_facts(body, rows, read_literal)
    role_rows = dict(facts.pop('native_dataflow_rows'))
    padding = {'0f1f4000', '662e0f1f840000000000', '660f1f840000000000', '6690',
               '660f1f440000', '66666666662e0f1f840000000000', '90'}
    for row in rows:
        pc = row['va']
        if pc in graph['branches']:
            role_rows[pc] = ['Decoded named scan/output branch']
        elif row['bytes'] in padding:
            role_rows[pc] = ['Exact native no-op padding']
        require(pc in role_rows, f'Adapter native instruction has no dataflow/CFG proof role: {pc:#x}')
    return {'range': [hex(BASE), hex(END)], 'span_sha256': hashlib.sha256(body).hexdigest(),
            'native_rows': len(rows), 'native_tool': version, 'native_command': argv,
            'cfg_edges': graph, 'operand_facts': facts, 'native_row_roles': role_rows}, listing


def prove_span(body, read_literal):
    result, listing = extract_span(body, read_literal)
    result['certificates'] = check(result['operand_facts'], result['cfg_edges'])
    result['write_protocol'] = {
        'sampled_pointer_values': 'B=load64(A+16),D=load64(A),V=load64(A+8), at the actual post-prologue load sites',
        'entry_caches': {'B': '0x157d02f -> rbp-0x50', 'D': '0x157d037 -> rbp-0x48',
                         'V': '0x157d03e -> rbp-0x40'},
        'indent_request': {'site': '0x157d23a', 'condition': 'current byte(B)!=0',
                           'arguments': ['cached D', 'VA0x20a058', '4'],
                           'target': 'current load64(cached V+0x18)'},
        'flag_store': {'site': '0x157d074', 'value': 'selected last byte==LF', 'order': 'before payload callback'},
        'payload_request': {'site': '0x157d081', 'arguments': ['cached D', 'p+emitted', 'selected_end-emitted'],
                            'target': 'current load64(cached V+0x18)'},
        'indent_failure': 'Nonzero AL reaches0x157d25d before this piece flag store/payload request.',
        'payload_failure': 'TEST0x157d087 flags survive MOVs/reloadedEAX to JNE0x157d09d, reaching AL1 after the pre-callback flag store.',
        'success': 'All-success exit clears EAX at0x157d259; failed normal returns set AL1 only.',
        'empty_input_or_empty_tail': 'No B-directed protocol access or callback; unchanged physical N additionally requires frame/alias separation.',
    }
    result['conditions'] = [
        'Finite valid input bytes remain unchanged during this invocation, with no relevant range/address wrapping.',
        'Normal callbacks preserve callee-save registers, protected frame/control slots and saved inputs.',
        'The flag does not alias own frame/prologue/control writes, input bytes or later-needed metadata in a corrupting way.',
        'D/V/B mean actual cached load values after the prologue; no pre-prologue memory-value assumption.',
        'Method entries are fresh loads from cached V. Stable writer identity additionally needs method-slot preservation.',
        'Final flag contents require callbacks to preserve the flag; otherwise only the ordered pre-callback store is qualified.',
        'No physical output, private Rust layout/type/ABI, arbitrary alias safety or captured/emulated execution is claimed.',
    ]
    result['captured_or_emulated_execution'] = False
    return result, listing
