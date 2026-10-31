#!/usr/bin/env python3
"""RE-013: visor's bounded large-request arithmetic and conditional zero return.

Only static authenticated bytes and tiny private raw-span disassembly are used.
The family checker binds every selected operator/register/control edge; it is
not an instruction interpreter, allocator model or original ABI implementation.
New code is independently authored under the repository MIT license.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tempfile

from elf_index import sections
from fde_extents import fde_extents

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/visor/captured/hl-visor'
TARGET_SIZE = 8305392
TARGET_SHA256 = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
START, END = 0x70a170, 0x70bf2b
FDE_SHA256 = '2f01803745648097e4afde2091787f7f3473ce91cdb270839121b1b00fdf2b90'
U64_END = 1 << 64
# Operator/register/control-edge signatures, not executable transplanted code.
# Variable fields below are decoded independently and used in the proof.
SCOPES = (
    ('entry-guards', 0x70a170, 0x70a1c7),
    ('large-classifier', 0x70a620, 0x70a678),
    ('class-join-guard', 0x70a1db, 0x70a1e8),
    ('zero-error-block', 0x70a43c, 0x70a44f),
    ('normal-epilogue', 0x70a2b0, 0x70a2dc),
)
OPERATORS = (
    (0x70a170, 'f30f1efa', None),  # endbr64
    (0x70a174, '4157', None),  # push   r15
    (0x70a176, '4156', None),  # push   r14
    (0x70a178, '4155', None),  # push   r13
    (0x70a17a, '4154', None),  # push   r12
    (0x70a17c, '55', None),  # push   rbp
    (0x70a17d, '4889fd', None),  # mov    rbp,rdi
    (0x70a180, '53', None),  # push   rbx
    (0x70a181, '4881ec98000000', None),  # sub    rsp,0x98
    (0x70a188, '64488b1c2500000000', None),  # mov    rbx,QWORD PTR fs:0x0
    (0x70a191, '64488b042528000000', None),  # mov    rax,QWORD PTR fs:0x28
    (0x70a19a, '4889842488000000', None),  # mov    QWORD PTR [rsp+0x88],rax
    (0x70a1a2, '48c7c080f3ffff', None),  # mov    rax,0xfffffffffffff380
    (0x70a1a9, '4801c3', None),  # add    rbx,rax
    (0x70a1ac, '6480b83003000000', None),  # cmp    BYTE PTR fs:[rax+0x330],0x0
    (0x70a1b4, '0f8596020000', None),  # jne    0x70a450
    (0x70a1ba, '4881fd00100000', (3, 7, 'small_limit', True)),  # cmp    rbp,0x1000
    (0x70a1c1, '0f8759040000', None),  # ja     0x70a620
    (0x70a620, '49bd0000000000000070', (2, 10, 'maximum', False)),  # movabs r13,0x7000000000000000
    (0x70a62a, '4939ed', None),  # cmp    r13,rbp
    (0x70a62d, '0f8209feffff', None),  # jb     0x70a43c
    (0x70a633, '4c8d642dff', None),  # lea    r12,[rbp+rbp*1-0x1]
    (0x70a638, 'b907000000', (1, 5, 'shift_floor', False)),  # mov    ecx,0x7
    (0x70a63d, '48c7c2ffffffff', None),  # mov    rdx,0xffffffffffffffff
    (0x70a644, 'be06000000', (1, 5, 'class_floor', False)),  # mov    esi,0x6
    (0x70a649, '4d0fbdd4', None),  # bsr    r10,r12
    (0x70a64d, '4c8d7dff', None),  # lea    r15,[rbp-0x1]
    (0x70a651, '4139ca', None),  # cmp    r10d,ecx
    (0x70a654, '410f43ca', None),  # cmovae ecx,r10d
    (0x70a658, '83e903', (2, 3, 'shift_subtract', False)),  # sub    ecx,0x3
    (0x70a65b, '48d3e2', None),  # shl    rdx,cl
    (0x70a65e, '4c21fa', None),  # and    rdx,r15
    (0x70a661, '48d3ea', None),  # shr    rdx,cl
    (0x70a664, '83e203', (2, 3, 'fraction_mask', False)),  # and    edx,0x3
    (0x70a667, '4139f2', None),  # cmp    r10d,esi
    (0x70a66a, '440f42d6', None),  # cmovb  r10d,esi
    (0x70a66e, '468d7492e9', (4, 5, 'class_bias', True)),  # lea    r14d,[rdx+r10*4-0x17]
    (0x70a673, 'e963fbffff', None),  # jmp    0x70a1db
    (0x70a1db, '4181fee7000000', (3, 7, 'class_limit', False)),  # cmp    r14d,0xe7
    (0x70a1e2, '0f8754020000', None),  # ja     0x70a43c
    (0x70a43c, 'e85fc40900', (1, 5, 'call_displacement', True)),  # call   0x7a68a0
    (0x70a441, '4531e4', None),  # xor    r12d,r12d
    (0x70a444, 'c7000c000000', (2, 6, 'stored_word', False)),  # mov    DWORD PTR [rax],0xc
    (0x70a44a, 'e961feffff', None),  # jmp    0x70a2b0
    (0x70a2b0, '488b842488000000', None),  # mov    rax,QWORD PTR [rsp+0x88]
    (0x70a2b8, '64482b042528000000', None),  # sub    rax,QWORD PTR fs:0x28
    (0x70a2c1, '0f857c140000', None),  # jne    0x70b743
    (0x70a2c7, '4881c498000000', None),  # add    rsp,0x98
    (0x70a2ce, '4c89e0', None),  # mov    rax,r12
    (0x70a2d1, '5b', None),  # pop    rbx
    (0x70a2d2, '5d', None),  # pop    rbp
    (0x70a2d3, '415c', None),  # pop    r12
    (0x70a2d5, '415d', None),  # pop    r13
    (0x70a2d7, '415e', None),  # pop    r14
    (0x70a2d9, '415f', None),  # pop    r15
    (0x70a2db, 'c3', None),  # ret
)


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, indent=2) + '\n'


def authenticate(data):
    """Authenticate a caller-owned bytes/mmap view; never open an image path."""
    require(len(data) == TARGET_SIZE, 'visor input size differs')
    require(sha(data) == TARGET_SHA256, 'visor input SHA-256 differs')
    return {'sha256': TARGET_SHA256, 'bytes': TARGET_SIZE, 'release': 'captured visor'}


def class_intervals(constants):
    """Analytic interval lemma, not evaluation of captured instructions.

    For k>=3, r in [(4+t)*2**(k-3)+1,(5+t)*2**(k-3)] has
    floor(log2(2*r-1))=k and ((r-1)>>(k-3))&3=t. Intersecting
    these consecutive quarters with the observed guards covers every integer
    in the proof domain. Endpoint tests corroborate, not replace, this lemma.
    """
    c = constants
    require(c['small_limit'] >= 0, 'sign-extended negative CMP immediate outside bounded proof family')
    low, high = c['small_limit'] + 1, c['maximum']
    require(8 <= low <= high < (1 << 63), 'large-domain doubling/BSR proof does not apply')
    require(c['shift_subtract'] == 3 and c['fraction_mask'] == 3,
            'quarter interval lemma needs shift-subtract 3 and mask 3')
    minimum_k = (2 * low - 1).bit_length() - 1
    require(c['shift_floor'] <= minimum_k and c['class_floor'] <= minimum_k,
            'observed clamp is not inert over the entire domain')
    out = []
    for k in range(minimum_k, 64):
        step = 1 << (k - 3)
        for fractional in range(4):
            lower = max(low, (4 + fractional) * step + 1)
            upper = min(high, (5 + fractional) * step)
            if lower <= upper:
                value = 4 * k + fractional + c['class_bias']
                require(0 <= value < (1 << 32), 'class LEA would wrap its 32-bit result')
                out.append({'lower': lower, 'upper': upper, 'class': value,
                            'k': k, 'fractional': fractional})
    require(out and out[0]['lower'] == low and out[-1]['upper'] == high,
            'interval proof endpoints differ')
    require(all(a['upper'] + 1 == b['lower'] for a, b in zip(out, out[1:])),
            'analytic intervals leave a gap or overlap')
    return out


def intervals_tsv(intervals):
    return 'lower\tupper\tclass\n' + ''.join(
        f"{row['lower']}\t{row['upper']}\t{row['class']}\n" for row in intervals)


def prove_fragments(fragments):
    """Derive a conditional family certificate from five copied raw spans.

    This deliberately unpinned seam supports actual-byte counterfactuals. It
    never admits an artifact: use inspect/authenticate for target claims.
    Each row, register flow and control edge has an operand signature. Altered
    immediates can produce a different certificate; unsupported operators or
    paths fail with a named witness rather than only a whole-body hash.
    """
    require(set(fragments) == {name for name, _, _ in SCOPES}, 'fragment domain differs')
    at, bindings = {}, []
    for name, start, end in SCOPES:
        raw = fragments[name]
        require(isinstance(raw, bytes) and len(raw) == end - start, 'fragment extent differs')
        at.update({a: (name, start, raw) for a, _, _ in OPERATORS if start <= a < end})
    constants = {}
    coverage = {name: bytearray(end - start) for name, start, end in SCOPES}
    for address, signature, field in OPERATORS:
        name, start, raw = at[address]
        expected = bytes.fromhex(signature)
        actual = raw[address - start:address - start + len(expected)]
        if field is not None:
            begin, end, key, signed = field
            require(actual[:begin] == expected[:begin] and actual[end:] == expected[end:],
                    f'operator/register witness differs at {address:#x}')
            constants[key] = int.from_bytes(actual[begin:end], 'little', signed=signed)
        else:
            require(actual == expected, f'operator/control/output witness differs at {address:#x}')
        for offset in range(address - start, address - start + len(expected)):
            require(coverage[name][offset] == 0, 'operator witnesses overlap')
            coverage[name][offset] = 1
        bindings.append({'va': hex(address), 'hex': actual.hex()})
    require(all(all(bits) for bits in coverage.values()), 'unbound instruction byte')
    constants['call_target'] = 0x70a43c + 5 + constants.pop('call_displacement')
    constants['class_scale'] = 4  # Bound SIB byte 0x92 in the R14D LEA.
    intervals = class_intervals(constants)
    path = [0x70a43c, 0x70a441, 0x70a444, 0x70a44a,
            0x70a2b0, 0x70a2b8, 0x70a2c1, 0x70a2c7,
            0x70a2ce, 0x70a2d1, 0x70a2d2, 0x70a2d3,
            0x70a2d5, 0x70a2d7, 0x70a2d9, 0x70a2db]
    # The path's exact branch/jump targets, post-call zero, four-byte store,
    # RAX<-R12 before POP R12 and actual RET are all bound above.
    return {
        'constants': constants, 'intervals': intervals,
        'interval_lemma': 'PROOF.md L3; analytic contiguous quarters, not finite sample equivalence',
        'interval_count': len(intervals), 'selected_bytes': sum(map(len, fragments.values())),
        'selected_instructions': len(bindings), 'instruction_bindings': bindings,
        'class_range': [min(r['class'] for r in intervals), max(r['class'] for r in intervals)],
        'class_join_cannot_reject': all(r['class'] <= constants['class_limit'] for r in intervals),
        'request_guard': {'gate_byte_address': 'architectural FS base - 0x950',
                          'selected_gate_value': 0, 'request_register': 'entry RDI -> RBP',
                          'large_request_unsigned_strictly_above': constants['small_limit'],
                          'oversize_unsigned_strictly_above': constants['maximum'],
                          'nonzero_gate_route': '0x70a450 (opaque, before size checks)'},
        'conditional_zero_return': {
            'actual_path_witnesses': [hex(a) for a in path],
            'opaque_call': hex(constants['call_target']),
            'after_normal_call': 'R12D is zeroed; DWORD at returned RAX is written',
            'store_width_bytes': 4, 'store_value': constants['stored_word'],
            'normal_return_word': 0,
            'premises': ['opaque call returns at 0x70a441 with expected stack restored',
                         'four-byte store through returned RAX completes',
                         'physical saved guard equals current FS+0x28 after call/store',
                         'physical saved-register and hardware-return slots are preserved and usable',
                         'entry/prologue, own stores and all selected reads are valid; image immutable'],
            'no_callee_saved_GPR_promise_needed_for_zero': True,
            'no_errno_or_purity_or_heap_preservation_claim': True},
        'open': ['nonzero gate route', 'small request table', 'later class-size table and allocation',
                 'opaque callee effects and body', 'TLS initialization', 'canary-failure route',
                 'allocation freshness/capacity/alignment/lifetime', 'private types/ABI',
                 'original runtime equivalence and whole-visor reconstruction'],
        'all_component_gates_unchanged': True}


def inspect(data):
    """Same-view authenticated metadata, raw operands and analytic oracle.

    For a mutable mmap the owner must authenticate again after inspection.
    Returned fragments are copied bytes; this function never invokes a native
    tool, captured executable, network client or compiler.
    """
    target = authenticate(data)
    secs = sections(data)
    def read(address, size):
        candidates = [s for s in secs if s['type'] != 8 and s['address'] <= address
                      and address + size <= s['address'] + s['size']]
        require(len(candidates) == 1, 'span has no unique file-backed section mapping')
        section = candidates[0]
        offset = section['offset'] + address - section['address']
        return offset, bytes(data[offset:offset + size])
    _, fdes, _ = fde_extents(data)
    matches = [f for f in fdes if f['start'] == START]
    require(len(matches) == 1 and matches[0]['end'] == END, 'slow FDE extent differs')
    fde = dict(matches[0])
    body_offset, body = read(START, END - START)
    require(sha(body) == FDE_SHA256, 'full unwind-described body SHA differs')
    metadata = []
    for key in ('fde', 'cie'):
        offset, first = read(fde[key], 4)
        length = struct.unpack('<I', first)[0] + 4
        _, raw = read(fde[key], length)
        metadata.append({'kind': key, 'va': hex(fde[key]), 'file_offset': offset,
                         'bytes': length, 'hex': raw.hex(), 'sha256': sha(raw)})
    fragments, records = {}, []
    for name, start, end in SCOPES:
        offset, raw = read(start, end - start)
        fragments[name] = raw
        records.append({'name': name, 'start_va': hex(start), 'end_va': hex(end),
                        'file_offset': offset, 'bytes': len(raw), 'hex': raw.hex(), 'sha256': sha(raw)})
    proof = prove_fragments(fragments)
    authenticate(data)
    return {'schema': 1, 'target': target, 'coordinate_system': 'linked ELF virtual addresses',
            'fde': {**{k: hex(v) if isinstance(v, int) else v for k, v in fde.items()},
                    'body_file_offset': body_offset, 'body_bytes': END - START,
                    'body_sha256': sha(body), 'metadata': metadata,
                    'full_body_decoded': False, 'boundary_claim': 'unwind-described extent only'},
            'fragments': records, 'proof': proof,
            'captured_execution': False, 'instruction_emulation': False,
            'original_or_reference_source_copied': False}


def read_authenticated(binary):
    """Read through one fd and reject path replacement or changed source bytes.

    Hard-link ctime changes alone are not byte changes. The pinned full hash is
    retained; source fd and current path dev/inode/size must still agree.
    All subsequent native consumers receive only immutable copied fragments.
    """
    path = Path(binary)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode), 'target must be regular')
        with os.fdopen(os.dup(fd), 'rb') as stream:
            data = stream.read(TARGET_SIZE + 1)
        authenticate(data)
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            digest.update(chunk)
        after, current = os.fstat(fd), path.stat(follow_symlinks=False)
        identities = [(s.st_dev, s.st_ino, s.st_size) for s in (before, after, current)]
        require(len(set(identities)) == 1 and stat.S_ISREG(current.st_mode), 'source path/identity changed')
        require(digest.hexdigest() == TARGET_SHA256, 'source bytes changed during admission')
        return data
    finally:
        os.close(fd)


def native_rows(raw, name, start):
    """Decode an owned tiny non-executable snapshot, never the original ELF path."""
    with tempfile.TemporaryDirectory(prefix='vlarge-') as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        path = directory / (name + '.raw')
        path.write_bytes(raw)
        path.chmod(0o600)
        before = path.stat()
        argv = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel',
                '--insn-width=16', '--adjust-vma=' + hex(start), path.name]
        result = subprocess.run(argv, cwd=directory, capture_output=True, check=True)
        after = path.stat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        require(identity(before) == identity(after) and path.read_bytes() == raw,
                'owned native snapshot changed')
        require(not result.stderr, 'unexpected objdump diagnostic')
    rows = []
    for line in result.stdout.decode().splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$', line)
        if match:
            address, body = int(match[1], 16), bytes.fromhex(match[2])
            rows.append({'va': hex(address), 'hex': body.hex(), 'assembly': match[3]})
    require(rows and int(rows[0]['va'], 16) == start, 'native initial coordinate differs')
    cursor = start
    for row in rows:
        address, body = int(row['va'], 16), bytes.fromhex(row['hex'])
        require(address == cursor and raw[address - start:address - start + len(body)] == body,
                'native gap, overlap or bytes differ')
        cursor += len(body)
    require(cursor == start + len(raw), 'native extent differs')
    return rows, result.stdout


# Actual operand mutations keep fragment sizes fixed. They test dataflow and
# the arithmetic/return claim, rather than deliberately failing target hashes.
CONTROLS = (
    ('strict-large-guard', 0x70a1c2, '87', '83', 'unsigned strict large-route edge'),
    ('signed-upper-guard', 0x70a62e, '82', '8c', 'unsigned maximum comparison'),
    ('upper-bound-endpoint', 0x70a622, '0000000000000070', '0100000000000070', 'accepted maximum endpoint'),
    ('upper-bound-overflow', 0x70a622, '0000000000000070', '0000000000000080', 'nonwrapping doubling domain'),
    ('large-domain-start', 0x70a1bd, '00100000', '01100000', 'first analytic interval endpoint'),
    ('sign-extended-negative-limit', 0x70a1bd, '00100000', 'ffffffff', 'REX.W CMP imm32 sign extension'),
    ('double-minus-two', 0x70a637, 'ff', 'fe', '2*r-1 logarithm operand'),
    ('bsf-for-bsr', 0x70a64b, 'bd', 'bc', 'highest-set-bit logarithm'),
    ('active-shift-clamp', 0x70a639, '07000000', '0e000000', 'inert shift clamp premise'),
    ('shift-minus-four', 0x70a65a, '03', '04', 'quarter interval width'),
    ('fraction-mask-seven', 0x70a666, '03', '07', 'two-bit quarter field'),
    ('class-bias-minus24', 0x70a672, 'e9', 'e8', 'actual class numbers'),
    ('join-limit230', 0x70a1de, 'e7000000', 'e6000000', 'join cannot-reject result'),
    ('different-opaque-callee', 0x70a43d, '5fc40900', '60c40900', 'opaque call target identity'),
    ('zero-different-register', 0x70a443, 'e4', 'ed', 'post-call R12 zero witness'),
    ('numeric-store13', 0x70a446, '0c000000', '0d000000', 'stored numeric word'),
    ('store-through-rdx', 0x70a445, '00', '02', 'returned-RAX store destination'),
    ('skip-epilogue-witnesses', 0x70a44b, '61feffff', '8afeffff', 'actual epilogue entry path'),
    ('return-r13', 0x70a2d0, 'e0', 'e8', 'zero source before POP R12'),
    ('invert-canary-guard', 0x70a2c2, '85', '84', 'physical saved-guard equality path'),
    ('different-stack-release', 0x70a2ca, '98000000', '90000000', 'saved-frame and RET positions'),
)


def semantic_summary(proof):
    return {'constants': proof['constants'], 'first_interval': proof['intervals'][0],
            'last_interval': proof['intervals'][-1], 'class_range': proof['class_range'],
            'class_join_cannot_reject': proof['class_join_cannot_reject'],
            'intervals_sha256': sha(intervals_tsv(proof['intervals']).encode())}


def counterfactuals(fragments, decode=False):
    baseline = semantic_summary(prove_fragments(fragments))
    results = []
    for name, address, before, after, obligation in CONTROLS:
        owner = next((row for row in SCOPES if row[1] <= address < row[2]), None)
        require(owner is not None, 'counterfactual address outside selected scope')
        fragment, start, _ = owner
        raw = bytearray(fragments[fragment])
        offset = address - start
        old, new = bytes.fromhex(before), bytes.fromhex(after)
        require(len(old) == len(new) and raw[offset:offset+len(old)] == old,
                'counterfactual before bytes differ')
        raw[offset:offset+len(old)] = new
        changed = {**fragments, fragment: bytes(raw)}
        record = {'name': name, 'va': hex(address), 'before': before, 'after': after,
                  'obligation': obligation, 'actual_input_bytes': len(raw),
                  'actual_mutant_sha256': sha(raw), 'target_artifact_modified': False}
        if decode:
            rows, _ = native_rows(bytes(raw), fragment + '-mutant', start)
            record['actual_native_mutated_rows'] = [r for r in rows
                if int(r['va'], 16) <= address < int(r['va'], 16) + len(bytes.fromhex(r['hex']))]
            require(record['actual_native_mutated_rows'], 'native mutant site not decoded')
        try:
            summary = semantic_summary(prove_fragments(changed))
        except ValueError as error:
            record.update(disposition='rejected-unsupported-witness', reason=str(error))
        else:
            require(summary != baseline, 'counterfactual accepted the unchanged semantic certificate')
            record.update(disposition='different-derived-certificate', changed_summary=summary)
        results.append(record)
    return {'actual_byte_controls': len(results), 'baseline': baseline, 'controls': results,
            'whole_target_hash_not_used_to_reject_mutants': True,
            'not_instruction_emulation': True}


def collect(binary):
    report = inspect(read_authenticated(binary))
    version = subprocess.run(['objdump', '--version'], capture_output=True, check=True).stdout.decode().splitlines()[0]
    require(version.startswith('GNU objdump'), 'GNU objdump is required')
    exports, all_rows = {}, []
    for fragment in report['fragments']:
        name, start = fragment['name'], int(fragment['start_va'], 16)
        rows, stdout = native_rows(bytes.fromhex(fragment['hex']), name, start)
        exports[name + '.objdump.txt'] = stdout
        all_rows.extend(rows)
    require([(r['va'], r['hex']) for r in sorted(all_rows, key=lambda r: int(r['va'], 16))]
            == sorted([(r['va'], r['hex']) for r in report['proof']['instruction_bindings']],
                      key=lambda r: int(r[0], 16)), 'native instruction boundaries differ from bound operators')
    report['native'] = {'version': version, 'format': 'five private raw binary snapshots, x86-64 Intel',
                        'owned_snapshot_mode': '0600', 'owned_directory_mode': '0700',
                        'selected_bytes': 251, 'selected_instructions': len(all_rows),
                        'whole_image_path_opened_by_native_tool': False,
                        'normalization_masks': [], 'captured_execution': False}
    exports['controls.json'] = canonical(counterfactuals(
        {f['name']: bytes.fromhex(f['hex']) for f in report['fragments']}, decode=True)).encode()
    exports['record.json'] = canonical(report).encode()
    exports['class-intervals.tsv'] = intervals_tsv(report['proof']['intervals']).encode()
    exports['native-rows.tsv'] = ('va\thex\tassembly\n' + ''.join(
        f"{r['va']}\t{r['hex']}\t{r['assembly']}\n" for r in sorted(all_rows, key=lambda r: int(r['va'], 16)))).encode()
    return exports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--out-dir', type=Path, required=True)
    args = parser.parse_args()
    exports = collect(args.binary)
    args.out_dir.mkdir(parents=True, exist_ok=False)
    for name, body in exports.items():
        (args.out_dir / name).write_bytes(body)
    print(canonical({'files': {name: sha(body) for name, body in sorted(exports.items())},
                     'selected_bytes': 251, 'selected_rows': 56, 'captured_execution': False}), end='')


if __name__ == '__main__':
    main()
