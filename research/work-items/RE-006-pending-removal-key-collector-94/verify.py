#!/usr/bin/env python3
"""Static evidence replay; never executes or evaluates captured instructions."""
import argparse
from collections import Counter
import hashlib
import itertools
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import fde_extents

SHA = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET = ROOT / 'artifacts/node/94/hl-node'
COLLECTOR = (0x4450210, 0x44503d3)
CALLER = (0x4311140, 0x4314d9f)
BUILDER = (0x49273c0, 0x49274a4)
CORRIDOR = (0x4312aa1, 0x4312bae)
# Every entry is an independently inspected operand/control obligation.
PINS = (
    ('empty difference', 0x445022a, '4929f5741b'),
    ('allocation bytes = row-span / 4', 0x4450232, '4d89f449c1ec024c89e7'),
    ('small allocation gate', 0x445023c, '4983fd1c761c'),
    ('empty output leaves pointer unspecified', 0x445024a, '48c7030000000048c7431000000000e9cf000000'),
    ('row count and residual', 0x4450275, '49c1ee05498d4eff4489f083e0034883f9037304'),
    ('four row projection', 0x44502a0, '488b7ea049893ccf488b7ec049897ccf08488b7ee049897ccf10488b3e49897ccf18'),
    ('four row progress', 0x44502c2, '4883c1044883ee804839ca75d1'),
    ('tail index scaling', 0x44502d8, '48c1e1054801cdc1e00331c9'),
    ('single row projection and progress', 0x44502f0, '488b748d004889340a4883c1084839c875ee'),
    ('one row bypasses sort', 0x4450302, '4983fd207537'),
    ('iterator descriptor', 0x4450308, '4b8d04f74c897c24084c897c24104c897424184889442420'),
    ('set builder edge', 0x4450328, 'e893704d00'),
    ('twenty versus twenty-one', 0x445033f, '4981fda0020000735c'),
    ('unsigned adjacent order', 0x445036a, '4c8b41f8488b314c39c673e7'),
    ('unsigned backward order', 0x4450383, '4d8b443ff04883c7f84c39c672e8'),
    ('delegated sort arguments and call', 0x44503a4, '488d5424084c89ff4c89f6ff159b4b3201'),
    ('caller 32-byte end computation', 0x4312aa1, '488bb42498020000488b9424a002000048c1e2054801f2'),
    ('caller collector edge', 0x4312ac8, 'e843d71300'),
    ('caller next row', 0x4312b2f, '4983c7204939df7476'),
    ('caller key and user', 0x4312b38, '498b2f418b4718898424e0090000410f1047080f298424d0090000'),
    ('caller relation delegate', 0x4312b8f, 'e85c26ffff'),
    ('caller reason dispatch', 0x4312b94, '410fb6471c83f8020f8465ffffff83f8017488b001e95bffffff'),
)


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def render(value):
    return json.dumps(value, sort_keys=True, indent=2) + '\n'


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)
        names = [x['name'] for x in self.sections]
        require(len(names) == len(set(names)), 'duplicate section names')

    def offset(self, va, length):
        matches = [s for s in self.sections if s['type'] != 8 and
                   s['address'] <= va and va + length <= s['address'] + s['size']]
        require(length > 0 and len(matches) == 1, f'ambiguous mapping {va:#x}+{length}')
        return matches[0]['offset'] + va - matches[0]['address']

    def read(self, va, length):
        pos = self.offset(va, length)
        return bytes(self.data[pos:pos + length])

    def record(self, va):
        length = struct.unpack('<I', self.read(va, 4))[0] + 4
        return self.window(va, va + length)

    def window(self, start, end):
        raw = self.read(start, end - start)
        return dict(start=hex(start), end=hex(end), file_offset=hex(self.offset(start, len(raw))),
                    bytes=len(raw), sha256=sha(raw), raw_hex=raw.hex())


def local_obligations(image):
    for name, va, expected in PINS:
        require(image.read(va, len(bytes.fromhex(expected))) == bytes.fromhex(expected),
                'operand/control mismatch: ' + name)


def qualify_extent(extents, start, end):
    fdes = [x for x in extents if x['start'] == start]
    require(len(fdes) == 1 and fdes[0]['end'] == end, f'FDE extent mismatch: {start:#x}')
    return fdes[0]


def decode_output(text, start, end):
    rows = []
    for line in text.splitlines():
        match = re.match(r'^\s*([0-9a-fA-F]+):\s*((?:[0-9a-fA-F]{2}[ \t]+)+)(.*)$', line)
        if match:
            va = int(match[1], 16)
            raw = bytes.fromhex(match[2])
            rows.append((va, raw, match[3].strip()))
    require(bool(rows), 'empty disassembly')
    pos = start
    for va, raw, _ in rows:
        require(va == pos, f'noncontiguous instruction partition at {pos:#x}')
        pos += len(raw)
    require(pos == end, f'decoded end {pos:#x} != FDE end {end:#x}')
    return rows


def native(image, start, end, llvm):
    common = ['-d', f'--start-address={start}', f'--stop-address={end}']
    commands = [ ['objdump', *common, '-M', 'intel', '--insn-width=16', str(TARGET)],
                 [llvm, *common, '--x86-asm-syntax=intel', '--print-imm-hex', str(TARGET)] ]
    streams, parts = [], []
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        stream = result.stdout.replace(str(TARGET), '<authenticated-node94>')
        streams.append(stream)
        rows = decode_output(stream, start, end)
        require(b''.join(raw for _, raw, _ in rows) == image.read(start, end - start), 'decode bytes differ')
        parts.append(rows)
    require([(a, b) for a, b, _ in parts[0]] == [(a, b) for a, b, _ in parts[1]], 'native partitions disagree')
    return streams, parts[0]


def graph(rows, allow_external=False):
    starts = {va for va, _, _ in rows}
    out, calls = [], []
    for va, raw, text in rows:
        after = va + len(raw)
        dest = None
        if raw[0] in (0xe8, 0xe9):
            dest = after + struct.unpack('<i', raw[1:5])[0]
        elif raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f:
            dest = after + struct.unpack('<b', raw[1:2])[0]
        elif raw[:1] == b'\x0f' and 0x80 <= raw[1] <= 0x8f:
            dest = after + struct.unpack('<i', raw[2:6])[0]
        if raw[0] == 0xe8:
            calls.append(dict(site=hex(va), target=hex(dest), kind='direct', raw_hex=raw.hex()))
        elif raw[:2] == b'\xff\x15':
            slot = after + struct.unpack('<i', raw[2:6])[0]
            calls.append(dict(site=hex(va), slot=hex(slot), kind='indirect', raw_hex=raw.hex()))
        conditional = 0x70 <= raw[0] <= 0x7f or (raw[:1] == b'\x0f' and 0x80 <= raw[1] <= 0x8f)
        if conditional or raw[0] in (0xe9, 0xeb):
            require(dest in starts or allow_external, f'branch leaves local FDE or targets interior byte {va:#x}')
            out.append(dict(site=hex(va), target=hex(dest), fallthrough=hex(after) if conditional else None,
                            target_inside_export=dest in starts, raw_hex=raw.hex(), native=text))
    return out, calls


def local_cfg(rows):
    branches, _ = graph(rows)
    by_site = {int(x['site'], 16): x for x in branches}
    nodes = []
    for va, raw, _ in rows:
        if va in by_site:
            edge = by_site[va]
            successors = [edge['target']] + ([edge['fallthrough']] if edge['fallthrough'] else [])
        elif raw == b'\xc3' or raw == b'\x0f\x0b':
            successors = []
        else:
            successors = [hex(va + len(raw))]
        # CALL fallthrough is conditional on normal return. This is not a
        # no-throw or no-return contract for the called code.
        nodes.append(dict(site=hex(va), bytes=len(raw), successors=successors,
                          fallthrough_requires_normal_return=raw[0] == 0xe8 or raw[:2] == b'\xff\x15'))
    return nodes


def project_model(rows):
    """Independently authored value projection, NOT a target instruction evaluator."""
    require(len(rows) % 32 == 0, 'partial row')
    count = len(rows) // 32
    result = []
    block_end = count - count % 4
    for i in range(0, block_end, 4):
        result.extend(struct.unpack_from('<Q', rows, (i + j) * 32)[0] for j in range(4))
    for i in range(block_end, count):
        result.append(struct.unpack_from('<Q', rows, i * 32)[0])
    if count <= 20:
        for i in range(1, count):
            key, j = result[i], i
            while j and key < result[j - 1]:
                result[j] = result[j - 1]
                j -= 1
            result[j] = key
    return result, ('empty' if count == 0 else 'single' if count == 1 else 'inline' if count <= 20 else 'delegate')


def synthetic_controls():
    # The oracle reads rows independently, without block/remainder decomposition.
    counts = list(range(0, 25)) + [31, 32, 33, 63, 64, 65, 127, 255, 1024, 4096]
    cases = []
    for n in counts:
        words = [((i * 0x9e3779b97f4a7c15) ^ (i << 61)) & ((1 << 64) - 1) for i in range(n)]
        if n >= 5:
            words[:5] = [2**64 - 1, 0, 2**63, 1, 2**63]
        raw = b''.join(struct.pack('<QQQQ', key, i ^ 0x5555, 2**64 - 1 - i, i + 17) for i, key in enumerate(words))
        output, path = project_model(raw)
        expected = sorted(words) if n <= 20 else words
        require(output == expected, 'projection/oracle mismatch')
        require(Counter(output) == Counter(words), 'projection loses duplicates')
        # Tail fields, including reason, must not influence the projection.
        changed = b''.join(raw[i:i+8] + bytes([0xa5]) * 24 for i in range(0, len(raw), 32))
        require(project_model(changed) == (output, path), 'metadata affects keys')
        cases.append(dict(rows=n, path=path, input_sha256=sha(raw), output_sha256=sha(b''.join(struct.pack('<Q', x) for x in output))))
    permutations = 0
    for order in itertools.permutations([0, 1, 2, 2**63 - 1, 2**63, 2**64 - 1]):
        raw = b''.join(struct.pack('<Q', x) + bytes(24) for x in order)
        require(project_model(raw)[0] == sorted(order), 'unsigned permutation mismatch')
        permutations += 1
    rejected = False
    try:
        project_model(bytes(33))
    except ValueError:
        rejected = True
    require(rejected, 'partial row accepted')
    unsigned_words = [2**64 - 1, 0, 2**63, 1, 2**63]
    signed_wrong = sorted(unsigned_words, key=lambda x: x if x < 2**63 else x - 2**64)
    require(signed_wrong != sorted(unsigned_words), 'signed comparator control ineffective')
    raw = b''.join(struct.pack('<QQQQ', key, i + 200, i + 300, i + 400)
                   for i, key in enumerate(unsigned_words))
    wrong_stride = [struct.unpack_from('<Q', raw, i * 24)[0] for i in range(len(unsigned_words))]
    require(sorted(wrong_stride) != sorted(unsigned_words), 'wrong stride control ineffective')
    for count, expected_path in [(0, 'empty'), (1, 'single'), (2, 'inline'), (20, 'inline'), (21, 'delegate')]:
        require(project_model(bytes(count * 32))[1] == expected_path, 'path threshold control')
    return dict(cases=cases, unsigned_permutations=permutations, malformed_row_rejected=True,
                wrong_signed_comparator_rejected=True, wrong_row_stride_rejected=True,
                scope='Independent model and arithmetic/projection oracle only; no target execution/evaluation or delegate semantics.')


def collect(llvm):
    data = TARGET.read_bytes()
    require(len(data) == 91774280 and sha(data) == SHA, 'target identity mismatch')
    image = Image(data)
    local_obligations(image)
    _, extents, _ = fde_extents(data)
    files, functions = {}, []
    for label, (start, end) in [('collector', COLLECTOR), ('selected-caller', CALLER), ('credited-set-builder', BUILDER)]:
        fde = qualify_extent(extents, start, end)
        export_start, export_end = CORRIDOR if label == 'selected-caller' else (start, end)
        streams, rows = native(image, export_start, export_end, llvm)
        branches, calls = graph(rows, allow_external=label == 'selected-caller')
        body = image.window(start, end)
        if label == 'selected-caller':
            del body['raw_hex']  # Full caller digest/bounds; only corridor bytes are exported.
        functions.append(dict(label=label, body=body, native_export=image.window(export_start, export_end),
                              unwind={k: hex(v) if isinstance(v, int) else v for k, v in fde.items()},
                              fde_record=image.record(fde['fde']), cie_record=image.record(fde['cie']),
                              instructions=len(rows), branches=branches, calls=calls))
        if label == 'collector':
            functions[-1]['normal_cfg'] = local_cfg(rows)
        for provider, stream in zip(('gnu', 'llvm'), streams):
            files[f'raw/{label}-{provider}.txt'] = stream
    # Bind the selected call plus the whole local corridor, independently of the whole-caller hash.
    corridor = image.window(*CORRIDOR)
    relocs = []
    wanted = {int(c['slot'], 16) for c in functions[0]['calls'] if 'slot' in c}
    for sec in image.sections:
        if sec['type'] == 4:
            require(sec['size'] % 24 == 0, 'partial relocation')
            for pos in range(sec['offset'], sec['offset'] + sec['size'], 24):
                slot, info, addend = struct.unpack_from('<QQq', data, pos)
                if slot in wanted:
                    relocs.append(dict(slot=hex(slot), info=hex(info), addend=hex(addend),
                                       record_file_offset=hex(pos), raw_hex=data[pos:pos+24].hex()))
    require({int(r['slot'], 16) for r in relocs} == wanted and len(relocs) == len(wanted), 'missing/duplicate collector relocation')
    controls = []
    for name, va, expected in PINS:
        changed = bytearray(data)
        changed[image.offset(va, 1)] ^= 1
        try:
            local_obligations(Image(changed))
        except ValueError as error:
            controls.append(dict(name=name, va=hex(va), outcome='rejected below SHA admission', reason=str(error)))
        else:
            raise ValueError('local corruption survived: ' + name)
    # Check FDE range corruption through the real parser, separately from operand pins.
    collector_fde = next(x for x in extents if x['start'] == COLLECTOR[0])
    changed = bytearray(data)
    changed[image.offset(collector_fde['fde'] + 12, 1)] ^= 1
    _, corrupted, _ = fde_extents(changed)
    try:
        qualify_extent(corrupted, *COLLECTOR)
    except ValueError as error:
        controls.append(dict(name='FDE range corruption', outcome='rejected below SHA admission', reason=str(error)))
    else:
        raise ValueError('FDE corruption survived expected endpoint check')
    versions = {name: subprocess.check_output([program, '--version'], text=True).splitlines()[0]
                for name, program in [('gnu', 'objdump'), ('llvm', llvm)]}
    files['records.json'] = render(dict(task='RE-006', component='orderbook', target_sha256=SHA,
        target_bytes=len(data), base='56c0ec672bd8fdcfaa80f2db700a61e6240b3663',
        coordinates='linked ELF virtual addresses; each window also retains exact section-derived file offset',
        functions=functions, selected_caller_corridor=corridor, collector_relocations=relocs,
        native_versions=versions, normalization_masks=[],
        scope='Complete collector/credited-builder native partitions and selected caller corridor; full caller FDE/digest only. Collector local normal branches validated; corridor outward edges recorded. Exception LSDA edges and external helper semantics remain open.'))
    files['controls.json'] = render(dict(local_corruptions=controls, synthetic=synthetic_controls()))
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--write', action='store_true', help='regenerate this authored packet')
    parser.add_argument('--llvm', default=os.environ.get('LLVM_OBJDUMP', 'llvm-objdump'))
    args = parser.parse_args()
    files = collect(args.llvm)
    for name, value in files.items():
        if args.write:
            (HERE / name).parent.mkdir(parents=True, exist_ok=True)
            (HERE / name).write_text(value)
        else:
            require((HERE / name).read_text() == value, 'stale evidence: ' + name)
    print(f'Static replay passed: {len(files)} exports; {len(PINS)+1} local corruption controls; 35 row counts and 720 unsigned permutations. No target execution/evaluation.')


if __name__ == '__main__':
    main()
