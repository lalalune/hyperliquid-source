#!/usr/bin/env python3
"""RE-013: visor allocator local cache-return provenance, not allocator correctness."""
import argparse
from contextlib import contextmanager
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
from fde_extents import eh_frame_records

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / 'artifacts/visor/captured/hl-visor'
SIZE = 8305392
SHA256 = '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'
START, END, SLOW = 0x70bf30, 0x70bff2, 0x70a170
BODY_SHA256 = '37b645c34271feafce1f86d72cc64b1b657e63e6bf48f16a01608f91a1909b08'
BLOCKS = {
    0x70bf30: (0x70bf41, 'f30f1efa4881ff001000000f877f000000'),
    0x70bf41: (0x70bf79, '488d1578053000488d470748c7c180f3ffff48c1e803488d35a2073000440fb60402644c8b91380300004e0314c6644c3b91400300007347'),
    0x70bf79: (0x70bfa4, '644c8b1c25000000004f8d0c404b8d04cb4801c8488b9060030000488b324c8d4208663b90700300007424'),
    0x70bfa4: (0x70bfbf, '4c898060030000644c89913803000048838068030000014889f0c3'),
    0x70bfbf: (0x70bfc0, '90'),
    0x70bfc0: (0x70bfc5, 'e9abe1ffff'),
    0x70bfc5: (0x70bfc8, '0f1f00'),
    0x70bfc8: (0x70bfd1, '663b907403000074ef'),
    0x70bfd1: (0x70bff2, '4c8980600300006644898070030000644c8991380300004883806803000001ebc9'),
}
CALLER_WINDOWS = {
    0x61da89: '4989c64c89ffff15cb701c00',
    0x61db12: '488934244889f7ff1541701c00',
    0x61dbaf: '4889efff15a86f1c00',
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


class Image:
    def __init__(self, data):
        self.data, self.sections = data, sections(data)

    def section(self, va, size):
        matches = [s for s in self.sections if s['address'] <= va and va + size <= s['address'] + s['size']]
        require(size > 0 and len(matches) == 1, 'Selected memory range lacks a unique section')
        return matches[0]

    def read(self, va, size):
        s = self.section(va, size)
        require(s['type'] != 8, 'NOBITS runtime state has no admitted initialized file bytes')
        offset = s['offset'] + va - s['address']
        require(offset + size <= len(self.data), 'Selected file-backed range is truncated')
        return offset, bytes(self.data[offset:offset + size])

    def window(self, va, size):
        offset, raw = self.read(va, size)
        return {'va': hex(va), 'file_offset': hex(offset), 'bytes': size, 'hex': raw.hex(), 'sha256': sha(raw)}


@contextmanager
def private_span(body):
    with tempfile.TemporaryDirectory(prefix='valloc-') as temporary:
        directory = Path(temporary)
        require(stat.S_IMODE(directory.stat().st_mode) == 0o700, 'Native directory is not private')
        path = directory / 'allocator.bin'
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(body)
        path.chmod(0o400)
        before = path.lstat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and stat.S_IMODE(before.st_mode) == 0o400
                and path.read_bytes() == body, 'Private native span differs')
        yield path
        require(identity(before) == identity(path.lstat()) and path.read_bytes() == body,
                'Private native span changed')


def decode(body):
    environment = {**os.environ, 'LC_ALL': 'C'}
    version = subprocess.check_output(['objdump', '--version'], env=environment, encoding='utf-8').splitlines()[0]
    require(version.startswith('GNU objdump'), 'GNU objdump is required')
    argv = ['objdump', '-D', '-b', 'binary', '-m', 'i386:x86-64', '-M', 'intel', '--show-raw-insn',
            '--insn-width=16', '--adjust-vma=' + hex(START), 'allocator.bin']
    with private_span(body) as path:
        result = subprocess.run(argv, cwd=path.parent, env=environment, capture_output=True, check=True)
        require(not result.stderr, 'Unexpected native diagnostic')
        text = result.stdout.decode('utf-8')
        rows, cursor = [], START
        for line in text.splitlines():
            match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(\S.*)$', line)
            if not match:
                continue
            va, raw = int(match[1], 16), bytes.fromhex(match[2])
            require(va == cursor and 1 <= len(raw) <= 15 and va + len(raw) <= END
                    and raw == body[va - START:va - START + len(raw)], 'Native row bytes/extent differ from admitted span')
            rows.append({'va': va, 'hex': raw.hex(), 'assembly': match[3]})
            cursor += len(raw)
        require(cursor == END and len(rows) == 37, 'Native rows do not tile the complete194-byte extent')
    return rows, text, {'tool': version, 'argv': argv, 'input_bytes': len(body), 'input_sha256': sha(body),
                        'original_ELF_path_reopened': False, 'LC_ALL': 'C', 'text_encoding': 'UTF-8/LF'}


def graph_proof(rows, body):
    for va, (end, expected) in BLOCKS.items():
        require(body[va - START:end - START].hex() == expected, f'Allocator block operands changed at {va:#x}')
    by_va = {r['va']: r for r in rows}
    require(len(by_va) == 37, 'Duplicate native instruction address')
    edges, branches = {}, []
    for row in rows:
        va, raw = row['va'], bytes.fromhex(row['hex'])
        following, mnemonic = va + len(raw), row['assembly'].split()[0]
        if raw == b'\xc3':
            successors = []
        elif raw[0] in (0xe9, 0xeb) or 0x70 <= raw[0] <= 0x7f or raw[:1] == b'\x0f' and 0x80 <= raw[1] <= 0x8f:
            offset = 2 if raw[0] == 0x0f else 1
            require(len(raw) - offset in (1, 4), 'Unsupported branch encoding')
            destination = following + int.from_bytes(raw[offset:], 'little', signed=True)
            require(destination in by_va or destination == SLOW, 'Branch leaves admitted instruction boundaries')
            conditional = raw[0] not in (0xe9, 0xeb)
            successors = [following, destination] if conditional else [destination]
            branches.append({'site': hex(va), 'target': hex(destination), 'conditional': conditional})
        else:
            require(not mnemonic.startswith(('j', 'call', 'ret', 'loop', 'sys', 'int', 'ud2', 'hlt')),
                    'Unclassified control instruction')
            successors = [following]
        edges[va] = successors
    require(len(branches) == 6 and [r['va'] for r in rows if r['assembly'] == 'ret'] == [0x70bfbe],
            'Allocator branch/return census differs')
    def paths(va, prefix=()):
        require(va not in prefix, 'Unexpected cycle in local allocator body')
        if va == SLOW or not edges[va]:
            return [prefix + (va,)]
        return [p for nxt in edges[va] for p in paths(nxt, prefix + (va,))]
    all_paths = paths(START)
    local = [p for p in all_paths if p[-1] == 0x70bfbe]
    tails = [p for p in all_paths if p[-1] == SLOW]
    require(len(local) == 2 and len(tails) == 3, 'Complete terminal-path partition differs')
    require(all(0x70bf94 in p and 0x70bfbb in p for p in local), 'Local return bypasses the cache-word load/forwarding')
    require(sum(0x70bfa4 in p for p in local) == 1 and sum(0x70bfd1 in p for p in local) == 1,
            'Accepted cursor routes differ')
    reached = {v for p in all_paths for v in p if v != SLOW}
    require(len(reached) == 35, 'Local ordinary entry projection differs')
    return {'branches': branches, 'local_return': '0x70bfbe', 'external_tail_target': hex(SLOW),
            'local_return_paths': [[hex(v) for v in p] for p in local],
            'open_tail_paths': [[hex(v) for v in p] for p in tails],
            'reachable_instruction_rows': len(reached), 'padding_rows': [hex(v) for v in by_va if v not in reached],
            'cache_word_load_dominates_every_local_return': True,
            'limits': 'Only this entry-to-local-RET or tail-transfer graph; no slow-callee, exception, cache-correctness or runtime invariant proof.'}


def derive(data):
    """Below-digest seam for actual-byte counterfactuals; public collect pins the artifact."""
    image = Image(data)
    cies, frames = eh_frame_records(data, image.sections)
    matches = [f for f in frames if f['start'] == START]
    require(matches == [{'fde': 0x25e494, 'cie': 0x22a3a0, 'start': START, 'end': END, 'lsda': None}],
            'Actual allocator FDE differs')
    cie = cies[0x22a3a0]
    require((cie['augmentation'], cie['code_align'], cie['data_align'], cie['fde_encoding'],
             cie['lsda_encoding'], cie['personality_slot']) == ('zR', 1, -8, 0x1b, None, None), 'Allocator CIE profile differs')
    body = image.read(START, END - START)[1]
    rows, native, method = decode(body)
    graph = graph_proof(rows, body)
    unsigned = lambda va, size: int.from_bytes(image.read(va, size)[1], 'little')
    signed = lambda va, size: int.from_bytes(image.read(va, size)[1], 'little', signed=True)
    terms = {'request_upper_inclusive': unsigned(0x70bf37, 4), 'round_addend': unsigned(0x70bf4b, 1),
             'index_shift': unsigned(0x70bf56, 1), 'header_bias': signed(0x70bf4f, 4),
             'used_displacement': unsigned(0x70bf67, 4), 'limit_displacement': unsigned(0x70bf73, 4),
             'class_size_stride': 8, 'header_class_stride': 24,
             'cursor_displacement': unsigned(0x70bf90, 4), 'cursor_step': unsigned(0x70bf9a, 1),
             'first_low16_displacement': unsigned(0x70bf9e, 4), 'second_low16_displacement': unsigned(0x70bfcb, 4),
             'counter_displacement': unsigned(0x70bfb6, 4), 'counter_addend': unsigned(0x70bfba, 1)}
    require(terms == {'request_upper_inclusive': 4096, 'round_addend': 7, 'index_shift': 3, 'header_bias': -3200,
                      'used_displacement': 0x338, 'limit_displacement': 0x340, 'class_size_stride': 8,
                      'header_class_stride': 24, 'cursor_displacement': 0x360, 'cursor_step': 8,
                      'first_low16_displacement': 0x370, 'second_low16_displacement': 0x374,
                      'counter_displacement': 0x368, 'counter_addend': 1}, 'Allocator address arithmetic operands differ')
    maps = []
    for site, va, size, why in ((0x70bf41, 0xa0c4c0, 513, 'ceil(request/8) for request0..4096'),
                               (0x70bf57, 0xa0c700, 2048, 'one qword for each possible unsigned classbyte0..255')):
        require(site + 7 + signed(site + 3, 4) == va, 'Actual RIP table address differs')
        s = image.section(va, size)
        require(s['type'] == 8 and s['name'] == '.bss', 'Runtime table storage is no longer observed NOBITS')
        maps.append({'va': hex(va), 'envelope_bytes': size, 'envelope_basis': why, 'section': s,
                     'file_backed': False, 'initialized_values_observed': False,
                     'limits': 'SHT_NOBITS has no captured initialized table bytes; loader-zero state is not an observed live allocator initialization.'})
    relocation = None
    for s in image.sections:
        if s['type'] != 4:
            continue
        require(s['size'] % 24 == 0, 'Incomplete RELA table')
        for offset in range(s['offset'], s['offset'] + s['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', data, offset)
            if slot == 0x7e4b60:
                require(relocation is None and (info, addend) == (8, START), 'Used allocation binding differs')
                relocation = {'slot': hex(slot), 'info': hex(info), 'addend': hex(addend),
                              'file_offset': hex(offset), 'raw': bytes(data[offset:offset + 24]).hex()}
    require(relocation is not None, 'Used allocation binding is missing')
    callers = []
    for va, expected in CALLER_WINDOWS.items():
        w = image.window(va, len(expected) // 2)
        require(w['hex'] == expected, 'Used collection size-argument/call witness differs')
        call = va + len(expected) // 2 - 6
        require(call + 6 + signed(call + 2, 4) == 0x7e4b60, 'Collection call no longer uses the actual allocator slot')
        callers.append(w)
    slow = [f for f in frames if f['start'] == SLOW]
    require(len(slow) == 1 and slow[0]['end'] == 0x70bf2b, 'Opaque slow-target metadata differs')
    slow_offset, slow_bytes = image.read(SLOW, slow[0]['end'] - SLOW)
    return ({'schema': 're013-visor-allocator-cache/1', 'task': 'RE-013', 'component': 'visor',
            'source_base': '1f8c67c63ca4794c9689235471c60297f8a5c985',
            'coordinates': 'Linked ELF VAs. A runtime load bias D is not observed; mapped code/tables and relocations require their external load conditions.',
            'target': {'bytes': len(data), 'sha256': sha(data)},
            'body': {**image.window(START, END - START), 'end': hex(END), 'fde': hex(matches[0]['fde']),
                     'cie': hex(matches[0]['cie']), 'lsda': None}, 'cie_profile': cie,
            'native': method, 'instructions': rows, 'graph': graph, 'actual_terms': terms,
            'runtime_tables': maps, 'actual_collection_binding': relocation, 'revisited_collection_callers': callers,
            'slow_target': {'fde': slow[0], 'body_metadata': {'file_offset': hex(slow_offset),
                            'bytes': len(slow_bytes), 'sha256': sha(slow_bytes)},
                            'native_decoded': False, 'postcondition': 'Unknown; tail transfer leaves RDI request unchanged'},
            'symbols': {'D': 'unobserved runtime image load bias; not assumed zero',
                        'r': 'entry RDI unsigned request', 'B': 'architectural FS base, unobserved',
                        'T': 'load64(B+0), NOT assumed equal B', 'i': '(r+7)>>3 under r<=4096; range0..512',
                        'c': 'load8(D+0xa0c4c0+i), live NOBITS table value unknown',
                        's': 'load64(D+0xa0c700+8*c), live NOBITS table value unknown',
                        'u': 'load64(B-0x948)', 'L': 'load64(B-0x940)', 'q': '(u+s) modulo2**64',
                        'H': '(T+24*c-0xc80) modulo2**64', 'p': 'load64(H+0x360), cache cursor',
                        'v': 'load64(p), returned pre-update word', 'b0': 'load16(H+0x370)', 'b1': 'load16(H+0x374)'},
            'guard_partition': [
                {'case': 'size fallback', 'condition': 'r>4096 unsigned', 'tail': hex(SLOW)},
                {'case': 'budget fallback', 'condition': 'r<=4096 and q>=L unsigned', 'tail': hex(SLOW)},
                {'case': 'fast A', 'condition': 'r<=4096 and q<L and low16(p)!=b0', 'local_return': 'v'},
                {'case': 'cursor fallback', 'condition': 'r<=4096 and q<L and low16(p)==b0==b1', 'tail': hex(SLOW),
                 'prior_read': 'load64(p) ALREADY occurred before both low16 comparisons'},
                {'case': 'fast B', 'condition': 'r<=4096 and q<L and low16(p)==b0 and low16(p)!=b1', 'local_return': 'v'}],
            'ordered_writes': {
                'fast A': [{'site': '0x70bfa4', 'width': 8, 'address': 'H+0x360', 'value': '(p+8) modulo2**64'},
                           {'site': '0x70bfab', 'width': 8, 'address': 'B-0x948', 'value': 'q'},
                           {'site': '0x70bfb3', 'width': 8, 'address': 'H+0x368', 'operation': 'Read counter NOW, add1 modulo2**64, write result'}],
                'fast B': [{'site': '0x70bfd1', 'width': 8, 'address': 'H+0x360', 'value': '(p+8) modulo2**64'},
                           {'site': '0x70bfd8', 'width': 2, 'address': 'H+0x370', 'value': 'low16(p+8)'},
                           {'site': '0x70bfe0', 'width': 8, 'address': 'B-0x948', 'value': 'q'},
                           {'site': '0x70bfe8', 'width': 8, 'address': 'H+0x368', 'operation': 'Read counter NOW, add1 modulo2**64, write result'}]},
            'proof_domain': ['Actually accessed cells have valid readable/writable intervals and ordinary valid original RET state; instruction bytes and needed bindings remain stable',
                             'Every local write preserves caller live frame/RET, immutable input/code regions and original hardware return; permissions and alias conditions are not runtime-checked',
                             'No asynchronous interference during the stated local instruction trace; actual concurrency/cache ownership is not recovered',
                             'Ordered writes may alias one another or the cache cell; no final independent pre-entry field equations or T==B identity is assumed'],
            'result_limits': ['v is not locally checked for null, alignment, requested capacity, freshness, lifetime or validity',
                              'No initialized class map/size values or nonwrapping counter-addition invariant is established',
                              'No full allocator, slow path, error, TLS ABI, target defect, target execution, reconstruction denominator or component gate claim'],
            'proof_method': 'Complete finite local graph and encoded register/address def-use, reviewed in PROOF.md; no target/emulator or general instruction interpreter'},
    {'allocator.objdump.txt': native})


def collect(data):
    require(len(data) == SIZE and sha(data) == SHA256, 'Captured visor identity differs')
    return derive(data)


def write_report(binary, output):
    binary, output = Path(binary), Path(output)
    require(not output.exists() and not output.is_symlink(), 'Output must be a new file')
    before = binary.stat()
    record, _ = collect(binary.read_bytes())
    after = binary.stat()
    identity = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns)
    require(identity(before) == identity(after) and sha(binary.read_bytes()) == SHA256,
            'Source changed before report publication')
    with output.open('x', encoding='utf-8', newline='\n') as stream:
        stream.write(json.dumps(record, indent=2) + '\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    write_report(args.binary, args.output)
    print(json.dumps({'status': 'LOCAL_CACHE_RETURN_PROVENANCE', 'native_bytes': END - START,
                      'target_executed': False, 'allocator_correctness_claimed': False}))
