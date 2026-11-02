#!/usr/bin/env python3
"""Static node115 admission and isolated public-source compilation witness.

Requires pyelftools 0.32 and Capstone 5.0.7. Never executes target/object code.
Run from this packet's final location under research/work-items/.
"""
import argparse
import bisect
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

import capstone
import elftools
from elftools.elf.elffile import ELFFile
from elftools.elf.relocation import RelocationSection

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from elf_index import sections
from fde_extents import eh_frame_records

TARGET_SHA = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SOURCE_SHA = 'd5f8444ef4e39c446d7b7807613495cf1e4cb6d98dcbb0671cacbbe4693c30df'
NAME = 'rustsecp256k1_v0_10_0_fe_impl_normalize'
STARTS = (0x631d630, 0x632c130)
SIZE = 259
B, C, P = 1 << 52, (1 << 32) + 977, (1 << 256) - (1 << 32) - 977
MASK64, MASK48 = (1 << 64) - 1, (1 << 48) - 1


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def public_source(directory=HERE):
    manifest = (directory / 'SOURCES.json').read_bytes()
    require(sha(manifest) == SOURCE_SHA, 'Public source manifest differs')
    sources = {}
    for row in json.loads(manifest)['files']:
        raw = (directory / 'third_party' / row['file']).read_bytes()
        require(len(raw) == row['bytes'] and sha(raw) == row['sha256'],
                'Public source differs: ' + row['file'])
        require(hashlib.sha1(('blob ' + str(len(raw)) + '\0').encode() + raw).hexdigest()
                == row['git_blob'], 'Public Git blob differs')
        sources[row['file']] = raw
    text = sources['field_5x52_impl.h'].decode()
    needle = 'static void ' + NAME + '('
    require(text.count(needle) == 1, 'Ambiguous public function')
    start = text.index(needle); end = text.index('\n}', start) + 2
    require('#  define SECP256K1_FE_VERIFY_FIELDS\n#endif' in sources['field.h'].decode(),
            'Non-VERIFY field expansion differs')
    require('#define VERIFY_CHECK(cond)\n#endif' in sources['util.h'].decode(),
            'Non-VERIFY assertion expansion differs')
    selected = text[start:end].encode()
    unit = (b'#define SECP256K1_FE_VERIFY_FIELDS\n#include "field_5x52.h"\n'
            b'#define VERIFY_CHECK(cond)\n' + selected + b'\n')
    return sources, unit, {'source_byte_interval': [start, end],
                           'selected_source_sha256': sha(selected),
                           'translation_unit_sha256': sha(unit)}


def mapped_bytes(raw, start, size):
    elf = ELFFile(io.BytesIO(raw))
    secs = [s for s in elf.iter_sections() if s['sh_type'] != 'SHT_NOBITS'
            and s['sh_addr'] <= start and start + size <= s['sh_addr'] + s['sh_size']]
    segs = [s for s in elf.iter_segments() if s['p_type'] == 'PT_LOAD'
            and s['p_vaddr'] <= start and start + size <= s['p_vaddr'] + s['p_filesz']]
    require(len(secs) == len(segs) == 1, 'Ambiguous or unmapped target interval')
    sec, seg = secs[0], segs[0]
    require(sec['sh_flags'] & 4 and seg['p_flags'] & 1, 'Non-executable target interval')
    off = sec['sh_offset'] + start - sec['sh_addr']
    require(off == seg['p_offset'] + start - seg['p_vaddr'], 'Section/load mapping differs')
    return raw[off:off + size], {'start_va': start, 'end_va_exclusive': start + size,
                               'file_offset': off, 'section': sec.name,
                               'section_flags': sec['sh_flags'], 'load_flags': seg['p_flags']}


def compare(a, b):
    return {'target_bytes': len(a), 'source_bytes': len(b), 'extent_equal': len(a) == len(b),
            'raw_equal': a == b, 'normalization_masks': [],
            'differing_offsets': [i for i, (x, y) in enumerate(zip(a, b)) if x != y]}


def disassemble(raw, start):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    ins = list(md.disasm(raw, start))
    require(sum(i.size for i in ins) == len(raw), 'Incomplete linear instruction decode')
    return ins


def instruction_text(ins):
    return '\n'.join(f'{i.address:016x}: {i.bytes.hex():24} {i.mnemonic} {i.op_str}'
                     for i in ins) + '\n'


def admit_target(raw, output=None):
    require(len(raw) == 105896032 and sha(raw) == TARGET_SHA, 'Full node115 identity differs')
    require(elftools.__version__ == '0.32' and capstone.__version__ == '5.0.7',
            'Expected pyelftools 0.32 and Capstone 5.0.7')
    secs = sections(raw); cies, fdes = eh_frame_records(raw, secs)
    fdes = sorted(fdes, key=lambda f: f['start']); starts = [f['start'] for f in fdes]
    elf = ELFFile(io.BytesIO(raw)); text = elf.get_section_by_name('.text')
    text_bytes, text_va = text.data(), text['sh_addr']
    rows, bodies = [], []
    for va in STARTS:
        body, mapping = mapped_bytes(raw, va, SIZE)
        fde = [f for f in fdes if f['start'] == va]
        require(len(fde) == 1 and fde[0]['end'] == va + SIZE, 'Unique complete FDE differs')
        fde = fde[0]; frame = elf.get_section_by_name('.eh_frame')
        frame_raw = frame.data()
        def frame_record(address):
            off = address - frame['sh_addr']; n = struct.unpack_from('<I', frame_raw, off)[0]
            return {'va': address, 'bytes_hex': frame_raw[off:off + 4 + n].hex()}
        ins = disassemble(body, va)
        require(ins[-1].mnemonic == 'ret' and sum(i.mnemonic == 'ret' for i in ins) == 1,
                'Unexpected return structure')
        require(not any(i.mnemonic.startswith(('j', 'call', 'loop')) for i in ins),
                'Unexpected branch or helper')
        require(not any('rip' in i.op_str for i in ins), 'Unexpected static-data reference')
        pad, _ = mapped_bytes(raw, va + SIZE, 13)
        require(pad == b'\xcc' * 13 and any(f['start'] == va + SIZE + 13 for f in fdes),
                'Following padding/function boundary differs')
        direct = []
        # This is a full .text E8/E9 relative-pattern scan, not an indirect-xref census.
        for opcode, mnemonic in ((0xe8, 'call'), (0xe9, 'jmp')):
            pos = 0
            while True:
                pos = text_bytes.find(bytes([opcode]), pos)
                if pos < 0:
                    break
                site = text_va + pos
                if pos + 5 <= len(text_bytes) and site + 5 + struct.unpack_from('<i', text_bytes, pos + 1)[0] == va:
                    index = bisect.bisect_right(starts, site) - 1
                    require(index >= 0 and site < fdes[index]['end'], 'Unqualified direct xref candidate')
                    parent = fdes[index]
                    caller, _ = mapped_bytes(raw, parent['start'], parent['end'] - parent['start'])
                    decoded = disassemble(caller, parent['start'])
                    require(any(i.address == site and i.mnemonic == mnemonic and i.size == 5 for i in decoded),
                            'Direct xref is not an instruction boundary')
                    direct.append({'site_va': site, 'kind': mnemonic, 'caller_fde': parent,
                                   'caller_body_sha256': sha(caller)})
                    if output:
                        (output / f'caller-{parent["start"]:x}.txt').write_text(instruction_text(decoded))
                pos += 1
        relocations, slots, counts = [], [], {}
        for section in elf.iter_sections():
            if isinstance(section, RelocationSection):
                counts[section.name] = section.num_relocations()
                for relocation in section.iter_relocations():
                    r = relocation.entry
                    if va <= r['r_offset'] < va + SIZE:
                        relocations.append(dict(r))
                    if r.get('r_addend') == va:
                        slots.append(dict(r))
        require(not relocations, 'Unexpected target code relocation')
        rows.append({**mapping, 'body_sha256': sha(body), 'body_hex': body.hex(),
                     'fde': fde, 'fde_record': frame_record(fde['fde']),
                     'cie_record': frame_record(fde['cie']), 'padding_int3_bytes': 13,
                     'instruction_count': len(ins), 'helper_calls': 0, 'rip_references': 0,
                     'direct_e8_e9_xrefs': direct, 'code_relocations': relocations,
                     'relocation_addends_naming_entry': slots, 'relocation_counts': counts})
        bodies.append(body)
        if output:
            (output / f'target-{va:x}.txt').write_text(instruction_text(ins))
    require(bodies[0] == bodies[1], 'Two target bodies differ')
    return bodies, {'target_sha256': TARGET_SHA, 'target_bytes': len(raw),
                    'fde_count': len(fdes), 'text_scan_bytes': len(text_bytes), 'functions': rows,
                    'target_bodies_equal': True,
                    'xref_limit': 'E8/E9 patterns boundary-qualified in enclosing FDE; no indirect, short-branch or complete reference census.'}


def object_body(raw):
    elf = ELFFile(io.BytesIO(raw))
    require(elf['e_type'] == 'ET_REL' and elf['e_machine'] == 'EM_X86_64', 'Wrong object kind')
    symtab = elf.get_section_by_name('.symtab')
    syms = [s for s in symtab.iter_symbols() if s.name == NAME]
    require(len(syms) == 1, 'Ambiguous source function')
    sym = syms[0]; section = elf.get_section(sym['st_shndx'])
    require(sym['st_info']['type'] == 'STT_FUNC' and sym['st_info']['bind'] == 'STB_LOCAL',
            'Wrong source symbol')
    require(sym['st_value'] == 0 and sym['st_size'] == section['sh_size'], 'Incomplete source extent')
    require(section['sh_flags'] & 6 == 6, 'Nonallocated/nonexecutable source section')
    relocations = []
    for relsec in elf.iter_sections():
        if isinstance(relsec, RelocationSection):
            require(relsec['sh_info'] != sym['st_shndx'] or relsec.num_relocations() == 0,
                    'Source code has relocations')
            relocations.append({'section': relsec.name, 'entries': [dict(r.entry) for r in relsec.iter_relocations()]})
    body = section.data()
    return body, {'object_sha256': sha(raw), 'object_bytes': len(raw), 'body_sha256': sha(body),
                  'symbol': NAME, 'symbol_bytes': sym['st_size'], 'section': section.name,
                  'object_relocations': relocations, 'code_relocations': []}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    parser.add_argument('--gcc', default='gcc')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(not os.path.lexists(args.output), 'Output exists')
    sources, unit, selection = public_source()
    gcc = shutil.which(args.gcc); require(gcc is not None, 'GCC unavailable')
    raw = args.binary.read_bytes(); args.output.mkdir(parents=True)
    bodies, admission = admit_target(raw, args.output)
    variants = [('build-a', '-fcf-protection=none', unit),
                ('build-b', '-fcf-protection=none', unit),
                ('cet-control', '-fcf-protection=branch', unit),
                ('constant-control', '-fcf-protection=none', unit.replace(b'0x1000003D1ULL', b'0x1000003D0ULL'))]
    rows, objects = [], []
    for label, cet, code in variants:
        directory = args.output / label; directory.mkdir()
        (directory / 'probe.c').write_bytes(code)
        (directory / 'field_5x52.h').write_bytes(sources['field_5x52.h'])
        command = [gcc, '-std=c99', '-O2', cet, '-fkeep-static-functions', '-c', 'probe.c', '-o', 'probe.o']
        process = subprocess.run(command, cwd=directory, capture_output=True)
        (directory / 'compiler.stdout').write_bytes(process.stdout)
        (directory / 'compiler.stderr').write_bytes(process.stderr)
        require(process.returncode == 0, 'Compilation failed: ' + label)
        obj = (directory / 'probe.o').read_bytes(); body, metadata = object_body(obj)
        (directory / 'code.bin').write_bytes(body)
        (args.output / (label + '.txt')).write_text(instruction_text(disassemble(body, 0)))
        objects.append(obj)
        rows.append({'variant': label, 'command': command, 'exit': process.returncode,
                     'translation_unit_sha256': sha(code), **metadata,
                     'comparisons': [compare(target, body) for target in bodies]})
    require(objects[0] == objects[1], 'Fresh object builds differ')
    require(all(c['raw_equal'] for r in rows[:2] for c in r['comparisons']), 'Positive comparison fails')
    require(not any(c['raw_equal'] for r in rows[2:] for c in r['comparisons']), 'Negative build matches')
    controls = []
    for index, function in enumerate(admission['functions']):
        bad = bytearray(raw); offset = function['file_offset'] + 2; bad[offset] ^= 1
        try:
            admit_target(bytes(bad))
        except ValueError as error:
            reason = str(error)
        else:
            raise ValueError('Corrupted full target admitted')
        changed = bytes(bad[function['file_offset']:function['file_offset'] + SIZE])
        comparison = compare(changed, bodies[index])
        require(not comparison['raw_equal'], 'Raw corruption comparison matched')
        controls.append({'origin': 'UNQUALIFIED_COUNTERFACTUAL', 'function_va': function['start_va'],
                         'relative_offset': 2, 'xor': 1, 'full_input_sha256': sha(bytes(bad)),
                         'admission_error': reason, 'raw_comparison': comparison})
    require(not compare(bodies[0], bodies[0][:-1])['raw_equal'], 'Truncation accepted')
    source_control_dir = args.output / 'source-control'
    shutil.copytree(HERE / 'third_party', source_control_dir / 'third_party')
    shutil.copyfile(HERE / 'SOURCES.json', source_control_dir / 'SOURCES.json')
    changed_source = source_control_dir / 'third_party/field_5x52_impl.h'
    changed_source.write_bytes(changed_source.read_bytes().replace(b'0x1000003D1ULL', b'0x1000003D0ULL'))
    try:
        public_source(source_control_dir)
    except ValueError as error:
        source_error = str(error)
    else:
        raise ValueError('Corrupted public source admitted')
    record = {'admission': admission, 'selection': selection, 'builds': rows,
              'compiler_version': subprocess.check_output([gcc, '--version'], text=True).splitlines()[0],
              'compiler_target': subprocess.check_output([gcc, '-dumpmachine'], text=True).strip(),
              'compiler_sha256': sha(Path(gcc).read_bytes()), 'source_manifest_sha256': SOURCE_SHA,
              'two_complete_objects_equal': True, 'target_corruptions': controls,
              'source_corruption': {'origin': 'UNQUALIFIED_COUNTERFACTUAL',
                                    'mutated_file_sha256': sha(changed_source.read_bytes()),
                                    'admission_error': source_error, 'compiler_invoked': False},
              'truncation_control': compare(bodies[0], bodies[0][:-1]),
              'captured_or_compiled_code_executed': False, 'progress_gate_requested': False}
    (args.output / 'record.json').write_text(json.dumps(record, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'target_functions': 2, 'raw_equal_bytes_each': SIZE,
                      'fresh_identical_builds': 2, 'negative_builds': 2,
                      'full_target_corruptions_rejected': 2}))


if __name__ == '__main__':
    main()
