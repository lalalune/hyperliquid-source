#!/usr/bin/env python3
"""Offline, licensed-source correspondence for two selected capture intervals.

This builds only owned ET_REL objects, never executes them or a captured target,
and establishes no original archive/version/compiler or runtime identity.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile

from elf_index import sections

ROOT = Path(__file__).resolve().parents[1]
PACKET = ROOT / 'research/work-items/RE-002-zstd-asm-correspondence'
SOURCE_ROOT = PACKET / 'third_party'
TARGETS = {
    '94': (91774280, '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
           [('A', 0x5631580, 0x56319fd), ('B', 0x56319fd, 0x5631ef2)]),
    '115': (105896032, 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301',
            [('A', 0x62e4700, 0x62e4b7d), ('B', 0x62e4b7d, 0x62e5072)]),
}
SOURCE_FILES = {'source': 'lib/decompress/huf_decompress_amd64.S',
                'header': 'lib/common/portability_macros.h', 'license': 'LICENSE'}
SOURCE_PINS = {
    '1.5.6': {
        'source': (15018, 'b98dce6a6e26ebf599cbf639640a0539896e1ab789c430dffa213f27c5bc81a8'),
        'header': (4487, '06ee0244cb0b07b6a38fb570387ca4abecbcf7fc1e90670d8b00e5454d4cbaac'),
        'license': (1549, '7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8')},
    '1.5.7': {
        'source': (15150, '7fe53316261517a8f877b793f3bfba8305a3f9ff05c5947f1d709aaff346f1dc'),
        'header': (4916, '75e2b43968b70decc6bd17876833be04894035594ddc1e745cd6b70be8265637'),
        'license': (1549, '7055266497633c9025b777c78eb7235af13922117480ed5c674677adc381c9d8')},
}
LABELS = ['HUF_decompress4X1_usingDTable_internal_fast_asm_loop',
          'HUF_decompress4X2_usingDTable_internal_fast_asm_loop']
TOOL_PINS = {
    'cc': 'a23ecab8ff08f09ad8c80602c2c5df7f49e09c25905cb8975902e101bf72635f',
    'cc1': '02675980109a4a5496cddf67d5286de57942759edc830deaa525e36f9a2a0291',
    'as': '07dd8551ea0aa065975e4dddb8e1bb7dc308d12d54eca22c3858db79467c7cb9',
    'objdump': '96afb8521834982d0e711b5d6e9785252bf82129fb0106b93a6bd54d83fae11f',
    'objcopy': '403f90bbd5d26c8ab9a2ad51f56255b812e8858a83aa8740ee71791071ddb580',
    'readelf': '4a387d80a70e6e97ef940a666fab59d5c38e7cf19ff907192fa983cb8505a7de',
}
HEADER_PINS = {'cet.h': '9d2ca23111e1d5c52ccb05965e3418b7babdbf313d70acacab218d5c385f1649',
               'stdc-predef.h': '82975831ea2d1f95b60225f37ddd6130225f0c3de2318674cb178fea661ad87b'}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def admit_file(path, size, sha256):
    with Path(path).open('rb') as stream:
        if os.fstat(stream.fileno()).st_size != size:
            raise ValueError('Wrong admitted file size: ' + str(path))
        data = stream.read(size + 1)
    if len(data) != size or digest(data) != sha256:
        raise ValueError('Wrong admitted file digest: ' + str(path))
    return data  # All later target/source readers use this immutable object.


def admit_sources(source_root=None):
    folder = Path(source_root) if source_root is not None else SOURCE_ROOT
    return {version: {key: admit_file(folder / ('zstd-' + version) / SOURCE_FILES[key], size, sha)
                      for key, (size, sha) in pins.items()}
            for version, pins in SOURCE_PINS.items()}


def read_targets(paths=None):
    paths = paths or {r: ROOT / 'artifacts/node' / r / 'hl-node' for r in TARGETS}
    result = {}
    for release, (size, sha, spans) in TARGETS.items():
        image = admit_file(paths[release], size, sha)
        secs = sections(image)
        phoff = struct.unpack_from('<Q', image, 32)[0]
        width, count = struct.unpack_from('<HH', image, 54)
        if width != 56 or not count or phoff + width * count > len(image):
            raise ValueError('Unsupported target program-header table')
        loads = []
        for index in range(count):
            typ, flags, off, va, _, n, memory_n, _ = struct.unpack_from('<IIQQQQQQ', image, phoff + width * index)
            if typ == 1:
                if n > memory_n or off + n > len(image):
                    raise ValueError('Invalid target PT_LOAD')
                loads.append({'flags': flags, 'offset': off, 'address': va, 'size': n})
        selected = {}
        for label, start, end in spans:
            owners = [s for s in secs if s['type'] != 8 and s['address'] <= start
                      and end <= s['address'] + s['size']]
            if len(owners) != 1 or owners[0]['name'] != '.text' or not owners[0]['flags'] & 4:
                raise ValueError('Target interval is not uniquely executable text')
            section = owners[0]
            off = section['offset'] + start - section['address']
            mapped = [p for p in loads if p['offset'] <= off and off + end - start <= p['offset'] + p['size']]
            if len(mapped) != 1 or not mapped[0]['flags'] & 1 or mapped[0]['address'] + off - mapped[0]['offset'] != start:
                raise ValueError('Target file/section/PT_LOAD coordinates disagree')
            raw = image[off:off + end - start]
            selected[label] = {'start': start, 'end': end, 'offset': off, 'sha256': digest(raw),
                               'section': section, 'load_segment': mapped[0], 'raw': raw}
        result[release] = {'sha256': sha, 'bytes': size, 'candidates': selected}
        del image
    return result


def parse_object(data):
    """Parse one immutable own ET_REL object; never infer sizes from STT_FUNC."""
    if type(data) is not bytes or len(data) < 64 or data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('Expected immutable ELF64-LE own-object bytes')
    if struct.unpack_from('<HH', data, 16) != (1, 62):
        raise ValueError('Expected x86-64 ET_REL own object')
    shoff = struct.unpack_from('<Q', data, 40)[0]
    width, count, names_index = struct.unpack_from('<HHH', data, 58)
    if width != 64 or not count or names_index >= count or shoff + width * count > len(data):
        raise ValueError('Invalid own-object section table')
    raw = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + width * i) for i in range(count)]

    def section_bytes(row):
        if row[1] == 8 or row[4] + row[5] > len(data):
            raise ValueError('Own-object section is not file backed')
        return data[row[4]:row[4] + row[5]]

    def string(table, at):
        if at >= len(table):
            raise ValueError('Own-object string offset outside table')
        end = table.find(b'\0', at)
        if end < 0:
            raise ValueError('Unterminated own-object string')
        return table[at:end].decode('ascii')

    names = section_bytes(raw[names_index])
    ss = []
    for i, row in enumerate(raw):
        if row[1] != 8 and row[4] + row[5] > len(data):
            raise ValueError('Own-object section outside file')
        ss.append({'index': i, 'name': string(names, row[0]), 'type': row[1], 'flags': row[2],
                   'address': row[3], 'offset': row[4], 'size': row[5], 'link': row[6],
                   'info': row[7], 'alignment': row[8], 'entrySize': row[9]})
    texts = [s for s in ss if s['name'] == '.text']
    tables = [s for s in ss if s['type'] == 2]
    if len(texts) != 1 or len(tables) != 1:
        raise ValueError('Ambiguous own-object text or symbol table')
    text, table = texts[0], tables[0]
    if text['type'] != 1 or not text['flags'] & 4 or text['address'] != 0:
        raise ValueError('Unexpected own-object executable text coordinates')
    if table['link'] >= count or table['entrySize'] != 24 or table['size'] % 24:
        raise ValueError('Invalid own-object symbol table')
    strings = section_bytes(raw[table['link']])
    symbols = []
    for off in range(table['offset'], table['offset'] + table['size'], 24):
        name, info, other, index, value, size = struct.unpack_from('<IBBHQQ', data, off)
        symbols.append({'name': string(strings, name), 'binding': info >> 4, 'type': info & 15,
                        'visibility': other & 3, 'section': index, 'value': value, 'size': size})
    chosen = []
    for name in LABELS:
        aliases = []
        for alias in (name, '_' + name):
            found = [s for s in symbols if s['name'] == alias]
            if len(found) != 1:
                raise ValueError('Missing or ambiguous actual source label: ' + alias)
            symbol = found[0]
            if (symbol['section'], symbol['binding'], symbol['visibility'], symbol['type'], symbol['size']) != (text['index'], 1, 2, 0, 0):
                raise ValueError('Source label section/visibility/NOTYPE/zero-size attributes changed')
            chosen.append(symbol)
            aliases.append(symbol['value'])
        if aliases[0] != aliases[1]:
            raise ValueError('Actual source aliases disagree')
    start, split = chosen[0]['value'], chosen[2]['value']
    if start != 0 or not start < split < text['size']:
        raise ValueError('Unexpected source-label layout; no prefix or padding trimming')
    relocations = []
    for sec in ss:
        if sec['type'] not in (4, 9) or sec['info'] != text['index']:
            continue
        wanted = 24 if sec['type'] == 4 else 16
        if sec['entrySize'] != wanted or sec['size'] % wanted:
            raise ValueError('Malformed text relocation section')
        for off in range(sec['offset'], sec['offset'] + sec['size'], wanted):
            where, info = struct.unpack_from('<QQ', data, off)
            relocation = {'section': sec['name'], 'offset': where, 'type': info & 0xffffffff, 'symbol': info >> 32}
            if sec['type'] == 4:
                relocation['addend'] = struct.unpack_from('<q', data, off + 16)[0]
            relocations.append(relocation)
    code = data[text['offset']:text['offset'] + text['size']]
    return {'objectBytes': len(data), 'objectSha256': digest(data), 'sections': ss,
            'selectedSymbols': chosen, 'codeRelocations': relocations,
            'textBytes': len(code), 'textSha256': digest(code), 'x1Offset': start, 'x2Offset': split,
            'hasEhFrame': any(s['name'] == '.eh_frame' for s in ss)}, code


def compare_object(data, refs):
    meta, code = parse_object(data)
    parts = {'A': code[:meta['x2Offset']], 'B': code[meta['x2Offset']:]}
    comparisons = {}
    for release in TARGETS:
        for label, emitted in parts.items():
            captured = refs[release]['candidates'][label]['raw']
            differences = [{'offset': i, 'emitted': emitted[i] if i < len(emitted) else None,
                            'captured': captured[i] if i < len(captured) else None}
                           for i in range(max(len(emitted), len(captured)))
                           if i >= len(emitted) or i >= len(captured) or emitted[i] != captured[i]]
            comparisons[release + '-' + label] = {
                'emittedBytes': len(emitted), 'capturedBytes': len(captured),
                'emittedSha256': digest(emitted), 'capturedSha256': digest(captured),
                'equal': emitted == captured, 'rawMismatchCount': len(differences), 'rawMismatches': differences}
    good = (meta['textBytes'] == 2418 and meta['x2Offset'] == 1149 and not meta['codeRelocations']
            and all(c['equal'] for c in comparisons.values()))
    return {'object': meta, 'comparisons': comparisons, 'matches': good}


def validate_positive(data, refs):
    result = compare_object(data, refs)
    if not result['matches']:
        raise ValueError('Complete raw source-object correspondence failed; no trims or masks')
    return result


def check_native_listing(text, listing):
    rows, cursor = [], 0
    for line in listing.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s+((?:[0-9a-f]{2}\s+)+)(\S.*)$', line)
        if not match:
            continue
        address, raw, asm = int(match[1], 16), bytes.fromhex(match[2]), match[3]
        if address != cursor or not raw or len(raw) > 15 or text[cursor:cursor + len(raw)] != raw:
            raise ValueError('Native own-object byte/address view disagrees with immutable text')
        rows.append({'address': address, 'encoding': raw.hex(), 'asm': asm})
        cursor += len(raw)
    if cursor != len(text):
        raise ValueError('Native listing does not cover full immutable own-object text')
    return rows


def toolchain():
    if not sys.platform.startswith('linux'):
        raise ValueError('This measured recipe requires a Linux GNU x86-64 toolchain')
    env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C'}

    def query(argv):
        return subprocess.check_output(argv, cwd='/tmp', env=env, stdin=subprocess.DEVNULL).decode('utf-8')

    cc = shutil.which('cc', path=env['PATH'])
    if cc is None:
        raise ValueError('Existing GNU cc is required; no tools are installed automatically')
    if digest(Path(cc).read_bytes()) != TOOL_PINS['cc']:
        raise ValueError('Unsupported qualified cc identity; this recipe pins Debian GCC14.2.0-19')
    version = query([cc, '--version'])
    target = query([cc, '-dumpmachine']).strip()
    if 'Free Software Foundation' not in version or not target.startswith('x86_64') or 'linux' not in target:
        raise ValueError('Existing GNU x86-64 Linux cc is required')
    programs = {'cc': cc}
    for name in ('as', 'cc1'):
        value = query([cc, '-print-prog-name=' + name]).strip()
        path = Path(value) if '/' in value else Path(shutil.which(value, path=env['PATH']) or '')
        if not path.is_file():
            raise ValueError('Cannot identify actual driver dependency: ' + name)
        programs[name] = str(path)
    for name in ('objdump', 'objcopy', 'readelf'):
        path = shutil.which(name, path=env['PATH'])
        if path is None:
            raise ValueError('Existing GNU ' + name + ' is required')
        if 'GNU' not in query([path, '--version']).splitlines()[0]:
            raise ValueError('A non-GNU native provider is not qualified: ' + name)
        programs[name] = path
    tools = {}
    for name, path in programs.items():
        p = Path(path).resolve()
        identity = digest(p.read_bytes())
        if identity != TOOL_PINS[name]:
            raise ValueError('Unsupported qualified native-provider identity: ' + name)
        tools[name] = {'path': str(p), 'bytes': p.stat().st_size, 'sha256': digest(p.read_bytes()),
                       'version': ('Actual cc1 selected by the measured driver' if name == 'cc1'
                                   else query([path, '--version']).splitlines()[0])}
    include = Path(query([cc, '-print-file-name=include']).strip())
    headers = {'cet.h': include / 'cet.h', 'stdc-predef.h': Path('/usr/include/stdc-predef.h')}
    for name, path in headers.items():
        if not path.is_file() or digest(path.read_bytes()) != HEADER_PINS[name]:
            raise ValueError('Unsupported qualified installed-header identity: ' + name)
    return {'target': target, 'tools': tools, 'header_paths': {k: str(v) for k, v in headers.items()},
            'qualified_recipe': 'Debian GCC14.2.0-19, GNU Binutils2.44 and the exact recorded host header identities; no silent substitute or install',
            'trust': 'Installed native toolchain and system headers are trusted and hashed before/after. These checks are not an atomic execution/provenance guarantee.'}


def collect(output_dir, target_paths=None, source_root=None):
    output_dir = Path(output_dir)
    if output_dir.exists():
        raise FileExistsError('Refusing existing evidence directory: ' + str(output_dir))
    # No subprocess or output is admitted before all target/source identities.
    sources = admit_sources(source_root)
    refs = read_targets(target_paths)
    compiler = toolchain()
    tools = compiler['tools']
    outputs, commands, host_headers = {}, [], {}

    def tools_unchanged():
        return all(digest(Path(t['path']).read_bytes()) == t['sha256'] for t in tools.values())

    with tempfile.TemporaryDirectory(prefix='hl-zstd-asm-', dir='/tmp') as private:
        private = Path(private)

        def stage(name, version):
            folder = private / name
            (folder / 'lib/decompress').mkdir(parents=True)
            (folder / 'lib/common').mkdir()
            (folder / 'build').mkdir()
            (folder / 'tmp').mkdir()
            for key, rel in SOURCE_FILES.items():
                (folder / rel).write_bytes(sources[version][key])
            return folder

        def staged_unchanged(folder, version):
            if any((folder / rel).read_bytes() != sources[version][key] for key, rel in SOURCE_FILES.items()):
                raise ValueError('Staged admitted source changed during compilation')

        def invoke(folder, logical_cwd, label, argv):
            # TMPDIR is the exact relative value used by the actual process.
            env = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C', 'TMPDIR': 'tmp'}
            run = subprocess.run(argv, cwd=folder, env=env, stdin=subprocess.DEVNULL, capture_output=True)
            prefix = logical_cwd + '/' + label
            outputs[prefix + '.stdout'] = run.stdout
            outputs[prefix + '.stderr'] = run.stderr
            commands.append({'argv': argv, 'cwd_relative_to_private_root': logical_cwd,
                             'environment': env, 'exit_code': run.returncode,
                             'stdout_file': prefix + '.stdout', 'stderr_file': prefix + '.stderr',
                             'stdout_sha256': digest(run.stdout), 'stderr_sha256': digest(run.stderr)})
            if run.returncode:
                raise RuntimeError('Native command failed: ' + repr(argv) + '\n' + run.stderr.decode('utf-8', 'replace'))
            return run.stdout

        def preprocess(folder, name, version, cet, effective=False):
            cc = tools['cc']['path']
            source = SOURCE_FILES['source']
            macro_raw = invoke(folder, name, 'macros', [cc, '-E', '-dM', '-fcf-protection=' + cet, source])
            deps_raw = invoke(folder, name, 'dependencies', [cc, '-M', '-fcf-protection=' + cet, source])
            preprocessed = invoke(folder, name, 'preprocessed', [cc, '-E', '-fcf-protection=' + cet, source])
            outputs[name + '/macros.txt'] = macro_raw
            outputs[name + '/dependencies.txt'] = deps_raw
            outputs[name + '/preprocessed.S'] = preprocessed
            macros = dict(re.findall(r'^#define (\S+)(?: (.*))?$', macro_raw.decode('ascii'), re.M))
            required = {'__ELF__': '1', '__x86_64__': '1', '__ASSEMBLER__': '1',
                        'DYNAMIC_BMI2': '1', 'ZSTD_ASM_SUPPORTED': '1',
                        'ZSTD_ENABLE_ASM_X86_64_BMI2': '1', 'ZSTD_CET_ENDBRANCH': '_CET_ENDBR'}
            if any(macros.get(k) != v for k, v in required.items()) or '_WIN32' in macros:
                raise ValueError('Actual GNU/Linux assembly configuration differs from the measured recipe')
            if cet == 'branch':
                if macros.get('__CET__') != '1' or macros.get('_CET_ENDBR') != 'endbr64':
                    raise ValueError('Actual CET entry macro did not produce endbr64')
            elif '__CET__' in macros or macros.get('_CET_ENDBR') != '':
                raise ValueError('Actual CET-disabled control did not remove the entry instruction')
            dep_text = deps_raw.decode('utf-8').replace('\\\n', ' ')
            deps = shlex.split(dep_text.split(':', 1)[1])
            project = {SOURCE_FILES['source'], 'lib/decompress/../common/portability_macros.h'}
            system = []
            for dep in deps:
                if dep in project:
                    continue
                p = Path(dep)
                if not p.is_absolute() or p.name not in HEADER_PINS:
                    raise ValueError('Unreviewed active compiler dependency: ' + dep)
                raw = p.read_bytes()
                if digest(raw) != HEADER_PINS[p.name] or str(p) != compiler['header_paths'][p.name]:
                    raise ValueError('Active installed-header identity differs from admission')
                record = {'bytes': len(raw), 'sha256': digest(raw),
                          'license_notice': ('GPLv3+ with GCC Runtime Library Exception3.1' if p.name == 'cet.h'
                                             else 'LGPLv2.1-or-later; installed GNU C Library header')}
                if dep in host_headers and host_headers[dep] != record:
                    raise ValueError('Trusted installed header changed across cases')
                host_headers[dep] = record
                system.append(dep)
            if not project.issubset(deps) or {Path(p).name for p in system} != {'cet.h', 'stdc-predef.h'}:
                raise ValueError('Incomplete measured compiler include closure')
            staged_unchanged(folder, version)
            result = {'version': version, 'cet': cet, 'dependencies': deps,
                      'selected_macros': {k: macros.get(k) for k in [*required, '__CET__', '_CET_ENDBR', 'STATIC_BMI2']}}
            if effective:
                raw = invoke(folder, name, 'effective-assembly', [cc, '-E', '-P', '-fcf-protection=' + cet, source])
                outputs[name + '/effective.S'] = raw
                result['effective_assembly_file'] = name + '/effective.S'
                result['effective_assembly_bytes'] = len(raw)
                result['effective_assembly_sha256'] = digest(raw)
            return result

        def build(name, cet, effective=False):
            folder = stage(name, '1.5.6')
            cpp = preprocess(folder, name, '1.5.6', cet, effective)
            invoke(folder, name, 'compile', [tools['cc']['path'], '-c', '-fcf-protection=' + cet,
                                           SOURCE_FILES['source'], '-o', 'build/huf.o'])
            staged_unchanged(folder, '1.5.6')
            # Admit this own object once. All object facts and provider inputs
            # below derive from this exact immutable object, never a reopened
            # compiler output pathname.
            data = (folder / 'build/huf.o').read_bytes()
            analysis = compare_object(data, refs)
            meta, text = parse_object(data)
            native = folder / 'native-view'
            native.mkdir()
            (native / 'tmp').mkdir()
            (native / 'object.o').write_bytes(data)
            readelf = invoke(native, name + '/native-view', 'readelf',
                             [tools['readelf']['path'], '-h', '-S', '-s', '-r', '-n', '-W', 'object.o'])
            listing = invoke(native, name + '/native-view', 'objdump',
                             [tools['objdump']['path'], '-d', '-r', '-w', '-Mintel', '--insn-width=16', 'object.o'])
            invoke(native, name + '/native-view', 'objcopy',
                   [tools['objcopy']['path'], '-O', 'binary', '--only-section=.text', 'object.o', 'text.bin'])
            if (native / 'object.o').read_bytes() != data or (native / 'text.bin').read_bytes() != text:
                raise ValueError('Native own-object view/export differs from the admitted snapshot')
            rows = check_native_listing(text, listing.decode('ascii'))
            outputs[name + '/object.o'] = data
            outputs[name + '/text.bin'] = text
            outputs[name + '/object.json'] = json_bytes(meta)
            outputs[name + '/readelf.txt'] = readelf
            outputs[name + '/objdump.txt'] = listing
            outputs[name + '/native-rows.json'] = json_bytes(rows)
            return {'object_file': name + '/object.o', 'text_file': name + '/text.bin',
                    'object_metadata_file': name + '/object.json', 'native_rows': len(rows),
                    'cpp': cpp, 'analysis': analysis}

        cases = {'positive-1': build('positive-1', 'branch', True),
                 'positive-2': build('positive-2', 'branch'),
                 'cet-none': build('cet-none', 'none')}
        adjacent_folder = stage('adjacent-157', '1.5.7')
        adjacent = preprocess(adjacent_folder, 'adjacent-157', '1.5.7', 'branch', True)
        staged_unchanged(adjacent_folder, '1.5.7')
        effective_equal = outputs['positive-1/effective.S'] == outputs['adjacent-157/effective.S']
        # This scope has no adjacent object build, even on disagreement. Do not
        # infer or synthesize an unmeasured 1.5.7 object hash.
        summary = {
            'positive_match': cases['positive-1']['analysis']['matches'] and cases['positive-2']['analysis']['matches'],
            'positive_object_reproducible': outputs['positive-1/object.o'] == outputs['positive-2/object.o'],
            'negative_rejected': not cases['cet-none']['analysis']['matches'] and
                all(not x['equal'] for x in cases['cet-none']['analysis']['comparisons'].values()),
            'adjacent_effective_equal': effective_equal, 'adjacent_object_count': 0,
        }
        if not tools_unchanged() or any(digest(Path(p).read_bytes()) != r['sha256'] for p, r in host_headers.items()):
            raise ValueError('Trusted installed tool/header identity changed during the experiment')
        summary['qualified_for_bounded_correspondence'] = all(summary[k] for k in (
            'positive_match', 'positive_object_reproducible', 'negative_rejected', 'adjacent_effective_equal'))
        target_metadata = {release: {**value, 'candidates': {label: {k: v for k, v in c.items() if k != 'raw'}
                           for label, c in value['candidates'].items()}} for release, value in refs.items()}
        report = {'schema_version': 1, 'task': 'RE-002', 'summary': summary, 'cases': cases,
                  'adjacent': adjacent, 'targets': target_metadata, 'toolchain': compiler,
                  'trusted_system_headers': host_headers,
                  'source_bindings': {version: {key: {'path': SOURCE_FILES[key], 'bytes': len(raw), 'sha256': digest(raw)}
                                      for key, raw in files.items()} for version, files in sources.items()},
                  'comparison': {'selected_text_bytes_per_object': cases['positive-1']['analysis']['object']['textBytes'],
                                 'code_byte_pairs_per_target_per_positive_build': sum(len(c['raw']) for c in refs['94']['candidates'].values()),
                                 'code_byte_pairs_per_positive_build': sum(c['capturedBytes'] for c in cases['positive-1']['analysis']['comparisons'].values()),
                                 'code_byte_pairs_across_two_positive_builds': sum(c['capturedBytes'] for name in ('positive-1', 'positive-2') for c in cases[name]['analysis']['comparisons'].values()),
                                 'positive_body_checks': sum(len(cases[name]['analysis']['comparisons']) for name in ('positive-1', 'positive-2')),
                                 'raw_masks': [], 'padding_trimmed': False,
                                 'symbol_sizes_fabricated': False, 'target_bytes_used_as_compiler_input': False},
                  'execution': {'own_objects_or_captures_executed': False, 'adjacent_object_built': False,
                                'commands_file': 'COMMANDS.json', 'cwd_coordinates': 'Relative to a fresh private /tmp staging root; argv/environment values are exact.'},
                  'source_tool_sha256': digest(Path(__file__).read_bytes()),
                  'analysis_source_bindings': {name: digest((ROOT / name).read_bytes()) for name in
                                               ('tools/zstd_asm_correspondence.py', 'tools/elf_index.py')},
                  'limits': ['Compatible licensed source/configuration only; original archive/fork/crate/commit/version/compiler/flags remain unproved.',
                             '1.5.7 result is exact measured line-marker-free preprocessed assembly equality, not a newly built object comparison.',
                             'No function/source/type/ABI identity, caller/dispatch/table/CPU/runtime qualification, Rust recovery or gate change.',
                             'Installed toolchain/header pre/post hashes assume trusted stable files; no atomic execution provenance is claimed.']}
        outputs['REPORT.json'] = json_bytes(report)
        outputs['COMMANDS.json'] = json_bytes(commands)
        outputs['OUTPUT-MANIFEST.json'] = json_bytes({name: digest(data) for name, data in sorted(outputs.items())})
        output_dir.mkdir(parents=True, exist_ok=False)
        for name, data in sorted(outputs.items()):
            destination = output_dir / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open('xb') as stream:
                stream.write(data)
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--source-root', type=Path, default=SOURCE_ROOT)
    parser.add_argument('--node94', type=Path, default=ROOT / 'artifacts/node/94/hl-node')
    parser.add_argument('--node115', type=Path, default=ROOT / 'artifacts/node/115/hl-node')
    args = parser.parse_args()
    report = collect(args.output_dir, {'94': args.node94, '115': args.node115}, args.source_root)
    print(json.dumps(report['summary']))
    if not report['summary']['qualified_for_bounded_correspondence']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
