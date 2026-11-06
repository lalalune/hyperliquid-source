#!/usr/bin/env python3
"""MIT. Fixed static HTTP logical-writer evidence; captured bytes never execute.

ELF/CFI/collection scaffold adapted from the repository's MIT wave27 checked-fold
collector. The scope is eight whole bodies, including credited baseline table/
writer evidence and active PR2943 feed context. No generic hash implementation,
physical-map evaluator, writer model, native oracle or source execution exists.
validate_inner supports below-identity static byte controls only.
"""
import argparse
import bisect
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile

PACKET = Path(__file__).resolve().parent
TARGET_SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
TARGET_SIZE = 105896032
OBLIGATIONS_SHA256 = 'f4c234777d336cd7a02a5e8ed645b07e94ba794561d055355f7eb3e2a4318303'
SCOPE = [(0x2e77070, 0x2e7792e), (0x2e81cc0, 0x2e81e5e), (0x2e81e60, 0x2e8200e),
         (0x2e7f650, 0x2e7f90d), (0x2e7f140, 0x2e7f317), (0x2e8dbe0, 0x2e8dc6e),
         (0x2e8daf0, 0x2e8dbd9), (0x2e768f0, 0x2e7690e)]
CAPTURE_HASHES = {TARGET_SHA256,
    '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f',
    '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31'}
ROW = re.compile(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)\s*(.*)$')


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_json(raw):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            require(key not in out, 'duplicate JSON key')
            out[key] = value
        return out
    return json.loads(raw, object_pairs_hook=unique)


def obligations():
    raw = (PACKET / 'obligations.json').read_bytes()
    require(digest(raw) == OBLIGATIONS_SHA256, 'obligations identity')
    return load_json(raw)


def authenticate(data):
    require(len(data) == TARGET_SIZE and digest(data) == TARGET_SHA256,
            'node115 identity mismatch')


def read_target(path):
    with Path(path).open('rb') as stream:
        data = stream.read(TARGET_SIZE + 1)
    authenticate(data)
    return data


class Image:
    """Unique, agreeing file-backed PT_LOAD and allocated-section mappings."""
    def __init__(self, data):
        self.data = data
        require(len(data) >= 64 and data[:6] == b'\x7fELF\x02\x01', 'ELF class/endian')
        require(struct.unpack_from('<HHI', data, 16) == (3, 62, 1), 'ELF type/machine')
        po, so = struct.unpack_from('<QQ', data, 32)
        eh, pe, pn, se, sn, st = struct.unpack_from('<HHHHHH', data, 52)
        require(eh == 64 and pe == 56 and se == 64 and 0 < st < sn, 'ELF header sizes')
        require(po + pe * pn <= len(data) and so + se * sn <= len(data), 'ELF tables')
        self.ph = [struct.unpack_from('<IIQQQQQQ', data, po + pe * i) for i in range(pn)]
        self.sh = [struct.unpack_from('<IIQQQQIIQQ', data, so + se * i) for i in range(sn)]
        for p in self.ph:
            if p[0] == 1:
                require(p[5] <= p[6] and p[2] + p[5] <= len(data), 'PT_LOAD file extent')
        for s in self.sh:
            if s[1] != 8:
                require(s[4] + s[5] <= len(data), 'section file extent')
        names = self.sh[st]
        require(names[1] == 3, 'section-name table')
        names = bytes(data[names[4]:names[4] + names[5]])
        self.sections = {}
        for s in self.sh:
            require(s[0] < len(names), 'section-name offset')
            end = names.find(b'\0', s[0])
            require(end >= s[0], 'section-name terminator')
            name = names[s[0]:end].decode('ascii')
            require(name not in self.sections, 'duplicate section name')
            self.sections[name] = s

    def offset(self, address, size):
        require(address >= 0 and size > 0, 'invalid VA span')
        p = [p for p in self.ph if p[0] == 1 and p[3] <= address and
             address + size <= p[3] + p[5]]
        s = [s for s in self.sh if s[1] != 8 and s[2] & 2 and s[3] <= address and
             address + size <= s[3] + s[5]]
        require(len(p) == len(s) == 1, 'nonunique or missing PT_LOAD/section mapping')
        po, so = p[0][2] + address - p[0][3], s[0][4] + address - s[0][3]
        require(po == so, 'PT_LOAD/section offset disagreement')
        return po

    def read(self, address, size):
        offset = self.offset(address, size)
        result = bytes(self.data[offset:offset + size])
        require(len(result) == size, 'short mapped read')
        return result

    def section(self, name):
        require(name in self.sections, 'missing section ' + name)
        return self.sections[name]

    def frame_index(self):
        s = self.section('.eh_frame_hdr')
        b = self.read(s[3], s[5])
        require(b[:4] == bytes([1, 0x1b, 3, 0x3b]), 'unwind-header encodings')
        require(s[3] + 4 + struct.unpack_from('<i', b, 4)[0] ==
                self.section('.eh_frame')[3], 'unwind-header frame pointer')
        count = struct.unpack_from('<I', b, 8)[0]
        require(12 + 8 * count == len(b), 'unwind-header table extent')
        out = {}
        previous = -1
        for i in range(count):
            start, fde = struct.unpack_from('<ii', b, 12 + 8 * i)
            start += s[3]
            require(start > previous, 'non-increasing FDE index')
            previous = start
            out[start] = s[3] + fde
        return out

    def relocations(self, spec):
        out = []
        for name, count in spec['relocation_counts'].items():
            s = self.section(name)
            require(s[1] == 4 and s[9] == 24 and s[5] == count * 24, 'RELA shape/count')
            b = self.read(s[3], s[5])
            for i in range(0, len(b), 24):
                slot, info, add = struct.unpack_from('<QQq', b, i)
                # All admitted target relocation kinds write one 64-bit word:
                # 64, GLOB_DAT, JUMP_SLOT, RELATIVE, TPOFF64 respectively.
                require(info & 0xffffffff in (1, 6, 7, 8, 18), 'unsupported RELA width/type')
                out.append({'section': name, 'record_va': hex(s[3] + i), 'slot': hex(slot),
                            'info': info, 'addend': add, 'raw': b[i:i + 24].hex()})
        return out


def validate_inner(data, spec=None):
    """Fixed byte/metadata guards below target/body SHA; no native evaluation."""
    spec = obligations() if spec is None else spec
    require(spec['target_sha256'] == TARGET_SHA256 and spec['target_bytes'] == TARGET_SIZE,
            'obligation target identity')
    require([(int(b['start'], 16), int(b['end'], 16)) for b in spec['bodies']] == SCOPE,
            'exact eight-body scope')
    image = Image(data)
    rows = {int(pc, 16): (bytes.fromhex(raw), label) for pc, raw, label in spec['row_guards']}
    require(len(rows) == len(spec['row_guards']) == 1145, 'instruction obligation count/uniqueness')
    controls = spec['semantic_controls']
    require(len(controls) == 48 and len({c['id'] for c in controls}) == 48 and
            len({c['pc'] for c in controls}) == 48, 'semantic control uniqueness')
    for control in controls:
        pc, raw = int(control['pc'], 16), bytes.fromhex(control['raw'])
        require(rows.get(pc) == (raw, control['id']), 'control preimage')
        require(image.read(pc, len(raw)) == raw, 'semantic guard ' + control['id'])
    for pc, (raw, label) in rows.items():
        require(raw and image.read(pc, len(raw)) == raw, f'instruction {label} at {pc:#x}')
    frames = image.frame_index(); header = image.section('.eh_frame_hdr')
    require(len(frames) == spec['frame_header_count'] == 135313, 'frame header entry count')
    hp = spec['frame_header_pins']
    require(len(hp) == 9 and int(hp[0]['address'], 16) == header[3] and
            len(bytes.fromhex(hp[0]['raw'])) == 12, 'header-prefix obligation')
    require([(e.get('start'), e.get('fde')) for e in hp[1:]] ==
            [(b['start'], b['fde_va']) for b in spec['bodies']], 'selected header obligation scope')
    starts = list(frames)
    for item in hp:
        va, raw = int(item['address'], 16), bytes.fromhex(item['raw'])
        require(image.read(va, len(raw)) == raw, 'selected header raw bytes')
        if 'start' in item:
            a = int(item['start'], 16)
            require(len(raw) == 8 and va == header[3]+12+starts.index(a)*8 and
                    header[3]+struct.unpack_from('<i', raw)[0] == a and
                    header[3]+struct.unpack_from('<i', raw, 4)[0] == int(item['fde'], 16),
                    'selected header entry binding')
    section = image.section('.eh_frame'); covered = set()
    for body in spec['bodies']:
        a, end = int(body['start'], 16), int(body['end'], 16)
        pc, count = a, 0
        while pc < end and pc in rows:
            covered.add(pc); count += 1; pc += len(rows[pc][0])
        require(pc == end and count == body['rows'], 'obligation full-body partition')
        f = int(body['fde_va'], 16)
        require(frames.get(a) == f, 'FDE-header binding')
        for kind in ('fde', 'cie'):
            va, raw = int(body[kind+'_va'], 16), bytes.fromhex(body[kind+'_raw'])
            require(section[3] <= va and va+len(raw) <= section[3]+section[5], 'CFI section extent')
            require(struct.unpack_from('<I', raw)[0]+4 == len(raw), 'CFI record size')
            require(image.read(va, len(raw)) == raw, f'full {kind.upper()} raw bytes')
        raw = bytes.fromhex(body['fde_raw'])
        require(f+8+struct.unpack_from('<i', raw, 8)[0] == a and
                a+struct.unpack_from('<I', raw, 12)[0] == end, 'FDE range')
        require(f+4-struct.unpack_from('<I', raw, 4)[0] == int(body['cie_va'], 16), 'CIE link')
        require(bytes.fromhex(body['cie_raw'])[4:8] == bytes(4), 'CIE identifier')
    require(covered == set(rows), 'uncovered instruction obligation')
    require(len(spec['transfers']) == 181 and len({e['pc'] for e in spec['transfers']}) == 181 and
            sum(e['text'].split()[0] == 'call' for e in spec['transfers']) == 36, 'transfer/CALL census')
    for edge in spec['transfers']:
        pc, raw = int(edge['pc'], 16), bytes.fromhex(edge['raw'])
        require(rows[pc][0] == raw, 'transfer encoded width')
        target = None
        if len(raw) == 5 and raw[0] in (0xe8, 0xe9):
            target = pc+5+struct.unpack_from('<i', raw, 1)[0]
        elif len(raw) == 2 and (raw[0] == 0xeb or 0x70 <= raw[0] <= 0x7f):
            target = pc+2+struct.unpack_from('<b', raw, 1)[0]
        elif len(raw) == 6 and raw[0] == 15 and 0x80 <= raw[1] <= 0x8f:
            target = pc+6+struct.unpack_from('<i', raw, 2)[0]
        if target is not None:
            require(hex(target) == edge.get('target') and 'slot' not in edge, 'transfer target binding')
            if edge['text'].split()[0] == 'call':
                require(target in {s for s, _ in SCOPE}, 'exact direct helper entry')
            else:
                owner = next((extent for extent in SCOPE if extent[0] <= pc < extent[1]), None)
                require(owner is not None and owner[0] <= target < owner[1], 'branch remains in selected body')
            require(target in rows, 'selected instruction-start destination')
        else:
            require(len(raw) == 6 and raw[:2] in (b'\xff\x15', b'\xff\x25') and
                    'target' not in edge and pc+6+struct.unpack_from('<i', raw, 2)[0] == int(edge['slot'], 16),
                    'indirect transfer slot')
    require(len(spec['rip_edges']) == 39 and len({e['pc'] for e in spec['rip_edges']}) == 39, 'RIP census')
    for edge in spec['rip_edges']:
        pc = int(edge['pc'], 16); raw = rows[pc][0]; off = edge['disp_offset']
        require(type(off) is int and off == len(raw)-4 and off >= 2, 'RIP displacement position')
        require(pc+len(raw)+struct.unpack_from('<i', raw, off)[0] == int(edge['target'], 16), 'RIP target binding')
    require(spec['relocation_counts'] == {'.rela.dyn': 60723, '.rela.plt': 278}, 'relocation census scope')
    relas = image.relocations(spec)
    ordered = sorted(relas, key=lambda r: int(r['slot'], 16)); positions = [int(r['slot'], 16) for r in ordered]

    def overlapping(va, size):
        return ordered[bisect.bisect_right(positions, va-8):bisect.bisect_left(positions, va+size)]

    for body in spec['bodies']:
        a, end = int(body['start'], 16), int(body['end'], 16)
        require(not overlapping(a, end-a), 'relocation overlays selected code')
        for kind in ('fde', 'cie'):
            require(not overlapping(int(body[kind+'_va'], 16), len(bytes.fromhex(body[kind+'_raw']))),
                    'relocation overlays selected CFI')
    for item in hp:
        require(not overlapping(int(item['address'], 16), len(bytes.fromhex(item['raw']))),
                'relocation overlays selected header')
    bound = {int(r['slot'], 16): r for r in spec['relocation_bindings']}
    locations = {0x645a950, 0x645a938, 0x645a968, 0x645d170, 0x6459478, 0x645a6c8}
    callslots = {0x64df508, 0x64df9f8, 0x64df688, 0x64df730, 0x64df620,
                 0x64df498, 0x64df580, 0x64df588, 0x64df590, 0x64df480}
    expected_slots = callslots | locations | {0x6459df8+8*i for i in range(81)}
    require(len(bound) == len(spec['relocation_bindings']) == 97 and set(bound) == expected_slots,
            'exact selected relocation scope')
    for slot, record in bound.items():
        require(overlapping(slot, 8) == [record], f'bound relocation/overlap {slot:#x}')
        require(image.read(slot, 8) == bytes(8), f'pre-relocation slot {slot:#x}')
        expected_info = (7 << 32)|6 if slot == 0x64df508 else (11 << 32)|6 if slot == 0x64df9f8 else 8
        require(record['info'] == expected_info, 'selected relocation type/symbol')
    for edge in spec['transfers']:
        require('slot' not in edge or int(edge['slot'], 16) in callslots, 'unbound transfer slot')
    require({(i['slot'], i['symbol_index'], i['name']) for i in spec['imports']} ==
            {('0x64df508', 7, 'memcpy'), ('0x64df9f8', 11, 'bcmp')} and len(spec['imports']) == 2,
            'exact GLOB_DAT imports')
    for imported in spec['imports']:
        slot, sym, nameva = (int(imported[k], 16) for k in ('slot', 'symbol_va', 'name_va'))
        require(imported['relocation'] == bound[slot] and imported['slot_raw'] == bytes(8).hex(), 'import slot binding')
        ds, strings = image.section('.dynsym'), image.section('.dynstr')
        require(ds[1] == 11 and ds[9] == 24 and sym == ds[3]+24*imported['symbol_index'] and
                image.sh[ds[6]] == strings, 'dynsym index/string table binding')
        raw = image.read(sym, 24); name = imported['name'].encode('ascii')+b'\0'
        require(not overlapping(sym, 24) and not overlapping(nameva, len(name)), 'relocation overlays import metadata')
        require(raw.hex() == imported['symbol_raw'], 'import symbol bytes')
        require(strings[3]+struct.unpack_from('<I', raw)[0] == nameva and
                strings[3] <= nameva and nameva+len(name) <= strings[3]+strings[5], 'dynstr name binding')
        require(image.read(nameva, len(name)) == name, 'import name bytes')
    seen = set()
    for item in spec['data']:
        va, raw = int(item['address'], 16), bytes.fromhex(item['raw'])
        require(raw and (va, len(raw)) not in seen, 'unique data spans'); seen.add((va, len(raw)))
        require(image.read(va, len(raw)) == raw and digest(raw) == item['sha256'], f'data anchor {va:#x}')
        require(all(int(r['slot'], 16) in bound and r == bound[int(r['slot'], 16)] for r in overlapping(va, len(raw))),
                'unbound data relocation')
    table = spec['header_table']; require(len(table) == 81, '81-name table')
    for i, item in enumerate(table):
        ptr, length = 0x6459df8+8*i, 0x620800+8*i
        require(item['ordinal'] == i and int(item['pointer_cell']['va'], 16) == ptr and
                int(item['length_cell']['va'], 16) == length, 'header ordinal/address binding')
        a = int(item['bytes']['va'], 16); raw = bytes.fromhex(item['bytes']['hex'])
        require((ptr, 8) in seen and (length, 8) in seen and (a, len(raw)) in seen, 'header data coverage')
        require(bound[ptr]['addend'] == a and struct.unpack('<Q', image.read(length, 8))[0] == len(raw) and
                len(raw) == item['bytes']['size'] and raw.decode('ascii') == item['name'], 'header pointer/length/name binding')
    require(len(spec['source_locations']) == 6 and
            {int(x['record']['va'], 16) for x in spec['source_locations']} == locations, 'Location scope')
    for item in spec['source_locations']:
        va, path = int(item['record']['va'], 16), int(item['source']['va'], 16)
        raw = image.read(va, 24); text = bytes.fromhex(item['source']['hex'])
        require((va, 24) in seen and (path, len(text)) in seen, 'Location data coverage')
        require(raw[:8] == bytes(8) and bound[va]['addend'] == path == 0x43c9be and
                raw.hex() == item['record']['hex'], 'Location pointer/raw binding')
        require(struct.unpack_from('<QII', raw, 8) == (len(text), item['line'], item['column']) and
                image.read(path, len(text)) == text, 'Location fields/path')
    require((0x4522f0, 16) in seen and (0x4511c0, 16) in seen and (0x620e92, 40) in seen,
            'hash and diagnostic context data coverage')
    return {'bodies': 8, 'bytes': 4659, 'rows': 1145, 'semantic_control_sites': len(controls),
            'transfers': 181, 'calls': 36, 'rip_edges': 39, 'relocation_bindings': 97,
            'imports': 2, 'header_names': 81, 'source_locations': 6, 'data_spans': len(seen),
            'relocation_records_scanned': len(relas)}


def decode_export(output, image, body, spec):
    start, end = int(body['start'], 16), int(body['end'], 16)
    expected = {int(pc, 16): raw for pc, raw, _ in spec['row_guards'] if start <= int(pc, 16) < end}
    position, count = start, 0
    for line in output.decode('utf-8').splitlines():
        match = ROW.match(line)
        if not match:
            continue
        address, code = int(match[1], 16), bytes.fromhex(match[2])
        require(address == position and address + len(code) <= end and
                code == image.read(address, len(code)), 'GNU/raw byte partition disagreement')
        require(match[3].strip(), 'unexpected GNU instruction continuation')
        require(code.hex() == expected.get(address), 'GNU instruction boundary/width disagreement')
        position += len(code)
        count += 1
    require(position == end and count == body['rows'], 'incomplete GNU full-body export')
    return count


def select_tool(objdump):
    require(objdump is not None and Path(objdump).is_absolute(), 'explicit absolute GNU path required')
    resolved = shutil.which(objdump)
    require(resolved is not None, 'installed GNU objdump required')
    tool = Path(resolved).resolve()
    require(tool.is_file() and os.access(tool, os.X_OK), 'objdump executable path')
    tool_sha = digest(tool.read_bytes())
    require(tool_sha not in CAPTURE_HASHES, 'captured binary is not an objdump provider')
    return tool, tool_sha


def collect(data, output, objdump=None):
    authenticate(data)  # before output, tool selection, spawning or private snapshots
    spec = obligations()
    facts = validate_inner(data, spec)
    image = Image(data)
    for body in spec['bodies']:
        start, end = int(body['start'], 16), int(body['end'], 16)
        require(digest(image.read(start, end - start)) == body['sha256'], 'full body digest')
    output = Path(output)
    require(not output.exists(), 'output must be fresh')
    tool, tool_sha = select_tool(objdump)
    output.mkdir(parents=True)
    (output / 'native').mkdir()
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C', 'LANG': 'C', 'DEBUGINFOD_URLS': ''}
    commands = []

    def run(label, argv, cwd):
        stdout_name = 'objdump-version.txt' if label == 'version' else f'native/{int(label, 16):x}.objdump.txt'
        stderr_name = 'objdump-version.stderr' if label == 'version' else f'native/{int(label, 16):x}.stderr'
        failure, code = None, None
        try:
            result = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, timeout=60)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as exc:
            stdout, stderr, failure = exc.stdout or b'', exc.stderr or b'', 'timeout'
        except OSError as exc:
            stdout, stderr, failure = b'', b'', 'launch-error'
            diagnostic = str(exc).encode()
            diagnostic_name = stdout_name + '.launch-error.txt'
            (output / diagnostic_name).write_bytes(diagnostic)
        (output / stdout_name).write_bytes(stdout)
        (output / stderr_name).write_bytes(stderr)
        commands.append({'label': label, 'argv': ['objdump', *argv[1:]], 'exit_code': code,
                         'failure': failure, 'stdout_file': stdout_name, 'stderr_file': stderr_name,
                         'stdout_sha256': digest(stdout), 'stderr_sha256': digest(stderr)})
        if failure == 'launch-error':
            commands[-1]['launch_error_diagnostic'] = {
                'file': diagnostic_name, 'sha256': digest(diagnostic), 'bytes': len(diagnostic)}
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        require(failure is None and code == 0 and not stderr, 'GNU tool failure/nonempty stderr')
        return stdout

    version = run('version', [str(tool), '--version'], output)
    require(b'GNU objdump' in version, 'GNU objdump required')
    exported = []
    with tempfile.TemporaryDirectory(prefix='node115-header-writer-static-') as tmp:
        native = Path(tmp) / 'authenticated-node115'
        native.write_bytes(data)
        native.chmod(0o400)
        require(digest(native.read_bytes()) == TARGET_SHA256, 'private snapshot identity')
        for body in spec['bodies']:
            start, end = int(body['start'], 16), int(body['end'], 16)
            argv = [str(tool), '-d', '-w', '-M', 'intel', '--insn-width=16',
                    f'--start-address={start:#x}', f'--stop-address={end:#x}', native.name]
            raw = run(hex(start), argv, tmp)
            count = decode_export(raw, image, body, spec)
            exported.append({'start': hex(start), 'end': hex(end), 'rows': count,
                             'body_sha256': body['sha256'], 'export_sha256': digest(raw)})
        require(digest(native.read_bytes()) == TARGET_SHA256, 'final private snapshot identity')
    require(digest(tool.read_bytes()) == tool_sha, 'objdump changed during collection')
    result = {'target_sha256': TARGET_SHA256, 'target_bytes': TARGET_SIZE,
              'obligations_sha256': OBLIGATIONS_SHA256, 'facts': facts, 'exports': exported,
              'tool_sha256': tool_sha, 'tool_version': version.decode().splitlines()[0],
              'bodies': spec['bodies'], 'transfers': spec['transfers'], 'rip_edges': spec['rip_edges'],
              'relocation_bindings': spec['relocation_bindings'], 'imports': spec['imports'], 'data': spec['data'],
              'header_table': spec['header_table'],
              'frame_header_pins': spec['frame_header_pins'], 'source_locations': spec['source_locations'],
              'limits': spec['limits'] + ['Known-capture hash refusal is an accident guard, not proof of arbitrary tool provenance.',
                  'One GNU decoder; no independent decoder or hosted CI claim. Raw CFI is not unwind semantics.']}
    (output / 'records.json').write_text(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
    return result


def compare_packet(output, expected=None):
    """Native bytes/commands are exact; only declared GNU version provenance may vary."""
    output, expected = Path(output), PACKET if expected is None else Path(expected)
    spec = obligations()
    native_names = {f'native/{int(b["start"], 16):x}.{suffix}' for b in spec['bodies']
                    for suffix in ('objdump.txt', 'stderr')}
    wanted = native_names | {'records.json', 'commands.json', 'objdump-version.txt', 'objdump-version.stderr'}
    actual = {str(p.relative_to(output)) for p in output.rglob('*') if p.is_file()}
    require(actual == wanted, 'generated artifact set mismatch')
    for name in wanted:
        require((expected / name).is_file(), 'missing committed artifact: ' + name)
    for name in native_names:
        require((output / name).read_bytes() == (expected / name).read_bytes(), 'native artifact mismatch: ' + name)
    a, e = [load_json((p / 'records.json').read_bytes()) for p in (output, expected)]
    provenance = {}
    for key in ('tool_sha256', 'tool_version'):
        require(key in a and key in e, 'missing tool provenance')
        provenance[key] = {'actual': a.pop(key), 'committed': e.pop(key)}
    require(a == e, 'native/data/CFI/RELA record mismatch')
    sequences = [load_json((p / 'commands.json').read_bytes()) for p in (output, expected)]
    for directory, commands in zip((output, expected), sequences):
        require(len(commands) == 1 + len(spec['bodies']), 'command count')
        for i, command in enumerate(commands):
            if i == 0:
                label, argv, stdout, stderr = 'version', ['objdump', '--version'], 'objdump-version.txt', 'objdump-version.stderr'
            else:
                body = spec['bodies'][i - 1]
                label = body['start']
                start, end = int(label, 16), int(body['end'], 16)
                argv = ['objdump', '-d', '-w', '-M', 'intel', '--insn-width=16',
                        f'--start-address={start:#x}', f'--stop-address={end:#x}', 'authenticated-node115']
                stdout, stderr = f'native/{start:x}.objdump.txt', f'native/{start:x}.stderr'
            require(command['label'] == label and command['argv'] == argv and
                    command['stdout_file'] == stdout and command['stderr_file'] == stderr and
                    command['exit_code'] == 0 and command['failure'] is None, 'command identity')
            for stream, name in [('stdout', stdout), ('stderr', stderr)]:
                require(digest((directory / name).read_bytes()) == command[stream + '_sha256'], 'command stream identity')
            require(not (directory / stderr).read_bytes(), 'committed GNU stderr is nonempty')
        for key in ('stdout_sha256', 'stderr_sha256'):
            commands[0].pop(key)
    require(sequences[0] == sequences[1], 'native command/provenance structure mismatch')
    return {'exact_native_files': len(native_names), 'semantic_records_equal': True,
            'provenance_exceptions': ['tool_sha256', 'tool_version', 'version stream hashes and raw version streams'],
            'tool_provenance': provenance}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, required=True, help='captured node115 data; never executed')
    parser.add_argument('--output', type=Path, required=True, help='fresh output directory')
    parser.add_argument('--objdump', required=True, help='caller-admitted installed GNU objdump')
    parser.add_argument('--check', type=Path, metavar='EXPECTED', help='compare exact native output to an earlier generated directory')
    args = parser.parse_args()
    result = collect(read_target(args.target), args.output, args.objdump)
    comparison = compare_packet(args.output, args.check) if args.check else None
    print(json.dumps({'facts': result['facts'], 'comparison': comparison}, sort_keys=True))


if __name__ == '__main__':
    main()
