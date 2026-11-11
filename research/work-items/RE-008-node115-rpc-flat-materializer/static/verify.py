"""DRAFT: static identity/structure checker, not a target instruction evaluator.

Do not run until the coordinator admits this exact source and scope. Mutations
alter captured bytes in memory and test explicit structural obligations only.
They do not execute, emulate, or predict a captured program's runtime behavior.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import sys
import types

HERE = Path(__file__).resolve().parent
REVIEWED_HELPERS = {
    'elf_index.py': 'f142a7c03b0c2aee07d547cf93b0f6ef4b330b43ec61909d9388f340d0cdd70e',
    'fde_extents.py': '69798abfa12273bf8e3fa0be6e46dcb0a7807f2803287bbaa0916143ae527714',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def need(value, label):
    if not value:
        raise ValueError(label)


def decode_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def pinned_json(name, digest):
    path = HERE / name
    need(path.is_file() and not path.is_symlink(), 'regular pinned input:' + name)
    raw = path.read_bytes()
    need(sha(raw) == digest, 'pinned input identity:' + name)
    return decode_json(raw)


def authenticate(data, scope):
    need(len(data) == scope['target']['size'] and sha(data) == scope['target']['sha256'], 'whole captured input identity')


def load_scope(expected_sha256):
    raw = (HERE / 'scope.json').read_bytes()
    need(re.fullmatch('[0-9a-f]{64}', expected_sha256) is not None and sha(raw) == expected_sha256, 'external scope identity')
    scope = decode_json(raw)
    need(sha(Path(__file__).read_bytes()) == scope['verifier_sha256'], 'paired verifier identity')
    return scope


def load_helpers(root, scope):
    modules = {}
    # This checker needs only these two already-reviewed readers. No scope field
    # can introduce another filename, path, expected hash, or import order.
    need(scope['helpers'] == REVIEWED_HELPERS, 'fixed reviewed helper closure')
    for name, digest in REVIEWED_HELPERS.items():
        path = root / 'tools' / name
        need(path.is_file() and not path.is_symlink(), 'regular helper source')
        source = path.read_bytes()
        need(sha(source) == digest, 'reviewed helper identity: ' + name)
        module = types.ModuleType(path.stem)
        module.__file__ = str(path)
        sys.modules[path.stem] = module
        # Only exact hash-admitted MIT Python helper source reaches compile/exec.
        # Captured input bytes are passed solely as data to its pure ELF readers.
        exec(compile(source, str(path), 'exec'), module.__dict__)
        modules[path.stem] = module
    return modules


class Image:
    def __init__(self, data, sections):
        self.data, self.sections = data, sections
        need(len({s['name'] for s in sections}) == len(sections), 'unique ELF section names')
        off = struct.unpack_from('<Q', data, 32)[0]
        size, count = struct.unpack_from('<HH', data, 54)
        need(size == 56 and off + size * count <= len(data), 'ELF64 program headers')
        self.loads = [struct.unpack_from('<IIQQQQQQ', data, off + i * size) for i in range(count)]

    def offset(self, va, size):
        rows = [s for s in self.sections if s['type'] != 8 and s['address'] <= va and va + size <= s['address'] + s['size']]
        need(len(rows) == 1, 'unique backed section span')
        off = rows[0]['offset'] + va - rows[0]['address']
        other = [p[2] + va - p[3] for p in self.loads if p[0] == 1 and p[3] <= va and va + size <= p[3] + p[5]]
        need(other == [off], 'PT_LOAD/section offset agreement')
        return off

    def get(self, va, size):
        off = self.offset(va, size)
        return bytes(self.data[off:off + size])


def export_rows(raw, start, end, body):
    cursor, result = start, []
    for line in raw.decode('utf-8').splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)(.*)$', line)
        if not match:
            continue
        va, encoding, text = int(match[1], 16), bytes.fromhex(match[2]), match[3].strip()
        need(va == cursor, 'contiguous export address')
        cursor += len(encoding)
        if result and not text:
            a, old, description = result.pop()
            result.append((a, old + encoding, description))
        elif result and result[-1][1:] == (b'\xf0', 'lock'):
            a, old, description = result.pop()
            result.append((a, old + encoding, description + ' ' + text))
        else:
            result.append((va, encoding, text))
    need(cursor == end and b''.join(x[1] for x in result) == body, 'complete export/captured bytes')
    return result


def structural_census(rows, lower, upper):
    starts = {a for a, _, _ in rows}
    branches, calls, returns = [], [], []
    for address, raw, text in rows:
        after = address + len(raw)
        target = None
        if raw[0] in range(0x70, 0x80) or raw[0] == 0xeb:
            target = after + int.from_bytes(raw[-1:], 'little', signed=True)
        elif raw[0] in (0xe8, 0xe9) or raw[:1] == b'\x0f' and len(raw) == 6 and raw[1] in range(0x80, 0x90):
            target = after + int.from_bytes(raw[-4:], 'little', signed=True)
        if text.startswith('j'):
            # The selected two bodies have no indirect branch. Context may have
            # direct tails outside its FDE: retain them without claiming closure.
            need(target is not None, 'recognized structural branch encoding')
            if lower <= target < upper:
                need(target in starts, 'branch targets an instruction boundary')
            branches.append({'site': hex(address), 'bytes': raw.hex(), 'target': hex(target)})
        if text.startswith('call'):
            call = {'site': hex(address), 'bytes': raw.hex()}
            if raw[0] == 0xe8:
                call['target'] = hex(target)
            elif raw[:2] == b'\xff\x15':
                call['slot'] = hex(after + int.from_bytes(raw[2:], 'little', signed=True))
            else:
                call['register_encoding'] = raw.hex()
            calls.append(call)
        if text == 'ret':
            returns.append(hex(address))
    return {'branches': branches, 'calls': calls, 'returns': returns}


def check_facts(image, facts):
    """Exact static operands/branches/data, with no value or PC-state machine."""
    for fact in facts:
        raw = image.get(int(fact['va'], 16), len(bytes.fromhex(fact['bytes'])))
        need(raw.hex() == fact['bytes'], 'obligation:' + fact['id'])


def metadata(image, modules, scope):
    sections, index = modules['elf_index'].unwind_index(image.data)
    cies, fdes = modules['fde_extents'].eh_frame_records(image.data, sections)
    for body in scope['bodies']:
        expected = body['fde']
        matches = [f for f in fdes if f['start'] == expected['start']]
        need(matches == [expected], 'full FDE:' + body['role'])
        need(cies[expected['cie']] == body['cie'], 'CIE:' + body['role'])
        indexed = [r for r in index if r['start'] == expected['start']]
        need(len(indexed) == 1 and indexed[0]['fde'] == expected['fde'], 'unwind index/FDE:' + body['role'])
    relas = []
    for s in sections:
        if s['type'] == 4:
            need(s['size'] % 24 == 0, 'complete RELA table')
            for off in range(s['offset'], s['offset'] + s['size'], 24):
                relas.append((*struct.unpack_from('<QQq', image.data, off), off))
    for slot, expected in scope['relocations'].items():
        address = int(slot, 16)
        matches = [r for r in relas if r[0] < address + 8 and address < r[0] + 8]
        need(len(matches) == 1, 'unique overlapping RELA:' + slot)
        r = matches[0]
        need(r[:3] == (address, int(expected['info'], 16), int(expected['addend'], 16)), 'RELA fields:' + slot)
        need(r[1] >> 32 == expected['symbol_index'], 'RELA symbol index:' + slot)
        if expected['target_fde'] is not None:
            target = expected['target_fde']
            need([f for f in fdes if f['start'] == target['start']] == [target], 'opaque target FDE binding:' + slot)
    # LSDA bytes and header/table pins are structural provenance only. The scope
    # explicitly excludes interpreting action/filter tables or unwinder effects.
    for fact in scope['provenance_facts']:
        need(image.get(int(fact['va'], 16), fact['size']).hex() == fact['bytes'], 'provenance:' + fact['id'])
    return {'fde_count': len(fdes), 'rela_records': len(relas)}


def admit(root, evidence, expected_scope_sha256):
    scope = load_scope(expected_scope_sha256)
    data = (root / scope['target']['path']).read_bytes()
    authenticate(data, scope)  # Before loading project helpers or any output.
    modules = load_helpers(root, scope)
    prior = scope['credited_packet_manifest']
    manifest = (root / prior['path']).read_bytes()
    need(sha(manifest) == prior['sha256'], 'credited packet manifest identity')
    prior_entries = 0
    for line in manifest.decode().splitlines():
        digest, name = line.split(None, 1)
        relative = Path(name)
        need(not relative.is_absolute() and '..' not in relative.parts, 'bounded credited manifest path')
        need(sha((root / relative).read_bytes()) == digest, 'credited packet entry:' + name)
        prior_entries += 1
    need(prior_entries == prior['entries'], 'credited manifest entry count')
    image = Image(data, modules['elf_index'].sections(data))
    meta = metadata(image, modules, scope)
    exports, bodies = {}, []
    for body in scope['bodies']:
        lower, upper = body['fde']['start'], body['fde']['end']
        raw = image.get(lower, upper - lower)
        need(sha(raw) == body['sha256'], 'body identity:' + body['role'])
        providers = []
        for provider in body['exports']:
            base = root if provider['origin'] == 'repository' else evidence
            blob = (base / provider['path']).read_bytes()
            need(sha(blob) == provider['sha256'], 'export identity')
            providers.append(export_rows(blob, lower, upper, raw))
        need([(a, r) for a, r, _ in providers[0]] == [(a, r) for a, r, _ in providers[1]], 'GNU/LLVM partition agreement')
        need(len(providers[0]) == body['rows'], 'retained row count')
        census = structural_census(providers[0], lower, upper)
        need(census == body['census'], 'complete structural census:' + body['role'])
        exports[body['role']] = providers[0]
        bodies.append({'role': body['role'], 'bytes': len(raw), 'rows': len(providers[0]), 'sha256': sha(raw), 'credit': body['credit']})
    facts = pinned_json('obligations.json', scope['obligations_sha256'])
    check_facts(image, facts)
    return scope, data, modules, image, facts, {'metadata': meta, 'bodies': bodies}


def controls(data, modules, scope, facts):
    definitions = pinned_json('controls.json', scope['controls_sha256'])
    by_id = {f['id']: f for f in facts}
    need(len(by_id) == len(facts), 'unique obligation IDs')
    altered = bytearray(data)
    image = Image(altered, modules['elf_index'].sections(data))
    results = []
    for control in definitions:
        fact = by_id[control['obligation']]
        address = int(control['va'], 16)
        old, new = bytes.fromhex(control['before']), bytes.fromhex(control['after'])
        need(len(old) == len(new) and old != new and image.get(address, len(old)) == old, 'actual mutation preimage')
        offset = image.offset(address, len(old))
        altered[offset:offset + len(old)] = new
        caught = None
        try:
            # Deliberately bypass full-image/body/export/metadata integrity
            # guards, which would otherwise trivially reject every mutation.
            check_facts(image, [fact])
        except ValueError as error:
            caught = str(error)
        finally:
            altered[offset:offset + len(old)] = old
        need(caught == 'obligation:' + fact['id'], 'specific beneath-hash obligation rejection')
        results.append({'id': control['id'], 'obligation': fact['id'], 'layer': 'actual-byte mutation below image/body/export/FDE guards', 'rejection': caught})
    need(bytes(altered) == data, 'control input restored')
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--scope-sha256', required=True)
    parser.add_argument('--controls', action='store_true')
    args = parser.parse_args()
    need(not args.output.exists(), 'fresh output directory')
    scope, data, modules, image, facts, result = admit(args.root.resolve(), args.evidence.resolve(), args.scope_sha256)
    result['controls'] = controls(data, modules, scope, facts) if args.controls else []
    result['limits'] = 'Structural source-evidence checks only; no native evaluation, numerical oracle, Rust equivalence or helper-effect proof.'
    authenticate((args.root / scope['target']['path']).read_bytes(), scope)
    args.output.mkdir(parents=True)
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'bodies': result['bodies'], 'controls': len(result['controls'])}, indent=2))


if __name__ == '__main__':
    main()
