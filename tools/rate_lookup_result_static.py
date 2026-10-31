#!/usr/bin/env python3
"""Node94: bounded static evidence for 0x4956d50 and its caller's result use."""
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

from artifacts import ROOT, check, digest
from elf_index import sections
from fde_extents import eh_frame_records

TARGET = 'artifacts/node/94/hl-node'
TARGET_SHA256 = '3b7179cd967d1b13b683e05debfc685ad4c750e918226402d5d575eff1c0459f'
TARGET_BYTES = 91774280
FDE_RANGES = {'lookup': (0x4956d50, 0x4956eeb), 'caller': (0x4714c10, 0x4714ffb)}
DISPLAY_RANGES = {'lookup': FDE_RANGES['lookup'], 'caller-result-use': (0x4714f17, 0x4714f66)}
CONTROLS = {
    0x4956d5a: '31c0483b077117',  # zero, compare input word, JNO
    0x4956d61: '4869471860020000',  # input index * 608
    0x4956d69: '48034708',  # plus input base
    0x4956d77: 'c3',
    0x4956e63: '488d7c2458488d742420488d9424b8020000',
    0x4956e75: 'e8a6210000',  # opaque helper
    0x4956e7a: '486944246860020000',  # stack index * 608
    0x4956e83: '4803442458',  # plus stack base
    0x4956e92: 'c3',
    0x4714f38: 'e8131e2400',
    0x4714f3d: '488d1504990101',
    0x4714f44: 'be01000000',
    0x4714f49: '4889c7',  # return word RAX to callback argument RDI
    0x4714f4c: 'f20f10442410',
    0x4714f52: 'ff1558a00501',
    0x4714f58: '31c9b001f00fb04d0075504489f0',
}
RELOCATIONS = {
    0x576e010: (8, 0x54c8cb0),
    0x576e040: (8, 0x1344760),
    0x576efb0: (8, 0x14027b0),
    0x576efc8: (8, 0x1403c30),
    0x576dfe0: (0x600000006, 0),
}
LIMITS = ('Static Node94 only. The label lookup is local shorthand, not a recovered symbol. '
          'FDEs are unwind extents, not proof of complete function boundaries. '
          'Opaque helpers, cleanup, indirect-call type, object validity, admission/TTL policy, '
          'source ownership, concurrency and runtime reachability remain unqualified. '
          'No implementation, equivalence claim, progress gate or other-target claim.')


class Image:
    def __init__(self, data):
        self.data = data
        self.sections = sections(data)

    def read(self, va, length):
        candidates = [s for s in self.sections if s['type'] != 8
                      and s['address'] <= va and va + length <= s['address'] + s['size']]
        if length < 0 or len(candidates) != 1:
            raise ValueError('Expected one file-backed selected range')
        offset = candidates[0]['offset'] + va - candidates[0]['address']
        return offset, self.data[offset:offset + length]


def controls(image):
    """Separate below-authentication controls permit real-input corruption tests."""
    for va, expected in CONTROLS.items():
        raw = bytes.fromhex(expected)
        if image.read(va, len(raw))[1] != raw:
            raise ValueError(f'Lookup-result instruction changed at {va:#x}')


def relocations(image):
    found = {}
    for section in image.sections:
        if section['type'] != 4:
            continue
        if section['size'] % 24:
            raise ValueError('Truncated RELA table')
        for offset in range(section['offset'], section['offset'] + section['size'], 24):
            slot, info, addend = struct.unpack_from('<QQq', image.data, offset)
            if slot not in RELOCATIONS:
                continue
            if slot in found or (info, addend) != RELOCATIONS[slot]:
                raise ValueError(f'Lookup-result relocation changed at {slot:#x}')
            found[slot] = {'slot_va': hex(slot), 'info': hex(info), 'addend': hex(addend),
                           'record_file_offset': hex(offset)}
    if set(found) != set(RELOCATIONS):
        raise ValueError('Missing lookup-result relocation')
    return [found[slot] for slot in sorted(found)]


def branch_targets(image):
    def rel32(va):
        return va + 5 + struct.unpack_from('<i', image.read(va, 5)[1], 1)[0]
    return {'caller_to_lookup': hex(rel32(0x4714f38)),
            'opaque_helper': hex(rel32(0x4956e75)),
            'jno_target': hex(0x4956d5f + 2 + struct.unpack('<b', image.read(0x4956d60, 1)[1])[0]),
            'callback_slot': hex(0x4714f52 + 6 + struct.unpack_from('<i', image.read(0x4714f52, 6)[1], 2)[0]),
            'caller_data_address': hex(0x4714f3d + 7 + struct.unpack_from('<i', image.read(0x4714f3d, 7)[1], 3)[0])}


def verify_listing(raw, image, start, end):
    """Require contiguous native display bytes for the exact selected range."""
    position = start
    for line in raw.splitlines():
        match = re.match(r'^\s*([0-9a-f]+):\s*((?:[0-9a-f]{2}\s+)+)', line)
        if not match:
            continue
        va = int(match[1], 16)
        body = bytes.fromhex(match[2])
        if va != position or not body or va + len(body) > end or image.read(va, len(body))[1] != body:
            raise ValueError('Noncontiguous, partial or changed selected disassembly')
        position += len(body)
    if position != end:
        raise ValueError('Incomplete selected disassembly')


def source_unchanged(binary, before, expected):
    """Source hard-link metadata may change; identity and complete bytes may not."""
    def identity(status):
        return (status.st_dev, status.st_ino, status.st_mode, status.st_size, status.st_mtime_ns)
    try:
        return identity(binary.stat()) == identity(before) and digest(binary) == expected
    except OSError:
        return False


@contextmanager
def native_snapshot(data):
    """Native readers consume only an owned, byte-bound, non-executable image."""
    expected = hashlib.sha256(data).hexdigest()
    with tempfile.TemporaryDirectory(prefix='rate-lookup-result-') as temporary:
        directory = Path(temporary)
        if stat.S_IMODE(directory.stat().st_mode) != 0o700:
            raise ValueError('Snapshot directory is not private')
        snapshot = directory / 'authenticated-input.elf'
        descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
        before = snapshot.lstat()
        if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1:
            raise ValueError('Snapshot is not an owned non-executable regular file')
        if digest(snapshot) != expected:
            raise ValueError('Snapshot differs from authenticated bytes')
        yield snapshot
        after = snapshot.lstat()
        def identity(status):
            return (status.st_dev, status.st_ino, status.st_mode, status.st_size,
                    status.st_mtime_ns, status.st_ctime_ns, status.st_nlink)
        if identity(before) != identity(after) or digest(snapshot) != expected:
            raise ValueError('Snapshot changed during static collection')


def generate(binary, output):
    if output.exists() or output.is_symlink():
        raise FileExistsError(f'Output already exists; preserve retained evidence: {output}')
    manifest = json.loads((ROOT / 'provenance/artifacts.json').read_text(encoding='utf-8'))
    identities = [i for i in manifest['files'] if i.get('path') == TARGET]
    if len(identities) != 1 or identities[0].get('sha256') != TARGET_SHA256 or identities[0].get('size') != TARGET_BYTES:
        raise ValueError('Expected the pinned Node94 manifest identity')
    before = binary.stat()
    check(binary, identities[0])
    data = binary.read_bytes()
    if len(data) != TARGET_BYTES or hashlib.sha256(data).hexdigest() != TARGET_SHA256:
        raise ValueError('Node94 bytes changed after authentication')
    image = Image(data)
    controls(image)
    selected_relocations = relocations(image)
    _, frames = eh_frame_records(data, image.sections)
    selected_frames = {}
    for name, (start, end) in FDE_RANGES.items():
        matches = [f for f in frames if (f['start'], f['end']) == (start, end)]
        if len(matches) != 1:
            raise ValueError(f'Expected one exact {name} FDE')
        offset, body = image.read(start, end - start)
        selected_frames[name] = {**{key: hex(value) if value is not None else None for key, value in matches[0].items()},
                                'file_offset': hex(offset), 'bytes': len(body),
                                'sha256': hashlib.sha256(body).hexdigest()}
    with native_snapshot(data) as snapshot:
        result, exports = native_exports(snapshot, image, selected_frames, selected_relocations)
    if not source_unchanged(binary, before, TARGET_SHA256):
        raise ValueError('Source changed during static collection')
    # Validate the snapshot and source before publishing any output. A later I/O
    # failure leaves only this newly created directory, never earlier evidence.
    output.mkdir(parents=True, exist_ok=False)
    for name, value in exports.items():
        (output / name).write_text(value, encoding='utf-8', newline='\n')
    return result


def native_exports(binary, image, selected_frames, selected_relocations):
    """Stage native text and records; the caller validates their input before writing."""
    versions = {}
    native_environment = {**os.environ, 'LC_ALL': 'C'}
    for tool in ('objdump', 'readelf'):
        versions[tool] = subprocess.check_output([tool, '--version'], encoding='utf-8',
                                                  env=native_environment).splitlines()[0]
        if not versions[tool].startswith('GNU '):
            raise ValueError(f'Expected GNU {tool}')
    frame_listing = subprocess.check_output(['readelf', '-wf', str(binary)], encoding='utf-8', env=native_environment)
    native_frames = [(int(a, 16), int(b, 16)) for a, b in re.findall(r'FDE[^\n]*pc=([0-9a-f]+)\.\.([0-9a-f]+)', frame_listing)]
    if any(native_frames.count(pair) != 1 for pair in FDE_RANGES.values()):
        raise ValueError('GNU readelf exact-FDE cross-check failed')
    displayed, exports = {}, {}
    for name, (start, end) in DISPLAY_RANGES.items():
        offset, body = image.read(start, end - start)
        raw = subprocess.check_output(['objdump', '-d', '--insn-width=16',
                                       f'--start-address={start:#x}', f'--stop-address={end:#x}', str(binary)],
                                      encoding='utf-8', env=native_environment)
        verify_listing(raw, image, start, end)
        exports[name + '.objdump.txt'] = raw.replace(str(binary), '<authenticated-node94>')
        displayed[name] = {'start_va': hex(start), 'end_va_exclusive': hex(end), 'file_offset': hex(offset),
                           'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}
    exports['frames.txt'] = '\n'.join(line for line in frame_listing.splitlines() if 'FDE' in line
        and any(f'pc={start:016x}..{end:016x}' in line for start, end in FDE_RANGES.values())) + '\n'
    relocation_listing = subprocess.check_output(['readelf', '-rW', str(binary)], encoding='utf-8', env=native_environment)
    selected_lines = [line for line in relocation_listing.splitlines()
                      if re.match(r'^[0-9a-f]+\s', line)
                      and int(line.split()[0], 16) in RELOCATIONS]
    if len(selected_lines) != len(RELOCATIONS):
        raise ValueError('GNU readelf selected-relocation cross-check failed')
    exports['relocations.txt'] = '\n'.join(selected_lines) + '\n'
    result = {'target_sha256': TARGET_SHA256, 'target_bytes': len(image.data), 'tools': versions,
              'fde_extents': selected_frames, 'displayed_ranges': displayed,
              'instruction_controls': {hex(va): value for va, value in CONTROLS.items()},
              'selected_relocations': selected_relocations, 'decoded_numeric_targets': branch_targets(image),
              'displayed_bytes': sum(row['bytes'] for row in displayed.values()),
              'captured_binary_executed': False, 'limits': LIMITS}
    exports['records.json'] = json.dumps(result, indent=2) + '\n'
    return result, exports


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT / TARGET)
    parser.add_argument('--output', type=Path, default=ROOT / 'work/rate-lookup-result-94')
    args = parser.parse_args()
    print(json.dumps(generate(args.binary.resolve(), args.output), indent=2))
